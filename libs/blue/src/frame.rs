//! Pure frame-to-fragment logic: assembling the Ethernet-shaped
//! `[dst][src][protocol][payload]` bytes, splitting them into fragments, and
//! (for the bare-metal backend) building each fragment's BLE AD-structure
//! bytes (see `crate::ad`).
//!
//! Shared by both backends and gated behind neither's feature: unlike the
//! radio I/O in `nrf_link.rs`/`std_link.rs`, which needs real silicon or a live
//! `bluetoothd`, this is ordinary host-testable logic — and where the two
//! backends' wire compatibility is pinned down.

use tracing::trace;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder_link_utils::FRAG_HDR_LEN;
use wayfinder_link_utils::MAX_FRAGMENTS;
use wayfinder_link_utils::pack_header;
use wayfinder_link_utils::parse_fragment;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::ad::build_ad_structure;
use crate::ad::{self};
use crate::addr::BleAddr;
use crate::mode::BleAdvFormat;

/// Fixed link-frame header length: `dst(6) + src(6) + protocol(2)`.
pub(crate) const HEADER_LEN: usize = 14;

/// Bytes of [`Mac`] carried in *every* fragment (not just the first), so a
/// fragment can be keyed for reassembly without ever having seen fragment 0.
///
/// This exists because the physical advertiser address cannot be trusted as
/// a reassembly key on this medium: `libs/blue/CLAUDE.md` documents that
/// `Privacy = device` was expected to hold one address for BlueZ's ~15-minute
/// RPA rotation timeout, but `btmon` against a real controller showed BlueZ
/// drawing a fresh random address on *every* advertising-set registration —
/// every multi-fragment message's fragments arrived under different
/// addresses, 100% of the time, so no multi-fragment message could ever
/// reassemble on that backend. Embedding the sender's own `Mac` here makes
/// reassembly correct regardless of what the medium's own address does.
pub(crate) const ORIGIN_LEN: usize = core::mem::size_of::<Mac>();

/// Bytes of [`BleAdvFormat`] tag carried at the head of *every* fragment,
/// ahead of the fragment header.
///
/// It exists because the per-fragment payload budget is a **compile-time**
/// property on the receive side: `wayfinder_link_utils::Reassembler` places a
/// fragment at `index * FRAG_PAYLOAD` with `FRAG_PAYLOAD` a const generic,
/// never a value read off the wire. A receiver therefore cannot reassemble a
/// peer's fragments unless it already knows which budget they were cut at,
/// and this byte is how it finds out — which in turn is what lets the two
/// formats be live simultaneously instead of requiring a fleet-wide cutover.
/// See `docs/design/implemented/07-ble-extended-advertising.md` §3.5.
pub(crate) const MODE_TAG_LEN: usize = 1;

/// Frame-content bytes carried by one **legacy** advertisement fragment:
/// legacy advertising's 31-byte total budget, minus our AD structure's own
/// framing, the mode tag, the fragment header, and the embedded origin. Far
/// smaller than RYLR998's (178) since legacy advertising's per-PDU budget is
/// much tighter than a LoRa packet's.
pub(crate) const FRAG_PAYLOAD_LEGACY: usize =
    ad::MAX_LEGACY_FRAGMENT_LEN - MODE_TAG_LEN - FRAG_HDR_LEN - ORIGIN_LEN;

/// Frame-content bytes carried by one **extended** advertisement fragment.
/// Roughly thirteen times [`FRAG_PAYLOAD_LEGACY`] (231 vs 18), which is what
/// collapses a full-cert OGM from 14 fragments to 2.
pub(crate) const FRAG_PAYLOAD_EXTENDED: usize =
    ad::MAX_EXTENDED_FRAGMENT_LEN - MODE_TAG_LEN - FRAG_HDR_LEN - ORIGIN_LEN;

/// Largest `[mode][frag_header][origin][body]` blob one fragment carries,
/// before any Manufacturer-Specific-Data framing is wrapped around it. Sized
/// for the **extended** case so one buffer serves both formats — a legacy
/// fragment simply uses less of it.
pub(crate) const MAX_FRAGMENT_BYTES: usize =
    MODE_TAG_LEN + FRAG_HDR_LEN + ORIGIN_LEN + FRAG_PAYLOAD_EXTENDED;

// `RawReport::len` is a `u8`, and this MR took `MAX_FRAGMENT_BYTES` from 27 to
// 240 — 16 short of the point where `n as u8` starts wrapping and every report
// claims a tiny length, giving a link that is alive and moves nothing. S140's
// 255-byte transmit maximum is openly discussed as the next place to raise
// `MAX_EXTENDED_ADV_DATA_LEN` to, so the headroom is smaller than it looks.
const _: () = assert!(
    MAX_FRAGMENT_BYTES <= u8::MAX as usize,
    "MAX_FRAGMENT_BYTES no longer fits RawReport::len's u8"
);

/// Largest reassembled frame this link will handle, in **either** format.
///
/// Bounded by the *tightest* format, not the roomiest: legacy can address at
/// most `MAX_FRAGMENTS * FRAG_PAYLOAD_LEGACY` bytes, and a single shared
/// ceiling is what keeps `BleSendMode::Both` coherent — every frame this link
/// accepts is sendable in both formats, so a `Both` sender can never emit an
/// extended copy whose legacy counterpart silently failed to fragment.
///
/// This is 270 rather than the 280 that preceded the mode tag: that byte came
/// out of `FRAG_PAYLOAD_LEGACY` (19 -> 18), taking `15 * 18 = 270` with it.
/// Still comfortably above a lazy-auth OGM (~100 bytes: header + an 8-byte
/// cert-fingerprint TVLV + a 64-byte signature TVLV, the intended shape for a
/// constrained link like this one) and above a full-cert OGM (~250 bytes)
/// with modest TVLV headroom. Design 07 §2 lists raising this as a separate,
/// later decision, now that extended reaches it in two fragments.
pub(crate) const MAX_REASSEMBLED_LEN: usize = 270;

// `Reassembler::new()` asserts this for each instantiation, but only where it
// is instantiated — which is a link's constructor, not this file. Asserting it
// here too puts the failure next to the constants whose arithmetic causes it,
// since the legacy budget is the binding one and it is the one the mode tag
// shrank.
const _: () = assert!(
    MAX_REASSEMBLED_LEN <= MAX_FRAGMENTS * FRAG_PAYLOAD_LEGACY,
    "MAX_REASSEMBLED_LEN exceeds what MAX_FRAGMENTS legacy fragments can carry"
);

/// Largest number of concurrent in-flight (incomplete) messages *each*
/// format's reassembler tracks — see `wayfinder_link_utils::Reassembler` for
/// the eviction policy this bounds. Applied per table rather than shared, so
/// a burst in one format cannot evict the other's in-flight messages.
pub(crate) const MAX_REASSEMBLIES: usize = 4;

/// The legacy format's reassembly table, keyed by the origin `Mac` embedded
/// in every fragment rather than the medium's own (unstable, on this backend)
/// advertiser address — see [`ORIGIN_LEN`].
pub(crate) type LegacyReassembler = wayfinder_link_utils::Reassembler<
    Mac,
    MAX_REASSEMBLIES,
    FRAG_PAYLOAD_LEGACY,
    MAX_REASSEMBLED_LEN,
>;

/// The extended format's reassembly table.
///
/// A **separate instantiation**, not a second instance of the same type: the
/// two differ in the `FRAG_PAYLOAD` const generic that decides where each
/// fragment's bytes land, so feeding one format's fragments to the other's
/// table would silently write them at the wrong offsets. That is precisely
/// why [`MODE_TAG_LEN`] exists.
pub(crate) type ExtendedReassembler = wayfinder_link_utils::Reassembler<
    Mac,
    MAX_REASSEMBLIES,
    FRAG_PAYLOAD_EXTENDED,
    MAX_REASSEMBLED_LEN,
>;

/// Assemble the Ethernet-shaped `[dst][src][protocol][payload]` bytes for
/// one `LinkT::send` call. Returns the buffer and the frame's actual length
/// (`<= MAX_REASSEMBLED_LEN`), or `BufferFull` if the frame doesn't fit.
pub(crate) fn assemble_frame(
    origin: Mac,
    data: &LinkFrameData<'_>,
) -> Result<([u8; MAX_REASSEMBLED_LEN], usize), LinkError> {
    let frame_len = HEADER_LEN + data.payload.len();
    if frame_len > MAX_REASSEMBLED_LEN {
        return Err(LinkError::BufferFull);
    }
    let mut frame = [0u8; MAX_REASSEMBLED_LEN];
    frame[..6].copy_from_slice(data.dst.as_bytes());
    frame[6..12].copy_from_slice(origin.as_bytes());
    frame[12..14].copy_from_slice(&data.protocol.to_be_bytes());
    frame[14..frame_len].copy_from_slice(data.payload);
    Ok((frame, frame_len))
}

/// Which fragment of which message to build, and in which format.
///
/// Grouped into a struct rather than passed as five positional parameters:
/// `msg_id`, `index` and `count` are all small integers, and transposing two
/// of them compiles cleanly while producing fragments no peer can reassemble.
/// Naming them at each call site is the cheapest defence against that.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FragmentSpec {
    /// Sender `Mac` embedded in this fragment — see [`ORIGIN_LEN`].
    pub(crate) origin: Mac,
    /// Message id shared by every fragment of one `send`.
    pub(crate) msg_id: u8,
    /// This fragment's index within the message, `0..count`.
    pub(crate) index: usize,
    /// Total fragments the message was split into **for this format**.
    pub(crate) count: usize,
    /// The on-air format this fragment is cut and framed for, which fixes its
    /// payload budget.
    pub(crate) format: BleAdvFormat,
}

/// Number of fragments `frame_len` bytes split into **for `format`**, or
/// `BufferFull` past `MAX_FRAGMENTS` — the wire format's 4-bit `count` field
/// ceiling.
///
/// The count is per-format because each format has its own payload budget:
/// the same frame is fragmented independently for each format a sender
/// transmits, never once and re-wrapped. Unreachable past `MAX_FRAGMENTS`
/// under today's `MAX_REASSEMBLED_LEN`, but checked so a change to either
/// constant fails loudly instead of corrupting the packed nibble.
pub(crate) fn fragment_count(frame_len: usize, format: BleAdvFormat) -> Result<usize, LinkError> {
    let count = frame_len.div_ceil(format.frag_payload());
    if count > MAX_FRAGMENTS {
        return Err(LinkError::BufferFull);
    }
    Ok(count)
}

/// Build the fragment `spec` names, cut at its format's payload budget — the
/// [`BleAdvFormat`] tag (see [`MODE_TAG_LEN`]), a packed fragment header (see
/// `wayfinder_link_utils::pack_header`), the origin (see [`ORIGIN_LEN`]), and
/// this fragment's slice of `frame` — into `out`, returning the number of
/// bytes written. `BufferFull` if the spec's index addresses a slice past the
/// end of `frame`.
///
/// `frame` is the assembled frame's *real* bytes, already truncated to
/// `assemble_frame`'s returned length — not the full backing array, which
/// would make every fragment past the real content read zero padding.
///
/// This is the *payload* of the Manufacturer Specific Data AD structure, not
/// the structure itself: what BlueZ wants, since it builds that framing on our
/// behalf. The bare-metal path wraps it itself — see [`build_fragment_ad`].
pub(crate) fn build_fragment(
    frame: &[u8],
    spec: FragmentSpec,
    out: &mut [u8; MAX_FRAGMENT_BYTES],
) -> Result<usize, LinkError> {
    let budget = spec.format.frag_payload();
    let start = spec.index * budget;
    let end = core::cmp::min(start + budget, frame.len());
    // `end` saturates at the frame's length, so an `index` addressing a slice
    // that starts past the frame would underflow `end - start` below.
    if start > end {
        return Err(LinkError::BufferFull);
    }

    out[0] = spec.format.tag();
    let hdr_start = MODE_TAG_LEN;
    out[hdr_start..hdr_start + FRAG_HDR_LEN].copy_from_slice(&pack_header(
        spec.msg_id,
        spec.index,
        spec.count,
    ));
    let origin_start = hdr_start + FRAG_HDR_LEN;
    out[origin_start..origin_start + ORIGIN_LEN].copy_from_slice(spec.origin.as_bytes());
    let body_start = origin_start + ORIGIN_LEN;
    out[body_start..body_start + (end - start)].copy_from_slice(&frame[start..end]);
    Ok(body_start + (end - start))
}

/// Parse `[mode][frag_header][origin][body]` off `bytes` —
/// [`build_fragment`]'s wire layout — returning the format the sender cut the
/// fragment for, the header, the embedded sender `Mac`, and the remaining
/// body.
///
/// The caller uses the returned [`BleAdvFormat`] to pick the matching
/// reassembler: the two differ in where a fragment's bytes land
/// ([`ExtendedReassembler`]), so this is not advisory.
///
/// `None` for an empty buffer, a tag naming a format this build does not know
/// (a future third format, or garbage off the air — dropped rather than
/// guessed at, since either reassembler would place its bytes wrongly), for
/// anything [`wayfinder_link_utils::parse_fragment`] itself would reject, or
/// for a fragment too short to hold [`ORIGIN_LEN`] bytes after its header.
pub(crate) fn parse_fragment_with_origin(
    bytes: &[u8],
) -> Option<(BleAdvFormat, wayfinder_link_utils::FragHeader, Mac, &[u8])> {
    let (tag, rest) = bytes.split_first()?;
    let Some(format) = BleAdvFormat::from_tag(*tag) else {
        // Distinguished from the generic "malformed fragment" drop both
        // backends log, because the two point at different faults. This byte
        // had to survive the AD structure's own length framing to get here,
        // so an unrecognised value is far more likely a peer running a build
        // with a third format than RF corruption — and "malformed" would send
        // an operator hunting the air interface instead of the fleet's
        // versions. Logged once here rather than in each backend's `recv`,
        // which is also what keeps the two from drifting.
        trace!(tag, "drop: unknown adv format tag");
        return None;
    };
    let (hdr, rest) = parse_fragment(rest)?;
    if rest.len() < ORIGIN_LEN {
        return None;
    }
    let (origin_bytes, body) = rest.split_at(ORIGIN_LEN);
    let origin = Mac::read_from_bytes(origin_bytes).ok()?;
    Some((format, hdr, origin, body))
}

/// Build the fragment `spec` names as BLE AD-structure bytes — the
/// [`build_fragment`] blob wrapped in this crate's own Manufacturer Specific
/// Data framing (see `crate::ad`) — into `out`. Returns the number of bytes
/// written, or `BufferFull` if they would exceed `format`'s own
/// advertising-data budget. Used by the bare-metal path, which hands the radio
/// a whole advertising-data buffer rather than a parsed structure — so off a
/// `hardware` build only the tests below reach it (cf. `crate::ad`).
///
/// `out` is sized for [`ad::MAX_EXTENDED_ADV_DATA_LEN`] regardless of
/// `format`, so one buffer serves both; a legacy fragment uses only the first
/// 31 bytes of it.
#[cfg_attr(not(feature = "hardware"), allow(dead_code))]
pub(crate) fn build_fragment_ad(
    frame: &[u8],
    spec: FragmentSpec,
    out: &mut [u8; ad::MAX_EXTENDED_ADV_DATA_LEN],
) -> Result<usize, LinkError> {
    let mut fragment = [0u8; MAX_FRAGMENT_BYTES];
    let n = build_fragment(frame, spec, &mut fragment)?;
    let written = build_ad_structure(&fragment[..n], out).ok_or(LinkError::BufferFull)?;
    // `out` is sized for the extended case so one buffer serves both formats,
    // which means the type no longer bounds a legacy advertisement to its own
    // 31-byte budget. Nothing below this crate does either — the SoftDevice
    // firmware rejects an oversized legacy advertisement, and BlueZ its own
    // way — so the ceiling is enforced here, at the one place both backends
    // build a fragment's advertising data.
    if written > spec.format.max_adv_data_len() {
        return Err(LinkError::BufferFull);
    }
    Ok(written)
}

/// One observed advertisement's relevant bytes, copied out of the stack that
/// reported it so it can be queued for `recv` to consume asynchronously.
///
/// Both backends need the copy, for different reasons: the SoftDevice's
/// scan-callback buffer is reused/invalidated the moment the callback
/// returns, and BlueZ hands out an owned `Vec` per property read that would
/// otherwise have to be kept alive across the queue.
pub struct RawReport {
    /// Advertiser address as reported by the scan stack. No longer the
    /// fragment-reassembly key (see [`ORIGIN_LEN`]) — kept for diagnostics
    /// only, e.g. the `"rx report"` trace line.
    pub(crate) addr: BleAddr,
    /// Received signal strength, when the reporting stack knows it — BlueZ
    /// reports none for a cached device that isn't currently in range.
    pub(crate) rssi: Option<i16>,
    /// Bytes of [`Self::data`] that are actually this report's fragment.
    ///
    /// A `u8` still suffices: [`MAX_FRAGMENT_BYTES`] is under 256 even sized
    /// for the extended format.
    pub(crate) len: u8,
    /// The `[mode][frag_header][origin][body]` blob, already stripped of
    /// whatever Manufacturer-Specific-Data framing carried it.
    ///
    /// Sized for the **extended** format, so one report type carries either.
    /// That makes a queued report nearly nine times what it was under
    /// legacy-only framing (240 bytes vs 27) — which is why both backends' report-queue depths
    /// (`REPORT_QUEUE_DEPTH`) are worth re-reading as a memory figure on the
    /// embedded side, where the queue is a `static`.
    pub(crate) data: [u8; MAX_FRAGMENT_BYTES],
}

/// Hand-written rather than derived, and deliberately omitting
/// [`RawReport::data`]: that field is frame payload, and CLAUDE.md's logging
/// rules forbid emitting payload bytes. A `#[derive(Debug)]` here would make
/// `{:?}` of a report leak them, so the constraint lives in the type rather
/// than in every call site's discipline.
impl core::fmt::Debug for RawReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawReport")
            .field("addr", &self.addr)
            .field("rssi", &self.rssi)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl RawReport {
    /// Copy `fragment` into a fixed-size `RawReport`, clamping to the
    /// buffer's capacity. A fragment recovered from a legacy, 31-byte-capped
    /// advertisement never actually exceeds this in practice, but the clamp
    /// lives here — the type's one constructor — rather than being trusted at
    /// each call site, since one of them (BlueZ) hands us a
    /// remotely-supplied, arbitrarily-long `Vec`.
    pub fn new(addr: BleAddr, rssi: Option<i16>, fragment: &[u8]) -> Self {
        let mut data = [0u8; MAX_FRAGMENT_BYTES];
        let n = fragment.len().min(data.len());
        data[..n].copy_from_slice(&fragment[..n]);
        Self {
            addr,
            rssi,
            len: n as u8,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// The `ORIGIN_LEN` length check in `parse_fragment_with_origin` is the
    /// only thing between bytes off the air and a `split_at` panic, and it is
    /// trivially reachable: any advertisement whose manufacturer data under
    /// `MESH_COMPANY_ID` is a few bytes long arrives here with `rest` shorter
    /// than a `Mac`.
    ///
    /// Pinned because the guard looks redundant — `Mac::read_from_bytes` does
    /// reject a short slice — and it is not: `split_at` runs first, and it
    /// panics rather than returning. Removing it turns any malformed or
    /// hostile advertisement into a one-packet kill of the link's `recv` task.
    #[test]
    fn parse_fragment_with_origin_rejects_a_fragment_too_short_for_its_origin() {
        // A well-formed mode tag and fragment header, then fewer than
        // `ORIGIN_LEN` bytes where the origin should be.
        for short in 0..ORIGIN_LEN {
            let mut bytes = vec![BleAdvFormat::Legacy.tag()];
            bytes.extend_from_slice(&pack_header(7, 0, 1));
            bytes.extend(core::iter::repeat_n(0xabu8, short));

            assert!(
                parse_fragment_with_origin(&bytes).is_none(),
                "a fragment with {short} origin bytes must be dropped, not panic"
            );
        }
    }

    fn spec(
        origin: Mac,
        msg_id: u8,
        index: usize,
        count: usize,
        format: BleAdvFormat,
    ) -> FragmentSpec {
        FragmentSpec {
            origin,
            msg_id,
            index,
            count,
            format,
        }
    }

    /// Both on-air formats, for the tests whose assertion is the same in
    /// either — most of them, since the mode tag is the only structural
    /// difference and the payload budget is a parameter everywhere else.
    const FORMATS: [BleAdvFormat; 2] = [BleAdvFormat::Legacy, BleAdvFormat::Extended];

    #[test]
    fn assemble_frame_lays_out_ethernet_shape() {
        let payload = [0xde, 0xad];
        let (frame, len) = assemble_frame(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
        )
        .unwrap();
        assert_eq!(len, HEADER_LEN + payload.len());
        assert_eq!(&frame[..6], &mac(2).0);
        assert_eq!(&frame[6..12], &mac(1).0);
        assert_eq!(&frame[12..14], &0x4305u16.to_be_bytes());
        assert_eq!(&frame[14..len], &payload);
    }

    #[test]
    fn assemble_frame_rejects_oversized_frame() {
        let big = [0u8; MAX_REASSEMBLED_LEN];
        let err = assemble_frame(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0,
                payload: &big,
            },
        )
        .unwrap_err();
        assert!(matches!(err, LinkError::BufferFull));
    }

    #[test]
    fn fragment_count_single_fragment_for_small_frame() {
        for format in FORMATS {
            assert_eq!(
                fragment_count(HEADER_LEN + 2, format).unwrap(),
                1,
                "{format:?}"
            );
        }
    }

    #[test]
    fn fragment_count_splits_frame_over_one_fragment_budget() {
        for format in FORMATS {
            assert_eq!(
                fragment_count(format.frag_payload() + 12, format).unwrap(),
                2,
                "{format:?}"
            );
        }
    }

    #[test]
    fn fragment_count_rejects_more_than_max_fragments() {
        // Exceeds MAX_FRAGMENTS regardless of MAX_REASSEMBLED_LEN, which
        // only `assemble_frame` (not `fragment_count` itself) enforces.
        for format in FORMATS {
            let err =
                fragment_count((MAX_FRAGMENTS + 1) * format.frag_payload(), format).unwrap_err();
            assert!(matches!(err, LinkError::BufferFull), "{format:?}");
        }
    }

    /// Design 07's headline claim, pinned as a test so a change to any of the
    /// framing constants that quietly gives back the win fails here rather
    /// than being discovered on the air. The two frame sizes are the ones
    /// §1's table costs out: a lazy-auth OGM and a full-cert OGM.
    #[test]
    fn extended_format_collapses_realistic_ogm_fragment_counts() {
        const LAZY_AUTH_OGM: usize = 100;
        const FULL_CERT_OGM: usize = 250;

        assert_eq!(
            fragment_count(LAZY_AUTH_OGM, BleAdvFormat::Legacy).unwrap(),
            6
        );
        assert_eq!(
            fragment_count(LAZY_AUTH_OGM, BleAdvFormat::Extended).unwrap(),
            1
        );

        assert_eq!(
            fragment_count(FULL_CERT_OGM, BleAdvFormat::Legacy).unwrap(),
            14
        );
        assert_eq!(
            fragment_count(FULL_CERT_OGM, BleAdvFormat::Extended).unwrap(),
            2
        );
    }

    /// The one place this design touches the *already-deployed* wire format:
    /// a legacy fragment now spends one byte on the mode tag, so its payload
    /// drops by one. Pinned because `MAX_REASSEMBLED_LEN`'s ceiling is
    /// derived from it (see the `const` assertion beside the constants).
    #[test]
    fn mode_tag_costs_exactly_one_byte_of_each_formats_payload() {
        assert_eq!(MODE_TAG_LEN, 1);
        assert_eq!(
            FRAG_PAYLOAD_LEGACY,
            ad::MAX_LEGACY_FRAGMENT_LEN - MODE_TAG_LEN - FRAG_HDR_LEN - ORIGIN_LEN
        );
        assert_eq!(
            FRAG_PAYLOAD_EXTENDED,
            ad::MAX_EXTENDED_FRAGMENT_LEN - MODE_TAG_LEN - FRAG_HDR_LEN - ORIGIN_LEN
        );
    }

    /// The tag's *values* are wire format, not an implementation detail: two
    /// backends and two firmware generations have to agree on them, so they
    /// are pinned to literals rather than to whatever the enum happens to
    /// discriminate as.
    #[test]
    fn mode_tag_byte_values_are_pinned() {
        assert_eq!(BleAdvFormat::Legacy.tag(), 0);
        assert_eq!(BleAdvFormat::Extended.tag(), 1);
        assert_eq!(BleAdvFormat::from_tag(0), Some(BleAdvFormat::Legacy));
        assert_eq!(BleAdvFormat::from_tag(1), Some(BleAdvFormat::Extended));
    }

    #[test]
    fn build_fragment_writes_the_mode_tag_as_its_first_byte() {
        let frame = [0u8; MAX_REASSEMBLED_LEN];
        for format in FORMATS {
            let mut out = [0u8; MAX_FRAGMENT_BYTES];
            let n = build_fragment(
                &frame[..HEADER_LEN],
                spec(mac(1), 0, 0, 1, format),
                &mut out,
            )
            .unwrap();
            assert_eq!(out[0], format.tag(), "{format:?}");
            assert!(n > MODE_TAG_LEN);
        }
    }

    /// A receiver that predates a future third format must drop its
    /// fragments rather than feed them to the wrong reassembler — the same
    /// fail-closed posture `parse_fragment` already takes for other
    /// malformed input off the air.
    #[test]
    fn parse_fragment_with_origin_rejects_an_unknown_mode_tag() {
        let frame = [0u8; MAX_REASSEMBLED_LEN];
        let mut out = [0u8; MAX_FRAGMENT_BYTES];
        let n = build_fragment(
            &frame[..HEADER_LEN],
            spec(mac(1), 0, 0, 1, BleAdvFormat::Legacy),
            &mut out,
        )
        .unwrap();
        assert!(parse_fragment_with_origin(&out[..n]).is_some());

        out[0] = 2;
        assert!(parse_fragment_with_origin(&out[..n]).is_none());
    }

    #[test]
    fn parse_fragment_with_origin_reports_the_format_it_read() {
        let frame = [0u8; MAX_REASSEMBLED_LEN];
        for format in FORMATS {
            let mut out = [0u8; MAX_FRAGMENT_BYTES];
            let n = build_fragment(
                &frame[..HEADER_LEN],
                spec(mac(1), 0, 0, 1, format),
                &mut out,
            )
            .unwrap();
            let (read, _, _, _) = parse_fragment_with_origin(&out[..n]).unwrap();
            assert_eq!(read, format);
        }
    }

    #[test]
    fn build_fragment_emits_raw_tag_header_origin_and_body_without_ad_framing() {
        // The BlueZ path hands BlueZ the bare `[mode][frag_header][origin]
        // [body]` blob and lets *it* build the Manufacturer-Specific-Data AD
        // structure, so this must not carry `crate::ad`'s own framing.
        let frame_len = HEADER_LEN + 3;
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        for (i, b) in frame[..frame_len].iter_mut().enumerate() {
            *b = i as u8;
        }
        for format in FORMATS {
            let mut out = [0u8; MAX_FRAGMENT_BYTES];
            let n = build_fragment(&frame[..frame_len], spec(mac(9), 5, 0, 1, format), &mut out)
                .unwrap();

            let (read, hdr, origin, body) = parse_fragment_with_origin(&out[..n]).unwrap();
            assert_eq!(read, format);
            assert_eq!((hdr.msg_id, hdr.index, hdr.count), (5, 0, 1));
            assert_eq!(origin, mac(9));
            assert_eq!(body, &frame[..frame_len]);
        }
    }

    /// The reassembly key must be derivable from *any single* fragment, not
    /// just the first — a lost fragment 0 must not strand a later fragment
    /// with no way to identify its message's sender.
    #[test]
    fn build_fragment_embeds_origin_in_every_fragment_not_just_the_first() {
        let frame = [0u8; MAX_REASSEMBLED_LEN];
        for format in FORMATS {
            let frame_len = format.frag_payload() + 12;
            let count = fragment_count(frame_len, format).unwrap();
            assert_eq!(count, 2);

            for index in 0..count {
                let mut out = [0u8; MAX_FRAGMENT_BYTES];
                let n = build_fragment(
                    &frame[..frame_len],
                    spec(mac(9), 5, index, count, format),
                    &mut out,
                )
                .unwrap();
                let (_, _, origin, _) = parse_fragment_with_origin(&out[..n]).unwrap();
                assert_eq!(origin, mac(9), "{format:?} fragment {index}");
            }
        }
    }

    #[test]
    fn build_fragment_and_build_fragment_ad_agree_on_the_wire() {
        // The two transmit paths (BlueZ-framed and self-framed) must put
        // byte-identical fragments on the air, or an nRF node and a Linux
        // node could not talk to each other. Run per format, since each has
        // its own fragmentation and its own tag byte.
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = i as u8;
        }
        for format in FORMATS {
            let frame_len = format.frag_payload() + 12;
            let count = fragment_count(frame_len, format).unwrap();

            for index in 0..count {
                let mut raw = [0u8; MAX_FRAGMENT_BYTES];
                let raw_n = build_fragment(
                    &frame[..frame_len],
                    spec(mac(7), 7, index, count, format),
                    &mut raw,
                )
                .unwrap();

                let mut framed = [0u8; ad::MAX_EXTENDED_ADV_DATA_LEN];
                let framed_n = build_fragment_ad(
                    &frame[..frame_len],
                    spec(mac(7), 7, index, count, format),
                    &mut framed,
                )
                .unwrap();

                assert_eq!(
                    ad::find_mesh_fragment(&framed[..framed_n]),
                    Some(&raw[..raw_n]),
                    "{format:?} fragment {index}"
                );
            }
        }
    }

    /// Nothing below this crate enforces the legacy budget — the SoftDevice
    /// firmware rejects an oversized legacy advertisement, and BlueZ its own
    /// way — so the ceiling has to hold here. Now that the output buffer is
    /// sized for the *extended* case, an arithmetic slip in the legacy path
    /// would otherwise be caught by neither the type nor the compiler.
    #[test]
    fn build_fragment_ad_stays_within_the_legacy_budget_in_legacy_format() {
        let frame = [0xabu8; MAX_REASSEMBLED_LEN];
        let format = BleAdvFormat::Legacy;
        let frame_len = MAX_REASSEMBLED_LEN;
        let count = fragment_count(frame_len, format).unwrap();

        for index in 0..count {
            let mut framed = [0u8; ad::MAX_EXTENDED_ADV_DATA_LEN];
            let n = build_fragment_ad(
                &frame[..frame_len],
                spec(mac(1), 0, index, count, format),
                &mut framed,
            )
            .unwrap();
            assert!(
                n <= ad::MAX_LEGACY_ADV_DATA_LEN,
                "fragment {index} framed to {n} bytes, past legacy's {} byte budget",
                ad::MAX_LEGACY_ADV_DATA_LEN
            );
        }
    }

    #[test]
    fn build_fragment_ad_stays_within_the_extended_budget_in_extended_format() {
        let frame = [0xabu8; MAX_REASSEMBLED_LEN];
        let format = BleAdvFormat::Extended;
        let frame_len = MAX_REASSEMBLED_LEN;
        let count = fragment_count(frame_len, format).unwrap();

        for index in 0..count {
            let mut framed = [0u8; ad::MAX_EXTENDED_ADV_DATA_LEN];
            let n = build_fragment_ad(
                &frame[..frame_len],
                spec(mac(1), 0, index, count, format),
                &mut framed,
            )
            .unwrap();
            assert!(n <= ad::MAX_EXTENDED_ADV_DATA_LEN, "fragment {index}: {n}");
        }
    }

    #[test]
    fn build_fragment_rejects_an_index_past_the_frame() {
        for format in FORMATS {
            let mut out = [0u8; MAX_FRAGMENT_BYTES];
            let err = build_fragment(
                &[0u8; MAX_REASSEMBLED_LEN][..HEADER_LEN],
                spec(mac(1), 0, 3, 4, format),
                &mut out,
            )
            .unwrap_err();
            assert!(matches!(err, LinkError::BufferFull), "{format:?}");
        }
    }

    #[test]
    fn build_fragment_ad_round_trips_single_fragment() {
        let frame_len = HEADER_LEN + 3;
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        for (i, b) in frame[..frame_len].iter_mut().enumerate() {
            *b = i as u8;
        }
        for format in FORMATS {
            let mut out = [0u8; ad::MAX_EXTENDED_ADV_DATA_LEN];
            let n = build_fragment_ad(&frame[..frame_len], spec(mac(9), 5, 0, 1, format), &mut out)
                .unwrap();

            let fragment = ad::find_mesh_fragment(&out[..n]).unwrap();
            let (read, hdr, origin, body) = parse_fragment_with_origin(fragment).unwrap();
            assert_eq!(read, format);
            assert_eq!((hdr.msg_id, hdr.index, hdr.count), (5, 0, 1));
            assert_eq!(origin, mac(9));
            assert_eq!(body, &frame[..frame_len]);
        }
    }

    #[test]
    fn build_fragment_ad_splits_across_multiple_fragments() {
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = i as u8;
        }
        for format in FORMATS {
            let budget = format.frag_payload();
            let frame_len = budget + 12;
            let count = fragment_count(frame_len, format).unwrap();
            assert_eq!(count, 2);

            let mut out0 = [0u8; ad::MAX_EXTENDED_ADV_DATA_LEN];
            let n0 = build_fragment_ad(
                &frame[..frame_len],
                spec(mac(9), 9, 0, count, format),
                &mut out0,
            )
            .unwrap();
            let (_, hdr0, origin0, body0) =
                parse_fragment_with_origin(ad::find_mesh_fragment(&out0[..n0]).unwrap()).unwrap();
            assert_eq!((hdr0.index, hdr0.count), (0, 2));
            assert_eq!(origin0, mac(9));
            assert_eq!(body0, &frame[..budget]);

            let mut out1 = [0u8; ad::MAX_EXTENDED_ADV_DATA_LEN];
            let n1 = build_fragment_ad(
                &frame[..frame_len],
                spec(mac(9), 9, 1, count, format),
                &mut out1,
            )
            .unwrap();
            let (_, hdr1, origin1, body1) =
                parse_fragment_with_origin(ad::find_mesh_fragment(&out1[..n1]).unwrap()).unwrap();
            assert_eq!((hdr1.index, hdr1.count), (1, 2));
            assert_eq!(origin1, mac(9));
            assert_eq!(body1, &frame[budget..frame_len]);
        }
    }
}
