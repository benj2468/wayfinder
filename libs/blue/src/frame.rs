//! Pure frame-to-fragment logic: assembling the Ethernet-shaped
//! `[dst][src][protocol][payload]` bytes, splitting them into fragments, and
//! (for the bare-metal backend) building each fragment's BLE AD-structure
//! bytes (see `crate::ad`).
//!
//! Shared by both backends and gated behind neither's feature: unlike the
//! radio I/O in `nrf_link.rs`/`std_link.rs`, which needs real silicon or a live
//! `bluetoothd`, this is ordinary host-testable logic — and where the two
//! backends' wire compatibility is pinned down.

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

/// Frame-content bytes carried by one BLE advertisement fragment: legacy
/// advertising's 31-byte total budget, minus our AD structure's own framing,
/// the fragment header, and the embedded origin. Far smaller than RYLR998's
/// (178) since legacy advertising's per-PDU budget is much tighter than a
/// LoRa packet's — see `libs/blue/CLAUDE.md` on why extended advertising
/// isn't used instead.
pub(crate) const FRAG_PAYLOAD: usize = ad::MAX_LEGACY_FRAGMENT_LEN - FRAG_HDR_LEN - ORIGIN_LEN;

/// Largest `[frag_header][origin][body]` blob one fragment carries, before
/// any Manufacturer-Specific-Data framing is wrapped around it. Sized for
/// [`build_fragment`]'s output buffer.
pub(crate) const MAX_FRAGMENT_BYTES: usize = FRAG_HDR_LEN + ORIGIN_LEN + FRAG_PAYLOAD;

/// Largest reassembled frame this link will handle. Below RYLR998's 512
/// since each fragment here carries far less, and capped by
/// `Reassembler::new()`'s `MAX_REASSEMBLED_LEN <= MAX_FRAGMENTS *
/// FRAG_PAYLOAD` check (15 * 19 = 285) now that [`ORIGIN_LEN`] eats into
/// `FRAG_PAYLOAD` — comfortably above a lazy-auth OGM (~100 bytes: header +
/// an 8-byte cert-fingerprint TVLV + a 64-byte signature TVLV, the intended
/// shape for a constrained link like this one), tighter than a full-cert OGM
/// (~250 bytes) but still enough for one with modest TVLV headroom.
pub(crate) const MAX_REASSEMBLED_LEN: usize = 280;

/// Largest number of concurrent in-flight (incomplete) messages the
/// reassembler tracks — see `wayfinder_link_utils::Reassembler` for the
/// eviction policy this bounds.
pub(crate) const MAX_REASSEMBLIES: usize = 4;

/// This link's reassembly table, keyed by the origin `Mac` embedded in every
/// fragment rather than the medium's own (unstable, on this backend)
/// advertiser address — see [`ORIGIN_LEN`].
pub(crate) type Reassembler =
    wayfinder_link_utils::Reassembler<Mac, MAX_REASSEMBLIES, FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>;

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

/// Number of fragments `frame_len` bytes split into, or `BufferFull` past
/// `MAX_FRAGMENTS` — the wire format's 4-bit `count` field ceiling.
/// Unreachable under today's `MAX_REASSEMBLED_LEN`, but checked so a change to
/// either constant fails loudly instead of corrupting the packed nibble.
pub(crate) fn fragment_count(frame_len: usize) -> Result<usize, LinkError> {
    let count = frame_len.div_ceil(FRAG_PAYLOAD);
    if count > MAX_FRAGMENTS {
        return Err(LinkError::BufferFull);
    }
    Ok(count)
}

/// Build fragment `index` of `count`'s bare on-air bytes — a packed fragment
/// header (see `wayfinder_link_utils::pack_header`), `origin` (see
/// [`ORIGIN_LEN`]), and this fragment's slice of `frame[..frame_len]` — into
/// `out`, returning the number of bytes written. `BufferFull` if `index`
/// addresses a slice past the end of the frame.
///
/// This is the *payload* of the Manufacturer Specific Data AD structure, not
/// the structure itself: what BlueZ wants, since it builds that framing on our
/// behalf. The bare-metal path wraps it itself — see [`build_fragment_ad`].
pub(crate) fn build_fragment(
    frame: &[u8],
    frame_len: usize,
    origin: Mac,
    msg_id: u8,
    index: usize,
    count: usize,
    out: &mut [u8; MAX_FRAGMENT_BYTES],
) -> Result<usize, LinkError> {
    let start = index * FRAG_PAYLOAD;
    let end = core::cmp::min(start + FRAG_PAYLOAD, frame_len);
    // `end` saturates at `frame_len`, so an `index` addressing a slice that
    // starts past the frame would underflow `end - start` below.
    if start > end {
        return Err(LinkError::BufferFull);
    }

    out[..FRAG_HDR_LEN].copy_from_slice(&pack_header(msg_id, index, count));
    out[FRAG_HDR_LEN..FRAG_HDR_LEN + ORIGIN_LEN].copy_from_slice(origin.as_bytes());
    let body_start = FRAG_HDR_LEN + ORIGIN_LEN;
    out[body_start..body_start + (end - start)].copy_from_slice(&frame[start..end]);
    Ok(body_start + (end - start))
}

/// Parse `[frag_header][origin][body]` off `bytes` — [`build_fragment`]'s
/// wire layout — returning the header, the embedded sender `Mac`, and the
/// remaining body. `None` for anything [`wayfinder_link_utils::parse_fragment`]
/// itself would reject, or a fragment too short to hold [`ORIGIN_LEN`] bytes
/// after its header.
pub(crate) fn parse_fragment_with_origin(
    bytes: &[u8],
) -> Option<(wayfinder_link_utils::FragHeader, Mac, &[u8])> {
    let (hdr, rest) = parse_fragment(bytes)?;
    if rest.len() < ORIGIN_LEN {
        return None;
    }
    let (origin_bytes, body) = rest.split_at(ORIGIN_LEN);
    let origin = Mac::read_from_bytes(origin_bytes).ok()?;
    Some((hdr, origin, body))
}

/// Build fragment `index` of `count`'s BLE AD-structure bytes — the
/// [`build_fragment`] blob wrapped in this crate's own Manufacturer Specific
/// Data framing (see `crate::ad`) — into `out`. Returns the number of bytes
/// written. Used by the bare-metal path, which hands the radio a whole
/// advertising-data buffer rather than a parsed structure — so off a
/// `hardware` build only the tests below reach it (cf. `crate::ad`).
#[cfg_attr(not(feature = "hardware"), allow(dead_code))]
pub(crate) fn build_fragment_ad(
    frame: &[u8],
    frame_len: usize,
    origin: Mac,
    msg_id: u8,
    index: usize,
    count: usize,
    out: &mut [u8; ad::MAX_LEGACY_ADV_DATA_LEN],
) -> Result<usize, LinkError> {
    let mut fragment = [0u8; MAX_FRAGMENT_BYTES];
    let n = build_fragment(
        frame,
        frame_len,
        origin,
        msg_id,
        index,
        count,
        &mut fragment,
    )?;
    build_ad_structure(&fragment[..n], out).ok_or(LinkError::BufferFull)
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
    pub(crate) len: u8,
    /// The `[frag_header][body]` blob, already stripped of whatever
    /// Manufacturer-Specific-Data framing carried it.
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
        assert_eq!(fragment_count(HEADER_LEN + 2).unwrap(), 1);
    }

    #[test]
    fn fragment_count_splits_frame_over_one_fragment_budget() {
        assert_eq!(fragment_count(FRAG_PAYLOAD + 12).unwrap(), 2);
    }

    #[test]
    fn fragment_count_rejects_more_than_max_fragments() {
        // Exceeds MAX_FRAGMENTS regardless of MAX_REASSEMBLED_LEN, which
        // only `assemble_frame` (not `fragment_count` itself) enforces.
        let err = fragment_count((MAX_FRAGMENTS + 1) * FRAG_PAYLOAD).unwrap_err();
        assert!(matches!(err, LinkError::BufferFull));
    }

    #[test]
    fn build_fragment_emits_raw_header_origin_and_body_without_ad_framing() {
        // The BlueZ path hands BlueZ the bare `[frag_header][origin][body]`
        // blob and lets *it* build the Manufacturer-Specific-Data AD
        // structure, so this must not carry `crate::ad`'s own framing.
        let frame_len = HEADER_LEN + 3;
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        for (i, b) in frame[..frame_len].iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut out = [0u8; MAX_FRAGMENT_BYTES];
        let n = build_fragment(&frame, frame_len, mac(9), 5, 0, 1, &mut out).unwrap();

        let (hdr, origin, body) = parse_fragment_with_origin(&out[..n]).unwrap();
        assert_eq!((hdr.msg_id, hdr.index, hdr.count), (5, 0, 1));
        assert_eq!(origin, mac(9));
        assert_eq!(body, &frame[..frame_len]);
    }

    /// The reassembly key must be derivable from *any single* fragment, not
    /// just the first — a lost fragment 0 must not strand a later fragment
    /// with no way to identify its message's sender.
    #[test]
    fn build_fragment_embeds_origin_in_every_fragment_not_just_the_first() {
        let frame_len = FRAG_PAYLOAD + 12;
        let frame = [0u8; MAX_REASSEMBLED_LEN];
        let count = fragment_count(frame_len).unwrap();
        assert_eq!(count, 2);

        for index in 0..count {
            let mut out = [0u8; MAX_FRAGMENT_BYTES];
            let n = build_fragment(&frame, frame_len, mac(9), 5, index, count, &mut out).unwrap();
            let (_, origin, _) = parse_fragment_with_origin(&out[..n]).unwrap();
            assert_eq!(origin, mac(9), "fragment {index} must carry the origin");
        }
    }

    #[test]
    fn build_fragment_and_build_fragment_ad_agree_on_the_wire() {
        // The two transmit paths (BlueZ-framed and self-framed) must put
        // byte-identical fragments on the air, or an nRF node and a Linux
        // node could not talk to each other.
        let frame_len = FRAG_PAYLOAD + 12;
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        for (i, b) in frame[..frame_len].iter_mut().enumerate() {
            *b = i as u8;
        }
        let count = fragment_count(frame_len).unwrap();

        for index in 0..count {
            let mut raw = [0u8; MAX_FRAGMENT_BYTES];
            let raw_n =
                build_fragment(&frame, frame_len, mac(7), 7, index, count, &mut raw).unwrap();

            let mut framed = [0u8; ad::MAX_LEGACY_ADV_DATA_LEN];
            let framed_n =
                build_fragment_ad(&frame, frame_len, mac(7), 7, index, count, &mut framed).unwrap();

            assert_eq!(
                ad::find_mesh_fragment(&framed[..framed_n]),
                Some(&raw[..raw_n])
            );
        }
    }

    #[test]
    fn build_fragment_rejects_an_index_past_the_frame() {
        let mut out = [0u8; MAX_FRAGMENT_BYTES];
        let err = build_fragment(
            &[0u8; MAX_REASSEMBLED_LEN],
            HEADER_LEN,
            mac(1),
            0,
            3,
            4,
            &mut out,
        )
        .unwrap_err();
        assert!(matches!(err, LinkError::BufferFull));
    }

    #[test]
    fn build_fragment_ad_round_trips_single_fragment() {
        let frame_len = HEADER_LEN + 3;
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        for (i, b) in frame[..frame_len].iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut out = [0u8; ad::MAX_LEGACY_ADV_DATA_LEN];
        let n = build_fragment_ad(&frame, frame_len, mac(9), 5, 0, 1, &mut out).unwrap();

        let fragment = ad::find_mesh_fragment(&out[..n]).unwrap();
        let (hdr, origin, body) = parse_fragment_with_origin(fragment).unwrap();
        assert_eq!((hdr.msg_id, hdr.index, hdr.count), (5, 0, 1));
        assert_eq!(origin, mac(9));
        assert_eq!(body, &frame[..frame_len]);
    }

    #[test]
    fn build_fragment_ad_splits_across_multiple_fragments() {
        let frame_len = FRAG_PAYLOAD + 12;
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        for (i, b) in frame[..frame_len].iter_mut().enumerate() {
            *b = i as u8;
        }
        let count = fragment_count(frame_len).unwrap();
        assert_eq!(count, 2);

        let mut out0 = [0u8; ad::MAX_LEGACY_ADV_DATA_LEN];
        let n0 = build_fragment_ad(&frame, frame_len, mac(9), 9, 0, count, &mut out0).unwrap();
        let (hdr0, origin0, body0) =
            parse_fragment_with_origin(ad::find_mesh_fragment(&out0[..n0]).unwrap()).unwrap();
        assert_eq!((hdr0.index, hdr0.count), (0, 2));
        assert_eq!(origin0, mac(9));
        assert_eq!(body0, &frame[..FRAG_PAYLOAD]);

        let mut out1 = [0u8; ad::MAX_LEGACY_ADV_DATA_LEN];
        let n1 = build_fragment_ad(&frame, frame_len, mac(9), 9, 1, count, &mut out1).unwrap();
        let (hdr1, origin1, body1) =
            parse_fragment_with_origin(ad::find_mesh_fragment(&out1[..n1]).unwrap()).unwrap();
        assert_eq!((hdr1.index, hdr1.count), (1, 2));
        assert_eq!(origin1, mac(9));
        assert_eq!(body1, &frame[FRAG_PAYLOAD..frame_len]);
    }
}
