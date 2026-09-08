#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! Hardware-agnostic framing for IEEE 802.15.4 mesh interfaces.
//!
//! This crate handles only the on-air frame shape: cutting a Wayfinder
//! [`LinkFrame`] into fragments, each wrapped in a minimal IEEE 802.15.4 MAC
//! header, and reassembling them on receive. It has no opinion about which
//! radio chip or HAL drives the actual transmit/receive — a `LinkT` impl for a
//! specific radio (`nrf-ieee802154`, `at86rf233`) is built on top of the
//! pieces here.
//!
//! Like the RYLR998 LoRa link, IEEE 802.15.4 is treated as a shared broadcast
//! medium: every fragment is addressed to the 802.15.4 broadcast PAN and
//! destination address, and the mesh layer filters on the 6-byte [`Mac`]
//! embedded in the reassembled [`LinkFrame`] rather than on 802.15.4-level
//! addressing.
//!
//! # Why fragmentation
//!
//! `aMaxPHYPacketSize` is 127 bytes, so one frame carries at most
//! [`FRAG_PAYLOAD`] (114) bytes of mesh frame after the MAC and fragment
//! headers. A full-cert OGM is around 250 bytes and the `nrf52840` capacity
//! profile's `max_frame_len` is 512, so a single-frame link could not carry
//! the traffic this mesh actually generates. Fragmentation reuses the shared
//! [`wayfinder_link_utils`] machinery, as `rylr998` and `blue` do.
//!
//! # The reassembly key is a real source address
//!
//! Fragments are keyed on the 16-bit **short source address** in the MAC
//! header ([`FragKey`]), not on anything embedded in the fragment body. This
//! is the one place worth contrasting with `libs/blue`: BLE draws a fresh
//! random advertiser address on *every* advertising-set registration, so no
//! multi-fragment message's fragments ever share an address, and that crate
//! has to spend 6 bytes per fragment carrying the sender's `Mac` instead.
//! 802.15.4 has a stable source address field this crate controls, so the key
//! costs 2 bytes.
//!
//! The address is [`short_address_of`] — the low 16 bits of the sender's mesh
//! [`Mac`]. **Two nodes whose MACs share their low 16 bits will corrupt each
//! other's reassembly**, the same deployment constraint `rylr998` documents
//! for its configured `AT+ADDRESS`. It costs dropped frames, never
//! misattributed ones: the authenticated mesh `Mac` travels *inside* the
//! reassembled [`LinkFrame`], so a corrupted reassembly fails the
//! `LinkFrame` parse or the signature check rather than arriving under the
//! wrong sender. See `docs/design/implemented/19-ieee802154-nrf-link.md` §5.3.

use interfaces::frame::LinkFrame;
use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;
use interfaces::link::LinkError;
use interfaces::link::LinkMetrics;
use tracing::trace;
use wayfinder_link_utils::FRAG_HDR_LEN;
use wayfinder_link_utils::FragHeader;
use wayfinder_link_utils::FragKey;
use wayfinder_link_utils::MAX_FRAGMENTS;
use wayfinder_link_utils::Reassembler;
use wayfinder_link_utils::pack_header;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::byteorder::little_endian::U16;

/// IEEE 802.15.4 Frame Control Field, frame type sub-field (bits 0-2): a Data
/// frame.
pub const FRAME_TYPE_DATA: u16 = 0b001;

/// IEEE 802.15.4 Frame Control Field, PAN ID compression (bit 6): the source
/// PAN ID is omitted because it equals the destination's. Both are the
/// broadcast PAN, so carrying it twice would waste two bytes of every
/// fragment.
pub const PAN_ID_COMPRESSION: u16 = 1 << 6;

/// IEEE 802.15.4 Frame Control Field, destination addressing mode sub-field
/// (bits 10-11): a 16-bit short address follows.
pub const DEST_ADDR_MODE_SHORT: u16 = 0b10 << 10;

/// IEEE 802.15.4 Frame Control Field, source addressing mode sub-field
/// (bits 14-15): a 16-bit short address follows.
pub const SRC_ADDR_MODE_SHORT: u16 = 0b10 << 14;

/// Frame Control Field written by [`build_fragment`] and required by
/// [`decode_fragment`]: `0x8841` — a Data frame with 16-bit short source and
/// destination addressing, PAN ID compression, and no security or
/// acknowledgement request.
pub const FRAME_CONTROL: u16 =
    FRAME_TYPE_DATA | PAN_ID_COMPRESSION | DEST_ADDR_MODE_SHORT | SRC_ADDR_MODE_SHORT;

/// IEEE 802.15.4 broadcast PAN ID and short address (`0xffff`).
/// [`build_fragment`] always targets this address; the radio is physically a
/// shared medium, like LoRa, so mesh addressing is done by the [`Mac`]
/// embedded in the reassembled frame instead.
pub const BROADCAST_ADDR: u16 = 0xffff;

/// Minimal IEEE 802.15.4 MAC header for a broadcast data frame: Frame Control
/// Field, sequence number, destination PAN ID, destination address, and
/// source address. The source PAN ID is omitted under
/// [`PAN_ID_COMPRESSION`]. All multi-byte fields are little-endian, per the
/// IEEE 802.15.4 wire format.
///
/// The 2-byte FCS that radio hardware appends on transmit and strips on
/// receive is *not* part of this struct or any buffer this crate produces.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Ieee802154Header {
    /// Frame type, addressing modes, and other control bits. Always
    /// [`FRAME_CONTROL`] for frames this crate produces.
    pub frame_control: U16,
    /// IEEE 802.15.4 MAC sequence number, set by the caller of
    /// [`build_fragment`].
    pub seq: u8,
    /// Destination PAN ID. Always [`BROADCAST_ADDR`].
    pub dest_pan_id: U16,
    /// Destination short address. Always [`BROADCAST_ADDR`].
    pub dest_addr: U16,
    /// Sender's short address — the reassembly key. See the module docs.
    pub src_addr: U16,
}

/// Size in bytes of [`Ieee802154Header`] (9).
pub const HEADER_LEN: usize = core::mem::size_of::<Ieee802154Header>();

/// IEEE 802.15.4's `aMaxPHYPacketSize`: the largest PHY payload, including the
/// 2-byte FCS appended by radio hardware.
const MAX_PHY_PACKET_SIZE: usize = 127;

/// Length of the FCS that radio hardware appends on transmit and strips on
/// receive; not part of any buffer this crate produces or accepts.
const FCS_LEN: usize = 2;

/// Largest buffer [`build_fragment`] will write or [`decode_fragment`] will
/// accept: `aMaxPHYPacketSize` minus the hardware-handled FCS.
pub const MAX_FRAME_LEN: usize = MAX_PHY_PACKET_SIZE - FCS_LEN;

/// Length of the `[dst][src][protocol]` header that prefixes every
/// [`LinkFrame`] (6 + 6 + 2 bytes).
pub const LINK_HEADER_LEN: usize = 14;

/// Frame-content bytes one fragment carries, once the MAC header and the
/// fragment header are subtracted: `125 - 9 - 2`.
///
/// A **compile-time property of the format, never carried on the wire** —
/// [`Reassembler`] places a fragment's bytes at `index * FRAG_PAYLOAD`, so
/// both ends must already agree on the budget. Changing it is a wire-format
/// break.
pub const FRAG_PAYLOAD: usize = MAX_FRAME_LEN - HEADER_LEN - FRAG_HDR_LEN;

/// Largest frame this link can reassemble, matching the `nrf52840` capacity
/// profile's `max_frame_len` — the router will not hand this link anything
/// bigger, and cannot accept anything bigger from it.
pub const MAX_REASSEMBLED_LEN: usize = 512;

/// Concurrent in-flight reassemblies tracked, matching `blue`'s. A fifth
/// sender evicts the oldest incomplete message rather than failing.
pub const MAX_REASSEMBLIES: usize = 4;

/// Largest mesh-frame payload [`assemble_frame`] will accept:
/// [`MAX_REASSEMBLED_LEN`] minus the [`LinkFrame`] header.
pub const MAX_PAYLOAD_LEN: usize = MAX_REASSEMBLED_LEN - LINK_HEADER_LEN;

/// The reassembly table an 802.15.4 `LinkT` adapter owns, keyed on the
/// 16-bit short source address. See the module docs for why that is the key.
pub type Ieee802154Reassembler =
    Reassembler<u16, MAX_REASSEMBLIES, FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>;

/// The 16-bit short source address a node transmits under: the low two bytes
/// of its mesh [`Mac`], big-endian.
///
/// Shared so a board's 802.15.4 and LoRa links derive the same short identity
/// from the same `Mac` rather than each rolling their own.
pub fn short_address_of(mac: Mac) -> u16 {
    u16::from_be_bytes([mac.0[4], mac.0[5]])
}

/// Which fragment of which message [`build_fragment`] should cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentSpec {
    /// IEEE 802.15.4 MAC sequence number for this frame. Advisory metadata
    /// for a sniffer; reassembly uses `msg_id` instead, since the MAC seqno
    /// is per-*frame* and every fragment of a message needs a shared id.
    pub seq: u8,
    /// The sender's short address — see [`short_address_of`].
    pub src_addr: u16,
    /// Sender-chosen message id, one per logical frame, wrapping.
    pub msg_id: u8,
    /// This fragment's index, `0..count`.
    pub index: usize,
    /// Total fragments in this message, from [`fragment_count`].
    pub count: usize,
}

/// Write the `[dst][src][protocol][payload]` [`LinkFrame`] bytes for `data`
/// sent from `origin` into `out`, returning the number of bytes written.
///
/// This is the input to fragmentation, not something that goes on air by
/// itself: the caller fragments the returned prefix of `out` with
/// [`fragment_count`] and [`build_fragment`].
///
/// Returns [`LinkError::BufferFull`] if `data.payload` exceeds
/// [`MAX_PAYLOAD_LEN`] or `out` is too small to hold the frame.
pub fn assemble_frame(
    origin: Mac,
    data: &LinkFrameData<'_>,
    out: &mut [u8],
) -> Result<usize, LinkError> {
    if data.payload.len() > MAX_PAYLOAD_LEN {
        return Err(LinkError::BufferFull);
    }
    let total = LINK_HEADER_LEN + data.payload.len();
    if out.len() < total {
        return Err(LinkError::BufferFull);
    }

    out[..6].copy_from_slice(&data.dst.0);
    out[6..12].copy_from_slice(&origin.0);
    out[12..14].copy_from_slice(&data.protocol.to_be_bytes());
    out[14..total].copy_from_slice(data.payload);
    Ok(total)
}

/// Number of fragments a `frame_len`-byte frame splits into, or
/// [`LinkError::BufferFull`] past [`MAX_FRAGMENTS`] — the wire format's 4-bit
/// `count` field ceiling.
///
/// Unreachable past `MAX_FRAGMENTS` under today's [`MAX_REASSEMBLED_LEN`]
/// (512 bytes is five fragments), but checked so a change to either constant
/// fails loudly instead of corrupting the packed nibble.
pub fn fragment_count(frame_len: usize) -> Result<usize, LinkError> {
    // `.max(1)`: a zero-length frame is not something `assemble_frame` can
    // produce, but `pack_header` debug-asserts `count >= 1`, so a caller
    // computing a count for an empty slice gets a valid single fragment
    // rather than a debug panic.
    let count = frame_len.div_ceil(FRAG_PAYLOAD).max(1);
    if count > MAX_FRAGMENTS {
        return Err(LinkError::BufferFull);
    }
    Ok(count)
}

/// Build the fragment `spec` names — an [`Ieee802154Header`], a packed
/// fragment header (see [`pack_header`]), and this fragment's slice of
/// `frame` — into `out`, returning the number of bytes written.
///
/// `frame` is [`assemble_frame`]'s output truncated to its returned length,
/// not the full backing array: every fragment past the real content would
/// otherwise carry zero padding.
///
/// Returns [`LinkError::InvalidPacket`] for a spec that could not describe a
/// real fragment — `count` outside `1..=MAX_FRAGMENTS`, or `index` not below
/// `count`. Those are checked here rather than left to `pack_header`'s
/// `debug_assert!`s, which are compiled out of the release firmware that
/// ships: a transposed index/count otherwise packs a nibble pair every
/// receiver rejects, so the sender spends airtime and nothing is ever
/// reassembled.
///
/// Returns [`LinkError::BufferFull`] if `spec.index` addresses a slice
/// starting past the end of `frame`, or if `out` is too small (it never is
/// for a `[u8; MAX_FRAME_LEN]`, which one full fragment exactly fills).
pub fn build_fragment(
    frame: &[u8],
    spec: FragmentSpec,
    out: &mut [u8],
) -> Result<usize, LinkError> {
    // `pack_header`'s own `index`/`count` checks are `debug_assert!`, so they
    // are compiled out of the release firmware that actually ships. Checked
    // here instead: a transposed index/count packs a nibble pair every
    // receiver rejects, which presents as a link that transmits, reports
    // bytes sent, and delivers nothing — on a board with no probe attached.
    if !(1..=MAX_FRAGMENTS).contains(&spec.count) || spec.index >= spec.count {
        return Err(LinkError::InvalidPacket);
    }

    // `checked_*` rather than plain arithmetic: on a 32-bit target a huge
    // `index` would wrap to a small *valid-looking* offset and cut the wrong
    // slice, which is worse than refusing. Unreachable through
    // `fragment_count`, but this is a `pub` entry point third-party drivers
    // are told to call with a spec they built themselves.
    let start = spec
        .index
        .checked_mul(FRAG_PAYLOAD)
        .ok_or(LinkError::InvalidPacket)?;
    let end = core::cmp::min(
        start
            .checked_add(FRAG_PAYLOAD)
            .ok_or(LinkError::InvalidPacket)?,
        frame.len(),
    );
    // `end` saturates at the frame's length, so an `index` addressing a slice
    // that starts past the frame would underflow `end - start` below.
    if start > end {
        return Err(LinkError::BufferFull);
    }
    let total = HEADER_LEN + FRAG_HDR_LEN + (end - start);
    if out.len() < total {
        return Err(LinkError::BufferFull);
    }

    let header = Ieee802154Header {
        frame_control: U16::new(FRAME_CONTROL),
        seq: spec.seq,
        dest_pan_id: U16::new(BROADCAST_ADDR),
        dest_addr: U16::new(BROADCAST_ADDR),
        src_addr: U16::new(spec.src_addr),
    };
    out[..HEADER_LEN].copy_from_slice(header.as_bytes());
    out[HEADER_LEN..HEADER_LEN + FRAG_HDR_LEN].copy_from_slice(&pack_header(
        spec.msg_id,
        spec.index,
        spec.count,
    ));
    out[HEADER_LEN + FRAG_HDR_LEN..total].copy_from_slice(&frame[start..end]);
    Ok(total)
}

/// Parse one received fragment (with the FCS already stripped by the radio)
/// into the sender's short address, its fragment header, and its body.
///
/// Returns [`LinkError::InvalidPacket`] if `buf` is too short to hold an
/// [`Ieee802154Header`] plus a fragment header, if the header is not exactly
/// the one [`build_fragment`] writes, or if the fragment header is malformed.
/// Fail-closed throughout: a frame this crate cannot make sense of is dropped,
/// never guessed at.
///
/// # Why the whole header is compared, not just the frame type
///
/// The addressing-mode and PAN-ID-compression bits are what fix the *byte
/// offsets* of every field after them. Checking only the frame-type
/// sub-field accepts any conforming 802.15.4 Data frame — a Thread or Zigbee
/// device sharing the channel, which channels 11-26 routinely carry — and
/// then overlays this crate's fixed 9-byte header on a longer one, reading
/// `src_addr` out of the middle of a stranger's destination address. That
/// key is plausible enough to occupy one of only [`MAX_REASSEMBLIES`]
/// reassembly slots and evict a real message, and the radio does no address
/// filtering of its own. Comparing the full FCF costs one `u16` compare and
/// makes this crate the only thing its own reassembler will accept.
pub fn decode_fragment(buf: &[u8]) -> Result<(u16, FragHeader, &[u8]), LinkError> {
    if buf.len() < HEADER_LEN + FRAG_HDR_LEN {
        return Err(LinkError::InvalidPacket);
    }

    let (header, rest) =
        Ieee802154Header::ref_from_prefix(buf).map_err(|_| LinkError::InvalidPacket)?;
    if header.frame_control.get() != FRAME_CONTROL
        || header.dest_pan_id.get() != BROADCAST_ADDR
        || header.dest_addr.get() != BROADCAST_ADDR
    {
        return Err(LinkError::InvalidPacket);
    }

    let (hdr, body) = wayfinder_link_utils::parse_fragment(rest).ok_or(LinkError::InvalidPacket)?;
    Ok((header.src_addr.get(), hdr, body))
}

/// Feed one received fragment to `reassembler`. On completion, copy the
/// assembled frame into `out` and return `(len, metrics)`; otherwise `None`.
///
/// The bridge between [`decode_fragment`] and [`Reassembler::accept`], here
/// rather than in each adapter so both build the [`FragKey`] the same way.
/// A fragment that does not parse is dropped at `trace!` — it is reachable
/// from arbitrary peer input and must not flood the logs.
pub fn accept_fragment(
    reassembler: &mut Ieee802154Reassembler,
    buf: &[u8],
    metrics: LinkMetrics,
    out: &mut [u8],
) -> Option<(usize, LinkMetrics)> {
    let (src_addr, hdr, body) = match decode_fragment(buf) {
        Ok(parsed) => parsed,
        Err(_) => {
            trace!(len = buf.len(), "drop: malformed 802.15.4 fragment");
            return None;
        }
    };
    reassembler.accept(
        FragKey {
            addr: src_addr,
            msg_id: hdr.msg_id,
        },
        &hdr,
        body,
        metrics,
        out,
    )
}

/// Reinterpret reassembled bytes as a [`LinkFrame`].
///
/// Returns [`LinkError::InvalidPacket`] if they are too short to hold a
/// [`LinkFrame`] header — which a corrupted reassembly (see the module docs
/// on colliding short addresses) can produce.
pub fn decode_frame(bytes: &[u8]) -> Result<&LinkFrame, LinkError> {
    LinkFrame::ref_from_bytes(bytes).map_err(|_| LinkError::InvalidPacket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Assemble `payload` from `origin` to `mac(2)` into a fresh buffer,
    /// returning the buffer and its real length.
    fn frame_of(origin: Mac, payload: &[u8]) -> ([u8; MAX_REASSEMBLED_LEN], usize) {
        let mut buf = [0u8; MAX_REASSEMBLED_LEN];
        let n = assemble_frame(
            origin,
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload,
            },
            &mut buf,
        )
        .unwrap();
        (buf, n)
    }

    /// Cut `frame` into every fragment `spec_for` names and feed them to
    /// `reassembler` in the order given by `order`, returning whatever
    /// completes.
    fn feed(
        reassembler: &mut Ieee802154Reassembler,
        frame: &[u8],
        src_addr: u16,
        msg_id: u8,
        order: &[usize],
        out: &mut [u8],
    ) -> Option<usize> {
        let count = fragment_count(frame.len()).unwrap();
        let mut completed = None;
        for &index in order {
            let mut air = [0u8; MAX_FRAME_LEN];
            let n = build_fragment(
                frame,
                FragmentSpec {
                    seq: index as u8,
                    src_addr,
                    msg_id,
                    index,
                    count,
                },
                &mut air,
            )
            .unwrap();
            if let Some((len, _)) =
                accept_fragment(reassembler, &air[..n], LinkMetrics::default(), out)
            {
                completed = Some(len);
            }
        }
        completed
    }

    // ── header ──────────────────────────────────────────────────────

    /// The 802.15.4 MAC header is 9 bytes once a short source address joins
    /// the short destination address — design 19 §3.4.
    #[test]
    fn header_is_nine_bytes() {
        assert_eq!(HEADER_LEN, 9);
        assert_eq!(core::mem::size_of::<Ieee802154Header>(), 9);
    }

    /// `build_fragment` writes the canonical `0x8841` Frame Control Field —
    /// Data frame, PAN ID compression, short destination *and* short source
    /// addressing — then the sequence number, broadcast PAN ID, broadcast
    /// destination, and the sender's short address, all little-endian.
    #[test]
    fn fragment_header_carries_short_source_address() {
        let (frame, len) = frame_of(mac(1), &[0xaa, 0xbb]);
        let mut air = [0u8; MAX_FRAME_LEN];
        build_fragment(
            &frame[..len],
            FragmentSpec {
                seq: 42,
                src_addr: 0x1234,
                msg_id: 7,
                index: 0,
                count: 1,
            },
            &mut air,
        )
        .unwrap();

        assert_eq!(
            &air[..HEADER_LEN],
            &[0x41, 0x88, 42, 0xff, 0xff, 0xff, 0xff, 0x34, 0x12]
        );
    }

    /// `decode_fragment` reads back the source address `build_fragment`
    /// wrote — the value the reassembly key is built from.
    #[test]
    fn decode_fragment_recovers_source_address() {
        let (frame, len) = frame_of(mac(1), &[0xaa]);
        let mut air = [0u8; MAX_FRAME_LEN];
        let n = build_fragment(
            &frame[..len],
            FragmentSpec {
                seq: 0,
                src_addr: 0xbeef,
                msg_id: 3,
                index: 0,
                count: 1,
            },
            &mut air,
        )
        .unwrap();

        let (src_addr, hdr, _) = decode_fragment(&air[..n]).unwrap();
        assert_eq!(src_addr, 0xbeef);
        assert_eq!(hdr.msg_id, 3);
        assert_eq!(hdr.index, 0);
        assert_eq!(hdr.count, 1);
    }

    // ── fragmentation budget ────────────────────────────────────────

    /// One fragment carries the PHY frame minus the MAC header and the
    /// 2-byte fragment header: `125 - 9 - 2`.
    #[test]
    fn frag_payload_is_the_phy_frame_less_both_headers() {
        assert_eq!(FRAG_PAYLOAD, MAX_FRAME_LEN - HEADER_LEN - FRAG_HDR_LEN);
        assert_eq!(FRAG_PAYLOAD, 114);
    }

    /// A frame of exactly `FRAG_PAYLOAD` bytes is one fragment; one byte
    /// more is two. The boundary the `div_ceil` has to get right.
    #[test]
    fn fragment_count_splits_at_the_payload_boundary() {
        assert_eq!(fragment_count(1).unwrap(), 1);
        assert_eq!(fragment_count(FRAG_PAYLOAD).unwrap(), 1);
        assert_eq!(fragment_count(FRAG_PAYLOAD + 1).unwrap(), 2);
        assert_eq!(fragment_count(2 * FRAG_PAYLOAD).unwrap(), 2);
    }

    /// Past `MAX_FRAGMENTS` fragments the 4-bit `count` nibble cannot encode
    /// the split, so it is refused rather than silently truncated.
    #[test]
    fn fragment_count_refuses_past_max_fragments() {
        assert!(fragment_count(MAX_FRAGMENTS * FRAG_PAYLOAD).is_ok());
        assert!(matches!(
            fragment_count(MAX_FRAGMENTS * FRAG_PAYLOAD + 1),
            Err(LinkError::BufferFull)
        ));
    }

    /// A single fragment occupies at most a whole PHY frame, so the radio
    /// buffer both adapters hand to `build_fragment` is never overrun.
    #[test]
    fn a_full_fragment_exactly_fills_a_phy_frame() {
        let (frame, len) = frame_of(mac(1), &[0u8; FRAG_PAYLOAD - LINK_HEADER_LEN]);
        assert_eq!(len, FRAG_PAYLOAD);

        let mut air = [0u8; MAX_FRAME_LEN];
        let n = build_fragment(
            &frame[..len],
            FragmentSpec {
                seq: 0,
                src_addr: 1,
                msg_id: 0,
                index: 0,
                count: 1,
            },
            &mut air,
        )
        .unwrap();
        assert_eq!(n, MAX_FRAME_LEN);
    }

    // ── round trips ─────────────────────────────────────────────────

    /// A frame small enough for one fragment round-trips unchanged.
    #[test]
    fn round_trips_a_single_fragment_frame() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let (frame, len) = frame_of(mac(1), &payload);

        let mut reassembler = Ieee802154Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let n = feed(&mut reassembler, &frame[..len], 0x0001, 5, &[0], &mut out).unwrap();

        let decoded = decode_frame(&out[..n]).unwrap();
        assert_eq!(decoded.src, mac(1));
        assert_eq!(decoded.dst, mac(2));
        assert_eq!(decoded.protocol.get(), 0x4305);
        assert_eq!(&decoded.payload, &payload);
    }

    /// A full-size frame round-trips with its fragments delivered **out of
    /// order** and with a **duplicate** — both of which a shared broadcast
    /// radio produces routinely.
    #[test]
    fn round_trips_a_max_frame_out_of_order_with_a_duplicate() {
        let payload = [0x5a; MAX_PAYLOAD_LEN];
        let (frame, len) = frame_of(mac(9), &payload);
        assert_eq!(len, MAX_REASSEMBLED_LEN);
        assert_eq!(fragment_count(len).unwrap(), 5);

        // Reverse order, with fragment 3 delivered twice — the duplicate
        // lands on a still-incomplete entry, which is the case worth
        // exercising.
        let order = [4, 3, 3, 2, 1, 0];

        let mut reassembler = Ieee802154Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let n = feed(&mut reassembler, &frame[..len], 0x0002, 6, &order, &mut out).unwrap();

        assert_eq!(n, len);
        let decoded = decode_frame(&out[..n]).unwrap();
        assert_eq!(decoded.src, mac(9));
        assert_eq!(&decoded.payload, &payload[..]);
    }

    /// A ~250-byte full-cert OGM is three fragments — design 19 §2.1's
    /// headline figure, pinned so a constant change that inflates it is
    /// noticed.
    #[test]
    fn a_full_cert_ogm_is_three_fragments() {
        assert_eq!(fragment_count(250).unwrap(), 3);
    }

    // ── the source address as a reassembly key ──────────────────────

    /// Two senders with distinct short addresses interleave fragments of
    /// equal `msg_id` without contaminating each other.
    #[test]
    fn distinct_source_addresses_do_not_cross_contaminate() {
        let (a_frame, a_len) = frame_of(mac(1), &[0x11; 200]);
        let (b_frame, b_len) = frame_of(mac(2), &[0x22; 200]);

        let mut reassembler = Ieee802154Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];

        // Interleave: A0, B0, A1, B1 — same msg_id, different src_addr.
        let count = fragment_count(a_len).unwrap();
        assert_eq!(count, 2);
        let mut completions = 0;
        for index in 0..count {
            for (frame, len, src) in [(&a_frame, a_len, 0x000a), (&b_frame, b_len, 0x000b)] {
                let mut air = [0u8; MAX_FRAME_LEN];
                let n = build_fragment(
                    &frame[..len],
                    FragmentSpec {
                        seq: 0,
                        src_addr: src,
                        msg_id: 4,
                        index,
                        count,
                    },
                    &mut air,
                )
                .unwrap();
                if let Some((n, _)) = accept_fragment(
                    &mut reassembler,
                    &air[..n],
                    LinkMetrics::default(),
                    &mut out,
                ) {
                    completions += 1;
                    let decoded = decode_frame(&out[..n]).unwrap();
                    // Whichever completed, its payload must be uniform — a
                    // mixed reassembly would interleave 0x11 and 0x22.
                    let first = decoded.payload[0];
                    assert!(decoded.payload.iter().all(|&b| b == first));
                }
            }
        }
        assert_eq!(completions, 2);
    }

    /// Two senders sharing a short address **and** a `msg_id` corrupt each
    /// other's reassembly. This pins design 19 §3.4's documented deployment
    /// constraint and §5.3's claim about what it costs: the result is a
    /// wrong frame that fails a later check, never a frame misattributed to
    /// the wrong sender — the mesh `Mac` rides inside the reassembled bytes,
    /// so it is whatever the fragment carrying it said, not what the short
    /// address claimed.
    #[test]
    fn colliding_source_addresses_corrupt_rather_than_misattribute() {
        let (a_frame, a_len) = frame_of(mac(1), &[0x11; 200]);
        let (b_frame, b_len) = frame_of(mac(2), &[0x22; 200]);
        let count = fragment_count(a_len).unwrap();

        let mut reassembler = Ieee802154Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];

        // A's fragment 0 and B's fragment 1, both claiming src 0x000a/msg 4.
        let mut completed = None;
        for (frame, len, index) in [(&a_frame, a_len, 0), (&b_frame, b_len, 1)] {
            let mut air = [0u8; MAX_FRAME_LEN];
            let n = build_fragment(
                &frame[..len],
                FragmentSpec {
                    seq: 0,
                    src_addr: 0x000a,
                    msg_id: 4,
                    index,
                    count,
                },
                &mut air,
            )
            .unwrap();
            if let Some((n, _)) = accept_fragment(
                &mut reassembler,
                &air[..n],
                LinkMetrics::default(),
                &mut out,
            ) {
                completed = Some(n);
            }
        }

        let n = completed.expect("the two halves together look complete");
        assert_ne!(&out[..n], &a_frame[..a_len]);
        assert_ne!(&out[..n], &b_frame[..b_len]);
    }

    // ── fail-closed parsing ─────────────────────────────────────────

    /// A frame whose Frame Control Field encodes a non-Data type (an Ack, a
    /// beacon, a MAC command from an unrelated device sharing the channel)
    /// is rejected rather than fed to the reassembler.
    #[test]
    fn decode_fragment_rejects_non_data_frames() {
        let mut air = [0u8; MAX_FRAME_LEN];
        air[0] = 0b010; // Ack
        assert!(matches!(
            decode_fragment(&air[..HEADER_LEN + FRAG_HDR_LEN + 1]),
            Err(LinkError::InvalidPacket)
        ));
    }

    /// A *conforming* 802.15.4 Data frame that is not this crate's format is
    /// rejected rather than reinterpreted.
    ///
    /// FCF `0xCC01` is Data with 64-bit source and destination addressing — an
    /// ordinary Thread or Zigbee frame, and channels 11-26 routinely carry
    /// them. Its MAC header is longer than nine bytes, so overlaying
    /// [`Ieee802154Header`] on it reads `src_addr` out of the middle of a
    /// stranger's destination address. That key is plausible enough to take
    /// one of only [`MAX_REASSEMBLIES`] slots and evict a real message, and
    /// the radio does no address filtering of its own.
    ///
    /// Checking only the frame-type sub-field accepted this; comparing the
    /// whole FCF is what makes the crate docs' "fail-closed throughout" true.
    #[test]
    fn decode_fragment_rejects_conforming_foreign_frames() {
        let mut air = [0u8; MAX_FRAME_LEN];
        // Data + long addressing, then bytes that would parse as a valid
        // single-fragment header at offsets 9/10.
        air[..2].copy_from_slice(&0xCC01u16.to_le_bytes());
        air[HEADER_LEN] = 7;
        air[HEADER_LEN + 1] = 0x01;
        assert!(matches!(
            decode_fragment(&air[..HEADER_LEN + FRAG_HDR_LEN + 4]),
            Err(LinkError::InvalidPacket)
        ));
    }

    /// A Data frame carrying this crate's own FCF but addressed to a
    /// non-broadcast PAN or destination is not ours either.
    #[test]
    fn decode_fragment_rejects_non_broadcast_addressing() {
        let (frame, len) = frame_of(mac(1), &[0xaa]);
        let mut good = [0u8; MAX_FRAME_LEN];
        let n = build_fragment(
            &frame[..len],
            FragmentSpec {
                seq: 0,
                src_addr: 1,
                msg_id: 0,
                index: 0,
                count: 1,
            },
            &mut good,
        )
        .unwrap();

        // The destination PAN (bytes 3..5) is no longer broadcast.
        let mut air = good;
        air[3] = 0x22;
        assert!(matches!(
            decode_fragment(&air[..n]),
            Err(LinkError::InvalidPacket)
        ));

        // The destination address (bytes 5..7) is no longer broadcast.
        let mut air = good;
        air[5] = 0x22;
        assert!(matches!(
            decode_fragment(&air[..n]),
            Err(LinkError::InvalidPacket)
        ));
    }

    /// A spec that could not describe a real fragment is refused by
    /// `build_fragment` itself.
    ///
    /// `pack_header`'s own checks are `debug_assert!`, so they vanish from the
    /// release image the boards actually run — a transposed index/count would
    /// otherwise pack a nibble pair every receiver rejects, spending airtime
    /// on frames nothing can reassemble.
    #[test]
    fn build_fragment_rejects_an_impossible_spec() {
        let (frame, len) = frame_of(mac(1), &[0u8; 300]);
        let mut air = [0u8; MAX_FRAME_LEN];
        let spec = |index, count| FragmentSpec {
            seq: 0,
            src_addr: 1,
            msg_id: 0,
            index,
            count,
        };

        for (index, count) in [(0, 0), (1, 1), (3, 1), (0, MAX_FRAGMENTS + 1)] {
            assert!(
                matches!(
                    build_fragment(&frame[..len], spec(index, count), &mut air),
                    Err(LinkError::InvalidPacket)
                ),
                "index {index} of {count} should be refused"
            );
        }
    }

    /// The short address is the low 16 bits of the mesh `Mac`, big-endian.
    ///
    /// Pinned against a literal with distinct bytes: the `mac(n)` helper every
    /// other test uses leaves byte 4 zero, which makes big-endian,
    /// little-endian and `mac.0[5] as u16` indistinguishable. This is also the
    /// derivation a board's LoRa `AT+ADDRESS` shares, so the two radios agree
    /// on one node's short identity only while it stays put.
    #[test]
    fn short_address_is_the_low_two_mac_bytes_big_endian() {
        assert_eq!(short_address_of(Mac([1, 2, 3, 4, 0xAA, 0xBB])), 0xAABB);
        assert_eq!(short_address_of(Mac([0, 0, 0, 0, 0, 9])), 9);
    }

    /// A buffer too short to hold a MAC header plus a fragment header is
    /// rejected.
    #[test]
    fn decode_fragment_rejects_short_buffers() {
        let air = [0u8; HEADER_LEN + FRAG_HDR_LEN - 1];
        assert!(matches!(
            decode_fragment(&air),
            Err(LinkError::InvalidPacket)
        ));
    }

    /// A fragment header that parses but declares an impossible
    /// index/count is rejected by `decode_fragment` rather than reaching the
    /// reassembler.
    #[test]
    fn decode_fragment_rejects_malformed_fragment_headers() {
        let (frame, len) = frame_of(mac(1), &[0xaa]);
        let mut air = [0u8; MAX_FRAME_LEN];
        let n = build_fragment(
            &frame[..len],
            FragmentSpec {
                seq: 0,
                src_addr: 1,
                msg_id: 0,
                index: 0,
                count: 1,
            },
            &mut air,
        )
        .unwrap();

        // index (high nibble) >= count (low nibble)
        air[HEADER_LEN + 1] = 0x21;
        assert!(matches!(
            decode_fragment(&air[..n]),
            Err(LinkError::InvalidPacket)
        ));
    }

    // ── size limits ─────────────────────────────────────────────────

    /// The largest payload is what `MAX_REASSEMBLED_LEN` leaves after the
    /// `LinkFrame` header; one byte more is refused before `out` is touched.
    #[test]
    fn assemble_frame_rejects_an_oversized_payload() {
        assert_eq!(MAX_PAYLOAD_LEN, MAX_REASSEMBLED_LEN - LINK_HEADER_LEN);

        let mut buf = [0u8; MAX_REASSEMBLED_LEN];
        let big = [0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(
            assemble_frame(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0,
                    payload: &big,
                },
                &mut buf,
            ),
            Err(LinkError::BufferFull)
        ));
    }

    /// `assemble_frame` refuses an output buffer too small for the frame,
    /// even when the payload itself is within `MAX_PAYLOAD_LEN`.
    #[test]
    fn assemble_frame_rejects_an_undersized_buffer() {
        let mut buf = [0u8; LINK_HEADER_LEN];
        assert!(matches!(
            assemble_frame(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0,
                    payload: &[0xaa],
                },
                &mut buf,
            ),
            Err(LinkError::BufferFull)
        ));
    }

    /// A fragment index addressing a slice that starts past the end of the
    /// frame is refused rather than producing a zero-padded fragment.
    #[test]
    fn build_fragment_rejects_an_index_past_the_frame() {
        let (frame, len) = frame_of(mac(1), &[0xaa]);
        let mut air = [0u8; MAX_FRAME_LEN];
        assert!(matches!(
            build_fragment(
                &frame[..len],
                FragmentSpec {
                    seq: 0,
                    src_addr: 1,
                    msg_id: 0,
                    index: 3,
                    count: 4,
                },
                &mut air,
            ),
            Err(LinkError::BufferFull)
        ));
    }
}
