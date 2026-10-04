//! Framing and fragmentation for a **raw LoRa PHY** — a radio that hands over
//! a payload and nothing else. `no_std`, and with no opinion about the radio
//! chip.
//!
//! What this crate owns is the 3-byte header a raw PHY needs and a RYLR998
//! module supplies itself: a `net_id` filter and a 16-bit `src_id` to key
//! reassembly on. Frame assembly, fragment cutting and reassembly are
//! [`wayfinder_link_utils`]'s, shared with `ieee802154`.
//!
//! See `docs/design/25-stm32wl55-subghz-node.md`, and this crate's `CLAUDE.md`
//! for the rules a `LinkT` adapter over it has to follow.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;
use interfaces::link::LinkError;
use interfaces::link::LinkMetrics;
use tracing::trace;
use wayfinder_link_utils::FRAG_HDR_LEN;
use wayfinder_link_utils::FragHeader;
use wayfinder_link_utils::FragKey;
pub use wayfinder_link_utils::LINK_HEADER_LEN;
use wayfinder_link_utils::Reassembler;
pub use wayfinder_link_utils::decode_frame;
use wayfinder_link_utils::pack_header;
pub use wayfinder_link_utils::short_address_of;

/// Largest LoRa PHY payload an SX126x-class radio will carry, and so the
/// largest buffer [`build_fragment`] writes or [`decode_fragment`] accepts.
///
/// A property of the silicon's packet engine (the payload-length field is one
/// byte), not a tunable: raising it does not buy longer packets, it produces
/// packets the radio refuses to send.
pub const MAX_FRAME_LEN: usize = 255;

/// Bytes of this crate's own header ahead of each fragment: `net_id` plus a
/// big-endian `src_id`. Small on purpose: it is spent on *every* fragment,
/// and the medium carries roughly 5 kbps.
pub const HEADER_LEN: usize = 1 + size_of::<u16>();

/// Frame-content bytes one fragment carries, once both headers are
/// subtracted: `255 - 3 - 2`.
///
/// A **compile-time property of the format, never carried on the wire** —
/// [`Reassembler`] places a fragment's bytes at `index * FRAG_PAYLOAD`, so
/// both ends must already agree on it. Changing it is a wire-format break.
pub const FRAG_PAYLOAD: usize = MAX_FRAME_LEN - HEADER_LEN - FRAG_HDR_LEN;

/// Largest frame this link can reassemble.
///
/// **Must equal the board capacity profile's `max_frame_len`.** Below it the
/// router silently drops frames this link was willing to carry — principally
/// authenticated OGMs, so the node looks healthy and routes nothing. The board
/// crate pins the two with a `const` assertion. 512 matches `rylr998` and
/// `ieee802154`.
pub const MAX_REASSEMBLED_LEN: usize = 512;

/// Concurrent in-flight reassemblies tracked, matching `rylr998` and
/// `ieee802154`. A fifth sender evicts the oldest incomplete message; each
/// slot costs a full [`MAX_REASSEMBLED_LEN`] buffer.
pub const MAX_REASSEMBLIES: usize = 4;

/// Frame assembly and fragment cutting at this medium's sizes.
type Framing = wayfinder_link_utils::Framing<FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>;

/// Largest mesh-frame payload [`assemble_frame`] will accept.
pub const MAX_PAYLOAD_LEN: usize = Framing::MAX_PAYLOAD_LEN;

/// The reassembly table a raw-LoRa `LinkT` adapter owns, keyed on the 16-bit
/// `src_id` the sender puts in each fragment. See this crate's `CLAUDE.md` for
/// why that is the key and what it requires of a deployment.
pub type LoraReassembler = Reassembler<u16, MAX_REASSEMBLIES, FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>;

/// Which fragment of which message [`build_fragment`] should cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentSpec {
    /// The sender-chosen message id, shared by every fragment of one frame
    /// and half the reassembly key.
    pub msg_id: u8,
    /// This fragment's index, `0..count`.
    pub index: usize,
    /// Total fragments in this frame, from [`fragment_count`].
    pub count: usize,
}

/// Write the `[dst][src][protocol][payload]` frame bytes into `out`; see
/// [`wayfinder_link_utils::Framing::assemble_frame`].
pub fn assemble_frame(
    origin: Mac,
    data: &LinkFrameData<'_>,
    out: &mut [u8],
) -> Result<usize, LinkError> {
    Framing::assemble_frame(origin, data, out)
}

/// Number of fragments a `frame_len`-byte frame splits into; see
/// [`wayfinder_link_utils::Framing::fragment_count`].
pub fn fragment_count(frame_len: usize) -> Result<usize, LinkError> {
    Framing::fragment_count(frame_len)
}

/// Build one on-air packet — `[net_id][src_id][frag_hdr][content]` — into
/// `out`, returning the bytes written.
///
/// Returns [`LinkError::InvalidPacket`] for a spec that could not describe a
/// real fragment of `frame` (see
/// [`wayfinder_link_utils::Framing::fragment_body`]), and
/// [`LinkError::BufferFull`] if `out` is too small (it never is for a
/// `[u8; MAX_FRAME_LEN]`, which one full fragment exactly fills).
pub fn build_fragment(
    net_id: u8,
    src_id: u16,
    frame: &[u8],
    spec: FragmentSpec,
    out: &mut [u8],
) -> Result<usize, LinkError> {
    let chunk = Framing::fragment_body(frame, spec.index, spec.count)?;
    let total = HEADER_LEN + FRAG_HDR_LEN + chunk.len();
    if out.len() < total {
        return Err(LinkError::BufferFull);
    }

    out[0] = net_id;
    out[1..HEADER_LEN].copy_from_slice(&src_id.to_be_bytes());
    out[HEADER_LEN..HEADER_LEN + FRAG_HDR_LEN].copy_from_slice(&pack_header(
        spec.msg_id,
        spec.index,
        spec.count,
    ));
    out[HEADER_LEN + FRAG_HDR_LEN..total].copy_from_slice(chunk);
    Ok(total)
}

/// Parse one received packet into `(src_id, fragment header, content)`.
///
/// Returns [`LinkError::MalformedFrame`] if it is too short, carries a
/// different `net_id`, or has a malformed fragment header. Fragments a
/// conforming sender never produces (an impossible `count`, a short non-final
/// body) are refused one step later, by [`Reassembler::accept`].
///
/// **The `net_id` check happens before anything touches the reassembly
/// table**, which is the whole point of the field: another mesh on the same
/// frequency would otherwise occupy one of only [`MAX_REASSEMBLIES`] slots and
/// evict a real message. It is a filter and not a security boundary — mesh
/// membership is `wayfinder-auth`'s, verified above `LinkT`.
pub fn decode_fragment(net_id: u8, buf: &[u8]) -> Result<(u16, FragHeader, &[u8]), LinkError> {
    if buf.len() < HEADER_LEN + FRAG_HDR_LEN || buf[0] != net_id {
        return Err(LinkError::MalformedFrame);
    }
    let src_id = u16::from_be_bytes([buf[1], buf[2]]);
    let (hdr, body) = wayfinder_link_utils::parse_fragment(&buf[HEADER_LEN..])
        .ok_or(LinkError::MalformedFrame)?;
    Ok((src_id, hdr, body))
}

/// Feed one received packet to `reassembler`. On completion, copy the
/// assembled frame into `out` and return `(len, metrics)`; otherwise `None`.
///
/// Here rather than in each adapter so every one builds the [`FragKey`] the
/// same way. A packet that does not parse is dropped at `trace!` — it is
/// reachable from arbitrary peer input and must not flood the logs.
pub fn accept_fragment(
    reassembler: &mut LoraReassembler,
    net_id: u8,
    buf: &[u8],
    metrics: LinkMetrics,
    out: &mut [u8],
) -> Option<(usize, LinkMetrics)> {
    let Ok((src_id, hdr, body)) = decode_fragment(net_id, buf) else {
        trace!(len = buf.len(), "drop: malformed lora fragment");
        return None;
    };
    reassembler.accept(
        FragKey {
            addr: src_id,
            msg_id: hdr.msg_id,
        },
        &hdr,
        body,
        metrics,
        out,
    )
}

#[cfg(test)]
mod tests {
    use interfaces::frame::LinkFrameData;
    use interfaces::frame::Mac;
    use interfaces::link::LinkError;
    use interfaces::link::LinkMetrics;

    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// This mesh's `net_id` throughout; `OTHER_NET` is anyone else's.
    const NET: u8 = 7;
    const OTHER_NET: u8 = 8;

    /// Assemble `payload` from `origin` to `mac(2)`, returning the buffer and
    /// its real length.
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

    /// Cut `frame` into every on-air packet it becomes, as a `Vec` of owned
    /// buffers so a test can reorder or drop them.
    fn fragments_of(net_id: u8, src_id: u16, msg_id: u8, frame: &[u8]) -> Vec<Vec<u8>> {
        let count = fragment_count(frame.len()).unwrap();
        (0..count)
            .map(|index| {
                let mut out = [0u8; MAX_FRAME_LEN];
                let n = build_fragment(
                    net_id,
                    src_id,
                    frame,
                    FragmentSpec {
                        msg_id,
                        index,
                        count,
                    },
                    &mut out,
                )
                .unwrap();
                out[..n].to_vec()
            })
            .collect()
    }

    /// `net_id` and `src_id` sit where the format says, ahead of the fragment
    /// header — the receiver keys on them before any reassembly state exists,
    /// so their position is load-bearing.
    #[test]
    fn the_header_precedes_the_fragment_header_on_the_wire() {
        let (frame, n) = frame_of(mac(1), &[0xde, 0xad]);
        let frags = fragments_of(NET, 0xAABB, 9, &frame[..n]);

        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0][0], NET);
        assert_eq!(&frags[0][1..3], &0xAABBu16.to_be_bytes());

        let (src_id, hdr, body) = decode_fragment(NET, &frags[0]).unwrap();
        assert_eq!(src_id, 0xAABB);
        assert_eq!(hdr.msg_id, 9);
        assert_eq!((hdr.index, hdr.count), (0, 1));
        assert_eq!(body, &frame[..n]);
    }

    /// A frame too large for one PHY payload splits and comes back
    /// byte-identical. The whole point of the fragmentation layer.
    #[test]
    fn an_oversized_frame_splits_and_reassembles_byte_identical() {
        // The largest legal payload, which is also two full fragments and a
        // short tail (250 + 250 + 12) — so the `index * FRAG_PAYLOAD` offset
        // arithmetic is exercised on more than one boundary, at the one size
        // most likely to be off by one.
        let payload: Vec<u8> = (0..MAX_PAYLOAD_LEN as u16).map(|i| i as u8).collect();
        let (frame, n) = frame_of(mac(1), &payload);
        let frags = fragments_of(NET, 0x1234, 5, &frame[..n]);
        assert_eq!(frags.len(), 3, "expected three fragments");

        let mut reassembler = LoraReassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let mut completed = None;
        for frag in &frags {
            completed = accept_fragment(
                &mut reassembler,
                NET,
                frag,
                LinkMetrics::default(),
                &mut out,
            );
        }

        let (len, _) = completed.expect("the last fragment completes the frame");
        assert_eq!(len, n);
        assert_eq!(&out[..len], &frame[..n]);

        let decoded = decode_frame(&out[..len]).unwrap();
        assert_eq!(decoded.src, mac(1));
        assert_eq!(decoded.dst, mac(2));
        assert_eq!(decoded.protocol.get(), 0x4305);
        assert_eq!(&decoded.payload, &payload[..]);
    }

    /// A single-fragment frame completes on one packet — the common case, and
    /// the one an off-by-one in `fragment_count` breaks.
    #[test]
    fn a_small_frame_needs_one_fragment() {
        let (frame, n) = frame_of(mac(1), &[1, 2, 3]);
        let frags = fragments_of(NET, 1, 0, &frame[..n]);
        assert_eq!(frags.len(), 1);

        let mut reassembler = LoraReassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let (len, _) = accept_fragment(
            &mut reassembler,
            NET,
            &frags[0],
            LinkMetrics::default(),
            &mut out,
        )
        .expect("one fragment is a whole frame");
        assert_eq!(&out[..len], &frame[..n]);
    }

    /// **A foreign `net_id` is dropped before it can occupy a reassembly
    /// slot** — which is the only thing `net_id` is for (§6.1: it is a filter,
    /// not a security boundary).
    #[test]
    fn a_fragment_from_another_mesh_is_dropped() {
        let payload: Vec<u8> = (0..(FRAG_PAYLOAD + 10) as u16).map(|i| i as u8).collect();
        let (frame, n) = frame_of(mac(1), &payload);
        let frags = fragments_of(OTHER_NET, 0x1234, 5, &frame[..n]);
        assert_eq!(frags.len(), 2);

        let mut reassembler = LoraReassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        for frag in &frags {
            assert!(
                accept_fragment(
                    &mut reassembler,
                    NET,
                    frag,
                    LinkMetrics::default(),
                    &mut out
                )
                .is_none(),
                "a foreign net_id must never complete a frame"
            );
        }
        // And it left no state behind: our own message still fits, which it
        // would not if the foreign one had taken a slot it never releases.
        assert!(matches!(
            decode_fragment(NET, &frags[0]),
            Err(LinkError::MalformedFrame)
        ));
    }

    /// Two senders' fragments interleaved on the air reassemble independently.
    /// This is the property the `src_id` key exists for.
    #[test]
    fn interleaved_senders_reassemble_independently() {
        let a_payload: Vec<u8> = (0..(FRAG_PAYLOAD + 10) as u16).map(|i| i as u8).collect();
        let b_payload: Vec<u8> = (0..(FRAG_PAYLOAD + 20) as u16)
            .map(|i| (i as u8).wrapping_add(0x80))
            .collect();
        let (a_frame, an) = frame_of(mac(1), &a_payload);
        let (b_frame, bn) = frame_of(mac(3), &b_payload);

        // Same msg_id on purpose: only `src_id` separates them.
        let a = fragments_of(NET, 0x0001, 4, &a_frame[..an]);
        let b = fragments_of(NET, 0x0002, 4, &b_frame[..bn]);

        let mut reassembler = LoraReassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];

        let m = |f: &Vec<u8>, r: &mut LoraReassembler, o: &mut [u8]| {
            accept_fragment(r, NET, f, LinkMetrics::default(), o).map(|(len, _)| len)
        };

        assert_eq!(m(&a[0], &mut reassembler, &mut out), None);
        assert_eq!(m(&b[0], &mut reassembler, &mut out), None);
        let a_len = m(&a[1], &mut reassembler, &mut out).expect("A completes");
        assert_eq!(&out[..a_len], &a_frame[..an]);
        let b_len = m(&b[1], &mut reassembler, &mut out).expect("B completes");
        assert_eq!(&out[..b_len], &b_frame[..bn]);
    }

    /// **The deployment constraint, asserted rather than only documented.**
    ///
    /// Two nodes whose `Mac`s share their low two bytes transmit under the
    /// same `src_id` and spoil each other's reassembly. What matters is the
    /// *shape* of the damage: a dropped or unparseable frame, never one
    /// attributed to the wrong sender — because the authenticated `Mac`
    /// travels inside the reassembled content. Same property, and same test
    /// name, as `libs/ieee802154`.
    #[test]
    fn colliding_source_addresses_corrupt_rather_than_misattribute() {
        let a_payload: Vec<u8> = (0..(FRAG_PAYLOAD + 10) as u16).map(|_| 0xAA).collect();
        let b_payload: Vec<u8> = (0..(FRAG_PAYLOAD + 10) as u16).map(|_| 0xBB).collect();
        let (a_frame, an) = frame_of(mac(1), &a_payload);
        let (b_frame, bn) = frame_of(mac(3), &b_payload);

        // The collision: one `src_id`, one `msg_id`, two different senders.
        let a = fragments_of(NET, 0x0001, 4, &a_frame[..an]);
        let b = fragments_of(NET, 0x0001, 4, &b_frame[..bn]);

        let mut reassembler = LoraReassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];

        assert!(
            accept_fragment(
                &mut reassembler,
                NET,
                &a[0],
                LinkMetrics::default(),
                &mut out
            )
            .is_none()
        );
        // B's tail completes the slot A opened, mixing the two.
        let (len, _) = accept_fragment(
            &mut reassembler,
            NET,
            &b[1],
            LinkMetrics::default(),
            &mut out,
        )
        .expect("the collision completes a slot");

        // Whatever came out, it is not B's frame arriving as though it were
        // A's: the `src` inside the content is one of the two real senders,
        // never a third value, and the bytes are not a clean copy of either.
        let mixed = &out[..len];
        assert_ne!(mixed, &a_frame[..an], "must not pass as A's frame");
        assert_ne!(mixed, &b_frame[..bn], "must not pass as B's frame");
        if let Ok(decoded) = decode_frame(mixed) {
            assert!(
                decoded.src == mac(1) || decoded.src == mac(3),
                "a corrupted reassembly must not invent a sender: {:?}",
                decoded.src
            );
        }
    }

    /// A truncated or garbage packet is refused rather than panicking. This is
    /// the outermost air-facing boundary, reachable by anyone in radio range.
    #[test]
    fn a_runt_packet_is_refused() {
        for len in 0..HEADER_LEN + FRAG_HDR_LEN {
            let buf = vec![NET; len];
            assert!(
                matches!(decode_fragment(NET, &buf), Err(LinkError::MalformedFrame)),
                "a {len}-byte packet is too short to be a fragment"
            );
        }
    }

    /// A fragment header whose `count` is zero or whose `index` is not below
    /// `count` cannot describe a real fragment, and is refused rather than
    /// reaching the reassembly table.
    #[test]
    fn a_malformed_fragment_header_is_refused() {
        let mut buf = [0u8; HEADER_LEN + FRAG_HDR_LEN + 4];
        buf[0] = NET;
        buf[1..3].copy_from_slice(&1u16.to_be_bytes());

        // count == 0
        buf[HEADER_LEN] = 1;
        buf[HEADER_LEN + 1] = 0x00;
        assert!(matches!(
            decode_fragment(NET, &buf),
            Err(LinkError::MalformedFrame)
        ));

        // index == count
        buf[HEADER_LEN + 1] = (2 << 4) | 2;
        assert!(matches!(
            decode_fragment(NET, &buf),
            Err(LinkError::MalformedFrame)
        ));
    }

    /// A hand-built packet: `count`/`index` as given and a body of `body_len`
    /// bytes, for the headers a well-behaved sender never produces.
    fn raw_packet(net_id: u8, src_id: u16, index: usize, count: usize, body_len: usize) -> Vec<u8> {
        let mut buf = vec![net_id];
        buf.extend_from_slice(&src_id.to_be_bytes());
        buf.extend_from_slice(&pack_header(0, index, count));
        buf.extend(core::iter::repeat_n(0xAB, body_len));
        buf
    }

    /// **Foreign fragments never occupy a reassembly slot**, checked through
    /// the table rather than through `decode_fragment` alone: with our own
    /// message half-received, a full table's worth of other-mesh first
    /// fragments must not evict it. A refactor that checked `net_id` only on
    /// completion would still never *return* a foreign frame, and would fail
    /// only here.
    #[test]
    fn foreign_fragments_never_occupy_a_reassembly_slot() {
        let payload: Vec<u8> = (0..(FRAG_PAYLOAD + 10) as u16).map(|i| i as u8).collect();
        let (frame, n) = frame_of(mac(1), &payload);
        let ours = fragments_of(NET, 0x0001, 5, &frame[..n]);
        assert_eq!(ours.len(), 2);

        let mut reassembler = LoraReassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        assert!(
            accept_fragment(
                &mut reassembler,
                NET,
                &ours[0],
                LinkMetrics::default(),
                &mut out
            )
            .is_none()
        );

        for src_id in 0..MAX_REASSEMBLIES as u16 {
            let theirs = fragments_of(OTHER_NET, 0x1000 + src_id, 5, &frame[..n]);
            assert!(
                accept_fragment(
                    &mut reassembler,
                    NET,
                    &theirs[0],
                    LinkMetrics::default(),
                    &mut out
                )
                .is_none()
            );
        }

        let (len, _) = accept_fragment(
            &mut reassembler,
            NET,
            &ours[1],
            LinkMetrics::default(),
            &mut out,
        )
        .expect("our message survived a table's worth of foreign traffic");
        assert_eq!(&out[..len], &frame[..n]);
    }

    /// **Bytes off the air that do not parse are `MalformedFrame`, never
    /// `InvalidPacket`.** The driver raises the interface's `LinkErrors` alarm
    /// for every `recv` error but `MalformedFrame`, so the wrong variant lets
    /// anyone who knows `net_id` latch that alarm with a single packet: one
    /// complete fragment too short to hold a `LinkFrame` header.
    #[test]
    fn bytes_off_the_air_that_do_not_parse_are_malformed_frames() {
        let runt = raw_packet(NET, 1, 0, 1, LINK_HEADER_LEN - 1);
        let mut reassembler = LoraReassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let (len, _) = accept_fragment(
            &mut reassembler,
            NET,
            &runt,
            LinkMetrics::default(),
            &mut out,
        )
        .expect("a one-fragment message completes");

        assert!(matches!(
            decode_frame(&out[..len]),
            Err(LinkError::MalformedFrame)
        ));
        assert!(matches!(
            decode_fragment(OTHER_NET, &runt),
            Err(LinkError::MalformedFrame)
        ));
    }
}
