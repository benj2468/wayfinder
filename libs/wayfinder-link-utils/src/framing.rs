//! The `[dst][src][protocol][payload]` frame every small-MTU link fragments,
//! and the arithmetic for cutting it — the parts that do not depend on a
//! medium's own header. A medium crate (`ieee802154`, `lora-link`) adds only
//! its header encode/decode around these.

use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use zerocopy::FromBytes;

use crate::MAX_FRAGMENTS;

/// Length of the `[dst][src][protocol]` header prefixing every [`LinkFrame`]
/// (6 + 6 + 2 bytes).
pub const LINK_HEADER_LEN: usize = 14;

/// `LINK_HEADER_LEN` is written as a literal because it is quoted in wire
/// format docs; this is what keeps it honest if [`Mac`] ever changes width,
/// where `assemble_frame` would otherwise write the payload at the wrong
/// offset and `decode_frame` would still parse the result.
const _: () = assert!(LINK_HEADER_LEN == 2 * size_of::<Mac>() + size_of::<u16>());

/// The 16-bit short identity a node transmits under on a medium whose header
/// carries one: the low two bytes of its mesh [`Mac`], big-endian.
///
/// Shared so every link on one node derives the same short identity. Two
/// nodes whose `Mac`s share their low two bytes spoil each other's
/// reassembly, so a deployment must keep them distinct.
pub fn short_address_of(mac: Mac) -> u16 {
    u16::from_be_bytes([mac.0[4], mac.0[5]])
}

/// Reinterpret reassembled bytes as a [`LinkFrame`].
///
/// Returns [`LinkError::MalformedFrame`] if they are too short to hold a
/// [`LinkFrame`] header — which a corrupted reassembly or a stranger's runt
/// can produce. `MalformedFrame` because the bytes came off the medium.
pub fn decode_frame(bytes: &[u8]) -> Result<&LinkFrame, LinkError> {
    LinkFrame::ref_from_bytes(bytes).map_err(|_| LinkError::MalformedFrame)
}

/// Frame assembly and fragment cutting for a medium carrying `FRAG_PAYLOAD`
/// frame-content bytes per fragment and reassembling frames of up to
/// `MAX_REASSEMBLED_LEN` bytes — the same two constants its
/// [`Reassembler`](crate::Reassembler) is instantiated with.
///
/// A medium crate names its instantiation once (`type Framing =
/// wayfinder_link_utils::Framing<FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>`) and
/// wraps these with its own header.
pub struct Framing<const FRAG_PAYLOAD: usize, const MAX_REASSEMBLED_LEN: usize>;

impl<const FRAG_PAYLOAD: usize, const MAX_REASSEMBLED_LEN: usize>
    Framing<FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>
{
    /// Largest mesh-frame payload [`Self::assemble_frame`] will accept:
    /// `MAX_REASSEMBLED_LEN` minus the [`LinkFrame`] header.
    pub const MAX_PAYLOAD_LEN: usize = MAX_REASSEMBLED_LEN - LINK_HEADER_LEN;

    /// Write the `[dst][src][protocol][payload]` frame bytes for `data` sent
    /// from `origin` into `out`, returning the length written.
    ///
    /// This is the input to fragmentation, not something that goes on air by
    /// itself: the caller cuts the returned prefix of `out` with
    /// [`Self::fragment_count`] and [`Self::fragment_body`].
    ///
    /// Returns [`LinkError::BufferFull`] if `data.payload` exceeds
    /// [`Self::MAX_PAYLOAD_LEN`] or `out` is too small. **Never truncates** —
    /// a short frame parses and lies.
    pub fn assemble_frame(
        origin: Mac,
        data: &LinkFrameData<'_>,
        out: &mut [u8],
    ) -> Result<usize, LinkError> {
        if data.payload.len() > Self::MAX_PAYLOAD_LEN {
            return Err(LinkError::BufferFull);
        }
        let total = LINK_HEADER_LEN + data.payload.len();
        if out.len() < total {
            return Err(LinkError::BufferFull);
        }

        out[..6].copy_from_slice(&data.dst.0);
        out[6..12].copy_from_slice(&origin.0);
        // Big-endian, matching `LinkFrame`'s EtherType-style protocol field.
        out[12..14].copy_from_slice(&data.protocol.to_be_bytes());
        out[14..total].copy_from_slice(data.payload);
        Ok(total)
    }

    /// Number of fragments a `frame_len`-byte frame splits into, or
    /// [`LinkError::BufferFull`] past [`MAX_FRAGMENTS`] — the wire format's
    /// 4-bit `count` field ceiling.
    pub fn fragment_count(frame_len: usize) -> Result<usize, LinkError> {
        // `.max(1)`: `pack_header` debug-asserts `count >= 1`, so an empty
        // slice gets a valid single fragment rather than a debug panic.
        let count = frame_len.div_ceil(FRAG_PAYLOAD).max(1);
        if count > MAX_FRAGMENTS {
            return Err(LinkError::BufferFull);
        }
        Ok(count)
    }

    /// The slice of `frame` that fragment `index` of `count` carries.
    ///
    /// `frame` is [`Self::assemble_frame`]'s output truncated to its returned
    /// length, not the full backing array: every fragment past the real
    /// content would otherwise carry zero padding.
    ///
    /// Returns [`LinkError::InvalidPacket`] for a spec that could not
    /// describe a real fragment of *this* frame: `count` outside
    /// `1..=MAX_FRAGMENTS`, `index` not below `count`, or a `count` other
    /// than [`Self::fragment_count`]'s. Checked here rather than left to
    /// `pack_header`'s `debug_assert!`s, which are compiled out of the
    /// release firmware that ships — a transposed index/count packs a nibble
    /// pair every receiver rejects, and a short count sends a prefix the
    /// receiver completes as a whole, truncated frame.
    pub fn fragment_body(frame: &[u8], index: usize, count: usize) -> Result<&[u8], LinkError> {
        if !(1..=MAX_FRAGMENTS).contains(&count) || index >= count {
            return Err(LinkError::InvalidPacket);
        }
        if count != Self::fragment_count(frame.len())? {
            return Err(LinkError::InvalidPacket);
        }
        // `index < count <= MAX_FRAGMENTS`, so neither can overflow, and a
        // count that matches the frame puts `start` inside it.
        let start = index * FRAG_PAYLOAD;
        let end = (start + FRAG_PAYLOAD).min(frame.len());
        Ok(&frame[start..end])
    }
}

#[cfg(test)]
mod tests {
    use wayfinder::interfaces::frame::LinkFrameData;
    use wayfinder::interfaces::frame::Mac;
    use wayfinder::interfaces::link::LinkError;

    use super::*;

    const FRAG_PAYLOAD: usize = 100;
    const MAX_REASSEMBLED_LEN: usize = 250;
    type TestFraming = Framing<FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn assemble(payload: &[u8], out: &mut [u8]) -> Result<usize, LinkError> {
        TestFraming::assemble_frame(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload,
            },
            out,
        )
    }

    #[test]
    fn assemble_frame_lays_out_dst_src_protocol_payload() {
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let n = assemble(&[0xde, 0xad], &mut out).unwrap();
        assert_eq!(n, LINK_HEADER_LEN + 2);

        let frame = decode_frame(&out[..n]).unwrap();
        assert_eq!(frame.dst, mac(2));
        assert_eq!(frame.src, mac(1));
        assert_eq!(frame.protocol.get(), 0x4305);
        assert_eq!(&frame.payload, &[0xde, 0xad]);
    }

    /// Refused, never truncated — a truncated frame parses and lies. The
    /// largest legal payload is accepted, so the bound is off by nothing.
    #[test]
    fn assemble_frame_refuses_a_payload_past_the_reassembly_ceiling() {
        let mut out = [0u8; MAX_REASSEMBLED_LEN + 1];
        let largest = vec![0u8; TestFraming::MAX_PAYLOAD_LEN];
        assert_eq!(assemble(&largest, &mut out).unwrap(), MAX_REASSEMBLED_LEN);

        let too_big = vec![0u8; TestFraming::MAX_PAYLOAD_LEN + 1];
        assert!(matches!(
            assemble(&too_big, &mut out),
            Err(LinkError::BufferFull)
        ));
        assert!(matches!(
            assemble(&[1, 2, 3], &mut [0u8; LINK_HEADER_LEN + 2]),
            Err(LinkError::BufferFull)
        ));
    }

    #[test]
    fn fragment_count_boundaries() {
        for (len, want) in [
            (0, 1),
            (1, 1),
            (FRAG_PAYLOAD, 1),
            (FRAG_PAYLOAD + 1, 2),
            (MAX_REASSEMBLED_LEN, 3),
            (MAX_FRAGMENTS * FRAG_PAYLOAD, MAX_FRAGMENTS),
        ] {
            assert_eq!(TestFraming::fragment_count(len).unwrap(), want, "len {len}");
        }
        assert!(matches!(
            TestFraming::fragment_count(MAX_FRAGMENTS * FRAG_PAYLOAD + 1),
            Err(LinkError::BufferFull)
        ));
    }

    /// Every fragment but the last is exactly `FRAG_PAYLOAD`, and the bodies
    /// concatenate back to the frame.
    #[test]
    fn fragment_body_cuts_full_fragments_and_a_short_tail() {
        let frame: Vec<u8> = (0..230u16).map(|i| i as u8).collect();
        let count = TestFraming::fragment_count(frame.len()).unwrap();
        assert_eq!(count, 3);

        let bodies: Vec<&[u8]> = (0..count)
            .map(|index| TestFraming::fragment_body(&frame, index, count).unwrap())
            .collect();
        assert_eq!(bodies[0].len(), FRAG_PAYLOAD);
        assert_eq!(bodies[1].len(), FRAG_PAYLOAD);
        assert_eq!(bodies[2].len(), 30);
        assert_eq!(bodies.concat(), frame);
    }

    /// A spec that could not describe a real fragment is refused in release
    /// builds too, rather than left to `pack_header`'s `debug_assert!`s.
    #[test]
    fn fragment_body_refuses_an_impossible_spec() {
        let frame = [0u8; 10];
        for (index, count) in [(0, 0), (1, 1), (0, MAX_FRAGMENTS + 1), (usize::MAX, 1)] {
            assert!(
                matches!(
                    TestFraming::fragment_body(&frame, index, count),
                    Err(LinkError::InvalidPacket)
                ),
                "index {index}, count {count} should be refused"
            );
        }
    }

    /// The count must be *this frame's*: too small sends a prefix the
    /// receiver completes as a whole (truncated) frame, too large an empty
    /// tail.
    #[test]
    fn fragment_body_refuses_a_count_that_does_not_match_the_frame() {
        let frame = [0u8; FRAG_PAYLOAD + 10];
        for count in [1, 3] {
            assert!(
                matches!(
                    TestFraming::fragment_body(&frame, 0, count),
                    Err(LinkError::InvalidPacket)
                ),
                "count {count} on a two-fragment frame should be refused"
            );
        }
    }

    /// Bytes that arrived off the air are the sender's fault, so a runt is
    /// `MalformedFrame` — the variant the driver keeps off the `LinkErrors`
    /// alarm.
    #[test]
    fn decode_frame_refuses_a_runt_as_malformed() {
        assert!(matches!(
            decode_frame(&[0u8; LINK_HEADER_LEN - 1]),
            Err(LinkError::MalformedFrame)
        ));
    }

    #[test]
    fn short_address_of_is_the_low_two_bytes_big_endian() {
        assert_eq!(short_address_of(Mac([0x02, 0, 0, 0, 0xAB, 0xCD])), 0xABCD);
    }
}
