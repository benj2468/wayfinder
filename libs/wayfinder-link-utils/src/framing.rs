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
