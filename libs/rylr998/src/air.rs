//! The packet a RYLR998 module actually puts on the air, beneath its AT
//! commands.
//!
//! `AT+SEND=<addr>,<len>,<data>` does not transmit `<data>` alone. The module
//! prefixes a five-byte header, and on receive its firmware **silently drops
//! any LoRa packet that does not carry one** — no `+RCV`, no `+ERR`. Both facts
//! were measured on hardware, against a NUCLEO-WL55JC1 sniffing and then
//! transmitting raw LoRa on matched PHY settings; the fixtures in this module's
//! tests are those captured bytes.
//!
//! ```text
//! [dst_lo, dst_hi, src_lo, src_hi, len][payload; len]
//! ```
//!
//! Addresses are little-endian `u16`s (`AT+ADDRESS`, `0` being broadcast) and
//! `len` is the payload length. The network id does not appear: the module's
//! default `AT+NETWORKID=18` heard a radio using the LoRa private sync word
//! (`0x12`), which suggests the id selects the sync word, though only that one
//! value has been checked.
//!
//! This exists for a radio that is *not* a RYLR998 and wants one to hear it —
//! the HIL echo firmware on the WL55 — not for [`RylrClient`](crate::RylrClient),
//! which never sees these bytes.

use thiserror::Error;

/// Bytes before the payload: destination, source, length.
pub const HEADER_LEN: usize = 5;

/// The largest payload the module accepts in one `AT+SEND`, and so the largest
/// one a module will deliver.
pub const MAX_PAYLOAD_LEN: usize = 240;

/// The destination address a module treats as "every module".
pub const BROADCAST: u16 = 0;

/// One packet as the module puts it on the air.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AirFrame<'a> {
    /// The `AT+SEND` target address; [`BROADCAST`] for all.
    pub dst: u16,
    /// The sender's `AT+ADDRESS`.
    pub src: u16,
    /// The payload, at most [`MAX_PAYLOAD_LEN`] bytes.
    pub payload: &'a [u8],
}

/// Why a frame could not be encoded or parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AirError {
    /// The payload is longer than a module accepts ([`MAX_PAYLOAD_LEN`]).
    #[error("payload longer than {MAX_PAYLOAD_LEN} bytes")]
    PayloadTooLong,
    /// The output buffer cannot hold the header and payload. Refused rather
    /// than truncated, since a short frame would carry a wrong length byte.
    #[error("output buffer too small for the frame")]
    BufferTooSmall,
    /// Fewer bytes than a header.
    #[error("packet shorter than the {HEADER_LEN}-byte header")]
    Truncated,
    /// The length byte disagrees with the bytes that follow it.
    #[error("length byte disagrees with the packet")]
    LengthMismatch,
}

/// Write `frame` into `out` as a module would transmit it, returning the
/// number of bytes written.
pub fn encode(frame: &AirFrame<'_>, out: &mut [u8]) -> Result<usize, AirError> {
    let len = frame.payload.len();
    if len > MAX_PAYLOAD_LEN {
        return Err(AirError::PayloadTooLong);
    }
    let total = HEADER_LEN + len;
    let out = out.get_mut(..total).ok_or(AirError::BufferTooSmall)?;
    let (header, payload) = out.split_at_mut(HEADER_LEN);
    header[..2].copy_from_slice(&frame.dst.to_le_bytes());
    header[2..4].copy_from_slice(&frame.src.to_le_bytes());
    // In range: `len <= MAX_PAYLOAD_LEN`, checked above.
    header[4] = len as u8;
    payload.copy_from_slice(frame.payload);
    Ok(total)
}

/// Read a packet as a module would have transmitted it.
///
/// Strict: the length byte must account for exactly the bytes after the
/// header.
pub fn parse(bytes: &[u8]) -> Result<AirFrame<'_>, AirError> {
    let (header, payload) = bytes
        .split_at_checked(HEADER_LEN)
        .ok_or(AirError::Truncated)?;
    if usize::from(header[4]) != payload.len() {
        return Err(AirError::LengthMismatch);
    }
    Ok(AirFrame {
        dst: u16::from_le_bytes([header[0], header[1]]),
        src: u16::from_le_bytes([header[2], header[3]]),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes captured off the air from a RYLR998 on 2026-10-03: the `AT+SEND`
    /// that produced each, then what the WL55 received.
    const SENT_0X1234_TO_0X0102_AAAAAA: &[u8] =
        &[2, 1, 0x34, 0x12, 6, b'A', b'A', b'A', b'A', b'A', b'A'];
    const SENT_0X1234_TO_0X0102_B: &[u8] = &[2, 1, 0x34, 0x12, 1, b'B'];
    const SENT_5_TO_0XFFFF_CCCC: &[u8] = &[0xFF, 0xFF, 5, 0, 4, b'C', b'C', b'C', b'C'];

    fn encode_to_vec(frame: &AirFrame<'_>) -> Result<std::vec::Vec<u8>, AirError> {
        let mut out = [0u8; HEADER_LEN + MAX_PAYLOAD_LEN];
        let n = encode(frame, &mut out)?;
        Ok(out[..n].to_vec())
    }

    #[test]
    fn encodes_exactly_what_a_module_was_captured_sending() {
        let cases: [(u16, u16, &[u8], &[u8]); 3] = [
            (0x0102, 0x1234, b"AAAAAA", SENT_0X1234_TO_0X0102_AAAAAA),
            (0x0102, 0x1234, b"B", SENT_0X1234_TO_0X0102_B),
            (0xFFFF, 5, b"CCCC", SENT_5_TO_0XFFFF_CCCC),
        ];
        for (dst, src, payload, captured) in cases {
            let frame = AirFrame { dst, src, payload };
            assert_eq!(
                encode_to_vec(&frame).unwrap(),
                captured,
                "dst {dst:#06x} src {src:#06x}"
            );
        }
    }

    #[test]
    fn parses_what_a_module_was_captured_sending() {
        let frame = parse(SENT_0X1234_TO_0X0102_AAAAAA).unwrap();
        assert_eq!(
            frame,
            AirFrame {
                dst: 0x0102,
                src: 0x1234,
                payload: b"AAAAAA"
            }
        );

        let frame = parse(SENT_5_TO_0XFFFF_CCCC).unwrap();
        assert_eq!(
            frame,
            AirFrame {
                dst: 0xFFFF,
                src: 5,
                payload: b"CCCC"
            }
        );
    }

    #[test]
    fn broadcast_is_address_zero() {
        let frame = AirFrame {
            dst: BROADCAST,
            src: 0x00AA,
            payload: b"WL55hi",
        };
        assert_eq!(
            &encode_to_vec(&frame).unwrap()[..HEADER_LEN],
            &[0, 0, 0xAA, 0, 6]
        );
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let frame = AirFrame {
            dst: 1,
            src: 2,
            payload: b"",
        };
        let bytes = encode_to_vec(&frame).unwrap();
        assert_eq!(bytes, [1, 0, 2, 0, 0]);
        assert_eq!(parse(&bytes).unwrap(), frame);
    }

    #[test]
    fn the_largest_payload_the_module_accepts_round_trips() {
        let payload = [b'x'; MAX_PAYLOAD_LEN];
        let frame = AirFrame {
            dst: 7,
            src: 9,
            payload: &payload,
        };
        let bytes = encode_to_vec(&frame).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + MAX_PAYLOAD_LEN);
        assert_eq!(parse(&bytes).unwrap(), frame);
    }

    #[test]
    fn a_payload_longer_than_the_module_accepts_is_refused() {
        let payload = [b'x'; MAX_PAYLOAD_LEN + 1];
        let frame = AirFrame {
            dst: 7,
            src: 9,
            payload: &payload,
        };
        let mut out = [0u8; HEADER_LEN + MAX_PAYLOAD_LEN + 1];
        assert_eq!(encode(&frame, &mut out), Err(AirError::PayloadTooLong));
    }

    #[test]
    fn encoding_into_a_short_buffer_is_refused_not_truncated() {
        let frame = AirFrame {
            dst: 1,
            src: 2,
            payload: b"abc",
        };
        let mut out = [0u8; HEADER_LEN + 2];
        assert_eq!(encode(&frame, &mut out), Err(AirError::BufferTooSmall));
    }

    #[test]
    fn fewer_bytes_than_a_header_is_truncated() {
        for len in 0..HEADER_LEN {
            assert_eq!(
                parse(&SENT_0X1234_TO_0X0102_B[..len]),
                Err(AirError::Truncated),
                "len {len}"
            );
        }
    }

    /// Strict in both directions by choice: every captured packet's length byte
    /// matched exactly, and how the module treats one that does not is
    /// unmeasured, so a disagreement is not something this parser guesses at.
    #[test]
    fn a_length_byte_that_disagrees_with_the_packet_is_refused() {
        // Claims 6 bytes, carries 5.
        assert_eq!(
            parse(&SENT_0X1234_TO_0X0102_AAAAAA[..HEADER_LEN + 5]),
            Err(AirError::LengthMismatch)
        );
        // Claims 1 byte, carries 2.
        let mut long = SENT_0X1234_TO_0X0102_B.to_vec();
        long.push(b'!');
        assert_eq!(parse(&long), Err(AirError::LengthMismatch));
    }
}
