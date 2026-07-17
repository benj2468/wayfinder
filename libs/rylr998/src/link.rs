//! [`LinkT`] adapter: bridge a [`RylrClient`] onto a Wayfinder mesh as one
//! self-routing radio interface.
//!
//! Three impedance mismatches are handled here:
//!
//! * **Addressing.**  The mesh next-hop is a 6-byte [`Mac`]; the RYLR module
//!   addresses peers with a 16-bit address.  LoRa is physically a broadcast
//!   medium and the module's address is only a firmware-side UART pre-filter, so
//!   we always transmit to RYLR broadcast ([`RYLR_BROADCAST_ADDR`]) and let the
//!   mesh layer filter on the authoritative 6-byte `Mac` carried *inside* the
//!   frame. The sender address reported on receive is not used for mesh
//!   filtering, but it *is* used as half of the fragment-reassembly key (see
//!   `frag`) — nodes must therefore be configured with distinct `AT+ADDRESS`
//!   values (see `libs/rylr998/CLAUDE.md`).
//! * **Encoding.**  A [`LinkFrame`] is arbitrary binary, but the RYLR `AT+SEND`
//!   / `+RCV` protocol is line- and comma-delimited text.  Each frame's
//!   `[dst][src][protocol][payload]` bytes are therefore base64-encoded (a
//!   URL-safe alphabet, `A-Za-z0-9-_` plus `=` padding — no comma, CR, or LF
//!   can appear) on the wire, which the existing line reader parses safely.
//!   Base64 expands size by 4:3 rather than hex's 2:1, so a single on-air
//!   fragment is at most [`MAX_FRAME_LEN`] bytes.
//! * **Fragmentation.**  A frame too large for one on-air fragment is
//!   transparently split on `send` and reassembled on `recv` — see the `frag`
//!   module. `LinkT` callers never observe that a frame was split.
//!
//! The impl uses the native `async fn` [`LinkT`] trait directly (no boxing), so
//! it is usable from a `no_std` executor driving the radio.

use embedded_io_async::{Read, Write};
use tracing::trace;
use wayfinder::interfaces::frame::{LinkFrame, LinkFrameData, Mac};
use wayfinder::interfaces::link::{LinkError, LinkMetrics};
use wayfinder::link::{LinkT, Received};
use zerocopy::{FromBytes, IntoBytes};

use crate::frag;
use crate::{LoraError, RylrClient};

/// RYLR broadcast address.  Every node in range receives a frame sent here,
/// matching LoRa's physical broadcast; delivery is decided by the embedded
/// 6-byte destination `Mac`, never by this address.
const RYLR_BROADCAST_ADDR: u16 = 0;

/// Fixed link-frame header length: `dst(6) + src(6) + protocol(2)`.
pub(crate) const HEADER_LEN: usize = 14;

/// Largest framed length (header + payload) we can put on air.  The module
/// accepts 240 data bytes and base64 expands size 4:3, so a frame may be at
/// most 180 bytes (240 / 4 * 3, chosen so the encoding lands exactly on the
/// 240-byte budget with no waste). `send` always fragments (even a
/// single-fragment message pays the 2-byte frag header — see `frag`), so
/// every on-air unit's actual usable payload ceiling is
/// `180 - 2 (frag header) - 14 (link header) = 164` bytes.
pub(crate) const MAX_FRAME_LEN: usize = 180;

/// Largest base64-encoded length of a [`MAX_FRAME_LEN`]-byte fragment: 4
/// output chars per 3 input bytes, rounded up.
pub(crate) const MAX_ENCODED_LEN: usize = MAX_FRAME_LEN.div_ceil(3) * 4;

impl<S> RylrClient<S>
where
    S: Read + Write,
{
    /// Allocate the next fragmentation message id, wrapping at 256. Shared by
    /// every fragmented `send()` call; a collision would require as many
    /// concurrent in-flight messages from this sender as the id space, far
    /// beyond the bounded reassembly table any receiver keeps.
    fn next_msg_id(&mut self) -> u8 {
        let id = self.msg_id_ctr;
        self.msg_id_ctr = self.msg_id_ctr.wrapping_add(1);
        id
    }
}

impl<S> LinkT for RylrClient<S>
where
    S: Read + Write + Send,
{
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let frame_len = HEADER_LEN + data.payload.len();
        if frame_len > frag::MAX_REASSEMBLED_LEN {
            return Err(LinkError::BufferFull);
        }

        // Assemble the Ethernet-shaped `[dst][src][protocol][payload]` bytes
        // once, then split them across as many fragments as needed. Protocol
        // is big-endian (network byte order), matching `LinkFrame`'s EtherType.
        let mut frame = [0u8; frag::MAX_REASSEMBLED_LEN];
        frame[..6].copy_from_slice(data.dst.as_bytes());
        frame[6..12].copy_from_slice(origin.as_bytes());
        frame[12..14].copy_from_slice(&data.protocol.to_be_bytes());
        frame[14..frame_len].copy_from_slice(data.payload);

        // frame_len >= HEADER_LEN > 0, so div_ceil is already >= 1. Given the
        // frame_len bound above and frag's own const assert tying
        // MAX_REASSEMBLED_LEN to MAX_FRAGMENTS * FRAG_PAYLOAD, count can never
        // exceed MAX_FRAGMENTS today — kept as an explicit guard (not just the
        // compile-time assert) so a future change to either constant fails
        // loudly here instead of silently corrupting `pack_header`'s packed
        // nibble if `count` ever exceeded 15.
        let count = frame_len.div_ceil(frag::FRAG_PAYLOAD);
        if count > frag::MAX_FRAGMENTS {
            return Err(LinkError::BufferFull);
        }
        let msg_id = self.next_msg_id();

        for index in 0..count {
            let start = index * frag::FRAG_PAYLOAD;
            let end = core::cmp::min(start + frag::FRAG_PAYLOAD, frame_len);

            // Base64 packs bits in 3-byte groups, so the frag header and the
            // frame slice must be concatenated *before* encoding — encoding
            // them in two separate calls would each pad to its own group
            // boundary and produce bytes `decode_base64`'s single call on
            // the reassembled string could not reverse.
            let mut fragment = [0u8; frag::FRAG_HDR_LEN + frag::FRAG_PAYLOAD];
            fragment[..frag::FRAG_HDR_LEN]
                .copy_from_slice(&frag::pack_header(msg_id, index, count));
            fragment[frag::FRAG_HDR_LEN..frag::FRAG_HDR_LEN + (end - start)]
                .copy_from_slice(&frame[start..end]);

            let mut b64 = heapless::String::<MAX_ENCODED_LEN>::new();
            push_base64(&mut b64, &fragment[..frag::FRAG_HDR_LEN + (end - start)])?;

            self.send_data(RYLR_BROADCAST_ADDR, &b64).await?;
        }

        Ok(frame_len)
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        // Keep consuming physical packets, feeding each into the reassembler,
        // until *some* message completes — not necessarily the fragment just
        // read. A lone fragment of an incomplete message is buffered and the
        // loop continues; it never causes an early or fabricated return.
        loop {
            let packet = self.listen_for_packet().await?;
            let mut raw = [0u8; MAX_FRAME_LEN];
            let n = decode_base64(packet.data.as_str(), &mut raw)?;
            let Some((hdr, body)) = frag::parse_fragment(&raw[..n]) else {
                trace!(
                    addr = packet.address,
                    len = n,
                    "drop: malformed fragment header"
                );
                continue;
            };
            let key = frag::FragKey {
                addr: packet.address,
                msg_id: hdr.msg_id,
            };
            let metrics = metrics_from(packet.rssi, packet.snr);

            if let Some((len, metrics)) =
                self.reassembler
                    .accept(key, &hdr, body, metrics, &mut self.rx_frame)
            {
                let frame = LinkFrame::ref_from_bytes(&self.rx_frame[..len])
                    .map_err(|_| LinkError::InvalidPacket)?;
                return Ok(Received { frame, metrics });
            }
        }
    }
}

/// Map a driver-level [`LoraError`] onto the link-layer [`LinkError`] the mesh
/// engine understands.
impl From<LoraError> for LinkError {
    fn from(e: LoraError) -> Self {
        match e {
            LoraError::Io => LinkError::Io,
            LoraError::RequestTooLarge => LinkError::BufferFull,
            LoraError::InvalidResponse => LinkError::InvalidPacket,
            LoraError::Timeout => LinkError::ReceiveFailed,
            LoraError::ModuleError(_) => LinkError::TransmitFailed,
        }
    }
}

/// Derive [`LinkMetrics`] from a received packet's RSSI/SNR, leaving `quality`
/// for the engine to compute from the curve.  RSSI fits `i16` and SNR fits `i8`
/// for any real LoRa reading.
fn metrics_from(rssi: i32, snr: i32) -> LinkMetrics {
    LinkMetrics {
        rssi_dbm: Some(rssi as i16),
        snr_db: Some(snr as i8),
        quality: None,
    }
}

/// URL-safe base64 alphabet (`A-Za-z0-9-_`, RFC 4648 §5) — chosen over the
/// standard `+/` alphabet purely as defensive margin: it keeps every encoded
/// character clear of `+`, the AT command prefix character, even though `+`
/// only appears command-initial and the data field is read as a fixed-length
/// blob (see the module doc comment).
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Append the base64 encoding (see [`BASE64_ALPHABET`]) of `bytes` to `out`,
/// `=`-padded to a multiple of 4 chars, erroring if it would overflow the
/// fixed-capacity string.
fn push_base64<const N: usize>(
    out: &mut heapless::String<N>,
    bytes: &[u8],
) -> Result<(), LinkError> {
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        let sextets = [
            b0 >> 2,
            ((b0 & 0x03) << 4) | (b1 >> 4),
            ((b1 & 0x0f) << 2) | (b2 >> 6),
            b2 & 0x3f,
        ];
        for (i, &s) in sextets.iter().enumerate() {
            // Positions past `chunk.len()` (i.e. beyond the real input bytes
            // that fed this sextet) are padding, not data.
            let c = if i <= chunk.len() {
                BASE64_ALPHABET[s as usize] as char
            } else {
                '='
            };
            out.push(c).map_err(|_| LinkError::BufferFull)?;
        }
    }
    Ok(())
}

/// Decode a base64 string (see [`BASE64_ALPHABET`]) into `out`, returning the
/// number of bytes written (0 for an empty `s`). Errors if the length isn't a
/// multiple of 4, on a non-alphabet/misplaced-padding character, or if `out`
/// is too small.
fn decode_base64(s: &str, out: &mut [u8]) -> Result<usize, LinkError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(LinkError::InvalidPacket);
    }

    let mut n = 0;
    let (chunks, _remainder) = bytes.as_chunks::<4>();
    for chunk in chunks {
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if pad2 && !pad3 {
            // '=' in position 2 without position 3 also padded is not a
            // valid encoding of any byte length.
            return Err(LinkError::InvalidPacket);
        }

        let s0 = sextet(chunk[0])?;
        let s1 = sextet(chunk[1])?;
        let group_out = out.get_mut(n..n + 3).ok_or(LinkError::BufferFull)?;

        group_out[0] = (s0 << 2) | (s1 >> 4);
        n += 1;
        if !pad2 {
            let s2 = sextet(chunk[2])?;
            group_out[1] = ((s1 & 0x0f) << 4) | (s2 >> 2);
            n += 1;
            if !pad3 {
                let s3 = sextet(chunk[3])?;
                group_out[2] = ((s2 & 0x03) << 6) | s3;
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Parse one base64 alphabet character (see [`BASE64_ALPHABET`]) into its
/// 0..=63 sextet value.
fn sextet(c: u8) -> Result<u8, LinkError> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(LinkError::InvalidPacket),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// In-memory `embedded_io_async` serial: `read` drains a preloaded inbound
    /// queue (the module's responses) and `write` records every byte the client
    /// sends, so a test can assert on the exact AT command emitted.
    struct FakeSerial {
        inbound: VecDeque<u8>,
        outbound: Vec<u8>,
    }

    impl FakeSerial {
        fn new(inbound: &[u8]) -> Self {
            Self {
                inbound: inbound.iter().copied().collect(),
                outbound: Vec::new(),
            }
        }
    }

    impl embedded_io::ErrorType for FakeSerial {
        type Error = embedded_io::ErrorKind;
    }

    impl embedded_io_async::Read for FakeSerial {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let n = core::cmp::min(buf.len(), self.inbound.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.inbound.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl embedded_io_async::Write for FakeSerial {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// A frame small enough for one on-air packet is sent as a single
    /// fragment: header `[msg_id=0][index=0<<4|count=1]` followed by the
    /// base64-encoded Ethernet-shaped `[dst][src][protocol][payload]` bytes.
    #[tokio::test]
    async fn send_base64_encodes_frame_to_broadcast() {
        let mut client = RylrClient::new(FakeSerial::new(b"+OK\r\n")).unwrap();

        let payload = [0xde, 0xad];
        let n = client
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x4305,
                    payload: &payload,
                },
            )
            .await
            .unwrap();

        assert_eq!(n, HEADER_LEN + payload.len());

        let sent = String::from_utf8(client.stream.outbound.clone()).unwrap();
        let cmd = sent.lines().next().unwrap();
        assert!(cmd.starts_with("AT+SEND=0,"));

        let (hdr, body) = decode_fragment_cmd(cmd);
        assert_eq!(hdr, (0, 1), "msg_id=0, index=0<<4|count=1");

        // Ethernet-shaped layout: dst=2, src=1, protocol 0x4305 -> bytes 43 05.
        let mut expected = [0u8; HEADER_LEN + 2];
        expected[..6].copy_from_slice(&mac(2).0);
        expected[6..12].copy_from_slice(&mac(1).0);
        expected[12..14].copy_from_slice(&0x4305u16.to_be_bytes());
        expected[14..].copy_from_slice(&payload);
        assert_eq!(body, expected);
    }

    /// A frame too large for one on-air packet is split into multiple
    /// `AT+SEND` fragments, each base64-prefixed with
    /// `[msg_id][index<<4|count]` and carrying its slice of the
    /// `[dst][src][protocol][payload]` bytes.
    #[tokio::test]
    async fn send_splits_oversized_frame_into_fragments() {
        let mut client = RylrClient::new(FakeSerial::new(b"+OK\r\n+OK\r\n")).unwrap();

        // A payload just over one fragment's FRAG_PAYLOAD-byte content
        // budget, so it splits into a full first fragment and a 12-byte tail.
        let payload_len = frag::FRAG_PAYLOAD - HEADER_LEN + 12;
        let payload: Vec<u8> = (0..payload_len as u16).map(|i| i as u8).collect();
        let frame_len = HEADER_LEN + payload.len();

        let n = client
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x4305,
                    payload: &payload,
                },
            )
            .await
            .unwrap();
        assert_eq!(n, frame_len);

        let sent = String::from_utf8(client.stream.outbound.clone()).unwrap();
        let cmds: Vec<&str> = sent.lines().collect();
        assert_eq!(cmds.len(), 2, "expected exactly 2 AT+SEND fragments");

        // Reconstruct the full frame bytes to compare fragment content against.
        let mut frame = vec![0u8; frame_len];
        frame[..6].copy_from_slice(&mac(2).0);
        frame[6..12].copy_from_slice(&mac(1).0);
        frame[12..14].copy_from_slice(&0x4305u16.to_be_bytes());
        frame[14..].copy_from_slice(&payload);

        let (hdr0, body0) = decode_fragment_cmd(cmds[0]);
        let (hdr1, body1) = decode_fragment_cmd(cmds[1]);

        assert_eq!(hdr0.0, hdr1.0, "same message id across fragments");
        assert_eq!(hdr0.1, 2, "fragment 0: index=0, count=2");
        assert_eq!(hdr1.1, (1 << 4) | 2, "fragment 1: index=1, count=2");
        assert_eq!(body0, &frame[0..frag::FRAG_PAYLOAD]);
        assert_eq!(body1, &frame[frag::FRAG_PAYLOAD..frame_len]);
    }

    /// Parse one `AT+SEND=<addr>,<len>,<base64>` command line emitted by
    /// `send`, returning `((msg_id, header_byte), frame_content_bytes)`.
    fn decode_fragment_cmd(cmd: &str) -> ((u8, u8), Vec<u8>) {
        let b64 = cmd.rsplit(',').next().unwrap();
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = decode_base64(b64, &mut buf).unwrap();
        ((buf[0], buf[1]), buf[2..n].to_vec())
    }

    /// `recv` parses a `+RCV` line carrying a single-fragment message
    /// (`index=0, count=1`), base64-decodes the reassembled frame, and
    /// surfaces the radio's RSSI/SNR as link metrics.
    #[tokio::test]
    async fn recv_decodes_base64_frame_and_metrics() {
        // Ethernet-shaped: dst=4, src=3, proto=0x4305 (BE bytes 43 05),
        // payload=[0xca, 0xfe].
        let content = {
            let mut b = [0u8; 16];
            b[..6].copy_from_slice(&mac(4).0);
            b[6..12].copy_from_slice(&mac(3).0);
            b[12..14].copy_from_slice(&0x4305u16.to_be_bytes());
            b[14..16].copy_from_slice(&[0xca, 0xfe]);
            b
        };
        let line = encode_rcv_line(0, frag::pack_header(9, 0, 1), &content, -50, 7);
        let mut client = RylrClient::new(FakeSerial::new(line.as_bytes())).unwrap();

        let received = client.recv().await.unwrap();
        assert_eq!(received.frame.src, mac(3));
        assert_eq!(received.frame.dst, mac(4));
        assert_eq!(received.frame.protocol.get(), 0x4305);
        assert_eq!(&received.frame.payload, &[0xca, 0xfe]);
        assert_eq!(received.metrics.rssi_dbm, Some(-50));
        assert_eq!(received.metrics.snr_db, Some(7));
        assert_eq!(received.metrics.quality, None);
    }

    /// Fragments of one logical frame can arrive out of order; `recv`
    /// reassembles them and returns one `Received` carrying the metrics of
    /// whichever fragment completed the message.
    #[tokio::test]
    async fn recv_reassembles_out_of_order_fragments() {
        let tail_len = 12;
        let full_len = frag::FRAG_PAYLOAD + tail_len;
        let mut full = vec![0u8; full_len];
        full[..6].copy_from_slice(&mac(2).0);
        full[6..12].copy_from_slice(&mac(1).0);
        full[12..14].copy_from_slice(&0x4305u16.to_be_bytes());
        for (i, b) in full[14..].iter_mut().enumerate() {
            *b = i as u8;
        }

        // Fragment 1 (final, tail_len content bytes) arrives before fragment 0.
        let line1 = encode_rcv_line(
            7,
            frag::pack_header(5, 1, 2),
            &full[frag::FRAG_PAYLOAD..full_len],
            -55,
            4,
        );
        let line0 = encode_rcv_line(
            7,
            frag::pack_header(5, 0, 2),
            &full[0..frag::FRAG_PAYLOAD],
            -50,
            7,
        );
        let mut input = line1;
        input.push_str(&line0);
        let mut client = RylrClient::new(FakeSerial::new(input.as_bytes())).unwrap();

        let received = client.recv().await.unwrap();
        assert_eq!(received.frame.dst, mac(2));
        assert_eq!(received.frame.src, mac(1));
        assert_eq!(received.frame.protocol.get(), 0x4305);
        assert_eq!(&received.frame.payload, &full[14..full_len]);
        // Metrics come from fragment 0, which completed the message.
        assert_eq!(received.metrics.rssi_dbm, Some(-50));
        assert_eq!(received.metrics.snr_db, Some(7));
    }

    /// `recv` keeps consuming fragments until *some* message completes, not
    /// necessarily the one just fed. A lone fragment of an incomplete
    /// message must not cause `recv` to return early or fabricate a frame.
    #[tokio::test]
    async fn recv_skips_incomplete_message_and_returns_next_complete_one() {
        // Fragment 0 of a 2-fragment message from address 0 — never completes.
        let content_a0 = {
            let mut b = [0u8; 15];
            b[..6].copy_from_slice(&mac(9).0);
            b[6..12].copy_from_slice(&mac(8).0);
            b[12..14].copy_from_slice(&0x4305u16.to_be_bytes());
            b[14] = 0x11;
            b
        };
        let line_a0 = encode_rcv_line(0, frag::pack_header(1, 0, 2), &content_a0, -60, 3);

        // A separate, complete single-fragment message from the same address.
        let content_b = {
            let mut b = [0u8; 16];
            b[..6].copy_from_slice(&mac(4).0);
            b[6..12].copy_from_slice(&mac(3).0);
            b[12..14].copy_from_slice(&0x4305u16.to_be_bytes());
            b[14..16].copy_from_slice(&[0xca, 0xfe]);
            b
        };
        let line_b = encode_rcv_line(0, frag::pack_header(2, 0, 1), &content_b, -50, 7);

        let mut input = line_a0;
        input.push_str(&line_b);
        let mut client = RylrClient::new(FakeSerial::new(input.as_bytes())).unwrap();

        let received = client.recv().await.unwrap();
        assert_eq!(received.frame.src, mac(3));
        assert_eq!(received.frame.dst, mac(4));
        assert_eq!(&received.frame.payload, &[0xca, 0xfe]);
        assert_eq!(received.metrics.rssi_dbm, Some(-50));
    }

    /// Encode a `+RCV=<addr>,<len>,<base64>,<rssi>,<snr>\r\n` line for one
    /// fragment: `header` followed by `content` (frame bytes), base64-encoded
    /// together (base64 packs bits in 3-byte groups, so `header` and
    /// `content` must be concatenated before encoding — see the comment in
    /// `LinkT::send`).
    fn encode_rcv_line(
        addr: u16,
        header: [u8; frag::FRAG_HDR_LEN],
        content: &[u8],
        rssi: i32,
        snr: i32,
    ) -> String {
        let mut fragment = Vec::with_capacity(frag::FRAG_HDR_LEN + content.len());
        fragment.extend_from_slice(&header);
        fragment.extend_from_slice(content);

        let mut b64 = heapless::String::<MAX_ENCODED_LEN>::new();
        push_base64(&mut b64, &fragment).unwrap();
        format!("+RCV={},{},{},{},{}\r\n", addr, b64.len(), b64, rssi, snr)
    }

    /// A frame too large even after fragmentation (its total size exceeds the
    /// reassembly buffer capacity) is rejected before any serial traffic.
    #[tokio::test]
    async fn send_rejects_oversized_frame() {
        let mut client = RylrClient::new(FakeSerial::new(b"")).unwrap();

        // HEADER_LEN + 600 > MAX_REASSEMBLED_LEN (512).
        let big = [0u8; 600];
        let err = client
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0,
                    payload: &big,
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(err, LinkError::BufferFull));
        assert!(client.stream.outbound.is_empty());
    }

    /// Base64 (URL-safe alphabet: `A-Za-z0-9-_`, `=`-padded — no comma, CR,
    /// or LF can appear, matching the AT protocol's line/comma-delimited
    /// framing) round-trips arbitrary bytes, at lengths that need 0, 1, and 2
    /// padding characters.
    #[test]
    fn base64_round_trips() {
        for bytes in [
            &[0x00, 0x7f, 0x80, 0xff, 0x12, 0xab][..], // 6 bytes: no padding
            &[0xde, 0xad][..],                         // 2 bytes: one '=' pad
            &[0xde][..],                               // 1 byte: two '=' pad
            &[][..],                                   // empty
        ] {
            let mut b64 = heapless::String::<64>::new();
            push_base64(&mut b64, bytes).unwrap();
            assert_eq!(b64.len() % 4, 0, "base64 output is always block-aligned");

            let mut out = [0u8; 8];
            let n = decode_base64(b64.as_str(), &mut out).unwrap();
            assert_eq!(&out[..n], bytes);
        }
    }

    /// A worked ASCII example spanning both a full 3-byte group and a
    /// 1-byte trailing (double-padded) group, cross-checked by hand against
    /// the URL-safe alphabet.
    #[test]
    fn base64_matches_known_vector() {
        let mut b64 = heapless::String::<64>::new();
        push_base64(&mut b64, b"any ").unwrap();
        assert_eq!(b64.as_str(), "YW55IA==");
    }

    /// Non-alphabet bytes (e.g. a comma, which the AT protocol treats as a
    /// field delimiter) are rejected rather than silently misparsed.
    #[test]
    fn decode_base64_rejects_invalid_input() {
        let mut out = [0u8; 8];
        assert!(matches!(
            decode_base64("YW,5IA==", &mut out),
            Err(LinkError::InvalidPacket)
        ));
        // Length not a multiple of 4.
        assert!(matches!(
            decode_base64("YW5", &mut out),
            Err(LinkError::InvalidPacket)
        ));
    }
}
