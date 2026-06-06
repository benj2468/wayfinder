//! [`LinkT`] adapter: bridge a [`RylrClient`] onto a Wayfinder mesh as one
//! self-routing radio interface.
//!
//! Two impedance mismatches are handled here:
//!
//! * **Addressing.**  The mesh next-hop is a 6-byte [`Mac`]; the RYLR module
//!   addresses peers with a 16-bit address.  LoRa is physically a broadcast
//!   medium and the module's address is only a firmware-side UART pre-filter, so
//!   we always transmit to RYLR broadcast ([`RYLR_BROADCAST_ADDR`]) and let the
//!   mesh layer filter on the authoritative 6-byte `Mac` carried *inside* the
//!   frame.  The sender address reported on receive is ignored.
//! * **Encoding.**  A [`LinkFrame`] is arbitrary binary, but the RYLR `AT+SEND`
//!   / `+RCV` protocol is line- and comma-delimited text.  Each frame's
//!   `[src][dst][protocol][payload]` bytes are therefore hex-encoded on the
//!   wire (no commas or newlines), which the existing line reader parses safely.
//!   Hex doubles the size, so a frame is at most [`MAX_FRAME_LEN`] bytes.
//!
//! The impl uses the native `async fn` [`LinkT`] trait directly (no boxing), so
//! it is usable from a `no_std` executor driving the radio.

use embedded_io_async::{Read, Write};
use wayfinder::interfaces::frame::{LinkFrame, LinkFrameData, Mac};
use wayfinder::interfaces::link::{LinkError, LinkMetrics};
use wayfinder::link::{LinkT, Received};
use zerocopy::{FromBytes, IntoBytes};

use crate::{LoraError, RylrClient};

/// RYLR broadcast address.  Every node in range receives a frame sent here,
/// matching LoRa's physical broadcast; delivery is decided by the embedded
/// 6-byte destination `Mac`, never by this address.
const RYLR_BROADCAST_ADDR: u16 = 0;

/// Fixed link-frame header length: `src(6) + dst(6) + protocol(2)`.
const HEADER_LEN: usize = 14;

/// Largest framed length (header + payload) we can put on air.  The module
/// accepts 240 data bytes and hex doubles size, so a frame may be at most 120
/// bytes — leaving `120 - 14 = 106` bytes of payload.
const MAX_FRAME_LEN: usize = 120;

impl<S> LinkT for RylrClient<S>
where
    S: Read + Write + Send,
{
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let frame_len = HEADER_LEN + data.payload.len();
        if frame_len > MAX_FRAME_LEN {
            return Err(LinkError::BufferFull);
        }

        // Hex-encode `[origin][dst][protocol][payload]` straight into the AT
        // payload.  Protocol is native-endian, matching the `LinkFrame` wire
        // convention used across the mesh.
        let mut hex = heapless::String::<{ MAX_FRAME_LEN * 2 }>::new();
        push_hex(&mut hex, origin.as_bytes())?;
        push_hex(&mut hex, data.dst.as_bytes())?;
        push_hex(&mut hex, &data.protocol.to_ne_bytes())?;
        push_hex(&mut hex, data.payload)?;

        self.send_data(RYLR_BROADCAST_ADDR, &hex).await?;
        Ok(frame_len)
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        let packet = self.listen_for_packet().await?;
        let n = decode_hex(packet.data.as_str(), &mut self.rx_frame)?;
        let frame =
            LinkFrame::ref_from_bytes(&self.rx_frame[..n]).map_err(|_| LinkError::InvalidPacket)?;
        Ok(Received {
            frame,
            metrics: metrics_from(packet.rssi, packet.snr),
        })
    }

    fn try_recv(&mut self) -> Option<Result<Received<'_>, LinkError>> {
        // The radio is driven over a blocking AT serial stream with no
        // non-blocking peek, so there is no cancel-safe poll to offer.
        None
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

/// Append the lowercase-hex encoding of `bytes` to `out`, erroring if it would
/// overflow the fixed-capacity string.
fn push_hex<const N: usize>(out: &mut heapless::String<N>, bytes: &[u8]) -> Result<(), LinkError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char)
            .map_err(|_| LinkError::BufferFull)?;
        out.push(HEX[(b & 0x0f) as usize] as char)
            .map_err(|_| LinkError::BufferFull)?;
    }
    Ok(())
}

/// Decode a hex string into `out`, returning the number of bytes written.
/// Errors on odd length or a non-hex digit, or if `out` is too small.
fn decode_hex(s: &str, out: &mut [u8]) -> Result<usize, LinkError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(LinkError::InvalidPacket);
    }
    let n = bytes.len() / 2;
    if n > out.len() {
        return Err(LinkError::BufferFull);
    }
    for (i, slot) in out[..n].iter_mut().enumerate() {
        *slot = (nibble(bytes[2 * i])? << 4) | nibble(bytes[2 * i + 1])?;
    }
    Ok(n)
}

/// Parse one ASCII hex digit (either case) into its 0..=15 value.
fn nibble(c: u8) -> Result<u8, LinkError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
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

    /// `send` hex-encodes `[src][dst][protocol][payload]` and emits one
    /// `AT+SEND` to the broadcast address, returning the framed byte length.
    #[tokio::test]
    async fn send_hex_encodes_frame_to_broadcast() {
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
        // protocol 0x4305 is written native-endian (little-endian test host):
        // bytes 05 43.
        let hex = "0000000000010000000000020543dead";
        let expected = format!("AT+SEND=0,{},{}\r\n", hex.len(), hex);
        assert_eq!(client.stream.outbound, expected.as_bytes());
    }

    /// `recv` parses a `+RCV` line, hex-decodes the frame, and surfaces the
    /// radio's RSSI/SNR as link metrics.
    #[tokio::test]
    async fn recv_decodes_hex_frame_and_metrics() {
        // src=3, dst=4, proto=0x4305 (LE bytes 05 43), payload=[0xca, 0xfe].
        let hex = "0000000000030000000000040543cafe";
        let line = format!("+RCV=0,{},{},-50,7\r\n", hex.len(), hex);
        let mut client = RylrClient::new(FakeSerial::new(line.as_bytes())).unwrap();

        let received = client.recv().await.unwrap();
        assert_eq!(received.frame.src, mac(3));
        assert_eq!(received.frame.dst, mac(4));
        assert_eq!({ received.frame.protocol }, 0x4305);
        assert_eq!(&received.frame.payload, &[0xca, 0xfe]);
        assert_eq!(received.metrics.rssi_dbm, Some(-50));
        assert_eq!(received.metrics.snr_db, Some(7));
        assert_eq!(received.metrics.quality, None);
    }

    /// A frame whose hex would exceed the module's 240-byte data limit is
    /// rejected before any serial traffic.
    #[tokio::test]
    async fn send_rejects_oversized_frame() {
        let mut client = RylrClient::new(FakeSerial::new(b"")).unwrap();

        // HEADER_LEN + this payload > MAX_FRAME_LEN.
        let big = [0u8; MAX_FRAME_LEN];
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

    /// Hex encode/decode round-trips an arbitrary byte string.
    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x7f, 0x80, 0xff, 0x12, 0xab];
        let mut hex = heapless::String::<64>::new();
        push_hex(&mut hex, &bytes).unwrap();
        assert_eq!(hex.as_str(), "007f80ff12ab");

        let mut out = [0u8; 8];
        let n = decode_hex(hex.as_str(), &mut out).unwrap();
        assert_eq!(&out[..n], &bytes);
    }
}
