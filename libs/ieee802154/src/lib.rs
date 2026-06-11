#![cfg_attr(not(test), no_std)]

//! Hardware-agnostic framing for IEEE 802.15.4 mesh interfaces.
//!
//! This crate handles only the on-air frame shape: wrapping a Wayfinder
//! [`LinkFrame`] in a minimal IEEE 802.15.4 MAC header on send, and
//! unwrapping it on receive. It has no opinion about which radio chip or HAL
//! drives the actual transmit/receive — a `LinkT` impl for a specific radio
//! is built on top of [`encode`]/[`decode`].
//!
//! Like the RYLR998 LoRa link, IEEE 802.15.4 is treated as a shared broadcast
//! medium: every frame is addressed to the 802.15.4 broadcast PAN/address,
//! and the mesh layer filters on the 6-byte [`Mac`] embedded in the
//! [`LinkFrame`] rather than on 802.15.4-level addressing.

use interfaces::frame::{LinkFrame, LinkFrameData, Mac};
use interfaces::link::LinkError;
use zerocopy::byteorder::little_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// IEEE 802.15.4 Frame Control Field, frame type sub-field (bits 0-2): a Data
/// frame.
const FRAME_TYPE_DATA: u16 = 0b001;

/// IEEE 802.15.4 Frame Control Field, destination addressing mode sub-field
/// (bits 10-11): a 16-bit short address follows.
const DEST_ADDR_MODE_SHORT: u16 = 0b10 << 10;

/// Frame Control Field written by [`encode`] and required by [`decode`]: a
/// Data frame with 16-bit short destination addressing, no security/ack/PAN
/// ID compression, and no source addressing (the embedded [`LinkFrame`]
/// carries the real mesh addresses).
const FRAME_CONTROL: u16 = FRAME_TYPE_DATA | DEST_ADDR_MODE_SHORT;

/// IEEE 802.15.4 broadcast PAN ID and short address (`0xffff`). [`encode`]
/// always targets this address; the radio is physically a shared medium, like
/// LoRa, so addressing is done by the embedded [`Mac`] instead.
const BROADCAST_ADDR: u16 = 0xffff;

/// Minimal IEEE 802.15.4 MAC header for a broadcast data frame: Frame Control
/// Field, sequence number, destination PAN ID, and destination address.
/// Source addressing is omitted entirely (the addressing-mode bits in
/// [`FRAME_CONTROL`] mark it "not present"). All multi-byte fields are
/// little-endian, per the IEEE 802.15.4 wire format.
///
/// The 2-byte FCS that radio hardware appends on transmit and strips on
/// receive is *not* part of this struct or any buffer this crate produces.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Ieee802154Header {
    /// Frame type, addressing modes, and other control bits. Always
    /// [`FRAME_CONTROL`] for frames this crate produces.
    pub frame_control: U16,
    /// IEEE 802.15.4 MAC sequence number, set by the caller of [`encode`].
    pub seq: u8,
    /// Destination PAN ID. Always [`BROADCAST_ADDR`].
    pub dest_pan_id: U16,
    /// Destination short address. Always [`BROADCAST_ADDR`].
    pub dest_addr: U16,
}

/// Size in bytes of [`Ieee802154Header`] (7).
pub const HEADER_LEN: usize = core::mem::size_of::<Ieee802154Header>();

/// IEEE 802.15.4's `aMaxPHYPacketSize`: the largest PHY payload, including the
/// 2-byte FCS appended by radio hardware.
const MAX_PHY_PACKET_SIZE: usize = 127;

/// Length of the FCS that radio hardware appends on transmit and strips on
/// receive; not part of any buffer this crate produces or accepts.
const FCS_LEN: usize = 2;

/// Largest buffer [`encode`] will write or [`decode`] will accept:
/// `aMaxPHYPacketSize` minus the hardware-handled FCS.
pub const MAX_FRAME_LEN: usize = MAX_PHY_PACKET_SIZE - FCS_LEN;

/// Length of the `[dst][src][protocol]` header that prefixes every
/// [`LinkFrame`] (6 + 6 + 2 bytes).
const LINK_HEADER_LEN: usize = 14;

/// Largest mesh-frame payload [`encode`] will accept: [`MAX_FRAME_LEN`] minus
/// the IEEE 802.15.4 header and the [`LinkFrame`] header.
pub const MAX_PAYLOAD_LEN: usize = MAX_FRAME_LEN - HEADER_LEN - LINK_HEADER_LEN;

/// Encode `data`, sent from `origin`, as a minimal broadcast IEEE 802.15.4
/// data frame into `buf`: a 7-byte [`Ieee802154Header`] (broadcast PAN ID and
/// destination address, `seq` as given) followed by the [`LinkFrame`]
/// `[dst][src][protocol][payload]` layout.
///
/// Returns the number of bytes written. Returns [`LinkError::BufferFull`] if
/// `data.payload` exceeds [`MAX_PAYLOAD_LEN`] or `buf` is too small to hold
/// the encoded frame.
pub fn encode(
    seq: u8,
    origin: Mac,
    data: &LinkFrameData<'_>,
    buf: &mut [u8],
) -> Result<usize, LinkError> {
    if data.payload.len() > MAX_PAYLOAD_LEN {
        return Err(LinkError::BufferFull);
    }
    let total = HEADER_LEN + LINK_HEADER_LEN + data.payload.len();
    if buf.len() < total {
        return Err(LinkError::BufferFull);
    }

    let header = Ieee802154Header {
        frame_control: U16::new(FRAME_CONTROL),
        seq,
        dest_pan_id: U16::new(BROADCAST_ADDR),
        dest_addr: U16::new(BROADCAST_ADDR),
    };
    buf[..HEADER_LEN].copy_from_slice(header.as_bytes());

    let link = &mut buf[HEADER_LEN..total];
    link[..6].copy_from_slice(&data.dst.0);
    link[6..12].copy_from_slice(&origin.0);
    link[12..14].copy_from_slice(&data.protocol.to_be_bytes());
    link[14..].copy_from_slice(data.payload);

    Ok(total)
}

/// Decode a received buffer (with the FCS already stripped by the radio) back
/// into a [`LinkFrame`] borrowed from `buf`.
///
/// Returns [`LinkError::InvalidPacket`] if `buf` is too short to hold an
/// [`Ieee802154Header`] plus a [`LinkFrame`] header, or if the header's frame
/// type is not Data (e.g. a beacon, ack, or command frame from another device
/// sharing the channel).
pub fn decode(buf: &[u8]) -> Result<&LinkFrame, LinkError> {
    if buf.len() < HEADER_LEN + LINK_HEADER_LEN {
        return Err(LinkError::InvalidPacket);
    }

    let (header, _) =
        Ieee802154Header::ref_from_prefix(buf).map_err(|_| LinkError::InvalidPacket)?;
    if header.frame_control.get() & 0x07 != FRAME_TYPE_DATA {
        return Err(LinkError::InvalidPacket);
    }

    LinkFrame::ref_from_bytes(&buf[HEADER_LEN..]).map_err(|_| LinkError::InvalidPacket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// `encode` writes the fixed broadcast 802.15.4 header — Frame Control
    /// Field `0x0801` (Data, short destination addressing, no source
    /// addressing), the given sequence number, and broadcast PAN ID /
    /// destination address — as the first 7 bytes, little-endian.
    #[test]
    fn encode_writes_minimal_broadcast_header() {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let payload = [0xaa, 0xbb];
        let n = encode(
            42,
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut buf,
        )
        .unwrap();

        assert_eq!(n, HEADER_LEN + LINK_HEADER_LEN + payload.len());
        assert_eq!(
            &buf[..HEADER_LEN],
            &[0x01, 0x08, 42, 0xff, 0xff, 0xff, 0xff]
        );
    }

    /// `encode` followed by `decode` round-trips the embedded `LinkFrame`'s
    /// src, dst, protocol, and payload.
    #[test]
    fn round_trips_link_frame() {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let n = encode(
            7,
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut buf,
        )
        .unwrap();

        let frame = decode(&buf[..n]).unwrap();
        assert_eq!(frame.src, mac(1));
        assert_eq!(frame.dst, mac(2));
        assert_eq!(frame.protocol.get(), 0x4305);
        assert_eq!(&frame.payload, &payload);
    }

    /// A payload larger than `MAX_PAYLOAD_LEN` is rejected before touching
    /// `buf`.
    #[test]
    fn encode_rejects_oversized_payload() {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let big = [0u8; MAX_PAYLOAD_LEN + 1];
        let err = encode(
            0,
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0,
                payload: &big,
            },
            &mut buf,
        )
        .unwrap_err();

        assert!(matches!(err, LinkError::BufferFull));
    }

    /// `encode` rejects a destination buffer too small to hold the encoded
    /// frame, even when the payload itself is within `MAX_PAYLOAD_LEN`.
    #[test]
    fn encode_rejects_undersized_buffer() {
        let mut buf = [0u8; HEADER_LEN];
        let payload = [0xaa];
        let err = encode(
            0,
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0,
                payload: &payload,
            },
            &mut buf,
        )
        .unwrap_err();

        assert!(matches!(err, LinkError::BufferFull));
    }

    /// A buffer too short to contain an `Ieee802154Header` plus a `LinkFrame`
    /// header is rejected.
    #[test]
    fn decode_rejects_short_buffer() {
        let buf = [0u8; HEADER_LEN + LINK_HEADER_LEN - 1];
        assert!(matches!(decode(&buf), Err(LinkError::InvalidPacket)));
    }

    /// A frame whose Frame Control Field encodes a non-Data frame type (e.g.
    /// an Ack) is rejected rather than misread as mesh data.
    #[test]
    fn decode_rejects_non_data_frame() {
        let mut buf = [0u8; HEADER_LEN + LINK_HEADER_LEN];
        // Frame type = 0b010 (Ack), all other fields zero.
        buf[0] = 0b010;
        assert!(matches!(decode(&buf), Err(LinkError::InvalidPacket)));
    }
}
