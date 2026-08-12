//! Shared Ethernet-shaped frame serialization: `[dst: Mac][src: Mac][ethertype:
//! u16 BE][payload]`, the wire layout every carrier that isn't a genuine
//! point-to-point pipe with an implicit peer needs to write for itself.
//!
//! [`LinkFrame`](crate::frame::LinkFrame) already *has* this layout, which is
//! what makes the module worth sharing: a carrier whose medium is real
//! Ethernet — a raw `AF_PACKET` socket on a host, a CDC-NCM USB function on a
//! board — can put a frame on the wire and take it off again with no
//! conversion, only a two-byte retag of the EtherType field.

use crate::frame::LinkFrameData;
use crate::frame::Mac;

/// Length of the Ethernet header preceding the payload: `[dst: 6][src: 6][ethertype: 2]`.
pub const ETH_HEADER_LEN: usize = 14;

/// Byte offset of the EtherType field within the Ethernet header, i.e. just
/// past the destination and source MACs.  This is the same offset as
/// [`LinkFrame::protocol`](crate::frame::LinkFrame::protocol), which is what
/// lets a caller with a separate wire-vs-mesh protocol split retag the field in
/// place — see [`retag_ethertype`].
pub const ETHERTYPE_OFFSET: usize = 12;

/// Serialize `origin` + `data` as an Ethernet-shaped frame into `buf`,
/// returning its length, or `None` when the framed frame would not fit `buf`.
///
/// Wire layout `[dst: Mac][src: Mac][ethertype: u16 BE][payload]` — identical
/// to the [`LinkFrame`](crate::frame::LinkFrame) layout.  `ethertype` is
/// written verbatim: a caller with no wire-vs-mesh distinction (a
/// point-to-point pipe, a multi-access UDP link) passes `data.protocol` through
/// unchanged; a caller that needs a separate wire transport label (the raw-L2
/// packet socket, the CDC-NCM USB link) passes that label instead and retags
/// the field back to the mesh protocol on receive.
///
/// The length check returns `None` rather than panicking on an out-of-bounds
/// copy: a frame larger than `buf` (only reachable with an over-large host MTU
/// plus the auth trailer) is dropped by the caller, never crashing the link
/// task.
pub fn frame_into_buf(
    origin: Mac,
    ethertype: u16,
    data: &LinkFrameData<'_>,
    buf: &mut [u8],
) -> Option<usize> {
    let end = ETH_HEADER_LEN + data.payload.len();
    if end > buf.len() {
        return None;
    }
    buf[0..6].copy_from_slice(&data.dst.0);
    buf[6..12].copy_from_slice(&origin.0);
    buf[ETHERTYPE_OFFSET..ETH_HEADER_LEN].copy_from_slice(&ethertype.to_be_bytes());
    buf[ETH_HEADER_LEN..end].copy_from_slice(data.payload);
    Some(end)
}

/// Read the EtherType off a received Ethernet frame, or `None` if `buf` is too
/// short to hold a complete header.
///
/// This is the receive-side filter for a carrier that shares its medium with
/// unrelated traffic: a raw packet socket sees every frame on the NIC, and a
/// CDC-NCM function sees whatever the host's IP stack emits on the interface
/// (IPv6 router solicitations and duplicate-address detection, mDNS). Only
/// frames bearing the link's own transport label are ours.
pub fn wire_ethertype(buf: &[u8]) -> Option<u16> {
    let bytes = buf.get(ETHERTYPE_OFFSET..ETH_HEADER_LEN)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Rewrite a received frame's EtherType field to `protocol`, in place.
///
/// The wire EtherType is a transport label the router does not understand; the
/// mesh protocol it demuxes on is a fixed property of the link (BATMAN). Because
/// the EtherType field sits at the same offset as
/// [`LinkFrame::protocol`](crate::frame::LinkFrame::protocol), overwriting those
/// two bytes turns the received Ethernet frame into a
/// [`LinkFrame`](crate::frame::LinkFrame) the router can demux, with no copy and
/// no length change.
///
/// # Panics
///
/// If `buf` is shorter than [`ETH_HEADER_LEN`]. Callers filter with
/// [`wire_ethertype`] first, which rejects exactly that case.
pub fn retag_ethertype(buf: &mut [u8], protocol: u16) {
    buf[ETHERTYPE_OFFSET..ETH_HEADER_LEN].copy_from_slice(&protocol.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// `frame_into_buf` lays down a genuine Ethernet frame: destination, source,
    /// the given EtherType (big-endian), then the payload.
    #[test]
    fn frame_into_buf_stamps_ethertype() {
        let mut buf = [0u8; 64];
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let n = frame_into_buf(
            mac(1),
            0xfafa,
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305, // not what's written; caller controls the wire value
                payload: &payload,
            },
            &mut buf,
        )
        .expect("frame fits buffer");
        assert_eq!(n, ETH_HEADER_LEN + payload.len());
        assert_eq!(&buf[0..6], &mac(2).0); // Ethernet destination
        assert_eq!(&buf[6..12], &mac(1).0); // Ethernet source
        assert_eq!(&buf[12..14], &[0xfa, 0xfa]); // stamped EtherType
        assert_eq!(&buf[14..n], &payload);
    }

    /// Correct for an empty payload (the minimum-length frame), leaving just
    /// `[dst][src][protocol]`.
    #[test]
    fn frame_into_buf_handles_empty_payload() {
        let mut buf = [0u8; 32];
        let n = frame_into_buf(
            mac(3),
            0x88b5,
            &LinkFrameData {
                dst: mac(4),
                protocol: 0x4305,
                payload: &[],
            },
            &mut buf,
        )
        .expect("frame fits buffer");
        assert_eq!(n, ETH_HEADER_LEN);
        assert_eq!(&buf[0..6], &mac(4).0);
        assert_eq!(&buf[6..12], &mac(3).0);
    }

    /// A payload that would overrun the buffer yields `None` (a drop) instead of
    /// panicking on the out-of-bounds copy — the caller must survive an
    /// over-large frame rather than aborting.
    #[test]
    fn frame_into_buf_rejects_oversize_payload() {
        let mut buf = [0u8; 32];
        // 32 - 14 header = 18 bytes fit; 19 does not.
        let payload = [0u8; 19];
        let out = frame_into_buf(
            mac(1),
            0xfafa,
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut buf,
        );
        assert_eq!(out, None);
    }

    /// `wire_ethertype` reads back exactly what `frame_into_buf` stamped.
    #[test]
    fn wire_ethertype_reads_the_stamped_label() {
        let mut buf = [0u8; 64];
        let n = frame_into_buf(
            mac(1),
            0xfafa,
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &[1, 2, 3],
            },
            &mut buf,
        )
        .expect("frame fits buffer");
        assert_eq!(wire_ethertype(&buf[..n]), Some(0xfafa));
    }

    /// A buffer too short to hold a complete Ethernet header has no EtherType to
    /// read, so the filter rejects it rather than indexing past the end. The
    /// boundary matters: exactly `ETH_HEADER_LEN` is a valid empty-payload
    /// frame, one byte less is a runt.
    #[test]
    fn wire_ethertype_rejects_a_runt() {
        let buf = [0u8; ETH_HEADER_LEN];
        assert_eq!(wire_ethertype(&buf), Some(0));
        assert_eq!(wire_ethertype(&buf[..ETH_HEADER_LEN - 1]), None);
        assert_eq!(wire_ethertype(&[]), None);
    }

    /// Retagging rewrites only the two EtherType bytes, leaving the addresses
    /// and payload byte-identical — that in-place edit is what lets a received
    /// Ethernet frame reinterpret as a `LinkFrame` with no copy.
    #[test]
    fn retag_ethertype_rewrites_only_the_protocol_field() {
        let mut buf = [0u8; 64];
        let payload = [0xaa, 0xbb, 0xcc];
        let n = frame_into_buf(
            mac(1),
            0xfafa,
            &LinkFrameData {
                dst: mac(2),
                protocol: 0,
                payload: &payload,
            },
            &mut buf,
        )
        .expect("frame fits buffer");

        retag_ethertype(&mut buf, 0x4305);

        assert_eq!(&buf[0..6], &mac(2).0);
        assert_eq!(&buf[6..12], &mac(1).0);
        assert_eq!(&buf[12..14], &[0x43, 0x05]);
        assert_eq!(&buf[14..n], &payload);
    }

    /// The round trip the raw-L2 and CDC-NCM carriers both depend on: a frame
    /// stamped with a wire transport label, retagged on receive, parses as a
    /// `LinkFrame` carrying the mesh protocol and the original addresses.
    #[test]
    fn stamp_then_retag_round_trips_into_a_link_frame() {
        use crate::frame::LinkFrame;
        use zerocopy::FromBytes;

        let mut buf = [0u8; 64];
        let payload = [1u8, 2, 3, 4, 5];
        let n = frame_into_buf(
            mac(7),
            0xfafa,
            &LinkFrameData {
                dst: mac(9),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut buf,
        )
        .expect("frame fits buffer");

        assert_eq!(wire_ethertype(&buf[..n]), Some(0xfafa));
        retag_ethertype(&mut buf[..n], 0x4305);

        let frame = LinkFrame::ref_from_bytes(&buf[..n]).expect("retagged bytes are a LinkFrame");
        assert_eq!(frame.dst, mac(9));
        assert_eq!(frame.src, mac(7));
        assert_eq!(frame.protocol.get(), 0x4305);
        assert_eq!(&frame.payload, &payload);
    }
}
