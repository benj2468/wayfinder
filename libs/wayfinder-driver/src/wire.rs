//! Shared Ethernet-shaped frame serialization: `[dst: Mac][src: Mac][ethertype:
//! u16 BE][payload]`, the wire layout every carrier that isn't a genuine
//! point-to-point pipe with an implicit peer needs to write for itself — a
//! point-to-point [`Link`](crate::transport::Link), the raw-L2 packet socket,
//! and a multi-access UDP socket all stamp the exact same bytes, so they share
//! one bounds-checked writer instead of each re-implementing the copy.

use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;

/// Length of the Ethernet header preceding the payload: `[dst: 6][src: 6][ethertype: 2]`.
pub(crate) const ETH_HEADER_LEN: usize = 14;

/// Byte offset of the EtherType field within the Ethernet header, i.e. just
/// past the destination and source MACs.  This is the same offset as
/// [`LinkFrame::protocol`](interfaces::frame::LinkFrame::protocol), which is
/// what lets a caller with a separate wire-vs-mesh protocol split (see
/// `raw::retag_ethertype`) retag the field in place.
pub(crate) const ETHERTYPE_OFFSET: usize = 12;

/// Serialize `origin` + `data` as an Ethernet-shaped frame into `buf`,
/// returning its length, or `None` when the framed frame would not fit `buf`.
///
/// Wire layout `[dst: Mac][src: Mac][ethertype: u16 BE][payload]` — identical
/// to the [`LinkFrame`](interfaces::frame::LinkFrame) layout.  `ethertype` is
/// written verbatim: a caller with no wire-vs-mesh distinction (a
/// point-to-point [`Link`](crate::transport::Link), a multi-access UDP link)
/// passes `data.protocol` through unchanged; a caller that needs a separate
/// wire transport label (the raw-L2 packet socket) passes that label instead
/// and retags the field back to the mesh protocol on receive.
///
/// The length check returns `None` rather than panicking on an out-of-bounds
/// copy: a frame larger than `buf` (only reachable with an over-large host MTU
/// plus the auth trailer) is dropped by the caller, never crashing the link
/// task.
pub(crate) fn frame_into_buf(
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
}
