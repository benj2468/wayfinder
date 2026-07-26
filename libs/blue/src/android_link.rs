//! `LinkT` adapter carrying the mesh over BLE connectionless advertising on
//! Android, generic over a platform-supplied [`BleAdvertiser`] rather than
//! driving a concrete BLE stack directly.
//!
//! Android's own BLE APIs (`BluetoothLeAdvertiser`/`BluetoothLeScanner`)
//! build/parse the Manufacturer Specific Data AD structure the same way
//! BlueZ does — from/to a raw byte payload — so this backend follows
//! [`crate::StdBleLink`]'s shape (bare `[frag_header][body]` fragments via
//! `frame::build_fragment`, no self-framing via `crate::ad`), not
//! [`crate::NrfBleLink`]'s. What's different is that the actual platform
//! call is injected rather than hard-wired: the JNI/UniFFI glue that will
//! drive Android's BLE APIs is a later phase, so this crate stays free of
//! any Android/JNI dependency while still being fully testable against a
//! fake [`BleAdvertiser`] — unlike either existing backend, which each need
//! real hardware/`bluetoothd` to exercise their I/O (see
//! `libs/blue/CLAUDE.md`'s "Testability" section).

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::trace;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::interfaces::link::LinkMetrics;
use wayfinder::link::LinkT;
use wayfinder::link::Received;
use wayfinder_link_utils::FragKey;
use wayfinder_link_utils::parse_fragment;
use zerocopy::FromBytes;

use crate::addr::BleAddr;
use crate::frame::MAX_FRAGMENT_BYTES;
use crate::frame::MAX_REASSEMBLED_LEN;
use crate::frame::RawReport;
use crate::frame::Reassembler;
use crate::frame::{self};

/// Depth of the queue between the platform's scan callback and `recv`'s
/// consumer. Not derived from a hard limit — a small multiple of what one
/// `recv` call can plausibly fall behind by; capacity pressure drops the
/// newest report rather than blocking the callback, matching
/// `StdBleLink`'s policy (`libs/blue/src/std_link.rs`).
const REPORT_QUEUE_DEPTH: usize = 32;

/// Platform hook for putting one already-built fragment on the air.
///
/// Implemented by the platform glue driving Android's `BluetoothLeAdvertiser`
/// (a later phase, not part of this crate yet): advertise `fragment` as
/// manufacturer-specific data tagged with `crate::ad::MESH_COMPANY_ID`, hold
/// it on air for whatever dwell the platform layer decides, then stop.
/// Unlike `StdBleLink`'s `advertise_dwell`, dwell timing is not a parameter
/// here — Android's advertising-set lifecycle is owned by the platform side
/// of this seam, not this crate, so it has no opinion on it.
///
/// Generic (not a trait object) so [`AndroidBleLink`] stays fully
/// host-testable against a fake implementation, with no JNI/Android
/// dependency in this crate.
#[allow(async_fn_in_trait)]
pub trait BleAdvertiser: Send {
    /// Broadcast `fragment` — the bare `[frag_header][body]` blob from
    /// `frame::build_fragment` — as this mesh's manufacturer data, then stop
    /// advertising it.
    async fn advertise(&self, fragment: &[u8]) -> Result<(), LinkError>;
}

/// Cloneable handle the platform's BLE scan callback feeds observed
/// mesh-tagged advertisements into. Kept separate from [`AndroidBleLink`]
/// itself since the scan callback and the `LinkT` consumer (the driver's
/// link array) are expected to live on opposite sides of the eventual JNI
/// boundary.
#[derive(Clone)]
pub struct AndroidBleReportSink {
    tx: mpsc::Sender<RawReport>,
}

impl AndroidBleReportSink {
    /// Submit one observed advertisement's mesh-tagged manufacturer data.
    /// Drops the report (logging at `trace!`) rather than blocking if the
    /// queue between the scan callback and [`LinkT::recv`] is full —
    /// backpressure on a lossy, fire-and-forget medium, matching
    /// `StdBleLink`'s policy.
    pub fn submit(&self, addr: BleAddr, rssi: Option<i16>, fragment: &[u8]) {
        let report = RawReport::new(addr, rssi, fragment);
        if let Err(TrySendError::Full(dropped)) = self.tx.try_send(report) {
            trace!(addr = ?dropped.addr, "drop: report queue full");
        }
    }
}

/// A [`LinkT`] carrying the mesh over BLE connectionless advertising on
/// Android, generic over a [`BleAdvertiser`] that performs the actual
/// platform advertise call. See the module doc comment for how this relates
/// to [`crate::StdBleLink`].
pub struct AndroidBleLink<A: BleAdvertiser> {
    /// Platform hook this link's `send` calls once per fragment.
    advertiser: A,
    /// Mesh-tagged advertisements submitted via this link's
    /// [`AndroidBleReportSink`].
    report_rx: mpsc::Receiver<RawReport>,
    /// Fragmentation message-id counter, incremented once per `send()` call.
    msg_id_ctr: u8,
    /// This link's reassembly table, keyed by advertiser address.
    reassembler: Reassembler,
    /// Scratch buffer for the fragment `send` is currently building.
    tx_fragment: [u8; MAX_FRAGMENT_BYTES],
    /// Scratch buffer holding the most recently reassembled mesh frame,
    /// borrowed by [`LinkT::recv`].
    rx_frame: [u8; MAX_REASSEMBLED_LEN],
}

impl<A: BleAdvertiser> AndroidBleLink<A> {
    /// Build a `LinkT`-ready handle wrapping `advertiser`, along with the
    /// [`AndroidBleReportSink`] the platform's scan callback feeds.
    pub fn new(advertiser: A) -> (Self, AndroidBleReportSink) {
        let (tx, rx) = mpsc::channel(REPORT_QUEUE_DEPTH);
        (
            Self {
                advertiser,
                report_rx: rx,
                msg_id_ctr: 0,
                reassembler: Reassembler::new(),
                tx_fragment: [0u8; MAX_FRAGMENT_BYTES],
                rx_frame: [0u8; MAX_REASSEMBLED_LEN],
            },
            AndroidBleReportSink { tx },
        )
    }

    /// Allocate the next fragmentation message id, wrapping at 256.
    fn next_msg_id(&mut self) -> u8 {
        let id = self.msg_id_ctr;
        self.msg_id_ctr = self.msg_id_ctr.wrapping_add(1);
        id
    }
}

impl<A: BleAdvertiser> LinkT for AndroidBleLink<A> {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let (frame_bytes, frame_len) = frame::assemble_frame(origin, data)?;
        let count = frame::fragment_count(frame_len)?;
        let msg_id = self.next_msg_id();

        for index in 0..count {
            let n = frame::build_fragment(
                &frame_bytes,
                frame_len,
                msg_id,
                index,
                count,
                &mut self.tx_fragment,
            )?;
            self.advertiser.advertise(&self.tx_fragment[..n]).await?;
        }

        trace!(?origin, dst = ?data.dst, frame_len, count, "tx frame");
        Ok(frame_len)
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        // Keep consuming physical reports, feeding each into the
        // reassembler, until *some* message completes — not necessarily the
        // fragment just read, mirroring `StdBleLink::recv`.
        loop {
            let Some(report) = self.report_rx.recv().await else {
                // The sink is gone, so no further report will ever arrive:
                // this link is dead, not momentarily idle.
                return Err(LinkError::ReceiveFailed);
            };
            let Some((hdr, body)) = parse_fragment(&report.data[..report.len as usize]) else {
                trace!(addr = ?report.addr, "drop: malformed fragment header");
                continue;
            };
            let key = FragKey {
                addr: report.addr,
                msg_id: hdr.msg_id,
            };
            let metrics = LinkMetrics {
                rssi_dbm: report.rssi,
                snr_db: None,
                quality: None,
            };

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn addr(n: u8) -> BleAddr {
        BleAddr::from([0, 0, 0, 0, 0, n])
    }

    /// Records every fragment handed to `advertise`, optionally failing
    /// instead — the seam Kotlin will later implement for real, stood in for
    /// here so `AndroidBleLink`'s logic is testable without any Android/JNI
    /// dependency.
    #[derive(Clone, Default)]
    struct FakeAdvertiser {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        fail: bool,
    }

    impl FakeAdvertiser {
        fn failing() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                fail: true,
            }
        }

        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl BleAdvertiser for FakeAdvertiser {
        async fn advertise(&self, fragment: &[u8]) -> Result<(), LinkError> {
            if self.fail {
                return Err(LinkError::TransmitFailed);
            }
            self.sent.lock().unwrap().push(fragment.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn send_advertises_each_fragment_in_order() {
        let advertiser = FakeAdvertiser::default();
        let (mut link, _sink) = AndroidBleLink::new(advertiser.clone());

        let payload: Vec<u8> = (0..30).collect();
        let frame_len = link
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x1234,
                    payload: &payload,
                },
            )
            .await
            .unwrap();

        let mut expected_frame = Vec::new();
        expected_frame.extend_from_slice(&mac(2).0);
        expected_frame.extend_from_slice(&mac(1).0);
        expected_frame.extend_from_slice(&0x1234u16.to_be_bytes());
        expected_frame.extend_from_slice(&payload);
        assert_eq!(frame_len, expected_frame.len());

        let sent = advertiser.sent();
        assert_eq!(sent.len(), 2);

        let (hdr0, body0) = parse_fragment(&sent[0]).unwrap();
        assert_eq!((hdr0.index, hdr0.count), (0, 2));
        assert_eq!(body0, &expected_frame[..frame::FRAG_PAYLOAD]);

        let (hdr1, body1) = parse_fragment(&sent[1]).unwrap();
        assert_eq!((hdr1.index, hdr1.count), (1, 2));
        assert_eq!(body1, &expected_frame[frame::FRAG_PAYLOAD..]);
        assert_eq!(hdr0.msg_id, hdr1.msg_id);
    }

    #[tokio::test]
    async fn send_propagates_advertiser_failure() {
        let (mut link, _sink) = AndroidBleLink::new(FakeAdvertiser::failing());
        let payload = [0xaa; 3];

        let err = link
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0,
                    payload: &payload,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LinkError::TransmitFailed));
    }

    #[tokio::test]
    async fn recv_reassembles_single_fragment_report() {
        let (mut link, sink) = AndroidBleLink::new(FakeAdvertiser::default());

        let payload = [0xde, 0xad];
        let (frame_bytes, frame_len) = frame::assemble_frame(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x55,
                payload: &payload,
            },
        )
        .unwrap();
        let mut fragment = [0u8; MAX_FRAGMENT_BYTES];
        let n = frame::build_fragment(&frame_bytes, frame_len, 9, 0, 1, &mut fragment).unwrap();

        sink.submit(addr(1), Some(-40), &fragment[..n]);

        let received = link.recv().await.unwrap();
        assert_eq!(received.frame.dst, mac(2));
        assert_eq!(received.frame.protocol.get(), 0x55);
        assert_eq!(&received.frame.payload, &payload);
        assert_eq!(received.metrics.rssi_dbm, Some(-40));
    }

    #[tokio::test]
    async fn recv_reassembles_multi_fragment_report() {
        let (mut link, sink) = AndroidBleLink::new(FakeAdvertiser::default());

        let payload: Vec<u8> = (0..30).collect();
        let (frame_bytes, frame_len) = frame::assemble_frame(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x77,
                payload: &payload,
            },
        )
        .unwrap();
        let count = frame::fragment_count(frame_len).unwrap();
        assert_eq!(count, 2);

        let mut fragment0 = [0u8; MAX_FRAGMENT_BYTES];
        let n0 =
            frame::build_fragment(&frame_bytes, frame_len, 3, 0, count, &mut fragment0).unwrap();
        let mut fragment1 = [0u8; MAX_FRAGMENT_BYTES];
        let n1 =
            frame::build_fragment(&frame_bytes, frame_len, 3, 1, count, &mut fragment1).unwrap();

        sink.submit(addr(1), Some(-60), &fragment0[..n0]);
        sink.submit(addr(1), Some(-60), &fragment1[..n1]);

        let received = link.recv().await.unwrap();
        assert_eq!(received.frame.dst, mac(2));
        assert_eq!(received.frame.protocol.get(), 0x77);
        assert_eq!(&received.frame.payload, payload.as_slice());
    }

    #[tokio::test]
    async fn recv_skips_malformed_fragment() {
        let (mut link, sink) = AndroidBleLink::new(FakeAdvertiser::default());

        // Malformed: count == 0 is rejected by `parse_fragment`.
        sink.submit(addr(1), None, &[0, 0]);

        let payload = [0x42];
        let (frame_bytes, frame_len) = frame::assemble_frame(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x11,
                payload: &payload,
            },
        )
        .unwrap();
        let mut fragment = [0u8; MAX_FRAGMENT_BYTES];
        let n = frame::build_fragment(&frame_bytes, frame_len, 1, 0, 1, &mut fragment).unwrap();
        sink.submit(addr(1), None, &fragment[..n]);

        let received = link.recv().await.unwrap();
        assert_eq!(&received.frame.payload, &payload);
    }

    #[tokio::test]
    async fn recv_returns_receive_failed_when_sink_dropped() {
        let (mut link, sink) = AndroidBleLink::new(FakeAdvertiser::default());
        drop(sink);

        assert!(matches!(link.recv().await, Err(LinkError::ReceiveFailed)));
    }
}
