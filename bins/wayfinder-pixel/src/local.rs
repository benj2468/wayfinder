//! The Android-hosted node's local "host device" — there is no TAP to write
//! to (no root on Android), so [`LoopbackLocal`] stands in as a [`FrameIo`]
//! backed by an mpsc channel, mirroring the pattern
//! `libs/wayfinder-test/src/test_router.rs`'s `ObservableEgress`/
//! `ChannelTransport` already use for exactly this in tests: no queued
//! traffic means the read side simply stays pending, and writes are recorded
//! (there, into a `Vec`; here, pushed to Kotlin via [`MeshLocalSink`]).
//!
//! `Driver<Local: FrameIo>`'s local device carries whole Ethernet-shaped
//! frames (`[dst MAC][src MAC][ethertype][payload]`) on both directions —
//! see `wayfinder-driver::driver::plan_host_frame`'s doc comment — so
//! [`LoopbackLocalTx::queue_local_send`] builds one around the bare payload
//! Kotlin supplies, and [`LoopbackLocal::send`] strips one back off before
//! handing the payload to [`MeshLocalSink`], so neither side of the UniFFI
//! boundary has to know the host-device wire format exists.

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::trace;
use wayfinder::interfaces::frame::Mac;
use wayfinder_driver::FrameIo;
use zerocopy::IntoBytes;

/// Length of the synthetic Ethernet header [`LoopbackLocal`] wraps every
/// locally-originated payload in: `[dst MAC(6)][src MAC(6)][ethertype(2)]`.
const ETH_HEADER_LEN: usize = 14;

/// Ethertype stamped on the synthetic host frame. Arbitrary — like
/// `wayfinder-test`'s own `HOST_ETHERTYPE`, the router demuxes mesh traffic
/// by the BATMAN payload, not by this field.
const HOST_ETHERTYPE: [u8; 2] = [0x08, 0x00];

/// Depth of the queue between [`LoopbackLocalTx::queue_local_send`] and
/// [`LoopbackLocal::recv`]. Mirrors `blue::BleReportSink`'s
/// `REPORT_QUEUE_DEPTH` reasoning: not a hard limit, just a small multiple of
/// what one `recv` call can plausibly fall behind by; capacity pressure drops
/// the newest send rather than blocking the producer.
const LOCAL_QUEUE_DEPTH: usize = 32;

/// Foreign-implemented (Kotlin) hook that receives one payload the router
/// delivered to this host — the UniFFI-exported counterpart of a TAP read on
/// `wayfinder-tap`. See [`crate::PixelBleAdvertiser`] for why this is its own
/// trait (rather than exporting `wayfinder_driver::FrameIo` directly) and why
/// it needs `#[async_trait]`.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MeshLocalSink: Send + Sync {
    /// Deliver one locally-destined payload, stripped of its synthetic
    /// Ethernet header.
    async fn deliver(&self, payload: Vec<u8>) -> Result<(), MeshLocalError>;
}

/// Error crossing the UniFFI boundary from a foreign [`MeshLocalSink`]
/// implementation. Deliberately a single variant, matching
/// [`crate::PixelBleError`]'s reasoning: the platform side reports only
/// success/failure of the delivery.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MeshLocalError {
    /// The platform's local-delivery callback failed.
    #[error("local delivery failed")]
    DeliverFailed,
}

/// The driver's host-facing [`FrameIo`] device on Android: no kernel TAP
/// exists, so inbound frames come from [`LoopbackLocalTx::queue_local_send`]
/// over an in-process channel, and outbound (locally-delivered) frames are
/// pushed to a foreign [`MeshLocalSink`] instead of written to a device node.
pub struct LoopbackLocal {
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    sink: Arc<dyn MeshLocalSink>,
}

/// Cloneable handle that queues host-originated payloads for
/// [`LoopbackLocal::recv`] to pick up. Split from [`LoopbackLocal`] itself
/// for the same reason `blue::BleReportSink` is split from `BleLink`: the
/// producer (a UniFFI-exported `MeshNode` method) and the consumer (the
/// driver's event loop, via `FrameIo::recv`) live on opposite sides of the
/// same task set and shouldn't need to share a lock to hand frames over.
#[derive(Clone)]
pub struct LoopbackLocalTx {
    /// This node's own identity, stamped as the synthetic frame's source MAC.
    mac: Mac,
    tx: mpsc::Sender<Vec<u8>>,
}

impl LoopbackLocal {
    /// Build the loopback host device, along with the [`LoopbackLocalTx`]
    /// handle a `MeshNode`'s `queue_local_send` method feeds.
    pub fn new(mac: Mac, sink: Arc<dyn MeshLocalSink>) -> (Self, LoopbackLocalTx) {
        let (tx, rx) = mpsc::channel(LOCAL_QUEUE_DEPTH);
        (
            Self {
                inbound: Mutex::new(rx),
                sink,
            },
            LoopbackLocalTx { mac, tx },
        )
    }
}

impl LoopbackLocalTx {
    /// Queue `payload` as if the local host had originated it, addressed to
    /// `dest` (or [`Mac::BROADCAST`] to flood). Drops the send (logging at
    /// `trace!`) rather than blocking if [`LoopbackLocal::recv`] has fallen
    /// behind — same lossy-producer posture as `BleReportSink::submit`.
    pub fn queue_local_send(&self, dest: Mac, payload: &[u8]) {
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + payload.len());
        frame.extend_from_slice(dest.as_bytes());
        frame.extend_from_slice(self.mac.as_bytes());
        frame.extend_from_slice(&HOST_ETHERTYPE);
        frame.extend_from_slice(payload);
        if let Err(TrySendError::Full(_)) = self.tx.try_send(frame) {
            trace!(?dest, "drop: local-send queue full");
        }
    }
}

#[async_trait::async_trait]
impl FrameIo for LoopbackLocal {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inbound.lock().await.recv().await {
            Some(frame) => {
                let n = frame.len().min(buf.len());
                buf[..n].copy_from_slice(&frame[..n]);
                Ok(n)
            }
            // The sender is kept alive for the node's lifetime (owned by the
            // same `MeshNode` that owns this device), so an exhausted channel
            // means the node is shutting down; stay pending rather than
            // report a spurious zero-length frame, matching
            // `ChannelTransport::recv`'s contract in the test harness.
            None => std::future::pending().await,
        }
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        // A frame shorter than an Ethernet header can only come from a
        // mesh-originated unicast whose payload was smaller than that (see
        // this module's doc comment on the wire format) — remotely
        // triggerable, so this is a drop-and-trace, not a propagated error
        // that would tear down the driver's event loop.
        if buf.len() < ETH_HEADER_LEN {
            trace!(
                len = buf.len(),
                "drop: local delivery shorter than an Ethernet header"
            );
            return Ok(buf.len());
        }
        let payload = buf[ETH_HEADER_LEN..].to_vec();
        self.sink
            .deliver(payload)
            .await
            .map_err(|_| std::io::Error::other("local sink delivery failed"))?;
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use wayfinder::interfaces::frame::Mac;

    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Records every payload handed to `deliver` — stands in for the
    /// Kotlin-implemented platform sink.
    #[derive(Clone, Default)]
    struct FakeMeshLocalSink {
        delivered: Arc<StdMutex<Vec<Vec<u8>>>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl MeshLocalSink for FakeMeshLocalSink {
        async fn deliver(&self, payload: Vec<u8>) -> Result<(), MeshLocalError> {
            if self.fail {
                return Err(MeshLocalError::DeliverFailed);
            }
            self.delivered.lock().unwrap().push(payload);
            Ok(())
        }
    }

    #[tokio::test]
    async fn queue_local_send_frames_ethernet_and_is_recv_able() {
        let (local, tx) = LoopbackLocal::new(mac(1), Arc::new(FakeMeshLocalSink::default()));

        tx.queue_local_send(mac(2), &[0xaa, 0xbb, 0xcc]);

        let mut buf = [0u8; 64];
        let n = local.recv(&mut buf).await.unwrap();
        let frame = &buf[..n];
        assert_eq!(&frame[0..6], mac(2).as_bytes());
        assert_eq!(&frame[6..12], mac(1).as_bytes());
        assert_eq!(&frame[14..], &[0xaa, 0xbb, 0xcc]);
    }

    #[tokio::test]
    async fn queue_local_send_drops_when_queue_is_full_without_panicking() {
        let (local, tx) = LoopbackLocal::new(mac(1), Arc::new(FakeMeshLocalSink::default()));

        for _ in 0..(LOCAL_QUEUE_DEPTH + 1) {
            tx.queue_local_send(mac(2), &[0x00]);
        }

        // Draining should yield exactly the frames that fit; the excess was
        // dropped rather than panicking or blocking the producer above.
        let mut buf = [0u8; 64];
        for _ in 0..LOCAL_QUEUE_DEPTH {
            local.recv(&mut buf).await.unwrap();
        }
    }

    #[tokio::test]
    async fn send_strips_ethernet_header_and_forwards_payload_to_sink() {
        let sink = Arc::new(FakeMeshLocalSink::default());
        let (local, _tx) = LoopbackLocal::new(mac(1), sink.clone());

        let mut frame = Vec::new();
        frame.extend_from_slice(mac(1).as_bytes());
        frame.extend_from_slice(mac(2).as_bytes());
        frame.extend_from_slice(&HOST_ETHERTYPE);
        frame.extend_from_slice(&[1, 2, 3]);

        local.send(&frame).await.unwrap();

        assert_eq!(sink.delivered.lock().unwrap().as_slice(), &[vec![1, 2, 3]]);
    }

    #[tokio::test]
    async fn send_drops_frame_shorter_than_ethernet_header_without_erroring() {
        let sink = Arc::new(FakeMeshLocalSink::default());
        let (local, _tx) = LoopbackLocal::new(mac(1), sink.clone());

        local.send(&[0, 0, 0]).await.unwrap();

        assert!(sink.delivered.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn send_propagates_sink_failure() {
        let sink = Arc::new(FakeMeshLocalSink {
            fail: true,
            ..Default::default()
        });
        let (local, _tx) = LoopbackLocal::new(mac(1), sink);

        let mut frame = vec![0u8; ETH_HEADER_LEN];
        frame.extend_from_slice(&[9]);

        assert!(local.send(&frame).await.is_err());
    }
}
