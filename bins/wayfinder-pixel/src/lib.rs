//! UniFFI-exported surface for the future Android-hosted mesh node.
//!
//! `#[uniffi::export]`s [`MeshNode`], generic over a foreign (Kotlin)
//! [`PixelBleAdvertiser`] implementation — the same seam
//! `blue::generic_link::BleLink`/`BleAdvertiser` were designed around, just
//! crossing an FFI boundary instead of a plain Rust generic. Deliberately
//! thin for now: no `wayfinder-driver::Driver`/management-API wiring yet (a
//! later phase). See `bins/wayfinder-pixel`'s own doc comment in `main.rs`
//! for how this crate's two targets (this `lib`, and the placeholder `bin`)
//! divide responsibility.

use std::sync::Arc;

use blue::BleLink;
use blue::BleReportSink;
use tokio::sync::Mutex;
use tracing::debug;
use wayfinder::interfaces::link::LinkError;

uniffi::setup_scaffolding!();

/// Foreign-implemented (Kotlin) hook that puts one already-built BLE
/// advertising fragment on the air — the UniFFI-exported counterpart of
/// `blue::BleAdvertiser`. Kept as its own trait rather than exporting
/// `blue`'s directly, since `#[uniffi::export]` must be applied where a
/// trait is defined and `BleAdvertiser` lives in an external crate;
/// [`ForeignAdvertiser`] bridges the two.
///
/// `#[async_trait]`: `#[uniffi::export(with_foreign)]`'s generated foreign
/// proxy (`UniFFICallbackHandlerPixelBleAdvertiser`) is handed back to Rust
/// as `Arc<dyn PixelBleAdvertiser>`, which needs this trait to be
/// dyn-compatible — not true of a plain native `async fn` in a trait, since
/// that isn't object-safe. `async-trait`'s boxed-future desugaring restores
/// object safety; every impl of this trait (real or fake) needs the same
/// attribute to match.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PixelBleAdvertiser: Send + Sync {
    /// Broadcast `fragment` — the bare `[frag_header][body]` blob `BleLink`
    /// hands it — as this mesh's manufacturer-specific data, then stop
    /// advertising it. See `blue::BleAdvertiser::advertise`.
    async fn advertise(&self, fragment: Vec<u8>) -> Result<(), PixelBleError>;
}

/// Error crossing the UniFFI boundary from a foreign [`PixelBleAdvertiser`]
/// implementation. Deliberately a single variant: the platform side reports
/// only success/failure of the advertise call, and any failure maps to
/// `LinkError::TransmitFailed` on the Rust side (see [`ForeignAdvertiser`]).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PixelBleError {
    /// The platform's `BluetoothLeAdvertiser` call failed.
    #[error("advertise failed")]
    AdvertiseFailed,
}

/// Bridges a foreign [`PixelBleAdvertiser`] implementation into `blue`'s
/// `BleAdvertiser`, so a [`BleLink`] can be constructed from it exactly as
/// in `blue`'s own tests — just with a real platform implementation this
/// time, plugged in across the UniFFI boundary instead of a fake.
struct ForeignAdvertiser {
    inner: Arc<dyn PixelBleAdvertiser>,
}

impl ForeignAdvertiser {
    fn new(inner: Arc<dyn PixelBleAdvertiser>) -> Self {
        Self { inner }
    }
}

impl blue::BleAdvertiser for ForeignAdvertiser {
    async fn advertise(&self, fragment: &[u8]) -> Result<(), LinkError> {
        // A `match`, not `map_err(|_| ...)`: `PixelBleError` has one variant
        // today, but an unconditional closure would keep silently absorbing
        // any variant added later into the same `TransmitFailed` — this way,
        // a new variant is a compile error here until its mapping is chosen.
        match self.inner.advertise(fragment.to_vec()).await {
            Ok(()) => Ok(()),
            Err(PixelBleError::AdvertiseFailed) => Err(LinkError::TransmitFailed),
        }
    }
}

/// Android-hosted mesh link handle, exported via UniFFI.
///
/// Wraps [`BleLink`] behind a foreign-implemented [`PixelBleAdvertiser`].
/// Deliberately thin for now: no `wayfinder-driver::Driver`/management-API
/// wiring yet (a later phase) — this exists to prove the UniFFI toolchain
/// (proc-macro export, async foreign callback interface, generated Kotlin
/// bindings) against this crate's actual shape before building the real
/// node API on top.
#[derive(uniffi::Object)]
pub struct MeshNode {
    // Not read by anything outside `#[cfg(test)]` yet — a later phase hands
    // this to `wayfinder-driver::Driver` as a `LinkT`. Kept now (rather than
    // deferred to that phase) because it's what lets this crate's own tests
    // prove `submit_report` actually reaches the reassembler, by driving
    // `recv()` directly on the same link `submit_report` feeds — see
    // `mod tests` below. Without it, `submit_report`'s only new logic (the
    // address-length gate) would be provable, but not that it correctly
    // wires into `blue`'s existing, already-tested reassembly path.
    #[cfg_attr(not(test), allow(dead_code))]
    link: Mutex<BleLink<ForeignAdvertiser>>,
    sink: BleReportSink,
}

#[uniffi::export]
impl MeshNode {
    /// Build a node backed by `advertiser` — the platform's
    /// `BluetoothLeAdvertiser` binding, implemented in Kotlin.
    #[uniffi::constructor]
    pub fn new(advertiser: Arc<dyn PixelBleAdvertiser>) -> Self {
        let (link, sink) = BleLink::new(ForeignAdvertiser::new(advertiser));
        Self {
            link: Mutex::new(link),
            sink,
        }
    }

    /// Called by the platform's BLE scan callback for every observed
    /// mesh-tagged advertisement. `addr` must be the 6-byte BLE device
    /// address; malformed input (wrong length) is dropped rather than
    /// raised as an error — `debug!`, not `trace!` like a malformed on-air
    /// fragment (`blue`'s `recv`), since this address comes from the local
    /// Kotlin scan-callback binding, not untrusted remote mesh traffic; a
    /// wrong length here signals a bug in that binding, not ambient RF
    /// noise, so it shouldn't be invisible at default log levels.
    pub fn submit_report(&self, addr: Vec<u8>, rssi: Option<i16>, fragment: Vec<u8>) {
        let addr_len = addr.len();
        let Ok(addr) = <[u8; 6]>::try_from(addr) else {
            debug!(addr_len, "drop: malformed BLE address");
            return;
        };
        self.sink.submit(addr.into(), rssi, &fragment);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;

    use blue::BleAdvertiser;
    use blue::BleLink;
    use wayfinder::interfaces::frame::LinkFrameData;
    use wayfinder::interfaces::frame::Mac;
    use wayfinder::interfaces::link::LinkError;
    use wayfinder::link::LinkT;

    use crate::ForeignAdvertiser;
    use crate::MeshNode;
    use crate::PixelBleAdvertiser;
    use crate::PixelBleError;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Records every fragment handed to `advertise` — stands in for the
    /// Kotlin-implemented platform advertiser, so this crate's UniFFI
    /// bridging logic is testable without an Android runtime.
    #[derive(Clone, Default)]
    struct FakePlatformAdvertiser {
        sent: Arc<StdMutex<Vec<Vec<u8>>>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl PixelBleAdvertiser for FakePlatformAdvertiser {
        async fn advertise(&self, fragment: Vec<u8>) -> Result<(), PixelBleError> {
            if self.fail {
                return Err(PixelBleError::AdvertiseFailed);
            }
            self.sent.lock().unwrap().push(fragment);
            Ok(())
        }
    }

    /// Records fragments handed to `blue::BleAdvertiser::advertise` — used
    /// to capture the exact on-air bytes a peer `BleLink` would send, so
    /// they can be fed back in through `MeshNode::submit_report` below.
    struct RecordingAdvertiser(Arc<StdMutex<Vec<Vec<u8>>>>);

    impl BleAdvertiser for RecordingAdvertiser {
        async fn advertise(&self, fragment: &[u8]) -> Result<(), LinkError> {
            self.0.lock().unwrap().push(fragment.to_vec());
            Ok(())
        }
    }

    /// Send `payload` from a fresh peer `BleLink`, returning the exact
    /// on-air fragment bytes it produced — the same shape a real Android
    /// scan callback would report per fragment. Lets tests build genuine
    /// `submit_report` input without reaching into `blue`'s private
    /// `frame` module.
    async fn fragments_for(payload: &[u8]) -> Vec<Vec<u8>> {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let (mut sender, _sender_sink) = BleLink::new(RecordingAdvertiser(sent.clone()));
        sender
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x9,
                    payload,
                },
            )
            .await
            .unwrap();
        sent.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn foreign_advertiser_forwards_fragment_bytes() {
        let fake = FakePlatformAdvertiser::default();
        let bridge = ForeignAdvertiser::new(Arc::new(fake.clone()));

        bridge.advertise(&[1, 2, 3]).await.unwrap();

        assert_eq!(fake.sent.lock().unwrap().as_slice(), &[vec![1, 2, 3]]);
    }

    #[tokio::test]
    async fn foreign_advertiser_maps_foreign_error_to_transmit_failed() {
        let fake = FakePlatformAdvertiser {
            fail: true,
            ..Default::default()
        };
        let bridge = ForeignAdvertiser::new(Arc::new(fake));

        let err = bridge.advertise(&[]).await.unwrap_err();

        assert!(matches!(err, LinkError::TransmitFailed));
    }

    #[tokio::test]
    async fn submit_report_delivers_a_fragment_sent_by_another_blue_link() {
        let payload = [0xaa, 0xbb, 0xcc];
        let fragments = fragments_for(&payload).await;
        assert_eq!(fragments.len(), 1);

        let node = MeshNode::new(Arc::new(FakePlatformAdvertiser::default()));
        node.submit_report(vec![9, 9, 9, 9, 9, 9], Some(-50), fragments[0].clone());

        let mut link = node.link.lock().await;
        let received = link.recv().await.unwrap();
        assert_eq!(received.frame.dst, mac(2));
        assert_eq!(received.frame.protocol.get(), 0x9);
        assert_eq!(&received.frame.payload, &payload);
        assert_eq!(received.metrics.rssi_dbm, Some(-50));
    }

    #[tokio::test]
    async fn submit_report_delivers_a_multi_fragment_message() {
        // A payload past one fragment's budget, split across 2 `submit_report`
        // calls with the same address — proves the wrapper composes across
        // repeated calls, not just a single one.
        let payload: Vec<u8> = (0..30).collect();
        let fragments = fragments_for(&payload).await;
        assert_eq!(fragments.len(), 2);

        let node = MeshNode::new(Arc::new(FakePlatformAdvertiser::default()));
        for fragment in &fragments {
            // `rssi = None` here, unlike the single-fragment test above —
            // covers the case BlueZ's own docs call out: no signal strength
            // for a report (e.g. a cached device currently out of range).
            node.submit_report(vec![9, 9, 9, 9, 9, 9], None, fragment.clone());
        }

        let mut link = node.link.lock().await;
        let received = link.recv().await.unwrap();
        assert_eq!(received.frame.dst, mac(2));
        assert_eq!(&received.frame.payload, payload.as_slice());
        assert_eq!(received.metrics.rssi_dbm, None);
    }

    #[tokio::test]
    async fn submit_report_drops_too_short_address_without_panicking() {
        let node = MeshNode::new(Arc::new(FakePlatformAdvertiser::default()));

        // Wrong address length; must not panic. Nothing else to observe
        // since the report never reaches the reassembler.
        node.submit_report(vec![1, 2, 3], None, vec![0, 0]);
    }

    #[tokio::test]
    async fn submit_report_drops_too_long_address_without_panicking() {
        let node = MeshNode::new(Arc::new(FakePlatformAdvertiser::default()));

        node.submit_report(vec![1, 2, 3, 4, 5, 6, 7], None, vec![0, 0]);
    }
}
