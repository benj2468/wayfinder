//! UniFFI-exported surface for the Android-hosted mesh node.
//!
//! `#[uniffi::export]`s [`MeshNode`], which owns a real
//! `wayfinder_driver::Driver` — the same tokio, event-driven `select!` loop
//! `bins/wayfinder-tap` runs — on its own dedicated background OS thread, so
//! OGM/Trickle timing stays reactive against live BLE hardware rather than
//! being paced by whatever cadence Kotlin happens to call in at. The mesh
//! interface is a foreign (Kotlin) [`PixelBleAdvertiser`] implementation
//! bridged through [`BleLink`] — the same seam
//! `blue::generic_link::BleLink`/`BleAdvertiser` were designed around, just
//! crossing an FFI boundary instead of a plain Rust generic; the host device
//! is [`local::LoopbackLocal`], since Android has no TAP. See
//! `bins/wayfinder-pixel`'s own doc comment in `main.rs` for how this crate's
//! two targets (this `lib`, and the placeholder `bin`) divide responsibility.

mod local;

use std::sync::Arc;

use blue::BleLink;
use blue::BleReportSink;
use prost::Message;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::debug;
use tracing::error;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder_driver::Driver;
use wayfinder_driver::DynLinkT;
use wayfinder_driver::QueryTx;
use wayfinder_protos::wayfinder_v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder_v1alpha::WayfinderResponse;

use crate::local::LoopbackLocal;
use crate::local::LoopbackLocalTx;
use crate::local::MeshLocalSink;

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

/// Error crossing the UniFFI boundary from [`MeshNode`]'s own methods —
/// distinct from [`PixelBleError`]/[`local::MeshLocalError`], which report a
/// *foreign* callback's failure.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MeshNodeError {
    /// A constructor argument that must be a 6-byte MAC address wasn't one.
    #[error("invalid MAC address")]
    InvalidMac,
    /// The background OS thread this node's event loop runs on failed to
    /// spawn (e.g. the OS refused, out of resources).
    #[error("failed to start the mesh node's event loop")]
    RuntimeStartFailed,
    /// `query_management_api`'s `request_bytes` didn't decode as a
    /// `WayfinderRequest`.
    #[error("invalid management-API request")]
    InvalidRequest,
    /// The event loop task has stopped (its `Driver::run` returned or
    /// panicked), so a channel to it is closed.
    #[error("the mesh node's event loop has stopped")]
    NodeStopped,
}

/// Android-hosted mesh node, exported via UniFFI.
///
/// Owns a real [`wayfinder_driver::Driver`] — the same tokio event loop
/// `wayfinder-tap` runs — on its own dedicated background OS thread, with one
/// mesh interface (a [`BleLink`] bridged to a foreign [`PixelBleAdvertiser`])
/// and [`local::LoopbackLocal`] standing in for the host TAP `wayfinder-tap`
/// would use. All interaction after construction goes through channels the
/// driver owns one end of ([`BleReportSink`], [`LoopbackLocalTx`],
/// [`QueryTx`]), never a shared reference to the driver itself — the same
/// reason `bins/wayfinder-tap`'s `main` never touches `Driver` again after
/// calling `run`.
///
/// A dedicated `std::thread` running its own single-threaded runtime, not a
/// task spawned onto a shared multi-thread `Runtime`: `Driver::run`'s future
/// isn't `Send` (it holds a [`wayfinder::link::DynLinkT`], whose
/// `dynosaur`-generated boxed futures aren't `Send`-bounded — never an issue
/// before, since `wayfinder-tap` only ever `.await`s it in place), so
/// `Runtime::spawn` cannot take it; `block_on` on a thread that never runs
/// anything else has no such requirement.
#[derive(uniffi::Object)]
pub struct MeshNode {
    sink: BleReportSink,
    local_tx: LoopbackLocalTx,
    query_tx: QueryTx,
    // Bookkeeping only. There is no way to signal this thread to stop early
    // — `Driver::run` has no cancellation hook, and Rust cannot force-cancel
    // a thread — so once started, this node's event loop runs for the
    // process's lifetime, same as `wayfinder-tap`'s. Dropping this handle
    // (e.g. when `MeshNode` itself is dropped) does not stop the thread.
    #[allow(dead_code)]
    driver_thread: std::thread::JoinHandle<()>,
}

#[uniffi::export]
impl MeshNode {
    /// Build and start a node identified by `mac` (this device's stable
    /// 6-byte mesh identity — Kotlin's to generate and persist, e.g. a
    /// random address stored in `SharedPreferences` on first launch),
    /// advertising over BLE through `advertiser` and delivering
    /// locally-destined mesh traffic to `local_sink`. Spawns the event loop
    /// on a fresh background thread immediately; there is no separate
    /// "start" call, and (see [`MeshNode`]'s doc comment) no way to stop it
    /// short of the process exiting.
    #[uniffi::constructor]
    pub fn new(
        mac: Vec<u8>,
        advertiser: Arc<dyn PixelBleAdvertiser>,
        local_sink: Arc<dyn MeshLocalSink>,
    ) -> Result<Self, MeshNodeError> {
        let mac_len = mac.len();
        let mac = Mac(<[u8; 6]>::try_from(mac).map_err(|_| {
            debug!(mac_len, "drop: malformed node MAC");
            MeshNodeError::InvalidMac
        })?);

        let (link, sink) = BleLink::new(ForeignAdvertiser::new(advertiser));
        let (local, local_tx) = LoopbackLocal::new(mac, local_sink);
        let (query_tx, query_rx) = mpsc::channel(16);

        let interfaces: Vec<Box<DynLinkT<'static>>> = vec![DynLinkT::new_box(link)];
        let mut driver = Driver::new(mac, local, interfaces, Vec::new(), Vec::new(), query_rx);

        let driver_thread = std::thread::Builder::new()
            .name("wayfinder-pixel-driver".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        error!(error = ?e, "failed to start the mesh node's event-loop runtime");
                        return;
                    }
                };
                runtime.block_on(async move {
                    if let Err(e) = driver.run().await {
                        error!(error = ?e, "mesh node event loop exited");
                    }
                });
            })
            .map_err(|_| MeshNodeError::RuntimeStartFailed)?;

        Ok(Self {
            sink,
            local_tx,
            query_tx,
            driver_thread,
        })
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

    /// Queue `payload` as if the local host had originated it, addressed to
    /// `dest` (this node's own mesh-level equivalent of writing to a TAP
    /// device). `dest` must be a 6-byte MAC address (or all-`0xff` to
    /// flood); malformed input is dropped like [`submit_report`](Self::submit_report)'s.
    pub fn queue_local_send(&self, dest: Vec<u8>, payload: Vec<u8>) {
        let dest_len = dest.len();
        let Ok(dest) = <[u8; 6]>::try_from(dest) else {
            debug!(dest_len, "drop: malformed destination MAC");
            return;
        };
        self.local_tx.queue_local_send(Mac(dest), &payload);
    }

    /// Send one management-API request to this node's own router and return
    /// its encoded response — a `WayfinderRequest`/`WayfinderResponse` (see
    /// `wayfinder-protos`) in, respectively, out. Reuses the same
    /// `QueryTx`/`QueryRx` channel every other transport
    /// (`wayfinder-server`'s TCP/Unix/UDP listeners) speaks, so Kotlin gets
    /// the exact same management API in-process, no socket required.
    pub async fn query_management_api(
        &self,
        request_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, MeshNodeError> {
        let request = WayfinderRequest::decode(request_bytes.as_slice())
            .map_err(|_| MeshNodeError::InvalidRequest)?;

        let (resp_tx, resp_rx) = oneshot::channel();
        self.query_tx
            .send((request, resp_tx))
            .await
            .map_err(|_| MeshNodeError::NodeStopped)?;
        let response: WayfinderResponse = resp_rx.await.map_err(|_| MeshNodeError::NodeStopped)?;

        Ok(response.encode_to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use blue::BleAdvertiser;
    use blue::BleLink;
    use tokio::sync::mpsc;
    use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
    use wayfinder::batman::wire::BATADV_UNICAST;
    use wayfinder::batman::wire::BatmanUnicastPacket;
    use wayfinder::interfaces::frame::LinkFrameData;
    use wayfinder::interfaces::frame::Mac;
    use wayfinder::interfaces::link::LinkError;
    use wayfinder::link::LinkT;
    use wayfinder_protos::wayfinder_v1alpha::GetNodeInfoRequest;
    use wayfinder_protos::wayfinder_v1alpha::WayfinderRequest;
    use wayfinder_protos::wayfinder_v1alpha::WayfinderResponse;
    use wayfinder_protos::wayfinder_v1alpha::wayfinder_request::Request as RequestKind;
    use wayfinder_protos::wayfinder_v1alpha::wayfinder_response::Response as ResponseKind;
    use zerocopy::IntoBytes;

    use crate::ForeignAdvertiser;
    use crate::MeshNode;
    use crate::PixelBleAdvertiser;
    use crate::PixelBleError;
    use crate::local::MeshLocalError;
    use crate::local::MeshLocalSink;

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

    /// Forwards every locally-delivered payload down an unbounded channel —
    /// stands in for the Kotlin-implemented platform sink. A channel (rather
    /// than a shared `Vec`, as `FakePlatformAdvertiser` uses) lets a test
    /// `.await` the delivery directly instead of polling: `MeshNode`'s
    /// driver runs on its own background runtime, a different thread than
    /// the `#[tokio::test]` runtime the assertion runs on.
    struct FakeMeshLocalSink {
        tx: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl MeshLocalSink for FakeMeshLocalSink {
        async fn deliver(&self, payload: Vec<u8>) -> Result<(), MeshLocalError> {
            let _ = self.tx.send(payload);
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

    /// Send `payload` from a fresh peer `BleLink` toward `dst` under `protocol`,
    /// returning the exact on-air fragment bytes it produced — the same shape
    /// a real Android scan callback would report per fragment. Lets tests
    /// build genuine `submit_report` input without reaching into `blue`'s
    /// private `frame` module.
    async fn fragments_for(dst: Mac, protocol: u16, payload: &[u8]) -> Vec<Vec<u8>> {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let (mut sender, _sender_sink) = BleLink::new(RecordingAdvertiser(sent.clone()));
        sender
            .send(
                mac(1),
                &LinkFrameData {
                    dst,
                    protocol,
                    payload,
                },
            )
            .await
            .unwrap();
        sent.lock().unwrap().clone()
    }

    /// A minimal `[BATADV_UNICAST]` packet addressed to `dest`, wrapping
    /// `inner` — enough for `CentralRouter::handle_unicast` to recognize it
    /// as self-destined and deliver `inner` locally without any prior route
    /// (a self-addressed unicast is delivered on sight; see
    /// `batman::engine::handle_unicast`'s "Rule 1"), so this needs no peer
    /// OGM exchange to set up.
    fn unicast_packet(dest: Mac, inner: &[u8]) -> Vec<u8> {
        let hdr = BatmanUnicastPacket {
            packet_type: BATADV_UNICAST,
            version: 0,
            ttl: 1,
            dest,
        };
        let mut bytes = hdr.as_bytes().to_vec();
        bytes.extend_from_slice(inner);
        bytes
    }

    /// A synthetic host Ethernet frame `[dst][src][ethertype][payload]` —
    /// the shape `local::LoopbackLocal` (and every real TAP) carries, and so
    /// what a `BATADV_UNICAST` packet's inner content actually is on the
    /// wire (a host frame `handle_local` wrapped, not a bare payload).
    /// Mirrors `wayfinder-test`'s own `host_frame` helper.
    fn eth_frame(dst: Mac, src: Mac, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(14 + payload.len());
        bytes.extend_from_slice(dst.as_bytes());
        bytes.extend_from_slice(src.as_bytes());
        bytes.extend_from_slice(&[0x08, 0x00]);
        bytes.extend_from_slice(payload);
        bytes
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
    async fn new_rejects_a_malformed_mac() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let err = MeshNode::new(
            vec![1, 2, 3],
            Arc::new(FakePlatformAdvertiser::default()),
            Arc::new(FakeMeshLocalSink { tx }),
        )
        .err()
        .unwrap();
        assert!(matches!(err, crate::MeshNodeError::InvalidMac));
    }

    #[tokio::test]
    async fn submit_report_drops_too_short_address_without_panicking() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let node = MeshNode::new(
            mac(1).0.to_vec(),
            Arc::new(FakePlatformAdvertiser::default()),
            Arc::new(FakeMeshLocalSink { tx }),
        )
        .unwrap();

        // Wrong address length; must not panic. Nothing else to observe
        // since the report never reaches the reassembler.
        node.submit_report(vec![1, 2, 3], None, vec![0, 0]);
    }

    #[tokio::test]
    async fn submit_report_drops_too_long_address_without_panicking() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let node = MeshNode::new(
            mac(1).0.to_vec(),
            Arc::new(FakePlatformAdvertiser::default()),
            Arc::new(FakeMeshLocalSink { tx }),
        )
        .unwrap();

        node.submit_report(vec![1, 2, 3, 4, 5, 6, 7], None, vec![0, 0]);
    }

    #[tokio::test]
    async fn queue_local_send_drops_malformed_dest_without_panicking() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let node = MeshNode::new(
            mac(1).0.to_vec(),
            Arc::new(FakePlatformAdvertiser::default()),
            Arc::new(FakeMeshLocalSink { tx }),
        )
        .unwrap();

        node.queue_local_send(vec![1, 2, 3], vec![0, 0]);
    }

    /// End-to-end proof that a fragment `submit_report` hands off actually
    /// reaches this node's own live `Driver`/`CentralRouter` and comes out
    /// the other side via `MeshLocalSink` — not just that it's accepted into
    /// `BleLink`'s reassembler (already covered by `blue`'s own tests).
    #[tokio::test]
    async fn submit_report_of_a_self_addressed_unicast_is_delivered_locally() {
        let this_node = mac(2);
        let sender = mac(9);
        let inner_payload = b"hello mesh".to_vec();
        let fragments = fragments_for(
            this_node,
            DEFAULT_BATMAN_ETHER_TYPE,
            &unicast_packet(this_node, &eth_frame(this_node, sender, &inner_payload)),
        )
        .await;
        // The BATMAN unicast header plus this payload doesn't fit in one BLE
        // fragment's small budget (see `libs/blue/CLAUDE.md`'s 31-byte legacy
        // advertising ceiling) — two `submit_report` calls compose the same
        // way `blue`'s own reassembler is already tested to.
        assert_eq!(fragments.len(), 2);

        let (tx, mut rx) = mpsc::unbounded_channel();
        let node = MeshNode::new(
            this_node.0.to_vec(),
            Arc::new(FakePlatformAdvertiser::default()),
            Arc::new(FakeMeshLocalSink { tx }),
        )
        .unwrap();

        for fragment in &fragments {
            node.submit_report(vec![9, 9, 9, 9, 9, 9], Some(-50), fragment.clone());
        }

        let delivered = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for local delivery")
            .expect("sink channel closed");
        assert_eq!(delivered, inner_payload);
    }

    /// End-to-end proof that `query_management_api` reaches the same live
    /// `Driver` — decodes a real `WayfinderRequest`, gets serviced by the
    /// router's `WayfinderService` on the driver's own task, and returns a
    /// correctly-encoded `WayfinderResponse`, all through the exact
    /// `QueryTx`/`QueryRx` channel `wayfinder-server`'s other transports use.
    #[tokio::test]
    async fn query_management_api_returns_this_nodes_info() {
        let this_node = mac(3);
        let (tx, _rx) = mpsc::unbounded_channel();
        let node = MeshNode::new(
            this_node.0.to_vec(),
            Arc::new(FakePlatformAdvertiser::default()),
            Arc::new(FakeMeshLocalSink { tx }),
        )
        .unwrap();

        let request = WayfinderRequest {
            request: Some(RequestKind::GetNodeInfo(GetNodeInfoRequest {})),
        };
        let response_bytes = tokio::time::timeout(
            Duration::from_secs(5),
            node.query_management_api(prost::Message::encode_to_vec(&request)),
        )
        .await
        .expect("timed out waiting for a management-API response")
        .unwrap();

        let response =
            <WayfinderResponse as prost::Message>::decode(response_bytes.as_slice()).unwrap();
        match response.response {
            Some(ResponseKind::NodeInfo(info)) => {
                assert_eq!(info.node_id, this_node.0.to_vec());
            }
            other => panic!("expected NodeInfo, got {other:?}"),
        }
    }
}
