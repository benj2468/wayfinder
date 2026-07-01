//! Test harness for the [`Driver`].
//!
//! [`TestRouter`] wraps a [`wayfinder_driver::Driver`] whose transports are
//! in-process channels: the mesh interfaces are [`PortComms`] duplexes into a
//! [`Switch`](crate::switch::Switch), and the host device is an observable
//! channel whose locally-delivered frames are captured for assertions.
//!
//! Because it is the *same* driver that runs in production (only the carriers
//! differ), tests exercise the real event-loop logic.  The driver is stepped
//! deterministically: [`poll`] drives the periodic OGM at a chosen instant and
//! [`drain_all`] processes every currently-pending frame in one non-blocking
//! sweep.
//!
//! [`poll`]: TestRouter::poll
//! [`drain_all`]: TestRouter::drain_all

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use interfaces::{
    frame::{LinkFrame, Mac},
    link::LinkMetrics,
};
use tokio::sync::mpsc;
use wayfinder::CentralRouter;
use wayfinder::config::TrickleConfig;
use wayfinder_driver::{Driver, DynLinkT, FrameIo, Link, QueryRx, QueryTx};
use zerocopy::{FromBytes, IntoBytes};

use crate::switch::PortComms;

/// EtherType stamped on the synthetic host Ethernet frames [`send_local`]
/// builds.  Arbitrary — the router demuxes mesh traffic by the BATMAN payload,
/// not by this field — but a real-looking IPv4 type keeps captures legible.
///
/// [`send_local`]: TestRouter::send_local
const HOST_ETHERTYPE: [u8; 2] = [0x00, 0x08];

// ── wire-format helpers ───────────────────────────────────────────────────────

/// Serialize a `LinkFrame` into a heap-allocated byte vector.
///
/// Wire layout (matches `#[repr(C, packed)]` of `LinkFrame`, which is
/// Ethernet-shaped):
/// ```text
/// [dst: Mac][src: Mac][protocol: u16 big-endian][payload ...]
/// ```
pub fn build_frame(src: Mac, dst: Mac, protocol: u16, payload: &[u8]) -> Vec<u8> {
    let ident_size = core::mem::size_of::<Mac>();
    let mut bytes = Vec::with_capacity(ident_size * 2 + 2 + payload.len());
    bytes.extend_from_slice(dst.as_bytes());
    bytes.extend_from_slice(src.as_bytes());
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// Build the host Ethernet frame `send_local` would inject for `(dst, src,
/// payload)`: `[dst MAC][src MAC][ethertype][payload]`.  Exposed so tests can
/// assert against the exact frame a neighbor delivers to its host.
pub fn host_frame(dst: Mac, src: Mac, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + payload.len());
    v.extend_from_slice(dst.as_bytes());
    v.extend_from_slice(src.as_bytes());
    v.extend_from_slice(&HOST_ETHERTYPE);
    v.extend_from_slice(payload);
    v
}

/// Zero-copy parse of raw bytes into a `&LinkFrame`.
pub fn parse_frame(bytes: &[u8]) -> &LinkFrame {
    LinkFrame::ref_from_bytes(bytes).expect("failed to parse LinkFrame from bytes")
}

// ── in-process transports ─────────────────────────────────────────────────────

/// A [`FrameIo`] mesh transport backed by a [`PortComms`] duplex into the
/// switch fabric.
struct ChannelTransport {
    egress: mpsc::Sender<Vec<u8>>,
    ingress: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl From<PortComms> for ChannelTransport {
    fn from(pc: PortComms) -> Self {
        Self {
            egress: pc.egress,
            ingress: tokio::sync::Mutex::new(pc.ingress),
        }
    }
}

#[async_trait]
impl FrameIo for ChannelTransport {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.ingress.lock().await.recv().await {
            Some(frame) => Ok(copy_into(&frame, buf)),
            // The duplex outlives the test; an exhausted channel must stay
            // pending so the deterministic non-blocking poll reports "nothing
            // ready" rather than a spurious zero-length frame.
            None => std::future::pending().await,
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        tracing::trace!(len = buf.len(), "channel transport tx");
        self.egress
            .send(buf.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "switch port closed"))?;
        Ok(buf.len())
    }
}

/// The host-facing device for a test node: frames the router delivers locally
/// are appended to a shared log instead of a kernel TAP, and the inbound side
/// stays pending (host traffic is injected directly via
/// [`Driver::inject_host_frame`]).
pub struct ObservableEgress {
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    deliveries: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl FrameIo for ObservableEgress {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        tracing::trace!("recv: waiting for frame");
        let mut inbound = self.inbound.lock().await;
        match inbound.recv().await {
            Some(frame) => {
                tracing::trace!(len = frame.len(), "recv: frame received");
                Ok(copy_into(&frame, buf))
            }
            None => {
                tracing::warn!("recv: channel closed");
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Channel Closed",
                ));
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.deliveries.lock().unwrap().push(buf.to_vec());
        Ok(buf.len())
    }
}

/// Copy `frame` into `buf`, returning the number of bytes written.
fn copy_into(frame: &[u8], buf: &mut [u8]) -> usize {
    let n = frame.len().min(buf.len());
    buf[..n].copy_from_slice(&frame[..n]);
    n
}

// ── TestRouter ────────────────────────────────────────────────────────────────

/// A [`Driver`] wired to in-process channels for deterministic multi-node tests.
///
/// Each [`poll`] and [`drain_all`] drives the underlying driver; locally
/// delivered frames are captured in [`local_deliveries`].
///
/// [`poll`]: TestRouter::poll
/// [`drain_all`]: TestRouter::drain_all
/// [`local_deliveries`]: TestRouter::local_deliveries
pub struct TestRouter {
    /// The underlying driver running the real event loop over channels.
    driver: Driver<ObservableEgress>,
    /// This node's mesh identifier.
    pub ident: Mac,
    /// Inner frames the router handed up for local delivery (what would be
    /// written to the TAP), in arrival order.
    deliveries: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Kept alive so the host-inbound channel never closes (the driver's
    /// host-device select arm must stay pending, not resolve to `None`).
    host_in: mpsc::Sender<Vec<u8>>,
    /// Kept alive so the management-query channel stays open.
    _query_tx: QueryTx,
}

impl TestRouter {
    /// Create a new test router with the given node identity, one switch-port
    /// duplex per mesh interface, and that interface's per-link OGM backoff
    /// bounds (in interface order; missing entries default).
    pub fn new(ident: Mac, interfaces: Vec<PortComms>, trickle: Vec<TrickleConfig>) -> Self {
        let links: Vec<Box<DynLinkT<'static>>> = interfaces
            .into_iter()
            .map(|pc| DynLinkT::new_box(Link::new(ChannelTransport::from(pc))))
            .collect();

        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let (host_in, host_rx) = mpsc::channel(64);
        let local = ObservableEgress {
            inbound: tokio::sync::Mutex::new(host_rx),
            deliveries: deliveries.clone(),
        };
        let (query_tx, query_rx): (QueryTx, QueryRx) = mpsc::channel(16);

        Self {
            driver: Driver::new(ident, local, links, trickle, query_rx),
            ident,
            deliveries,
            host_in,
            _query_tx: query_tx,
        }
    }

    /// The underlying router, for inspecting routing state (originator tables,
    /// route resolution).
    pub fn router(&self) -> &CentralRouter {
        self.driver.router()
    }

    /// The underlying router, mutably — for the metric-driven egress queries
    /// (`get_egress_interface`) and crafted-frame injection.
    pub fn router_mut(&mut self) -> &mut CentralRouter {
        self.driver.router_mut()
    }

    /// Get the underlying driver for this router.
    pub fn driver(&mut self) -> &mut Driver<ObservableEgress> {
        &mut self.driver
    }

    /// The inner frames the router has delivered locally so far (the full host
    /// Ethernet frames that would have been written to the TAP), in order.
    pub fn local_deliveries(&self) -> Vec<Vec<u8>> {
        self.deliveries.lock().unwrap().clone()
    }

    // ── outbound ─────────────────────────────────────────────────────────────

    /// Drive one periodic tick at `now`, emitting an OGM for each interface whose
    /// Trickle timer is due — the deterministic counterpart to the production
    /// periodic loop ([`Driver::poll_due`]).  This is the only emission path:
    /// like production, each due interface emits its own distinct-seqno OGM, so
    /// tests exercise the real per-interface dynamics rather than a lockstep
    /// single-seqno flood.
    pub async fn poll_due(&mut self, now: Duration) {
        self.driver
            .poll_due(now)
            .await
            .expect("poll_due dispatch failed");
    }

    /// Time until this node's soonest interface is next due to emit an OGM, as of
    /// `now` — used by the harness to advance the virtual clock event-to-event.
    pub fn next_broadcast_after(&self, now: Duration) -> Duration {
        self.router().next_broadcast_after(now)
    }

    /// Inject host application data destined for `dest` into the mesh.
    ///
    /// Wraps `payload` in a host Ethernet frame (see [`host_frame`]) addressed
    /// to `dest` and hands it to the driver as if the host had emitted it on
    /// the TAP, so the egress copies are dispatched immediately.
    pub async fn send_local(&mut self, dest: Mac, payload: &[u8]) -> anyhow::Result<()> {
        let eth = host_frame(dest, self.ident, payload);
        self.host_in.send(eth.clone()).await?;
        tracing::trace!(len = eth.len(), "send_local: frame sent");
        Ok(())
    }

    // ── inbound ───────────────────────────────────────────────────────────────

    /// Drain every currently-pending frame across all mesh interfaces (and the
    /// host/query channels) through the driver in one non-blocking sweep.
    pub async fn drain_all(&mut self) {
        self.driver
            .process_pending()
            .await
            .expect("process_pending failed");
    }

    /// Feed one crafted wire frame to the router with explicit [`LinkMetrics`],
    /// as if the radio had reported that RSSI/SNR on interface `iface_idx`.
    ///
    /// The channel transports cannot carry per-frame metrics, so this drives
    /// the router directly; any re-flood reply is discarded (these tests assert
    /// on routing state, not on forwarded frames).
    pub async fn receive_with_metrics(
        &mut self,
        now: Duration,
        iface_idx: usize,
        raw: &[u8],
        metrics: LinkMetrics,
    ) {
        let mut buf = [0u8; 1500];
        let frame = parse_frame(raw);
        let _ = self
            .driver
            .router_mut()
            .handle_frame_with_metrics(now, iface_idx, frame, metrics, &mut buf);
    }
}
