//! An async [`Driver`] harness for tests that need a real [`LinkT`].
//!
//! [`LinkTestRouter`] wraps the production [`wayfinder_driver::Driver`] over
//! caller-supplied [`LinkT`]s, and is the harness for the two suites that
//! exercise link *plumbing* rather than routing behaviour: `link_error_tests`
//! (send/recv error policy against deliberately failing links) and
//! `rylr998_integration_tests` (a real `RylrClient` over a simulated LoRa
//! medium).
//!
//! Everything else uses [`TestRouter`](crate::test_router::TestRouter), which
//! drives `wayfinder-tick-driver` synchronously. The split is deliberate: the
//! tick driver has no [`LinkT`] at all, so it cannot host these two suites —
//! and they are consequently what keeps the async driver's link handling
//! covered.
//!
//! [`LinkT`]: wayfinder::link::LinkT

use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use interfaces::frame::MAX_LINK_FRAME_LEN;
use interfaces::frame::Mac;
use interfaces::link::LinkMetrics;
use tokio::sync::mpsc;
use wayfinder::CentralRouter;
use wayfinder::config::TrickleConfig;
use wayfinder_driver::Driver;
use wayfinder_driver::DynLinkT;
use wayfinder_driver::FrameIo;
use wayfinder_driver::QueryRx;
use wayfinder_driver::QueryTx;

use crate::test_router::host_frame;
use crate::test_router::parse_frame;

// ── in-process transports ─────────────────────────────────────────────────────

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
        #[expect(
            clippy::expect_used,
            reason = "test harness: a poisoned mutex means another test thread already panicked, so this test is failing regardless"
        )]
        let mut deliveries = self.deliveries.lock().expect("deliveries mutex poisoned");
        deliveries.push(buf.to_vec());
        Ok(buf.len())
    }
}

/// Copy `frame` into `buf`, returning the number of bytes written.
fn copy_into(frame: &[u8], buf: &mut [u8]) -> usize {
    let n = frame.len().min(buf.len());
    buf[..n].copy_from_slice(&frame[..n]);
    n
}

// ── LinkTestRouter ────────────────────────────────────────────────────────────────

/// A [`Driver`] wired to in-process channels for deterministic multi-node tests.
///
/// Each [`poll`] and [`drain_all`] drives the underlying driver; locally
/// delivered frames are captured in [`local_deliveries`].
///
/// [`poll`]: LinkTestRouter::poll
/// [`drain_all`]: LinkTestRouter::drain_all
/// [`local_deliveries`]: LinkTestRouter::local_deliveries
pub struct LinkTestRouter {
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

impl LinkTestRouter {
    /// Create a new test router from already-constructed mesh links, one per
    /// interface (in interface order), with that interface's per-link OGM
    /// backoff bounds (missing entries default). Unlike [`new`](Self::new),
    /// which always builds channel-based (`Switch`-backed) links, this lets a
    /// caller mix in a non-channel `LinkT` implementation — e.g. a real
    /// `rylr998::RylrClient` boxed as `DynLinkT` — for tests that need to
    /// exercise an actual link driver rather than the in-process channel
    /// fabric.
    pub fn from_links(
        ident: Mac,
        links: Vec<Box<DynLinkT<'static>>>,
        trickle: Vec<TrickleConfig>,
    ) -> Self {
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let (host_in, host_rx) = mpsc::channel(64);
        let local = ObservableEgress {
            inbound: tokio::sync::Mutex::new(host_rx),
            deliveries: deliveries.clone(),
        };
        let (query_tx, query_rx): (QueryTx, QueryRx) = mpsc::channel(16);

        Self {
            // Links default to full participation here; a test that needs a
            // partially participating link sets it afterward via
            // `router_mut().set_link_features(..)`.
            driver: Driver::new(
                ident,
                local,
                links,
                trickle,
                Vec::new(),
                Vec::new(),
                query_rx,
            ),
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
        #[expect(
            clippy::expect_used,
            reason = "test harness: a poisoned mutex means another test thread already panicked, so this test is failing regardless"
        )]
        let deliveries = self.deliveries.lock().expect("deliveries mutex poisoned");
        deliveries.clone()
    }

    // ── outbound ─────────────────────────────────────────────────────────────

    /// Drive one periodic tick at `now`, emitting an OGM for each interface whose
    /// Trickle timer is due — the deterministic counterpart to the production
    /// periodic loop ([`Driver::poll_due`]).  This is the only emission path:
    /// like production, each due interface emits its own distinct-seqno OGM, so
    /// tests exercise the real per-interface dynamics rather than a lockstep
    /// single-seqno flood.
    pub async fn poll_due(&mut self, now: Duration) {
        #[expect(
            clippy::expect_used,
            reason = "test harness: the in-process channel transports have no failure mode reachable from a test"
        )]
        {
            self.driver
                .poll_due(now)
                .await
                .expect("poll_due dispatch failed");
        }
    }

    /// Time until this node's soonest interface is next due to emit an OGM, as of
    /// `now` — used by the harness to advance the virtual clock event-to-event.
    pub fn next_broadcast_after(&self, now: Duration) -> Duration {
        self.router().next_broadcast_after(now)
    }

    /// Drive one periodic keep-alive tick at `now`, emitting a heartbeat for
    /// each interface whose fixed-cadence timer is due — the deterministic
    /// counterpart to the production periodic loop
    /// ([`Driver::poll_due_keepalive`]). A test wanting keep-alive active on
    /// an interface arms it first via
    /// `router_mut().configure_interface_keepalive(idx, Some(interval), now)`,
    /// same pattern as `set_link_features` — this is not a `LinkTestRouter::new`/
    /// `from_links` constructor parameter.
    pub async fn poll_due_keepalive(&mut self, now: Duration) {
        #[expect(
            clippy::expect_used,
            reason = "test harness: the in-process channel transports have no failure mode reachable from a test"
        )]
        {
            self.driver
                .poll_due_keepalive(now)
                .await
                .expect("poll_due_keepalive dispatch failed");
        }
    }

    /// Time until this node's soonest interface is next due to emit a
    /// keep-alive, as of `now`.
    pub fn next_keepalive_after(&self, now: Duration) -> Duration {
        self.router().next_keepalive_after(now)
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
        #[expect(
            clippy::expect_used,
            reason = "test harness: the in-process channel transports have no failure mode reachable from a test"
        )]
        {
            self.driver
                .process_pending()
                .await
                .expect("process_pending failed");
        }
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
        let mut buf = [0u8; MAX_LINK_FRAME_LEN];
        let frame = parse_frame(raw);
        let _ = self
            .driver
            .router_mut()
            .handle_frame_with_metrics(now, iface_idx, frame, metrics, &mut buf);
    }
}
