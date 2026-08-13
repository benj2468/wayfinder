//! A synchronous test node, driving [`wayfinder_tick_driver`] over the
//! [`Switch`](crate::switch::Switch) fabric.
//!
//! [`TestRouter`] pairs a tick driver with one [`PortComms`] duplex per mesh
//! interface. The caller owns the clock: every step is an explicit
//! [`step`](TestRouter::step) at a chosen instant, with no executor, no
//! timeouts, and nothing to await.
//!
//! # Why not the async driver
//!
//! It used to wrap `wayfinder_driver::Driver`, which meant 63 `#[tokio::test]`s
//! that never actually tested tokio: they drove the deterministic
//! `poll_due`/`process_pending` API and never touched the `select!` loop. Since
//! all three driver shells now share one `wayfinder-driver-core` — the same
//! receive handling, the same timer handling, the same transmit decision —
//! stepping the tick driver exercises the same logic the tokio driver runs, and
//! does it synchronously.
//!
//! What that does *not* cover is real [`LinkT`] plumbing, because the tick
//! driver has no `LinkT` at all: interfaces are plain queues. That is
//! [`LinkTestRouter`](crate::link_router::LinkTestRouter)'s job.
//!
//! [`LinkT`]: wayfinder::link::LinkT

use std::time::Duration;

use interfaces::frame::LinkFrame;
use interfaces::frame::MAX_LINK_FRAME_LEN;
use interfaces::frame::Mac;
use interfaces::link::LinkMetrics;
use wayfinder::CentralRouter;
use wayfinder::config::TrickleConfig;
use wayfinder_tick_driver::Driver;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

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
    #[expect(
        clippy::expect_used,
        reason = "test helper: callers only pass bytes they built as a well-formed LinkFrame"
    )]
    let frame = LinkFrame::ref_from_bytes(bytes).expect("failed to parse LinkFrame from bytes");
    frame
}

// ── TestRouter ────────────────────────────────────────────────────────────────

/// One node in a simulated mesh: a tick driver plus its switch-port duplexes.
///
/// Frames move in three explicit moves, all synchronous — [`step`] pulls
/// whatever the switch has delivered into the driver, advances it to `now`, and
/// pushes whatever it produced back onto the ports. Locally delivered frames
/// accumulate in [`local_deliveries`].
///
/// [`step`]: TestRouter::step
/// [`local_deliveries`]: TestRouter::local_deliveries
pub struct TestRouter {
    /// The tick driver running the shared planning core over plain queues.
    driver: Driver,
    /// This node's mesh identifier.
    pub ident: Mac,
    /// One switch-port duplex per mesh interface, in interface order.
    ports: Vec<PortComms>,
    /// Inner frames the router handed up for local delivery (what would be
    /// written to the TAP), in arrival order.
    deliveries: Vec<Vec<u8>>,
}

impl TestRouter {
    /// Create a test router with the given identity, one switch-port duplex per
    /// mesh interface, and that interface's per-link OGM backoff bounds (in
    /// interface order; missing entries default).
    pub fn new(ident: Mac, interfaces: Vec<PortComms>, trickle: Vec<TrickleConfig>) -> Self {
        // The driver's interface count comes from the trickle slice, so pad it
        // to the port count when a caller supplied fewer entries than links.
        let mut trickle = trickle;
        trickle.resize(interfaces.len(), TrickleConfig::default());
        Self {
            // Links default to full participation; a test that needs a
            // partially participating link sets it afterward via
            // `router_mut().set_link_features(..)`.
            // Interfaces are left unnamed: the harness addresses them by
            // index, and a test that cares names one via
            // `router_mut().set_interface_name(..)`.
            driver: Driver::new(ident, &trickle, &[], &[]),
            ident,
            ports: interfaces,
            deliveries: Vec::new(),
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

    /// Pin the unix time that `now == 0` means, so certificate validity is
    /// judged against a real clock while tests keep driving a virtual one.
    pub fn set_auth_epoch_unix(&mut self, epoch_unix: u64) {
        self.driver.set_auth_epoch_unix(epoch_unix);
    }

    /// The inner frames the router has delivered locally so far (the full host
    /// Ethernet frames that would have been written to the TAP), in order.
    pub fn local_deliveries(&self) -> Vec<Vec<u8>> {
        self.deliveries.clone()
    }

    // ── stepping ─────────────────────────────────────────────────────────────

    /// Advance this node to `now`: take delivery of whatever the switch has
    /// queued, run one driver tick, and hand back whatever it produced.
    ///
    /// The single step every other driving method is built from. One call is
    /// one round of "receive, decide, transmit" — a frame received here is
    /// forwarded on this same call, not the next.
    pub fn step(&mut self, now: Duration) {
        self.step_schedules(now, true, true);
    }

    /// [`step`](Self::step), servicing only the selected periodic schedules.
    ///
    /// The split matters for fault injection: driving OGMs without keep-alives
    /// is how a test reproduces a node whose liveness signal has stopped while
    /// its routing chatter continues.
    pub fn step_schedules(&mut self, now: Duration, ogms: bool, keepalives: bool) {
        self.pump_in();
        self.driver.tick_schedules(now, ogms, keepalives);
        self.pump_out();
    }

    /// Drive one periodic tick at `now`, emitting an OGM for each interface
    /// whose Trickle timer is due.  Like production, each due interface emits
    /// its own distinct-seqno OGM, so tests exercise the real per-interface
    /// dynamics rather than a lockstep single-seqno flood.
    pub fn poll_due(&mut self, now: Duration) {
        self.step_schedules(now, true, false);
    }

    /// Drive one periodic keep-alive tick at `now`. A test wanting keep-alive
    /// active on an interface arms it first via
    /// `router_mut().configure_interface_keepalive(idx, Some(interval), now)`.
    ///
    /// Deliberately *only* the keep-alive schedule, mirroring the async
    /// driver's `poll_due_keepalive`: a test drives the two independently so it
    /// can stop one and leave the other running.
    pub fn poll_due_keepalive(&mut self, now: Duration) {
        self.step_schedules(now, false, true);
    }

    /// Drain every frame the switch has delivered, through the driver, at
    /// `now`.
    pub fn drain_all(&mut self, now: Duration) {
        self.step_schedules(now, false, false);
    }

    /// Time until this node's soonest interface is next due to emit an OGM, as
    /// of `now` — used by the harness to advance the virtual clock
    /// event-to-event.
    pub fn next_broadcast_after(&self, now: Duration) -> Duration {
        self.router().next_broadcast_after(now)
    }

    /// Time until this node's soonest interface is next due to emit a
    /// keep-alive, as of `now`.
    pub fn next_keepalive_after(&self, now: Duration) -> Duration {
        self.router().next_keepalive_after(now)
    }

    /// Inject host application data destined for `dest` into the mesh.
    ///
    /// Wraps `payload` in a host Ethernet frame (see [`host_frame`]) and queues
    /// it as if the host had emitted it on the TAP. It is dispatched on the
    /// next [`step`](Self::step), matching how the production loop picks host
    /// frames up on its next pass.
    pub fn send_local(&mut self, dest: Mac, payload: &[u8]) {
        let eth = host_frame(dest, self.ident, payload);
        tracing::trace!(len = eth.len(), "send_local: frame queued");
        self.driver.queue_local_send(dest, &eth);
    }

    /// Feed one crafted wire frame to the router with explicit [`LinkMetrics`],
    /// as if the radio had reported that RSSI/SNR on interface `iface_idx`.
    ///
    /// The switch ports cannot carry per-frame metrics, so this drives the
    /// router directly; any re-flood reply is discarded (these tests assert on
    /// routing state, not on forwarded frames).
    pub fn receive_with_metrics(
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

    // ── port plumbing ────────────────────────────────────────────────────────

    /// Move everything the switch has delivered on each port into the driver's
    /// receive queue for that interface.
    fn pump_in(&mut self) {
        for (idx, port) in self.ports.iter_mut().enumerate() {
            while let Ok(frame) = port.ingress.try_recv() {
                // A malformed frame on the fabric is a harness bug, not a
                // scenario under test — the switch only ever carries frames a
                // driver serialized.
                let _ = self.driver.push_rx(idx, LinkMetrics::default(), &frame);
            }
        }
    }

    /// Move everything the driver produced onto the switch ports, and collect
    /// anything it delivered locally.
    fn pump_out(&mut self) {
        for (idx, port) in self.ports.iter_mut().enumerate() {
            while let Some(frame) = self.driver.poll_egress(idx) {
                tracing::trace!(len = frame.len(), iface = idx, "port tx");
                // A full or closed port drops the frame, exactly as a lossy
                // medium would; the switch's own loss config models that too.
                let _ = port.egress.try_send(frame);
            }
        }
        while let Some(inner) = self.driver.poll_local() {
            self.deliveries.push(inner);
        }
    }
}
