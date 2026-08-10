//! The router event loop, bundling all long-lived state behind one [`Driver`].
//!
//! The driver is transport-agnostic: the local host device and every mesh
//! interface are [`FrameIo`] carriers, so the *same* loop runs against real
//! sockets in production and against in-process channels in tests.  Two ways to
//! drive it:
//!
//! * [`Driver::run`] / [`Driver::run_once`] — the free-running `select!` loop
//!   used in production: it awaits whichever event happens first (a mesh frame,
//!   a host frame, a management query, or the periodic-broadcast timer).
//! * [`Driver::poll`] + [`Driver::process_pending`] — deterministic stepping
//!   for tests: drive the periodic broadcast at a chosen instant, then drain
//!   every already-pending frame in one non-blocking sweep.

use std::time::Duration;
use std::time::Instant;

use futures::FutureExt;
use futures::future::select_all;
use tokio::time::sleep;
use tracing::trace;
use tracing::warn;
use wayfinder::CentralRouter;
use wayfinder::McastPlan;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::config::TrickleConfig;
use wayfinder::features::LinkFeatures;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN;
use wayfinder::interfaces::frame::Mac;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::MeshSink;
use wayfinder_protos::service::WayfinderService;
use wayfinder_server::AuthSnapshot;
use wayfinder_server::AuthSnapshotRx;
use wayfinder_server::CertAuthority;
use wayfinder_server::MeshAuthority;
use wayfinder_server::QueryRx;
use wayfinder_server::RouterAdapter;

use wayfinder::link::DynLinkT;
use wayfinder::link::LinkT;

use crate::snoop::McastSnooper;
use crate::transport::FrameIo;

/// One frame to put on the mesh, plus how to fan it out.  The owned,
/// `std`-side counterpart to [`wayfinder_driver_core::OutgoingFrame`] (whose
/// payload borrows the transmit scratchpad): this driver stages frames into a
/// [`Vec`] between planning and dispatch, so it copies the payload out.
struct OutgoingFrame {
    /// Destination ident (a next-hop neighbor, or `BROADCAST` for a flood).
    dst: Mac,
    /// EtherType-style protocol identifier stamped on the link frame.
    protocol: u16,
    /// Serialized payload to transmit.
    payload: Vec<u8>,
    /// How to dispatch this frame onto the mesh interfaces.
    egress: Egress,
}

/// One unit of work's outgoing frames.
struct LoopOutput {
    /// Frames to transmit onto the mesh, each dispatched via
    /// `get_egress_interface`.  Usually one, but a selectively-forwarded
    /// multicast frame produces one per listener.
    mesh: Vec<OutgoingFrame>,
    /// Inner frame to write back to the local host device.
    local: Option<Vec<u8>>,
}

impl LoopOutput {
    /// An empty unit of work — nothing to send anywhere.
    fn none() -> Self {
        Self {
            mesh: Vec::new(),
            local: None,
        }
    }
}

/// Stage the shared core's borrowed outputs into this owned unit of work: each
/// planned mesh frame is copied into `mesh` (its payload borrows the transmit
/// scratchpad, reused on the next planning call), and a local delivery into
/// `local`.
impl MeshSink for LoopOutput {
    fn emit(&mut self, frame: wayfinder_driver_core::OutgoingFrame<'_>) {
        self.mesh.push(OutgoingFrame {
            dst: frame.dst,
            protocol: frame.protocol,
            payload: frame.payload.to_vec(),
            egress: frame.egress,
        });
    }
    fn deliver_local(&mut self, inner: &[u8]) {
        self.local = Some(inner.to_vec());
    }
}

/// The router event loop and all the state it operates on.
///
/// `Local` is the host-facing device (a TUN/TAP in production, an observable
/// channel in tests); the mesh interfaces are type-erased [`LinkT`]s, so simple
/// point-to-point carriers and self-routing multi-access links can be mixed.
pub struct Driver<Local: FrameIo> {
    /// The local host network device.
    local: Local,
    /// The mesh interfaces, indexed by interface index.
    interfaces: Vec<Box<DynLinkT<'static>>>,
    /// The routing engine for this node.
    router: CentralRouter,
    /// Management-API queries forwarded from the server tasks.
    query_rx: QueryRx,
    /// Requests from the TLS management server for a snapshot of this node's
    /// authorization state (trust anchor + revocations), so a connection can be
    /// authorized without sharing the router across tasks.  `None` when no TLS
    /// management server is attached; set via
    /// [`set_auth_snapshot_rx`](Self::set_auth_snapshot_rx).
    auth_snapshot_rx: Option<AuthSnapshotRx>,
    /// This node's mesh identifier (its host device's MAC address).
    mac: Mac,
    /// Snoops IGMP on the host link to learn which multicast groups the local
    /// host listens to, so they can be announced to the mesh.
    snooper: McastSnooper,
    /// Reference instant for periodic-broadcast timing.
    start: Instant,
    /// Wall-clock unix time (seconds) corresponding to `now == 0` (the `start`
    /// instant).  The auth clock is then `auth_epoch_unix + now`, so it advances
    /// with the loop's `now` rather than reading the wall clock each tick — which
    /// lets a test drive certificate-validity time forward (faster than real
    /// time) via the `now` it already controls.  Defaults to the wall clock at
    /// construction; override with [`set_auth_epoch_unix`](Self::set_auth_epoch_unix).
    auth_epoch_unix: u64,
    /// Receive scratchpad for frames read from the host device.
    rx_buffer: [u8; MAX_LINK_FRAME_LEN],
    /// Transmit scratchpad the router builds outgoing frames into.
    tx_buffer: [u8; MAX_LINK_FRAME_LEN],
    /// The mesh certificate authority, present only when this node runs in
    /// provider mode (set via [`set_provider`](Self::set_provider)).  Serves the
    /// enrollment management-API requests; absent ⇒ those return an error.
    provider: Option<CertAuthority>,
}

impl<Local: FrameIo> Driver<Local> {
    /// Build a driver for node `mac` over the given host device, mesh
    /// interfaces, and management-query channel.  `trickle` supplies each
    /// interface's per-link adaptive OGM bounds (`i_min`/`i_max`), and `features`
    /// its per-link participation gates, both in interface order; interfaces
    /// without an entry fall back to [`TrickleConfig::default`] /
    /// [`LinkFeatures::default`] (full participation).
    ///
    /// [`LinkFeatures::default`]: wayfinder::features::LinkFeatures
    pub fn new(
        mac: Mac,
        local: Local,
        interfaces: Vec<Box<DynLinkT<'static>>>,
        trickle: Vec<TrickleConfig>,
        features: Vec<LinkFeatures>,
        query_rx: QueryRx,
    ) -> Self {
        let mut router = CentralRouter::new(mac);
        // Install each interface's adaptive OGM schedule and participation
        // features up front so the periodic loop and the egress gates have a
        // per-interface entry to consult from the start.  The Trickle timer is
        // armed on every interface regardless of `tx_ogm`; a `tx_ogm`-off link
        // simply has its emission suppressed at poll time, which keeps the
        // features runtime-toggleable without arming/disarming timers.
        // The router only tracks `MAX_INTERFACES` interfaces; links past that cap
        // are silently never OGM-scheduled *and* silently revert to full
        // participation (a `set_link_features` past the cap no-ops), so a link
        // configured as a read-only tap would still transmit. Warn rather than
        // ship that misconfiguration mutely.
        if interfaces.len() > wayfinder::MAX_INTERFACES {
            warn!(
                configured = interfaces.len(),
                max = wayfinder::MAX_INTERFACES,
                "more mesh links than the router supports; links past the cap are unscheduled and ungated"
            );
        }
        for idx in 0..interfaces.len() {
            let cfg = trickle.get(idx).copied().unwrap_or_default();
            router.configure_interface_ogm(idx, cfg.i_min(), cfg.i_max(), Duration::ZERO);
            let link_features = features.get(idx).copied().unwrap_or_default();
            router.set_link_features(idx, link_features);
            // Keep-alive rides on the same per-link `features` entry (no
            // separate constructor vector) — its `tx_keepalive` supplies the
            // schedule, `None` leaving that interface's timer unarmed.
            router.configure_interface_keepalive(
                idx,
                link_features.tx_keepalive.map(|c| c.interval()),
                Duration::ZERO,
            );
        }
        Self {
            local,
            interfaces,
            router,
            query_rx,
            mac,
            snooper: McastSnooper::new(),
            start: Instant::now(),
            auth_epoch_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            rx_buffer: [0u8; MAX_LINK_FRAME_LEN],
            tx_buffer: [0u8; MAX_LINK_FRAME_LEN],
            provider: None,
            auth_snapshot_rx: None,
        }
    }

    /// Enable provider (certificate-authority) mode: the node serves enrollment
    /// requests (`GetTrustAnchor`/`SubmitCsr`/`RevokeNode`) from this `ca`.
    pub fn set_provider(&mut self, ca: CertAuthority) {
        self.provider = Some(ca);
    }

    /// Attach the receiver the TLS management server uses to request
    /// authorization snapshots.  The driver answers each request with the
    /// router's current trust anchor and revocation set, which the server task
    /// evaluates a connection against.  Without this, a TLS management server has
    /// no way to authorize connections.
    pub fn set_auth_snapshot_rx(&mut self, rx: AuthSnapshotRx) {
        self.auth_snapshot_rx = Some(rx);
    }

    /// Set the wall-clock unix time (seconds) that corresponds to the driver's
    /// `now == 0`.  The auth clock used for certificate-validity checks is then
    /// `epoch + now`.  Tests set this to a fixed value and drive `now` forward to
    /// exercise expiry deterministically, faster than real time.
    pub fn set_auth_epoch_unix(&mut self, epoch_unix: u64) {
        self.auth_epoch_unix = epoch_unix;
    }

    /// Advance the auth state's certificate-validity clock to `auth_epoch_unix +
    /// now`.  A no-op when auth is disabled.  Called from every entry point that
    /// processes frames so cert expiry tracks the loop's `now` consistently.
    fn refresh_auth_clock(&mut self, now: Duration) {
        let epoch = self.auth_epoch_unix;
        let unix = epoch.saturating_add(now.as_secs());
        if let Some(auth) = self.router.auth_mut() {
            auth.set_time(unix);
        }
        // Keep the provider CA's issuance clock in step, so issued certificate
        // validity windows track the same time the router verifies against.
        if let Some(ca) = self.provider.as_mut() {
            ca.set_now_unix(unix);
        }
    }

    /// The underlying router, for inspecting routing state (originator tables,
    /// link quality, route resolution).
    pub fn router(&self) -> &CentralRouter {
        &self.router
    }

    /// The underlying router, mutably — lets callers inject crafted frames with
    /// explicit link metrics that the message-oriented transports cannot carry.
    pub fn router_mut(&mut self) -> &mut CentralRouter {
        &mut self.router
    }

    /// Run the event loop forever.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let now = self.start.elapsed();
            self.run_once(now, true, true, true, true).await?;
        }
    }

    /// Run a single iteration: wait for whichever happens first — a frame from a
    /// mesh interface, a frame from the local host device, a management query,
    /// or the periodic-broadcast timer — process it, then deliver any inner
    /// frame to the host and dispatch any outgoing frame onto the mesh.
    ///
    /// `now` is the current instant (relative to the driver's reference instant)
    /// stamped on received originator records and on any OGM produced, so a
    /// caller that controls time — e.g. a deterministic test — controls route
    /// ageing.  Production passes `self.start.elapsed()`.
    #[tracing::instrument(
        skip(self, check_local, check_mesh, check_server, check_periodic),
        fields(ident = ?self.mac)
    )]
    pub async fn run_once(
        &mut self,
        now: Duration,
        check_local: bool,
        check_mesh: bool,
        check_server: bool,
        check_periodic: bool,
    ) -> anyhow::Result<()> {
        // Advance the auth clock from the loop's `now` (see `refresh_auth_clock`).
        self.refresh_auth_clock(now);

        // When the soonest interface is next due to emit an OGM or a
        // keep-alive, on the tokio clock.  Each interface backs off (Trickle)
        // on its own OGM schedule and ticks its own independent fixed-cadence
        // keep-alive schedule, so the periodic arm sleeps until whichever
        // fires first, of either kind.  Recomputed every iteration, so a
        // timer reset by the frame just processed (an inconsistency) shortens
        // the next sleep automatically.
        let next_due = self
            .router
            .next_broadcast_after(now)
            .min(self.router.next_keepalive_after(now));

        // Destructure into disjoint field borrows so the `select!` can hold a
        // mutable borrow of the interfaces alongside the router and buffers.
        let Driver {
            local,
            interfaces,
            router,
            query_rx,
            mac,
            snooper,
            start: _,
            auth_epoch_unix: _,
            rx_buffer,
            tx_buffer,
            provider,
            auth_snapshot_rx,
        } = self;
        let mac = *mac;

        let output: LoopOutput = {
            tokio::select! {
                ((idx, result), _, _) = select_all(
                    interfaces.iter_mut().enumerate().map(|(i, iface)| {
                        Box::pin(async move { (i, iface.recv().await) })
                    })
                ), if check_mesh && !interfaces.is_empty() => {
                    let mut out = LoopOutput::none();
                    wayfinder_driver_core::handle_link_result(
                        now, router, idx, result, tx_buffer, &mut out,
                    );
                    out
                },
                Ok(len) = local.recv(rx_buffer), if check_local => {
                    trace!(len, "host device rx frame");
                    let eth = &rx_buffer[..len];
                    LoopOutput {
                        mesh: plan_host_frame(now, router, snooper, eth, tx_buffer),
                        local: None,
                    }
                },
                Some((request, resp_tx)) = query_rx.recv(), if check_server => {
                    let ca = provider.as_mut().map(|c| c as &mut dyn MeshAuthority);
                    let response = WayfinderService::new(RouterAdapter::new(&mut *router, ca, now)).handle(request);
                    let _ = resp_tx.send(response);
                    LoopOutput::none()
                },
                Some(reply) = recv_auth_snapshot(auth_snapshot_rx), if check_server => {
                    let _ = reply.send(build_auth_snapshot(router));
                    LoopOutput::none()
                },
                _ = sleep(next_due), if check_periodic => {
                    trace!("polling OGMs and keep-alives");
                    let mut out = LoopOutput::none();
                    wayfinder_driver_core::poll_due_ogms(router, now, tx_buffer, &mut out);
                    wayfinder_driver_core::poll_due_keepalives(router, now, tx_buffer, &mut out);
                    out
                }
            }
        };

        dispatch(local, interfaces, router, mac, now, output).await
    }

    /// Inject one host Ethernet frame as if it had arrived from the local
    /// device, wrapping it for the mesh and dispatching the resulting copies
    /// immediately.  Equivalent to the host-device arm of [`run_once`], exposed
    /// so a caller can push host traffic programmatically.
    ///
    /// [`run_once`]: Driver::run_once
    pub async fn inject_host_frame(&mut self, eth: &[u8]) -> anyhow::Result<()> {
        let now = self.start.elapsed();
        let mesh = plan_host_frame(
            now,
            &mut self.router,
            &mut self.snooper,
            eth,
            &mut self.tx_buffer,
        );
        self.dispatch_output(now, LoopOutput { mesh, local: None })
            .await
    }

    /// Drive one *per-interface* periodic tick at instant `now`: emit an OGM for
    /// each interface whose Trickle timer is due (advancing that timer), exactly
    /// as the production periodic arm does via [`poll_due_ogms`].  This is the
    /// deterministic, sleep-free counterpart to the `check_periodic` arm of
    /// [`run_once`] — where that arm `sleep`s until the soonest timer fires on the
    /// real tokio clock, this emits whatever is already due at the caller-supplied
    /// `now`, so a test controlling the clock exercises the true per-interface
    /// Trickle emission path (distinct seqno per interface) rather than the
    /// all-interface [`poll`](Self::poll) flood.
    ///
    /// [`run_once`]: Driver::run_once
    pub async fn poll_due(&mut self, now: Duration) -> anyhow::Result<()> {
        self.refresh_auth_clock(now);
        let mesh = poll_due_ogms(&mut self.router, now, &mut self.tx_buffer);
        let output = LoopOutput { mesh, local: None };
        dispatch(
            &self.local,
            &mut self.interfaces,
            &mut self.router,
            self.mac,
            now,
            output,
        )
        .await
    }

    /// Drive one *per-interface* keep-alive tick at instant `now`: emit a
    /// heartbeat for each interface whose fixed-cadence timer is due
    /// (advancing that timer), the keep-alive counterpart of
    /// [`poll_due`](Self::poll_due).
    pub async fn poll_due_keepalive(&mut self, now: Duration) -> anyhow::Result<()> {
        self.refresh_auth_clock(now);
        let mesh = poll_due_keepalives(&mut self.router, now, &mut self.tx_buffer);
        let output = LoopOutput { mesh, local: None };
        dispatch(
            &self.local,
            &mut self.interfaces,
            &mut self.router,
            self.mac,
            now,
            output,
        )
        .await
    }

    /// Drain every already-pending event — host frames, mesh frames, and
    /// management queries — in non-blocking sweeps until nothing remains.
    ///
    /// This is the deterministic counterpart to [`run_once`]: where `run_once`
    /// awaits the next single event, `process_pending` consumes the current
    /// backlog and returns.  Replies generated while draining are dispatched
    /// onto the egress channels, not fed back into this sweep, so the loop
    /// terminates.
    ///
    /// [`run_once`]: Driver::run_once
    pub async fn process_pending(&mut self) -> anyhow::Result<()> {
        self.refresh_auth_clock(self.start.elapsed());
        loop {
            let mut progressed = false;

            // Host device: a frame the local host wants to put on the mesh.
            let polled = self.local.recv(&mut self.rx_buffer).now_or_never();
            if let Some(result) = polled {
                let len = result?;
                progressed = true;
                let eth = self.rx_buffer[..len].to_vec();
                let mesh = plan_host_frame(
                    self.start.elapsed(),
                    &mut self.router,
                    &mut self.snooper,
                    &eth,
                    &mut self.tx_buffer,
                );
                self.dispatch_output(self.start.elapsed(), LoopOutput { mesh, local: None })
                    .await?;
            }

            // Mesh interfaces: forwarded/delivered frames.
            for idx in 0..self.interfaces.len() {
                let Some(result) = self.interfaces[idx].recv().now_or_never() else {
                    continue;
                };
                // Only a *successful* receive counts as progress. An erroring
                // link yields immediately and forever, so counting it would spin
                // this drain loop rather than terminate it.
                progressed |= result.is_ok();
                // Same posture as `run_once`, and the same shared handler: a
                // link recv error is traced and skipped, never propagated.
                let mut output = LoopOutput::none();
                wayfinder_driver_core::handle_link_result(
                    self.start.elapsed(),
                    &mut self.router,
                    idx,
                    result,
                    &mut self.tx_buffer,
                    &mut output,
                );
                self.dispatch_output(self.start.elapsed(), output).await?;
            }

            // Management queries from the in-process server.
            if let Ok((request, resp_tx)) = self.query_rx.try_recv() {
                progressed = true;
                let now = self.start.elapsed();
                let ca = self.provider.as_mut().map(|c| c as &mut dyn MeshAuthority);
                let response = WayfinderService::new(RouterAdapter::new(&mut self.router, ca, now))
                    .handle(request);
                let _ = resp_tx.send(response);
            }

            // Authorization-state snapshot requests from the TLS management server.
            if let Some(rx) = self.auth_snapshot_rx.as_mut()
                && let Ok(reply) = rx.try_recv()
            {
                progressed = true;
                let _ = reply.send(build_auth_snapshot(&self.router));
            }

            if !progressed {
                break;
            }
        }
        Ok(())
    }

    /// Deliver one unit of work via the borrowed `self` fields, stamping any
    /// transmit-rate accounting with `now`.
    async fn dispatch_output(&mut self, now: Duration, output: LoopOutput) -> anyhow::Result<()> {
        dispatch(
            &self.local,
            &mut self.interfaces,
            &mut self.router,
            self.mac,
            now,
            output,
        )
        .await
    }
}

/// Produce an OGM for each interface that is due to emit as of `now`, addressed
/// to that one interface.  Thin `std`-side wrapper that stages the shared
/// core's [`poll_due_ogms`](wayfinder_driver_core::poll_due_ogms) output into an
/// owned [`Vec`].
fn poll_due_ogms(
    router: &mut CentralRouter,
    now: Duration,
    tx_buffer: &mut [u8],
) -> Vec<OutgoingFrame> {
    let mut out = LoopOutput::none();
    wayfinder_driver_core::poll_due_ogms(router, now, tx_buffer, &mut out);
    out.mesh
}

/// Produce a keep-alive heartbeat for each interface that is due to emit as
/// of `now`, addressed to that one interface. Thin `std`-side wrapper that
/// stages the shared core's
/// [`poll_due_keepalives`](wayfinder_driver_core::poll_due_keepalives) output
/// into an owned [`Vec`].
fn poll_due_keepalives(
    router: &mut CentralRouter,
    now: Duration,
    tx_buffer: &mut [u8],
) -> Vec<OutgoingFrame> {
    let mut out = LoopOutput::none();
    wayfinder_driver_core::poll_due_keepalives(router, now, tx_buffer, &mut out);
    out.mesh
}

/// Await the next authorization-snapshot request from the TLS management server,
/// or never resolve when none is attached — keeping the corresponding `select!`
/// arm dormant rather than requiring a separate enable flag.
async fn recv_auth_snapshot(
    rx: &mut Option<AuthSnapshotRx>,
) -> Option<tokio::sync::oneshot::Sender<AuthSnapshot>> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Project the router's current authorization-relevant state — trust anchor and
/// revocations — into an [`AuthSnapshot`] the management server evaluates a
/// connection against.  Both are empty when auth is disabled (un-enrolled), which
/// the server treats as bootstrap mode.
fn build_auth_snapshot(router: &CentralRouter) -> AuthSnapshot {
    match router.auth() {
        Some(auth) => AuthSnapshot {
            anchor: Some(*auth.anchor()),
            revoked: auth.revoked_macs().collect(),
        },
        None => AuthSnapshot {
            anchor: None,
            revoked: Vec::new(),
        },
    }
}

/// Turn one host Ethernet frame into the mesh frames that carry it.
///
/// The host hands us a full Ethernet frame `[dst MAC][src MAC][ethertype][..]`.
/// We route by the destination MAC — which *is* the mesh ident — and carry the
/// whole frame across the mesh untouched: a normal unicast for a single host, a
/// flooded broadcast for the all-ones address (or as multicast fallback), or —
/// for a multicast group with a known, bounded listener set — an individual
/// `BatmanPacketType::Mcast` copy per interested node.  IGMP is snooped first so the
/// groups the host joins/leaves are announced on the next OGM.
fn plan_host_frame(
    now: Duration,
    router: &mut CentralRouter,
    snooper: &mut McastSnooper,
    eth: &[u8],
    tx_buffer: &mut [u8],
) -> Vec<OutgoingFrame> {
    if snooper.observe(eth) {
        router.set_local_mcast_groups(&snooper.groups());
    }

    let mut mesh: Vec<OutgoingFrame> = Vec::new();
    if eth.len() < 14 {
        return mesh;
    }

    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&eth[0..6]);
    let dst = Mac(dst_mac);

    // Locally originated frames flood out every interface (no ingress to omit).
    let flood = |router: &mut CentralRouter, mesh: &mut Vec<OutgoingFrame>, buf: &mut [u8]| {
        if let Ok(f) = router.handle_local(now, Mac::BROADCAST, eth, buf) {
            mesh.push(OutgoingFrame {
                dst: f.dst,
                protocol: f.protocol,
                payload: f.payload.to_vec(),
                egress: Egress::Auto { exclude: None },
            });
        }
    };

    if dst.is_broadcast() {
        flood(router, &mut mesh, tx_buffer);
    } else if dst.is_multicast() {
        match router.mcast_plan(dst) {
            McastPlan::Unicast => {
                let targets: Vec<Mac> = router.mcast_targets(dst).collect();
                for target in targets {
                    if let Ok(f) = router.handle_local_mcast(now, target, eth, tx_buffer) {
                        mesh.push(OutgoingFrame {
                            dst: f.dst,
                            protocol: f.protocol,
                            payload: f.payload.to_vec(),
                            egress: Egress::Auto { exclude: None },
                        });
                    }
                }
            }
            McastPlan::Flood => flood(router, &mut mesh, tx_buffer),
        }
    } else if let Ok(f) = router.handle_local(now, dst, eth, tx_buffer) {
        mesh.push(OutgoingFrame {
            dst: f.dst,
            protocol: f.protocol,
            payload: f.payload.to_vec(),
            egress: Egress::Auto { exclude: None },
        });
    }

    mesh
}

/// Deliver one unit of work: write any inner frame to the host device and
/// dispatch each outgoing frame onto the mesh via `get_egress_interface`.
async fn dispatch<Local: FrameIo>(
    local: &Local,
    interfaces: &mut [Box<DynLinkT<'static>>],
    router: &mut CentralRouter,
    mac: Mac,
    now: Duration,
    output: LoopOutput,
) -> anyhow::Result<()> {
    if let Some(inner) = output.local {
        trace!(len = inner.len(), "local output");
        local.send(&inner).await?;
    }

    for OutgoingFrame {
        dst,
        protocol,
        mut payload,
        egress,
    } in output.mesh
    {
        trace!(
            dst = ?dst,
            protocol = %format_args!("0x{protocol:04x}"),
            payload_len = payload.len(),
            "mesh output"
        );

        // Reserve the trailer bytes so the shared planner can write a pairwise
        // tag into them when this directed frame needs one, then resolve which
        // interfaces carry the frame (split-horizon and per-link transmit gates
        // included). `None` means auth is on but this directed frame cannot be
        // tagged — drop it rather than emit it in the clear.
        let body_len = payload.len();
        payload.resize(body_len + DIRECTED_TRAILER_LEN, 0);
        let num_interfaces = interfaces.len();
        let Some(plan) = wayfinder_driver_core::plan_dispatch(
            router,
            now,
            dst,
            protocol,
            egress,
            body_len,
            &mut payload,
            num_interfaces,
        ) else {
            continue;
        };

        let data = LinkFrameData {
            dst,
            protocol,
            payload: plan.payload(),
        };

        for idx in plan.targets().iter() {
            if let Some(iface) = interfaces.get_mut(idx) {
                send_on_link(iface, idx, router, mac, &data, now).await;
            }
        }
    }

    Ok(())
}

/// Transmit one frame on `iface`, recording the sent bytes on success.
///
/// A link send error drops this frame and logs a `warn!` — it never
/// propagates out of the event loop. Link errors are transient by contract
/// (a reconnecting transport returns `Io` until a later call succeeds), so
/// crashing here would kill the node before the link's own recovery ever ran;
/// the mesh's own redundancy (OGM cadence, retransmits) covers the lost frame.
async fn send_on_link(
    iface: &mut DynLinkT<'static>,
    iface_idx: usize,
    router: &mut CentralRouter,
    mac: Mac,
    data: &LinkFrameData<'_>,
    now: Duration,
) {
    match iface.send(mac, data).await {
        Ok(sent) => router.record_tx(iface_idx, sent, now),
        Err(e) => warn!(iface_idx, error = ?e, "link send failed; frame dropped"),
    }
}
