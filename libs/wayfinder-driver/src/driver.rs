//! The router event loop, bundling all long-lived state behind one [`Driver`].
//!
//! The driver is transport-agnostic: the local host device and every mesh
//! interface are [`FrameIo`] carriers, so the *same* loop runs against real
//! sockets in production and against in-process channels in tests.  Two ways to
//! drive it:
//!
//! * [`Driver::run`] / [`Driver::run_once`] — the free-running `select!` loop
//!   used in production: it awaits whichever event happens first (a mesh frame,
//!   a host frame, a management query, an authorization-snapshot request, a
//!   signed revocation from the certificate authority, or the
//!   periodic-broadcast timer).
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
use wayfinder::wayfinder_auth::Keypair;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::MeshSink;
use wayfinder_protos::service::handle_router;
use wayfinder_protos::service::handle_unowned;
use wayfinder_server::AuthSnapshot;
use wayfinder_server::AuthSnapshotRx;
use wayfinder_server::QueryRx;
use wayfinder_server::RouterAdapter;
use wayfinder_server::SettingsFile;
use wayfinder_server::SettingsStore;

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
    /// Wall-clock unix time corresponding to `now == 0` (the `start`
    /// instant).  The auth clock is then `epoch_unix + now`, so it advances
    /// with the loop's `now` rather than reading the wall clock each tick — which
    /// lets a test drive certificate-validity time forward (faster than real
    /// time) via the `now` it already controls.  Defaults to the wall clock at
    /// construction; override with [`set_epoch_unix`](Self::set_epoch_unix).
    epoch_unix: Duration,
    /// Everything exchanged with a certificate-authority task that does not
    /// share this loop: the clock and auth-present state this loop publishes,
    /// and the enrollment policy and signed revocations it receives back.
    ///
    /// One field rather than four channels because they are one relationship,
    /// and because wiring them separately is how one gets forgotten.  The
    /// publishing half is live on every node, including one that never runs an
    /// authority; see [`AuthorityComms`](wayfinder_server::AuthorityComms).
    authority: wayfinder_server::AuthorityComms,
    /// Receive scratchpad for frames read from the host device.
    rx_buffer: [u8; MAX_LINK_FRAME_LEN],
    /// Transmit scratchpad the router builds outgoing frames into.
    tx_buffer: [u8; MAX_LINK_FRAME_LEN],
    /// Where accepted security settings are recorded so they outlive a
    /// restart (set via [`set_settings_store`](Self::set_settings_store)).
    /// Absent ⇒ a runtime change applies in memory only.
    settings: Option<SettingsFile>,
    /// This node's own identity seed (set via
    /// [`set_identity_seed`](Self::set_identity_seed)), which the management
    /// API reports the public half of and certifies on enrollment.  Absent ⇒
    /// the node reports no identity and can only be handed a whole new one.
    identity_seed: Option<[u8; 32]>,
}

impl<Local: FrameIo> Driver<Local> {
    /// Build a driver for node `mac` over the given host device, mesh
    /// interfaces, and management-query channel.  `trickle` supplies each
    /// interface's per-link adaptive OGM bounds (`i_min`/`i_max`), `features`
    /// its per-link participation gates, and `names` its human-readable label,
    /// all in interface order; interfaces without an entry fall back to
    /// [`TrickleConfig::default`] / [`LinkFeatures::default`] (full
    /// participation) / unnamed.
    ///
    /// [`LinkFeatures::default`]: wayfinder::features::LinkFeatures
    pub fn new(
        mac: Mac,
        local: Local,
        interfaces: Vec<Box<DynLinkT<'static>>>,
        trickle: Vec<TrickleConfig>,
        features: Vec<LinkFeatures>,
        names: Vec<String>,
        query_rx: QueryRx,
    ) -> Self {
        let epoch_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
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
            if let Some(name) = names.get(idx) {
                router.set_interface_name(idx, name);
            }
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
            epoch_unix,
            authority: wayfinder_server::AuthorityComms::new(epoch_unix.as_secs()),
            rx_buffer: [0u8; MAX_LINK_FRAME_LEN],
            tx_buffer: [0u8; MAX_LINK_FRAME_LEN],
            settings: None,
            identity_seed: None,
            auth_snapshot_rx: None,
        }
    }

    /// Tell the driver which identity seed this node runs as — the same one its
    /// management TLS presents.
    ///
    /// The management API then reports its public half, so a client can ask a
    /// provider to certify *this* node, and can install the certificate that
    /// comes back without the node's identity (and therefore its MAC) changing
    /// underneath it. Without this the node reports no identity, and a
    /// `SetAuth` must carry a whole new one.
    pub fn set_identity_seed(&mut self, seed: [u8; 32]) {
        self.identity_seed = Some(seed);
    }

    /// Wire a certificate-authority task to this driver, returning everything
    /// that task needs to run.
    ///
    /// One call rather than four, so provider mode cannot be half-enabled: the
    /// clock and auth-present state this loop publishes, the enrollment policy
    /// `GetSecurityStatus` reports, and the signed revocations this loop floods
    /// are all wired together or not at all.  Hand the result straight to
    /// `wayfinder_server::serve_authority`.
    ///
    /// Only the revocation half is an edge running *into* this loop, and it is
    /// safe in that direction: this loop never waits on the authority for an
    /// answer, so no cycle can form back to it.
    pub fn attach_authority(
        &mut self,
        commands: wayfinder_server::AuthorityRx,
    ) -> wayfinder_server::AuthorityPorts {
        self.authority.attach(commands)
    }

    /// Record accepted security settings in `settings`, so a change made
    /// through the management API is still in force after a restart.
    ///
    /// Without this, the node still accepts such changes — it just applies
    /// them in memory and forgets them on restart.
    pub fn set_settings_store(&mut self, settings: SettingsFile) {
        self.settings = Some(settings);
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
    pub fn set_epoch_unix(&mut self, epoch_unix: Duration) {
        self.epoch_unix = epoch_unix;
        // Re-seed, or a subscriber that reads before the next loop iteration
        // sees the wall-clock seed this driver was built with rather than the
        // virtual epoch a test just set.
        self.authority
            .set_clock(epoch_unix.saturating_add(self.start.elapsed()).as_secs());
    }

    /// Advance the certificate-validity clock to `epoch_unix + now` and
    /// republish this node's auth-present state for the certificate authority.
    ///
    /// Called from every entry point that processes frames, so cert expiry
    /// tracks the loop's `now` consistently. Only the router's own `set_time` is
    /// skipped when auth is disabled — both publications happen either way, and
    /// the auth-disabled case is precisely the one the authority needs told.
    fn refresh_auth_clock(&mut self, now: Duration) {
        let unix = self.epoch_unix.saturating_add(now);
        let auth_present = match self.router.auth_mut() {
            Some(auth) => {
                auth.set_time(unix.as_secs());
                true
            }
            None => false,
        };
        // Published to whatever holds the other half — an authority task that
        // no longer shares this loop reads its issuance clock from here.  Both
        // facts go out every iteration rather than only when they change:
        // `SetAuth` can turn authentication on or off between iterations, and
        // the authority must not sign a revocation this node can no longer
        // flood.
        self.authority.publish(wayfinder_server::RouterFacts {
            unix_secs: unix.as_secs(),
            auth_present,
        });
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
    /// an authorization-snapshot request, a signed revocation from the
    /// certificate-authority task, or the periodic-broadcast timer — process
    /// it, then deliver any inner frame to the host and dispatch any outgoing
    /// frame onto the mesh.
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
        // keep-alive, or the soonest next-hop proof challenge falls due, on the
        // tokio clock.  Each interface backs off (Trickle) on its own OGM
        // schedule and ticks its own independent fixed-cadence keep-alive
        // schedule, so the periodic arm sleeps until whichever fires first, of
        // any of the three.  Recomputed every iteration, so a timer reset by
        // the frame just processed (an inconsistency) shortens the next sleep
        // automatically.
        //
        // The challenge deadline is the one that must not be dropped from this
        // `min`.  Without it proof rides the OGM timer, and a newly discovered
        // originator is not challenged until the next Trickle deadline — up to
        // a full `i_max` after its path was learned, on a mesh that has
        // settled into its quiet cadence.  With it, the frame that discovers a
        // path also shortens this sleep to zero, so the challenge goes out on
        // the next turn of the loop.
        let next_due = self
            .router
            .next_broadcast_after(now)
            .min(self.router.next_keepalive_after(now))
            .min(
                self.router
                    .next_challenge_after(now)
                    .unwrap_or(Duration::MAX),
            );

        // Destructure into disjoint field borrows so the `select!` can hold a
        // mutable borrow of the interfaces alongside the router and buffers.
        let Driver {
            local,
            interfaces,
            router,
            query_rx,
            mac,
            snooper,
            start,
            epoch_unix: _,
            rx_buffer,
            tx_buffer,
            settings,
            identity_seed,
            auth_snapshot_rx,
            authority,
        } = self;
        let mac = *mac;
        // Two disjoint borrows in one call: `select!` builds every branch's
        // future before polling any, so the revocation arm's `&mut` and the
        // policy read's `&` are live at the same moment.
        let (revocation_rx, enrollment_policy_rx) = authority.split();

        // Each arm reports the clock it planned against alongside its output:
        // every arm but the periodic one plans at the `now` sampled above,
        // while that one re-reads the clock after its sleep.  Dispatch must
        // use the same instant the frames were planned at, or the transmit
        // gate and auth tagging would judge them against a different one.
        let (now, output): (Duration, LoopOutput) = {
            tokio::select! {
                // `select_all` panics if constructed over an empty iterator, and
                // the `if` guard below only gates whether this branch's future is
                // *polled* — Rust evaluates the branch expression itself
                // unconditionally, before any guard is consulted. Wrapping the
                // construction in this `async` block defers it to first poll,
                // which the guard *does* control, so a linkless node (`links: []`,
                // a valid dashboard-only config) never reaches the panicking call
                // at all; it just never has a mesh frame to report.
                ((idx, result), _, _) = async {
                    if interfaces.is_empty() {
                        std::future::pending().await
                    } else {
                        select_all(interfaces.iter_mut().enumerate().map(|(i, iface)| {
                            Box::pin(async move { (i, iface.recv().await) })
                        }))
                        .await
                    }
                }, if check_mesh => {
                    let mut out = LoopOutput::none();
                    wayfinder_driver_core::handle_link_result(
                        now, router, idx, result, tx_buffer, &mut out,
                    );
                    (now, out)
                },
                Ok(len) = local.recv(rx_buffer), if check_local => {
                    trace!(len, "host device rx frame");
                    let eth = &rx_buffer[..len];
                    (now, LoopOutput {
                        mesh: plan_host_frame(now, router, snooper, eth, tx_buffer),
                        local: None,
                    })
                },
                Some((request, resp_tx)) = query_rx.recv(), if check_server => {
                    let mut adapter = RouterAdapter::new(&mut *router, now)
                        .with_epoch_unix(self.epoch_unix)
                        .with_identity(identity_seed)
                        .with_enrollment_policy(read_enrollment_policy(enrollment_policy_rx));
                    if let Some(store) = settings.as_mut() {
                        adapter = adapter.with_settings(store as &mut dyn SettingsStore);
                    }
                    // `handle_router`, not the combined service: the authority
                    // half is served by its own task now, and the connection
                    // task routes by `request_facet` so nothing else arrives
                    // here. What `handle_router` declines is answered by
                    // `handle_unowned`, which knows the transport-owned kinds
                    // and says which one this is — not the not-a-provider
                    // message, which would tell a client that repeated an
                    // `Authenticate` out of order that this node is not a
                    // certificate authority: false, and aimed at the wrong
                    // subsystem.
                    let response = handle_router(&mut adapter, request)
                        .unwrap_or_else(handle_unowned);
                    let _ = resp_tx.send(response);
                    (now, LoopOutput::none())
                },
                Some((record, ack)) = recv_revocation(revocation_rx), if check_server => {
                    // The authority signed and persisted this; flooding it is
                    // this loop's half of the act. Acknowledged either way, so
                    // the operator is told whether the revocation was actually
                    // announced rather than only that it was recorded.
                    ingest_and_report(router, &record, now, epoch_unix_secs(self.epoch_unix, now), ack);
                    (now, LoopOutput::none())
                },
                Some(reply) = recv_auth_snapshot(auth_snapshot_rx), if check_server => {
                    let _ = reply.send(build_auth_snapshot(router, *identity_seed));
                    (now, LoopOutput::none())
                },
                _ = sleep(next_due), if check_periodic => {
                    // Re-read the clock: `now` was sampled before the `select!`
                    // and this arm has just slept `next_due` past it, so using
                    // it here would stamp every schedule, proof and backoff the
                    // whole sleep in the past.  On a settled mesh that is a
                    // two-minute error, and it is the same clock the receive
                    // arm — which does *not* sleep — stamps proofs with, so the
                    // two would disagree about how old a proof is.
                    let now = start.elapsed();
                    trace!("polling OGMs, keep-alives and next-hop challenges");
                    let mut out = LoopOutput::none();
                    wayfinder_driver_core::poll_due_ogms(router, now, tx_buffer, &mut out);
                    wayfinder_driver_core::poll_due_keepalives(router, now, tx_buffer, &mut out);
                    wayfinder_driver_core::poll_due_challenges(router, now, tx_buffer, &mut out);
                    (now, out)
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

    /// Drain every already-pending event — host frames, mesh frames, management
    /// queries, authorization snapshots and signed revocations — in
    /// non-blocking sweeps until nothing remains.
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
                let (_, policy_rx) = self.authority.split();
                let policy = read_enrollment_policy(policy_rx);
                let mut adapter = RouterAdapter::new(&mut self.router, now)
                    .with_epoch_unix(self.epoch_unix)
                    .with_identity(&mut self.identity_seed)
                    .with_enrollment_policy(policy);
                if let Some(store) = self.settings.as_mut() {
                    adapter = adapter.with_settings(store as &mut dyn SettingsStore);
                }
                // See the same fallback in `run_once`: `handle_unowned` names the
                // transport-owned kind rather than misreporting the node's role.
                let response = handle_router(&mut adapter, request).unwrap_or_else(handle_unowned);
                let _ = resp_tx.send(response);
            }

            // Signed revocations from the certificate-authority task. Drained
            // here as well as in `run_once`: the authority awaits this
            // acknowledgement before serving anything else, so a sweep that
            // skipped it would park the authority forever and every later
            // request behind it.
            if let Some(rx) = self.authority.split().0.as_mut()
                && let Ok((record, ack)) = rx.try_recv()
            {
                progressed = true;
                let now = self.start.elapsed();
                let now_unix = epoch_unix_secs(self.epoch_unix, now);
                ingest_and_report(&mut self.router, &record, now, now_unix, ack);
            }

            // Authorization-state snapshot requests from the TLS management server.
            if let Some(rx) = self.auth_snapshot_rx.as_mut()
                && let Ok(reply) = rx.try_recv()
            {
                progressed = true;
                let _ = reply.send(build_auth_snapshot(&self.router, self.identity_seed));
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

/// The certificate-validity instant for `now`, as Unix seconds.
///
/// The same arithmetic the loop publishes to the authority, so a record is
/// verified against the instant the authority issued it against.
fn epoch_unix_secs(epoch_unix: Duration, now: Duration) -> u64 {
    epoch_unix.saturating_add(now).as_secs()
}

/// Fold a revocation the authority signed into the router, so it floods across
/// the mesh on this node's OGMs.
///
/// The router half of `RevokeNode`. The authority has already signed and
/// persisted by the time this runs, so a failure here means the revocation is
/// recorded but unannounced — which the caller reports rather than swallowing.
///
/// Takes the parsed record, not its bytes: the authority signed it in this same
/// process, so "the authority produced something this loop cannot parse" was
/// never a condition that could arise — only one the receiver had to invent an
/// answer for.
fn ingest_signed_revocation(
    router: &mut CentralRouter,
    record: &wayfinder::wayfinder_auth::RevocationRecord,
    now: Duration,
    now_unix: u64,
) -> Result<(), String> {
    // Every `Err` here is a *clause*, never a sentence: the authority's
    // `signed_but_not_flooded` supplies the "signed and recorded, but not
    // flooded to the mesh" framing. A reason that restated it produced a
    // message the operator actually read twice over.
    let Some(auth) = router.auth() else {
        return Err(
            "this node's mesh authentication is disabled, so a revocation has no OGMs to ride"
                .to_string(),
        );
    };
    // Checked explicitly rather than inferred from `ingest_revocation`'s
    // `false`, which collapses three causes into one. Verification failure is
    // the one worth naming on its own: it means the authority's root key and
    // this node's trust anchor have diverged, and it must be reported even when
    // the MAC below turns out to be revoked already — that benign-looking
    // success is exactly how a re-keyed mesh stays hidden.
    if let Err(e) = auth.anchor().verify_revocation(record, now_unix) {
        return Err(format!(
            "it does not verify against the trust anchor this node is running ({e:?}) — the \
             authority's root key and this node's anchor have diverged"
        ));
    }
    if router.ingest_revocation(record, now) {
        return Ok(());
    }
    // Already-known is the one benign `false` left. It verified above, so the
    // record is in the store and was flooded when it first arrived: the
    // operator's intent holds, even though this request re-floods nothing.
    if router
        .auth()
        .is_some_and(|auth| auth.revoked_macs().any(|m| m.0 == record.node_mac))
    {
        return Ok(());
    }
    Err("it names this node, which never floods its own revocation".to_string())
}

/// Fold a signed revocation in and report the verdict, logging a divergence
/// where it is *determined* rather than only where it is answered.
///
/// The `Err` travels back to the authority, which logs it — but that task may
/// already be gone (an aborted `JoinSet` on shutdown, a panic), and then the
/// acknowledgement is dropped and nothing anywhere records that this node's
/// certificate authority says "revoked" while the mesh was never told. That is
/// the precise divergence this hop exists to surface, so the log lives on this
/// side of the channel too.
fn ingest_and_report(
    router: &mut CentralRouter,
    record: &wayfinder::wayfinder_auth::RevocationRecord,
    now: Duration,
    now_unix: u64,
    ack: tokio::sync::oneshot::Sender<Result<(), String>>,
) {
    let outcome = ingest_signed_revocation(router, record, now, now_unix);
    if let Err(reason) = &outcome {
        tracing::error!(
            reason,
            node_mac = ?record.node_mac,
            "revocation signed and durably recorded, but this node could not flood it"
        );
    }
    if ack.send(outcome).is_err() {
        tracing::warn!(
            node_mac = ?record.node_mac,
            "no reader for the revocation verdict; the certificate-authority task is gone"
        );
    }
}

/// Await the next signed revocation from the certificate-authority task, or
/// never resolve when no authority is attached.
///
/// The only edge that runs from the authority into this loop. Safe in that
/// direction: this loop never waits on the authority for an *answer*, so no
/// cycle can form.
async fn recv_revocation(
    rx: &mut Option<wayfinder_server::RevocationRx>,
) -> Option<(
    wayfinder::wayfinder_auth::RevocationRecord,
    tokio::sync::oneshot::Sender<Result<(), String>>,
)> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
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

/// Read the authority's last-published enrollment policy, without waiting.
///
/// `watch::Receiver::borrow` is synchronous and never blocks, which is what
/// makes reporting the authority's policy from this loop safe: the authority may
/// be mid-Argon2id, and asking it would be the stall this design removes.
fn read_enrollment_policy(
    rx: &Option<wayfinder_server::EnrollmentPolicyRx>,
) -> Option<wayfinder_protos::service::EnrollmentPolicyStatusData> {
    rx.as_ref().and_then(|rx| rx.borrow().clone())
}

/// Project the router's current authorization-relevant state — this node's own
/// identity key, trust anchor, and revocations — into an [`AuthSnapshot`] the
/// management server evaluates a connection against.  Anchor and revocations
/// are both empty when auth is disabled (un-enrolled), which the server treats
/// as bootstrap mode.
///
/// Called fresh for every connection (never cached), which is what makes a
/// `SetAuth`-installed identity change take effect immediately: `identity_seed`
/// is read from the same in-memory slot [`Driver::set_identity_seed`] and
/// `SetAuth` both write through, so a seed the node has since rotated away
/// from stops equalling `own_key` on the very next connection rather than only
/// after a restart.
///
/// `own_key` is `None` when no identity seed is configured — a node with no
/// seed has no own key, so the self-key tier is simply unavailable rather than
/// resting on a sentinel value nothing can present. That pairing should be
/// unreachable in production (nothing drives an auth-snapshot request without a
/// TLS listener, and nothing configures a TLS listener without an identity
/// seed), so reaching it still warns: it silently disables the bootstrap grant
/// for this node.
fn build_auth_snapshot(router: &CentralRouter, identity_seed: Option<[u8; 32]>) -> AuthSnapshot {
    let own_key = identity_seed.map(|seed| Keypair::from_seed(&seed).ed_pubkey());
    if own_key.is_none() {
        warn!(
            "auth snapshot requested with no identity seed configured; the self-key tier is unavailable on this node"
        );
    }
    // The node's own mesh address, whether or not it is enrolled: it is what a
    // self-key management connection's VPN credential is minted for, and the
    // transport has no other trustworthy source for it.
    let own_mac = router.self_ident();
    match router.auth() {
        Some(auth) => AuthSnapshot {
            own_key,
            anchor: Some(*auth.anchor()),
            revoked: auth.revoked_macs().collect(),
            own_mac,
        },
        None => AuthSnapshot {
            own_key,
            anchor: None,
            revoked: Vec::new(),
            own_mac,
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
                egress: Egress::Auto,
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
                            egress: Egress::Auto,
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
            egress: Egress::Auto,
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
        // interfaces carry the frame (per-link transmit gates included).
        // `None` means auth is on but this directed frame cannot be tagged —
        // drop it rather than emit it in the clear.
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

#[cfg(test)]
mod tests {
    use super::*;
    // Only to mint a certificate for a `SetAuth`; the driver no longer holds an
    // authority of its own.
    use wayfinder_server::CertAuthority;
    use wayfinder_server::MeshAuthority as _;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A driver with no interfaces at all, for testing what the loop publishes.
    fn idle_driver() -> Driver<NeverIo> {
        let (_query_tx, query_rx) = tokio::sync::mpsc::channel(4);
        Driver::new(
            mac(1),
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        )
    }

    /// The clock an attached authority reads is seeded from `epoch_unix`, not
    /// from zero — before the loop has run a single iteration.
    ///
    /// This is the whole point of the seam. A `CertAuthority` whose `now_unix`
    /// is 0 fails closed on `submit_csr`, `authenticate_user` and `revoke` — so
    /// an authority that read this before the driver's first loop iteration
    /// would refuse every request, and would do it silently while every
    /// router-side test stayed green. Seeded, there is no such window.
    #[test]
    fn an_attached_authority_reads_a_usable_clock_before_the_loop_runs() {
        let mut driver = idle_driver();
        driver.set_epoch_unix(Duration::from_secs(1_700_000_000));

        let (_tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(rx);

        let seeded = ports.facts.borrow().unix_secs;
        assert!(
            seeded >= 1_700_000_000,
            "an authority reading this before the first publish must still see a real time, \
             got {seeded}"
        );
        assert_ne!(seeded, 0, "zero is the fail-closed value, never a seed");
    }

    /// The published clock is `epoch_unix + now` in whole seconds — the same
    /// instant the router verifies certificates against, so an authority
    /// issuing from it cannot drift from the router checking it.
    #[test]
    fn the_published_clock_is_epoch_plus_elapsed() {
        let mut driver = idle_driver();
        let (_tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(rx);

        driver.refresh_auth_clock(Duration::from_secs(42));

        let facts = *ports.facts.borrow();
        assert_eq!(facts.unix_secs, driver.epoch_unix.as_secs() + 42);
        assert!(
            !facts.auth_present,
            "a router with no auth state must say so, or the authority signs a \
             revocation that can never be flooded"
        );
    }

    /// Publishing with no authority attached is not an error: most nodes never
    /// run one, and an authority task that shut down first must not take the
    /// router loop with it.
    #[test]
    fn publishing_survives_having_no_authority_at_all() {
        let mut driver = idle_driver();

        // No `attach_authority`, and then one that is attached and dropped.
        driver.refresh_auth_clock(Duration::from_secs(1));
        let (_tx, rx) = tokio::sync::mpsc::channel(4);
        drop(driver.attach_authority(rx));
        driver.refresh_auth_clock(Duration::from_secs(2));
    }

    /// `own_key` is derived from whatever `identity_seed` this call was given
    /// — the un-enrolled (bootstrap) case, where the router has no auth state
    /// of its own to read an identity from at all.
    #[test]
    fn build_auth_snapshot_reports_own_key_from_the_current_identity_seed() {
        let router = CentralRouter::new(mac(1));
        let seed = [3u8; 32];

        let snapshot = build_auth_snapshot(&router, Some(seed));

        assert_eq!(
            snapshot.own_key,
            Some(Keypair::from_seed(&seed).ed_pubkey())
        );
        assert_eq!(snapshot.anchor, None);
        assert!(snapshot.revoked.is_empty());
    }

    /// The node's own mesh address travels with the snapshot, because the
    /// transport needs it and cannot ask the router directly.
    ///
    /// It is the identity a self-key connection's VPN credential is minted for
    /// (`libs/wayfinder-server/src/transport.rs`). Taken from the router
    /// rather than from the certificate on the connection: the self-key tier
    /// is granted before any certificate is verified, so a MAC read off one
    /// there would be a value the client chose.
    #[test]
    fn build_auth_snapshot_reports_the_routers_own_mac() {
        let router = CentralRouter::new(mac(1));

        let snapshot = build_auth_snapshot(&router, Some([3u8; 32]));

        assert_eq!(snapshot.own_mac, mac(1));
    }

    /// No identity seed configured at all reports no own key, rather than a
    /// sentinel standing in for one.
    ///
    /// The sentinel was the all-zero key, defended as unreachable by any real
    /// handshake key — but all-zeros is a valid Ed25519 encoding of a low-order
    /// point, and the self-key tier is full management access. `None` makes the
    /// question unaskable.
    #[test]
    fn build_auth_snapshot_reports_no_own_key_without_an_identity_seed() {
        let router = CentralRouter::new(mac(1));

        let snapshot = build_auth_snapshot(&router, None);

        assert_eq!(snapshot.own_key, None);
    }

    /// The core property the self-key staleness fix (§3.2) rests on: this
    /// function caches nothing internally, so calling it again with a
    /// *different* seed — exactly what happens on the very next connection
    /// after `SetAuth` writes a new seed into the slot the driver's query
    /// loop reads — reports the new key immediately, and the old seed's key
    /// is nowhere in the result.
    #[test]
    fn build_auth_snapshot_tracks_a_changed_identity_seed_on_the_next_call() {
        let router = CentralRouter::new(mac(1));
        let old_seed = [3u8; 32];
        let new_seed = [4u8; 32];
        let old_key = Keypair::from_seed(&old_seed).ed_pubkey();
        let new_key = Keypair::from_seed(&new_seed).ed_pubkey();

        assert_eq!(
            build_auth_snapshot(&router, Some(old_seed)).own_key,
            Some(old_key)
        );

        let snapshot = build_auth_snapshot(&router, Some(new_seed));
        assert_eq!(snapshot.own_key, Some(new_key));
        assert_ne!(
            snapshot.own_key,
            Some(old_key),
            "a rotated-away-from seed's key must not still be reported as own_key"
        );
    }

    /// A `FrameIo` that never receives anything — enough to construct a real
    /// `Driver` for a test that only exercises the management-query arm.
    #[derive(Clone, Default)]
    struct NeverIo;

    #[cfg_attr(feature = "std", async_trait::async_trait)]
    impl FrameIo for NeverIo {
        async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
            std::future::pending().await
        }
        async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
    }

    /// `process_pending` — the deterministic, non-`run_once` counterpart used
    /// by `LinkTestRouter` and any other synchronous-stepping caller — must
    /// build its management-query adapter with the *same* `epoch_unix` as
    /// `run_once`'s `select!` arm does. `set_auth`'s certificate-validity
    /// check reads it via `RouterAdapter::unix_now`; a `Driver` whose two
    /// query-handling call sites disagree would make a `SetAuth` reachable
    /// from one arm and reject as "not yet valid" from the other despite
    /// identical certificates and identical wall-clock time.
    #[tokio::test]
    async fn process_pending_threads_epoch_unix_into_set_auth_like_run_once_does() {
        use zerocopy::IntoBytes;

        let seed = [3u8; 32];
        let kp = Keypair::from_seed(&seed);
        let mac_addr = mac(1);

        let mut ca = CertAuthority::new(&[9u8; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_700_000_000);
        let cert = match ca
            .submit_csr(mac_addr.as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey(), "")
            .unwrap()
        {
            wayfinder_protos::service::CsrOutcome::Issued(issued) => issued.cert,
            other => panic!("expected the CSR to be issued outright, got {other:?}"),
        };
        let anchor = ca.trust_anchor_bytes();

        let (query_tx, query_rx) = tokio::sync::mpsc::channel(1);
        let mut driver = Driver::new(
            mac_addr,
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );
        driver.set_identity_seed(seed);
        // The same real wall-clock epoch `run_once` would use by default —
        // nowhere near the tiny monotonic `now` this freshly-built `Driver`
        // reports, which is exactly the gap that goes uncaught if
        // `process_pending` forgets to thread it through.
        driver.set_epoch_unix(Duration::from_secs(1_700_000_000));

        let request = wayfinder_protos::wayfinder::v1alpha::WayfinderRequest {
            request: Some(
                wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request::SetAuth(
                    wayfinder_protos::wayfinder::v1alpha::SetAuthRequest {
                        seed: Vec::new(),
                        cert,
                        trust_anchor: anchor,
                    },
                ),
            ),
        };
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        query_tx.send((request, resp_tx)).await.unwrap();

        driver.process_pending().await.unwrap();

        let response = resp_rx.await.unwrap();
        match response.response {
            Some(wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response::Empty(_)) => {}
            other => panic!(
                "expected SetAuth to succeed (a correctly-threaded epoch_unix), got {other:?}"
            ),
        }
        assert!(
            driver.router().auth().is_some(),
            "the certificate was actually installed"
        );
    }

    /// The claim this whole change exists to make: a slow authority request does
    /// not delay a router query.
    ///
    /// Argued in prose everywhere and, until this test, pinned nowhere — which
    /// is the dangerous kind of claim, because the regression that breaks it is
    /// invisible to every other test. Anyone who "simplifies" the enrollment
    /// policy watch into a request, or otherwise makes the router loop `await`
    /// the authority, turns this loop back into one that stalls for ~100 ms of
    /// Argon2id per login while emitting no OGMs. Everything else stays green.
    ///
    /// The authority is occupied with a login for an account that does not
    /// exist, which spends the full `ARGON2_MEMORY_KIB` by design — see
    /// `users.rs`'s `spend_absent_user_work`, whose whole point is that an
    /// unknown username costs what a known one does. That is also precisely the
    /// request an anonymous peer can send, which is why it is the one worth
    /// proving the router survives.
    ///
    /// The assertion is an *ordering*, not a duration: the router's answer must
    /// arrive while the authority's is still outstanding. A wall-clock threshold
    /// would be the flaky way to ask the same question.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_slow_authority_request_does_not_delay_a_router_query() {
        use wayfinder_protos::wayfinder::v1alpha::AuthenticateUserRequest;
        use wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest;
        use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as RespKind;

        let mut ca = CertAuthority::new(&[9u8; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_700_000_000);

        let (query_tx, query_rx) = tokio::sync::mpsc::channel(4);
        let mut driver = Driver::new(
            mac(1),
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );

        let (authority_tx, authority_rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(authority_rx);

        tokio::spawn(wayfinder_server::serve_authority(ca, ports));
        // The driver is not spawned: its link futures are not `Send`, so it is
        // driven in place below, concurrently with awaiting the reply. The
        // authority *is* spawned, which is the concurrency under test.

        // Occupy the authority. Unknown account on purpose: it spends the same
        // memory-hard work a real login does.
        let (authority_reply_tx, mut authority_reply_rx) = tokio::sync::oneshot::channel();
        authority_tx
            .send(wayfinder_server::AuthorityCommand::Request(
                WayfinderRequest {
                    request: Some(ReqKind::AuthenticateUser(AuthenticateUserRequest {
                        username: "nobody".into(),
                        password: "wrong".into(),
                        totp_code: String::new(),
                        ed_pubkey: [1u8; 32].to_vec(),
                        x_pubkey: [2u8; 32].to_vec(),
                    })),
                },
                authority_reply_tx,
            ))
            .await
            .expect("the authority accepts the command");

        // ...and ask the router something while it is busy.
        let (query_reply_tx, query_reply_rx) = tokio::sync::oneshot::channel();
        query_tx
            .send((
                WayfinderRequest {
                    request: Some(ReqKind::GetNodeInfo(GetNodeInfoRequest {})),
                },
                query_reply_tx,
            ))
            .await
            .expect("the router accepts the query");

        // Drive the router loop and await its answer together. If the loop were
        // still serving the authority's request — the arrangement this change
        // removes — this would not resolve until the Argon2id finished.
        let router_response = tokio::select! {
            outcome = driver.run() => panic!("the driver loop exited: {outcome:?}"),
            reply = query_reply_rx => reply.expect("the router answers while the authority works"),
        };
        assert!(
            matches!(router_response.response, Some(RespKind::NodeInfo(_))),
            "the router answered its own query, got {:?}",
            router_response.response
        );

        assert!(
            authority_reply_rx.try_recv().is_err(),
            "the authority was still working when the router answered — if it had already \
             finished, this test proved nothing and needs a slower authority request"
        );
    }
}
