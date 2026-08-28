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

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use futures::FutureExt;
use futures::future::select_all;
use tokio::sync::RwLock;
use tokio::sync::watch;
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
use wayfinder_server::ClockTrust;
use wayfinder_server::QueryRx;
use wayfinder_server::RouterAdapter;
use wayfinder_server::SettingsFile;
use wayfinder_server::SettingsStore;
use wayfinder_server::SharedRouter;

use wayfinder::link::DynLinkT;
use wayfinder::link::LinkT;

use crate::snoop::McastSnooper;
use crate::transport::FrameIo;

/// Where the driver's certificate-validity clock comes from.
///
/// Two variants because production and tests want opposite things from a clock,
/// and the old single mechanism gave production the test's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthClock {
    /// Read the host's wall clock at the moment it is needed, floored by
    /// `MIN_PLAUSIBLE_UNIX`.
    ///
    /// What a real node runs on, and it deliberately **ignores** the loop's
    /// elapsed offset. The previous scheme was `epoch + elapsed` with `epoch`
    /// sampled once in [`Driver::new`], so a node that booted before NTP
    /// reached it captured a wrong epoch and carried it for the rest of its
    /// life: a later `chronyd` step-correct never reached the router, and every
    /// certificate-validity check stayed offset by the original error. A clock
    /// that never consults a stored epoch cannot go stale that way.
    ///
    /// **Deliberately not gated on the NTP verdict.** This clock feeds the
    /// router's own `OgmAuth`, which judges every peer certificate's validity
    /// window against it. Handing it the fail-closed zero would make
    /// `verify_cert` return `NotYetValid` for every certificate ever issued, so
    /// an authenticated mesh would verify no peer and be verified by none —
    /// a total partition, and precisely the self-inflicted outage this feature
    /// exists to avoid. The gate belongs on *credential decisions*
    /// ([`Driver::credential_unix`]), not on the router's view of time.
    Host,
    /// `epoch + the loop's elapsed time`, in unix seconds.
    ///
    /// What a test drives, and why [`Host`](Self::Host) is an added variant
    /// rather than a replacement: pinning the epoch and stepping the loop's
    /// `now` is how the suite exercises certificate expiry faster than real
    /// time. Set by [`Driver::set_epoch_unix`].
    Epoch(u64),
}

impl AuthClock {
    /// The certificate-validity time to install, given how long the loop has
    /// been running.
    ///
    /// `elapsed` is consulted only by [`Epoch`](Self::Epoch) — see its and
    /// [`Host`](Self::Host)'s doc comments for why that asymmetry is the point.
    fn now_unix(self, elapsed: Duration) -> u64 {
        match self {
            Self::Epoch(epoch) => epoch.saturating_add(elapsed.as_secs()),
            // One shared definition of "plausible" with the authority's
            // `Clock::System`, rather than a second host-clock read here with a
            // different floor.
            Self::Host => wayfinder_server::host_unix_now(),
        }
    }
}

/// How often the host's NTP status word is re-read.
///
/// `refresh_auth_clock` runs on every frame, and `ntp_adjtime` is a syscall —
/// consulting it per frame would put a syscall on the data path to answer a
/// question whose answer changes on the order of minutes. Ten seconds is far
/// below any credential lifetime and far above the frame rate.
const CLOCK_RECHECK_INTERVAL: Duration = Duration::from_secs(10);

/// The certificate-validity time at loop instant `now`, expressed as the offset
/// [`RouterAdapter::with_epoch_unix`] wants — it adds the loop's `now` back on,
/// so what it needs is `absolute - now`.
///
/// The adapter's `epoch + now` shape predates the clock being read live and is
/// still right *for the adapter*, whose metrics are all stamped at one `now`;
/// only the source of the absolute time changed.
///
/// A free function rather than a method so it can be called while the router is
/// borrowed mutably out of the same struct.
/// The time a **credential decision** may be made against: the host clock, or
/// zero — the sentinel every credential path refuses on — while `trusted` is
/// false.
///
/// Distinct from [`AuthClock::now_unix`], which is the router's own view of
/// time and is deliberately never gated. See [`AuthClock::Host`] for why gating
/// that one partitions an authenticated mesh.
fn credential_unix(clock: AuthClock, trusted: bool, now: Duration) -> u64 {
    if trusted { clock.now_unix(now) } else { 0 }
}

fn epoch_offset(clock: AuthClock, trusted: bool, now: Duration) -> Duration {
    if !trusted {
        // Fail closed, deliberately. The adapter recovers `epoch + now`, so a
        // zero offset makes its `unix_now()` the loop's monotonic `now` — a few
        // seconds past 1970, which precedes every real certificate's
        // `not_before`, so a `SetAuth` install is refused as not-yet-valid.
        // There is no offset that recovers an exact zero, so this is the
        // fail-closed value rather than the sentinel itself; do not "fix" the
        // saturation below into something that produces a plausible time.
        return Duration::ZERO;
    }
    Duration::from_secs(credential_unix(clock, trusted, now)).saturating_sub(now)
}

/// Whether the host clock is currently trusted, from the driver's cached
/// verdict — the same answer its auth clock acted on, which is the point.
///
/// `true` before the first check has happened, and for an [`AuthClock::Epoch`],
/// which is a value its caller chose rather than a host reading. In practice
/// the cache is always populated by the time a management query is served:
/// `refresh_auth_clock` runs ahead of every request-handling path.
///
/// A free function for the same reason [`epoch_offset`] is — it is called while
/// the router is borrowed mutably out of the same struct.
fn clock_trusted(clock: AuthClock, checked: Option<(bool, Duration)>) -> bool {
    match clock {
        AuthClock::Epoch(_) => true,
        // `false` until the first check, not `true`: this field's whole job is
        // to not overstate the node's posture, and "we have not established
        // trust yet" is honestly reported as untrusted. Every path that serves
        // a management query calls `refresh_auth_clock` first, so in practice
        // the cache is already populated — but that is an ordering convention,
        // and guessing `true` when it is broken is the one answer this field
        // must never give.
        AuthClock::Host => checked.is_some_and(|(trusted, _)| trusted),
    }
}

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
    /// The routing engine for this node, and the identity seed beside it,
    /// behind the lock the management reads share.
    ///
    /// Behind a lock rather than owned outright because sixteen of the
    /// nineteen management answers only *read* it, and serving those on this
    /// loop meant a dashboard's poll built its response `Vec`s between mesh
    /// frames. This loop takes the write guard — in short scopes, never across
    /// a link send — and a connection task reads through a
    /// [`RouterHandle`](wayfinder_server::RouterHandle).
    shared: Arc<RwLock<SharedRouter>>,
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
    /// Where certificate-validity time comes from.
    ///
    /// Defaults to [`AuthClock::Host`], which reads the wall clock live. A test
    /// swaps in [`AuthClock::Epoch`] via
    /// [`set_epoch_unix`](Self::set_epoch_unix) to drive expiry
    /// deterministically.
    clock: AuthClock,
    /// Whether the host's clock is disciplined enough to make a *credential*
    /// decision against — separate from [`clock`](Self::clock), which is where
    /// time comes from. Kept apart because the two questions have different
    /// answers and different blast radii: an undisciplined clock must not stop
    /// the router judging routes, but must stop it installing a certificate.
    clock_trust: ClockTrust,
    /// The last NTP verdict and the loop instant it was taken at, so the status
    /// word is read on [`CLOCK_RECHECK_INTERVAL`] rather than once per frame.
    /// `None` until the first check.
    clock_checked: Option<(bool, Duration)>,
    /// The verdict above, republished for the management *reads* that no longer
    /// run on this loop.
    ///
    /// `GetNodeInfo` reports `clock_trusted`, and it is a `RouterRead` — so on a
    /// node with a [`RouterHandle`](wayfinder_server::RouterHandle) wired it is
    /// answered on a connection task that cannot see these fields at all. A
    /// `watch` for the same reason the enrollment policy is one: the reader must
    /// never await this loop, and this loop must never await the reader.
    ///
    /// Publishing it rather than recomputing it on the read side is the point.
    /// The posture a client is shown has to be the one the driver's auth clock
    /// actually acted on; two implementations of "is the clock trusted" is
    /// precisely how those drift apart without anything failing.
    clock_trusted_tx: watch::Sender<bool>,
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
        // Gated on the host's NTP verdict by default: a node whose clock
        // nothing is disciplining reports zero rather than a plausible wrong
        // time, and every certificate-validity check refuses on that sentinel.
        // `wayfinder-tap` overrides the policy from config.
        let clock = AuthClock::Host;
        let clock_trust = ClockTrust::default();
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
            shared: Arc::new(RwLock::new(SharedRouter::new(router))),
            query_rx,
            mac,
            snooper: McastSnooper::new(),
            start: Instant::now(),
            clock,
            clock_trust,
            clock_checked: None,
            // `false`, not `true`: no check has happened yet, and this field's
            // whole job is to not overstate the node's posture. The first
            // `refresh_auth_clock` — which runs ahead of every path that serves
            // a request — replaces it with a real verdict.
            clock_trusted_tx: watch::Sender::new(false),
            authority: wayfinder_server::AuthorityComms::new(clock.now_unix(Duration::ZERO)),
            rx_buffer: [0u8; MAX_LINK_FRAME_LEN],
            tx_buffer: [0u8; MAX_LINK_FRAME_LEN],
            settings: None,
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
    pub async fn set_identity_seed(&mut self, seed: [u8; 32]) {
        self.shared.write().await.identity_seed = Some(seed);
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
        self.clock = AuthClock::Epoch(epoch_unix.as_secs());
        self.clock_checked = None;
        self.publish_clock_trust();
        // Re-seed, or a subscriber that reads before the next loop iteration
        // sees the wall-clock seed this driver was built with rather than the
        // virtual epoch a test just set.
        self.authority
            .set_clock(self.clock.now_unix(self.start.elapsed()));
    }

    /// Choose where certificate-validity time comes from.
    ///
    /// `wayfinder-tap` calls this to apply the operator's `require_time_sync` /
    /// `max_clock_error_us` settings; everything else wants the default.
    pub fn set_clock_trust(&mut self, trust: ClockTrust) {
        self.clock_trust = trust;
        // A cached verdict was taken under the old policy and says nothing
        // about the new one.
        self.clock_checked = None;
        self.publish_clock_trust();
    }

    /// What the host says about this node's clock, for the alarm and the
    /// operator-facing projection.
    #[must_use]
    pub fn clock_sync(&self) -> wayfinder_server::ClockSync {
        match self.clock {
            AuthClock::Host => wayfinder_server::clock_sync(self.clock_trust),
            // A pinned epoch is a value its caller chose; there is nothing to
            // ask the host about.
            AuthClock::Epoch(_) => wayfinder_server::ClockSync::Unsupported,
        }
    }

    /// Refresh the cached NTP verdict, at most once per
    /// [`CLOCK_RECHECK_INTERVAL`], and report whether the clock is trusted.
    ///
    /// The verdict is cached because this runs once per turn of the driver loop
    /// — so on a busy node, per frame — and `ntp_adjtime` is a real syscall,
    /// unlike the vDSO wall-clock read beside it. Its answer changes on the
    /// order of minutes.
    ///
    /// Each refresh that finds the clock untrusted raises an alarm. The board
    /// coalesces it into one latched row, so a node that has been
    /// unsynchronised for an hour reports one condition rather than a flood.
    fn refresh_clock_trust(&mut self, now: Duration) -> bool {
        if let AuthClock::Epoch(_) = self.clock {
            // A pinned epoch is a value its caller chose; there is no host
            // verdict to seek and nothing to warn about.
            return true;
        }
        if let Some((trusted, at)) = self.clock_checked
            && now.saturating_sub(at) < CLOCK_RECHECK_INTERVAL
        {
            return trusted;
        }
        let sync = wayfinder_server::clock_sync(self.clock_trust);
        self.clock_checked = Some((sync.is_trusted(), now));
        if !sync.is_trusted() {
            wayfinder_alarm::alarm!(
                wayfinder_alarm::Severity::Warning,
                wayfinder_alarm::AlarmKind::ClockUnsynchronized,
                wayfinder_alarm::Subject::None,
                "state={}",
                sync.name()
            );
        }
        sync.is_trusted()
    }

    /// Republish the clock-trust verdict for readers off this loop.
    ///
    /// Goes through the same [`clock_trusted`] free function the on-loop adapter
    /// uses, so the two paths cannot answer the same question differently.
    fn publish_clock_trust(&self) {
        self.clock_trusted_tx
            .send_replace(clock_trusted(self.clock, self.clock_checked));
    }

    /// Advance the certificate-validity clock to the current auth time and
    /// republish this node's auth-present state for the certificate authority.
    ///
    /// Called from every entry point that processes frames, so cert expiry
    /// tracks the loop's `now` consistently. Only the router's own `set_time` is
    /// skipped when auth is disabled — both publications happen either way, and
    /// the auth-disabled case is precisely the one the authority needs told.
    async fn refresh_auth_clock(&mut self, now: Duration) {
        // Refresh the verdict for the alarm and the reported status, but do
        // *not* let it gate the value: the router judges every peer
        // certificate's validity window against this clock, and handing it the
        // fail-closed zero would reject every certificate ever issued. See
        // `AuthClock::Host`.
        //
        // Ahead of the guard below, deliberately: this reads the host's NTP
        // status and touches no router state, so there is no reason for it to
        // happen with every management read excluded.
        self.refresh_clock_trust(now);
        self.publish_clock_trust();
        let unix = Duration::from_secs(self.clock.now_unix(now));
        // A short write guard: setting the clock is a field store, and holding
        // the lock any longer than this would stall every management read for
        // no reason.
        let auth_present = match self.shared.write().await.router.auth_mut() {
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

    /// Read the router under the shared lock.
    ///
    /// A scoped callback rather than a returned guard, so a caller cannot hold
    /// the lock across an `await` it did not think about — which on this type
    /// means stalling the mesh, since the event loop needs the write half for
    /// every frame it forwards.
    pub async fn with_router<R>(&self, f: impl FnOnce(&CentralRouter) -> R) -> R {
        f(&self.shared.read().await.router)
    }

    /// Mutate the router under the shared lock — lets callers inject crafted
    /// frames with explicit link metrics that the message-oriented transports
    /// cannot carry.
    ///
    /// Scoped for the same reason as [`with_router`](Self::with_router), and
    /// more so: this takes the write half, which excludes every reader.
    pub async fn with_router_mut<R>(&self, f: impl FnOnce(&mut CentralRouter) -> R) -> R {
        f(&mut self.shared.write().await.router)
    }

    /// A handle the management transport serves its *reads* through, so they
    /// run on the connection's own task rather than on this loop.
    ///
    /// Read-only by construction: [`RouterHandle`](wayfinder_server::RouterHandle)
    /// exposes no way to take the write guard, so wiring one up cannot move a
    /// mutation off this loop by accident.
    pub fn router_handle(&self) -> wayfinder_server::RouterHandle {
        wayfinder_server::RouterHandle::new(Arc::clone(&self.shared), self.start)
            .with_enrollment_policy(Some(self.authority.enrollment_policy_rx()))
            .with_clock_trust(Some(self.clock_trusted_tx.subscribe()))
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
        self.refresh_auth_clock(now).await;

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
        let next_due = {
            // A *read* guard, and dropped before the `select!`: holding it
            // across the sleep would block every management read for as long as
            // the mesh is quiet, which on a settled network is minutes.
            let guard = self.shared.read().await;
            guard
                .router
                .next_broadcast_after(now)
                .min(guard.router.next_keepalive_after(now))
                .min(
                    guard
                        .router
                        .next_challenge_after(now)
                        .unwrap_or(Duration::MAX),
                )
        };

        // Cloned before the destructure below, which borrows `self`: an `Arc`
        // clone is two atomics, and it keeps the shared router reachable from
        // inside the `select!` arms without entangling it in those borrows.
        //
        // Deliberately *not* locked here. Every arm takes its own guard in its
        // own body, so the lock is never held across the `select!` itself —
        // which waits, often for the whole of `next_due`.
        let shared = Arc::clone(&self.shared);
        // Destructure into disjoint field borrows so the `select!` can hold a
        // mutable borrow of the interfaces alongside the buffers.
        let Driver {
            local,
            interfaces,
            shared: _,
            query_rx,
            mac,
            snooper,
            start,
            clock,
            clock_trust: _,
            clock_checked,
            // Published by `refresh_auth_clock`, which has already run for this
            // turn of the loop; no arm below republishes.
            clock_trusted_tx: _,
            rx_buffer,
            tx_buffer,
            settings,
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
                        now, &mut shared.write().await.router, idx, result, tx_buffer, &mut out,
                    );
                    (now, out)
                },
                Ok(len) = local.recv(rx_buffer), if check_local => {
                    trace!(len, "host device rx frame");
                    let eth = &rx_buffer[..len];
                    (now, LoopOutput {
                        mesh: plan_host_frame(
                            now, &mut shared.write().await.router, snooper, eth, tx_buffer,
                        ),
                        local: None,
                    })
                },
                Some((request, resp_tx)) = query_rx.recv(), if check_server => {
                    // Still served here, and still under the write guard. Reads
                    // reaching this arm are the ones from a transport with no
                    // `RouterHandle` wired (the in-process channel server);
                    // everything else arriving here is a mutation, which has to
                    // be on this task because `set_auth` writes back through the
                    // identity-seed slot beside the router.
                    //
                    // The clock verdict is resolved before the guard is taken:
                    // both are `Copy` fields of this struct rather than router
                    // state, so reading them under the write guard would widen
                    // its scope for nothing.
                    let clock_trusted = clock_trusted(*clock, *clock_checked);
                    let epoch_offset = epoch_offset(*clock, clock_trusted, now);
                    let mut guard = shared.write().await;
                    let SharedRouter { router, identity_seed } = &mut *guard;
                    let mut adapter = RouterAdapter::new(router, now)
                        .with_epoch_unix(epoch_offset)
                        .with_clock_trusted(clock_trusted)
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
                    // announced rather than only that it was recorded — short
                    // of this loop itself being torn down between the receive
                    // and the write guard below, which drops the ack with the
                    // process. Only `run_until_shutdown` cancels `run_once`,
                    // and every arm of it ends the process, so that window is
                    // not reachable in a running node.
                    ingest_and_report(
                        &mut shared.write().await.router,
                        &record,
                        now,
                        clock.now_unix(now),
                        ack,
                    );
                    (now, LoopOutput::none())
                },
                Some(reply) = recv_auth_snapshot(auth_snapshot_rx), if check_server => {
                    // A *read* guard: projecting the snapshot mutates nothing,
                    // so this does not have to exclude the management reads.
                    let guard = shared.read().await;
                    let _ = reply.send(build_auth_snapshot(&guard.router, guard.identity_seed));
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
                    let mut guard = shared.write().await;
                    let router = &mut guard.router;
                    wayfinder_driver_core::poll_due_ogms(router, now, tx_buffer, &mut out);
                    wayfinder_driver_core::poll_due_keepalives(router, now, tx_buffer, &mut out);
                    wayfinder_driver_core::poll_due_challenges(router, now, tx_buffer, &mut out);
                    drop(guard);
                    (now, out)
                }
            }
        };

        dispatch(local, interfaces, &shared, mac, now, output).await
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
            &mut self.shared.write().await.router,
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
        self.refresh_auth_clock(now).await;
        let mesh = poll_due_ogms(
            &mut self.shared.write().await.router,
            now,
            &mut self.tx_buffer,
        );
        let output = LoopOutput { mesh, local: None };
        dispatch(
            &self.local,
            &mut self.interfaces,
            &self.shared,
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
        self.refresh_auth_clock(now).await;
        let mesh = poll_due_keepalives(
            &mut self.shared.write().await.router,
            now,
            &mut self.tx_buffer,
        );
        let output = LoopOutput { mesh, local: None };
        dispatch(
            &self.local,
            &mut self.interfaces,
            &self.shared,
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
        self.refresh_auth_clock(self.start.elapsed()).await;
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
                    &mut self.shared.write().await.router,
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
                    &mut self.shared.write().await.router,
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
                let clock_trusted = clock_trusted(self.clock, self.clock_checked);
                let epoch_offset = epoch_offset(self.clock, clock_trusted, now);
                let mut guard = self.shared.write().await;
                let SharedRouter {
                    router,
                    identity_seed,
                } = &mut *guard;
                let mut adapter = RouterAdapter::new(router, now)
                    .with_epoch_unix(epoch_offset)
                    .with_clock_trusted(clock_trusted)
                    .with_identity(identity_seed)
                    .with_enrollment_policy(policy);
                if let Some(store) = self.settings.as_mut() {
                    adapter = adapter.with_settings(store as &mut dyn SettingsStore);
                }
                // See the same fallback in `run_once`: `handle_unowned` names the
                // transport-owned kind rather than misreporting the node's role.
                let response = handle_router(&mut adapter, request).unwrap_or_else(handle_unowned);
                drop(guard);
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
                let now_unix = self.clock.now_unix(now);
                ingest_and_report(
                    &mut self.shared.write().await.router,
                    &record,
                    now,
                    now_unix,
                    ack,
                );
            }

            // Authorization-state snapshot requests from the TLS management server.
            if let Some(rx) = self.auth_snapshot_rx.as_mut()
                && let Ok(reply) = rx.try_recv()
            {
                progressed = true;
                let guard = self.shared.read().await;
                let snapshot = build_auth_snapshot(&guard.router, guard.identity_seed);
                drop(guard);
                let _ = reply.send(snapshot);
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
            &self.shared,
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
    // Already-known is the one benign `false` left. It verified above, so this
    // exact record is in the store and was flooded when it first arrived: the
    // operator's intent holds, even though this request re-floods nothing.
    //
    // Matched on the whole record rather than on the MAC. `revoked_macs()`
    // would also match a *stale* record for the same MAC — one the authority
    // has since superseded, naming a node it re-admitted in between — and
    // report success for a purge this node never recorded and never flooded.
    if router.auth().is_some_and(|auth| {
        auth.revocations()
            .any(|r| r.node_mac == record.node_mac && r.not_before.get() == record.not_before.get())
    }) {
        return Ok(());
    }
    // The remaining `false` from `ingest_revocation`: the record names this
    // node, which never floods its own revocation — peers enforce it against
    // us. Still a failure to *flood*, which is what the authority asked for
    // and what this reports.
    Err(
        "it names this node, which never floods its own revocation; no peer will \
         learn of the revocation from here"
            .to_string(),
    )
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
    tx: &wayfinder_server::EnrollmentPolicyTx,
) -> Option<wayfinder_protos::service::EnrollmentPolicyStatusData> {
    tx.borrow().clone()
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
            revoked: auth.revocations().copied().collect(),
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
    shared: &RwLock<SharedRouter>,
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
        // Planning needs the router; sending does not. The guard is scoped to
        // the plan and dropped before any link I/O, because a link send is a
        // radio transmission — holding the write lock across one would block
        // every management read for the length of a LoRa frame.
        //
        // `DispatchPlan` borrows the payload buffer, not the router, which is
        // what makes dropping the guard here sound.
        //
        // The visible consequence: between this plan and the `record_tx` below,
        // a concurrent `GetThroughput` sees a router that has planned a
        // transmission but not yet counted its bytes, so tx rate under-reports
        // by up to one frame for the length of the send. Accepted — the rate is
        // a decaying EWMA and the next sample corrects it — and strictly better
        // than the alternative, which is holding the lock across the radio.
        let plan = {
            let mut guard = shared.write().await;
            wayfinder_driver_core::plan_dispatch(
                &mut guard.router,
                now,
                dst,
                protocol,
                egress,
                body_len,
                &mut payload,
                num_interfaces,
            )
        };
        let Some(plan) = plan else {
            continue;
        };

        let data = LinkFrameData {
            dst,
            protocol,
            payload: plan.payload(),
        };

        // Collected rather than recorded as they go, so the lock is taken once
        // per frame instead of once per interface — and, more importantly, only
        // after every send has finished.
        let mut sent = Vec::new();
        for idx in plan.targets().iter() {
            if let Some(iface) = interfaces.get_mut(idx)
                && let Some(bytes) = send_on_link(iface, idx, mac, &data).await
            {
                sent.push((idx, bytes));
            }
        }
        if !sent.is_empty() {
            let mut guard = shared.write().await;
            for (idx, bytes) in sent {
                guard.router.record_tx(idx, bytes, now);
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
    mac: Mac,
    data: &LinkFrameData<'_>,
) -> Option<usize> {
    match iface.send(mac, data).await {
        // Returned rather than recorded here: the caller holds no router lock
        // while this runs, and taking one inside a send loop is exactly what
        // this signature exists to prevent.
        Ok(sent) => Some(sent),
        Err(e) => {
            warn!(iface_idx, error = ?e, "link send failed; frame dropped");
            None
        }
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

    /// The production auth clock reads the host at the moment it is asked, and
    /// ignores the loop's elapsed offset entirely.
    ///
    /// That indifference *is* the fix. The old clock was `epoch + elapsed` with
    /// `epoch` sampled once in `Driver::new`, so a node that booted before NTP
    /// reached it captured a wrong epoch and carried it for the rest of its
    /// life — a later `chronyd` step-correct never reached the router, and
    /// every certificate-validity check stayed offset by the original error. A
    /// clock that ignores the offset cannot go stale that way.
    #[test]
    fn a_host_auth_clock_ignores_the_loop_offset() {
        let clock = AuthClock::Host;
        let host_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the test host's clock is after the epoch")
            .as_secs();

        let fresh = clock.now_unix(Duration::ZERO);
        let after_an_hour = clock.now_unix(Duration::from_secs(3_600));
        assert_eq!(
            fresh, after_an_hour,
            "a host clock must not drift with how long the loop has been running"
        );
        assert!(fresh.abs_diff(host_now) <= 5, "and it is the host's time");
    }

    /// An undisciplined clock must NOT gate the router's own view of time.
    ///
    /// This is the scope boundary, and getting it wrong partitions the mesh.
    /// The router judges every peer certificate's validity window against this
    /// clock; hand it the fail-closed zero and `verify_cert` returns
    /// `NotYetValid` for every certificate ever issued, so an authenticated
    /// node verifies no peer and is verified by none. An earlier revision of
    /// this branch did exactly that while five operator-facing strings promised
    /// "routing is unaffected".
    #[tokio::test]
    async fn an_untrusted_clock_does_not_gate_the_routers_view_of_time() {
        let mut driver = idle_driver();
        let (_tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(rx);
        driver.set_clock_trust(ClockTrust::Never);

        driver.refresh_auth_clock(Duration::ZERO).await;

        let host_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the test host's clock is after the epoch")
            .as_secs();
        let published = ports.facts.borrow().unix_secs;
        assert!(
            published.abs_diff(host_now) <= 5,
            "the router keeps a usable clock even while credentials are refused: \
             got {published}, host says {host_now}"
        );
    }

    /// ...while a *credential* decision made at the same instant is refused.
    ///
    /// The other half of the boundary: the gate did not simply disappear, it
    /// moved to the decisions that can afford to fail closed.
    #[test]
    fn an_untrusted_clock_does_gate_a_credential_decision() {
        let mut driver = idle_driver();
        driver.set_clock_trust(ClockTrust::Never);

        let trusted = driver.refresh_clock_trust(Duration::ZERO);
        assert_eq!(
            credential_unix(driver.clock, trusted, Duration::ZERO),
            0,
            "a credential decision has no usable time while the clock is untrusted"
        );

        driver.set_clock_trust(ClockTrust::Assume);
        let trusted = driver.refresh_clock_trust(Duration::ZERO);
        assert!(
            credential_unix(driver.clock, trusted, Duration::ZERO) > 1_700_000_000,
            "and it recovers as soon as the clock is trusted again"
        );
    }

    /// The reported status is `false` before the first check rather than `true`.
    ///
    /// A status field about a security posture must never overstate it; "not
    /// yet established" is honestly untrusted.
    #[test]
    fn the_reported_clock_status_does_not_guess_before_the_first_check() {
        assert!(!clock_trusted(AuthClock::Host, None));
        assert!(clock_trusted(AuthClock::Epoch(1_000), None));
    }

    /// The cached verdict expires, so a clock that becomes good is picked up.
    ///
    /// Without this the MR would reintroduce its own bug one layer up: a node
    /// that captured "untrusted" and never re-read would refuse credentials
    /// forever after chronyd arrived.
    #[test]
    fn the_clock_verdict_cache_expires() {
        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::default());
        wayfinder_alarm::with_board(&board, || {
            let mut driver = idle_driver();
            driver.set_clock_trust(ClockTrust::Never);

            driver.refresh_clock_trust(Duration::ZERO);
            driver.refresh_clock_trust(Duration::from_secs(5));
            assert_eq!(
                board.snapshot_at(0).alarms[0].count,
                1,
                "inside the interval the cached verdict is reused, no syscall"
            );

            driver.refresh_clock_trust(CLOCK_RECHECK_INTERVAL);
            assert_eq!(
                board.snapshot_at(0).alarms[0].count,
                2,
                "past the interval the verdict is re-read"
            );
        });
    }

    /// Changing the policy invalidates the cached verdict immediately, rather
    /// than leaving the old answer standing for up to a recheck interval.
    #[test]
    fn changing_the_policy_invalidates_the_cached_verdict() {
        let mut driver = idle_driver();
        driver.set_clock_trust(ClockTrust::Never);
        let trusted = driver.refresh_clock_trust(Duration::ZERO);
        assert_eq!(credential_unix(driver.clock, trusted, Duration::ZERO), 0);

        driver.set_clock_trust(ClockTrust::Assume);
        let trusted = driver.refresh_clock_trust(Duration::ZERO);
        assert!(
            credential_unix(driver.clock, trusted, Duration::ZERO) > 1_700_000_000,
            "a stale 'untrusted' must not outlive the policy that produced it"
        );
    }

    /// An untrusted clock raises the alarm, on the board a `GetAlarms` reads.
    ///
    /// The link this whole feature turns on: routing stays up and the node
    /// looks healthy, so without a raised condition an operator sees only
    /// enrollment and logins failing for no stated reason. Scoped to a local
    /// board so the assertion does not depend on what else ran in this process.
    #[test]
    fn an_untrusted_clock_raises_an_alarm_an_operator_can_read() {
        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::default());
        wayfinder_alarm::with_board(&board, || {
            let mut driver = idle_driver();
            driver.set_clock_trust(ClockTrust::Never);

            // Driven to completion inside the board scope, which is a
            // thread-local around a synchronous closure. `refresh_auth_clock`
            // only awaits an uncontended lock here, and a `#[tokio::test]`
            // could not hold the scope across the await anyway.
            futures::executor::block_on(driver.refresh_auth_clock(Duration::ZERO));

            let raised = board.snapshot_at(0);
            assert!(
                raised
                    .alarms
                    .iter()
                    .any(|a| a.kind == wayfinder_alarm::AlarmKind::ClockUnsynchronized),
                "an untrusted clock must be reported, not merely acted on: {:?}",
                raised.alarms.iter().map(|a| a.kind).collect::<Vec<_>>()
            );
        });
    }

    /// A trusted clock raises nothing. Pinned because an alarm that is always
    /// present is an alarm nobody reads.
    #[test]
    fn a_trusted_clock_raises_nothing() {
        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::default());
        wayfinder_alarm::with_board(&board, || {
            let mut driver = idle_driver();
            driver.set_clock_trust(ClockTrust::Assume);

            // Driven to completion inside the board scope, which is a
            // thread-local around a synchronous closure. `refresh_auth_clock`
            // only awaits an uncontended lock here, and a `#[tokio::test]`
            // could not hold the scope across the await anyway.
            futures::executor::block_on(driver.refresh_auth_clock(Duration::ZERO));

            assert!(board.snapshot_at(0).alarms.is_empty());
        });
    }

    /// The epoch clock still advances with the loop, so a test can drive
    /// certificate expiry forward faster than real time. Preserving this is why
    /// the production clock is a separate variant rather than a replacement.
    #[test]
    fn an_epoch_auth_clock_advances_with_the_loop() {
        let clock = AuthClock::Epoch(1_000);
        assert_eq!(clock.now_unix(Duration::ZERO), 1_000);
        assert_eq!(clock.now_unix(Duration::from_secs(500)), 1_500);
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

    /// The published clock is whatever the driver's own clock says — the same
    /// instant the router verifies certificates against, so an authority
    /// issuing from it cannot drift from the router checking it.
    ///
    /// Pinned on an epoch clock so the assertion is arithmetic rather than a
    /// read of the build machine's wall clock; the production `Host` variant is
    /// covered by `a_host_auth_clock_ignores_the_loop_offset`.
    #[tokio::test]
    async fn the_published_clock_is_epoch_plus_elapsed() {
        let mut driver = idle_driver();
        let (_tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(rx);
        driver.set_epoch_unix(Duration::from_secs(1_700_000_000));

        driver.refresh_auth_clock(Duration::from_secs(42)).await;

        let facts = *ports.facts.borrow();
        assert_eq!(facts.unix_secs, 1_700_000_000 + 42);
        assert!(
            !facts.auth_present,
            "a router with no auth state must say so, or the authority signs a \
             revocation that can never be flooded"
        );
    }

    /// Publishing with no authority attached is not an error: most nodes never
    /// run one, and an authority task that shut down first must not take the
    /// router loop with it.
    #[tokio::test]
    async fn publishing_survives_having_no_authority_at_all() {
        let mut driver = idle_driver();

        // No `attach_authority`, and then one that is attached and dropped.
        driver.refresh_auth_clock(Duration::from_secs(1)).await;
        let (_tx, rx) = tokio::sync::mpsc::channel(4);
        drop(driver.attach_authority(rx));
        driver.refresh_auth_clock(Duration::from_secs(2)).await;
    }

    /// The clock-trust posture a client is shown comes from the driver's own
    /// verdict, even when the read is served off the loop entirely.
    ///
    /// `GetNodeInfo` reports `clock_trusted` and is a `RouterRead`, so on a node
    /// with a `RouterHandle` wired it is answered on a connection task that
    /// cannot see the driver's clock fields at all. Nothing fails if that
    /// posture is never plumbed through: the read still succeeds, and reports
    /// `RouterView`'s default of "trusted" — a node refusing every credential
    /// operation while its dashboard says the clock is fine. That is the exact
    /// failure `RouterReads::clock_trusted`'s doc comment refuses to let a
    /// defaulted trait method cause, restated for the second read path.
    ///
    /// Handle taken *before* the policy is set, for the same reason
    /// `a_handle_taken_before_attach_still_sees_the_policy` does it: a handle
    /// that captured a value rather than a receiver passes the other order.
    #[tokio::test]
    async fn a_handle_served_read_reports_the_drivers_clock_verdict() {
        let mut driver = idle_driver();
        let handle = driver.router_handle();
        driver.set_clock_trust(ClockTrust::Never);

        // What the loop does every turn, and what publishes the verdict.
        driver.refresh_auth_clock(Duration::ZERO).await;

        assert!(
            !handle_says_clock_trusted(&handle).await,
            "a node refusing every credential operation reported a trusted clock \
             on the read path"
        );

        // And the other way, so the assertion above is not passing on a
        // constant: the same handle follows the driver's verdict when it changes.
        driver.set_clock_trust(ClockTrust::Assume);
        driver.refresh_auth_clock(Duration::ZERO).await;
        assert!(handle_says_clock_trusted(&handle).await);
    }

    /// `clock_trusted` as a `GetNodeInfo` served through `handle` reports it.
    async fn handle_says_clock_trusted(handle: &wayfinder_server::RouterHandle) -> bool {
        let response = handle
            .serve_read(wayfinder_protos::wayfinder::v1alpha::WayfinderRequest {
                request: Some(
                    wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request::GetNodeInfo(
                        wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest {},
                    ),
                ),
            })
            .await
            .expect("GetNodeInfo is a router read");
        match response.response {
            Some(wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response::NodeInfo(
                info,
            )) => info.clock_trusted,
            other => panic!("expected NodeInfo, got {other:?}"),
        }
    }

    /// A `RouterHandle` taken *before* the authority attaches still observes the
    /// policy that authority publishes afterwards.
    ///
    /// The receiver used to be captured by value from an `Option` that `attach`
    /// filled in, so a handle built first captured `None` and reported "no
    /// enrollment policy" for the life of the process — on a certificate
    /// authority, which is the one node that has one. Nothing failed; the same
    /// request forwarded to the loop answered correctly, so the two paths
    /// disagreed silently about a security posture a dashboard renders.
    ///
    /// `wayfinder-tap` happens to attach first today. This pins the property
    /// rather than the call order, because the call order is one refactor from
    /// changing and `router_handle()` only needs `&self`.
    #[tokio::test]
    async fn a_handle_taken_before_attach_still_sees_the_policy() {
        let mut driver = idle_driver();

        // Deliberately the wrong order: handle first, authority second.
        let handle = driver.router_handle();

        let (_tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(rx);
        ports.policy.send_replace(Some(
            wayfinder_protos::service::EnrollmentPolicyStatusData {
                auto_approve: true,
                ..Default::default()
            },
        ));

        let response = handle
            .serve_read(wayfinder_protos::wayfinder::v1alpha::WayfinderRequest {
                request: Some(
                    wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request::GetSecurityStatus(
                        wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusRequest {},
                    ),
                ),
            })
            .await
            .expect("GetSecurityStatus is a router read");

        match response.response {
            Some(
                wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response::SecurityStatus(
                    status,
                ),
            ) => assert!(
                status.enrollment.is_some(),
                "a handle built before attach_authority reported no enrollment policy"
            ),
            other => panic!("expected SecurityStatus, got {other:?}"),
        }
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
        driver.set_identity_seed(seed).await;
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
            driver.with_router(|r| r.auth().is_some()).await,
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
