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

use crate::renew::CertCondition;
use crate::renew::RENEWAL_ATTEMPT_TIMEOUT;
use crate::renew::RenewalGate;
use crate::renew::Renewed;
use futures::FutureExt;
use futures::future::select_all;
use tokio::sync::RwLock;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use wayfinder::CentralRouter;
use wayfinder::McastPlan;
use wayfinder::auth::MAX_TRAILER_LEN;
use wayfinder::config::TrickleConfig;
use wayfinder::features::LinkFeatures;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN;
use wayfinder::interfaces::frame::Mac;
use wayfinder::router_ops::OgmAuthOps;
use wayfinder::router_ops::RouterOps;
use wayfinder::wayfinder_auth::Keypair;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::MeshSink;
use wayfinder_protos::service::RenewalProviderData;
use wayfinder_protos::service::RouterWrites;
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
use core::num::NonZeroU8;
use interfaces::engine::FrameSink;

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
    /// **Deliberately not gated on the NTP verdict**, though no longer for the
    /// reason it once was. Under design 20 §4.2 a gated reading would hand the
    /// router [`Clocked::Unknown`](wayfinder::wayfinder_auth::Clocked), which
    /// is not a partition at all — every signature is still checked and the
    /// node still routes. What it *would* do is switch expiry enforcement off:
    /// a correctly-synchronised stock Linux host commonly reads as
    /// unsynchronised (chrony clears `STA_UNSYNC` only under `rtcsync`, which
    /// nothing sets on a workstation), so gating here would disable passive
    /// revocation-by-expiry across the whole host fleet to guard against an
    /// error of hours. The gate belongs on *credential decisions*
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

    /// The router's wall-clock **posture** at `elapsed` (design 20 §4.2).
    ///
    /// [`Host`](Self::Host) reads the system clock through `host_unix_now`,
    /// which floors an implausible reading to zero — an unset RTC reading as
    /// 1970, which *looks* like a valid instant. Judged as `At`, such a reading
    /// precedes every real certificate's `not_before`, so the node would refuse
    /// every peer as `NotYetValid`. Zero is not a time, so it is reported as
    /// `Clocked::Unknown` and the node routes while judging no validity window
    /// instead.
    ///
    /// Still deliberately **not** gated on the NTP verdict — see
    /// [`Host`](Self::Host). A plausible reading a host cannot vouch for is
    /// worse than no reading for a *credential decision*
    /// ([`Driver::credential_unix`] handles that), but for the router's own
    /// view of time it is far better than nothing: rounding every ordinary
    /// Linux node whose chrony lacks `rtcsync` down to `Unknown` would switch
    /// passive revocation-by-expiry off across the whole host fleet to guard
    /// against an error of hours.
    ///
    /// A non-zero [`Epoch`](Self::Epoch) is a value its caller chose, so it is
    /// reported verbatim; the floor exists for the reading nobody chose. An
    /// `Epoch(0)` is the "no epoch pinned" state and reports `Unknown` on the
    /// same terms as an implausible host reading.
    fn wall(self, elapsed: Duration) -> wayfinder::wayfinder_auth::Clocked {
        use wayfinder::wayfinder_auth::Clocked;
        // `Epoch(0)` is checked on the *epoch*, not on the sum: an unpinned
        // epoch plus a running loop is `At(elapsed)` — a handful of seconds
        // past 1970, which precedes every real certificate's `not_before` and
        // would refuse every peer as `NotYetValid`. It is the "no epoch
        // pinned" state and belongs with the implausible host reading below.
        if matches!(self, Self::Epoch(0)) {
            return Clocked::Unknown;
        }
        match self {
            // One spelling of "below 2025 is not a time", shared with every
            // other host that has to make this call. `host_unix_now` already
            // floors the reading, so this is belt and braces — but a second
            // hand-rolled comparison here is how the two end up disagreeing.
            Self::Host => Clocked::from_unix(self.now_unix(elapsed)),
            // A chosen epoch is reported verbatim: flooring it would make a
            // test asking about second 1000 silently ask about something else.
            Self::Epoch(_) => Clocked::At(self.now_unix(elapsed)),
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
/// that one would switch expiry enforcement off across the host fleet.
fn credential_unix(clock: AuthClock, trusted: bool, now: Duration) -> u64 {
    if trusted { clock.now_unix(now) } else { 0 }
}

fn epoch_offset(clock: AuthClock, trusted: bool, now: Duration) -> Duration {
    if !trusted {
        // Fail closed, deliberately — though what enforces that is no longer
        // this value. The adapter recovers `epoch + now`, and since design 20
        // `RouterAdapter::wall()` reports `Clocked::Unknown` whenever
        // `clock_trusted` is false, so a `SetAuth` on an untrusted host clock
        // is verified without a validity window rather than refused as
        // not-yet-valid. This offset is what that `unix_now()` would have been;
        // it is kept at the fail-closed value so nothing downstream reads a
        // plausible-looking time out of an untrusted clock. There is no offset
        // that recovers an exact zero, so do not "fix" the saturation below
        // into something that produces one.
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
    /// Always accepts: the host shell stages into a `Vec`.
    fn emit(&mut self, frame: wayfinder_driver_core::OutgoingFrame<'_>) -> bool {
        self.mesh.push(OutgoingFrame {
            dst: frame.dst,
            protocol: frame.protocol,
            payload: frame.payload.to_vec(),
            egress: frame.egress,
        });
        true
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
///
/// Generic over the router type `R: RouterOps`, defaulting to [`CentralRouter`]
/// at the `default` profile's capacities — the way `wayfinder-embedded-driver`'s `Driver`
/// already is (design 26 phase 1 slice 2). The event loop, planning and
/// dispatch are expressed against `R` alone; the management-API surface
/// (`router_handle`, `with_router`/`with_router_mut`, `run`/`run_once`/
/// `process_pending`) is expressed against a concrete `CentralRouter`
/// const-generic over its eleven table capacities instead — matching
/// `wayfinder-server`'s `RouterAdapter`/`RouterHandle`, which are themselves
/// const-generic over those capacities rather than generic over `RouterOps`
/// (design 26 phase 1 slice 3). So that surface reaches every capacity
/// *profile* `CentralRouter` is built at, but — like `RouterAdapter` — not an
/// arbitrary `R: RouterOps` implementor.
pub struct Driver<Local: FrameIo, R: RouterOps = CentralRouter> {
    /// The local host network device.
    local: Local,
    /// The mesh interfaces, indexed by interface index.
    interfaces: Vec<Box<DynLinkT<'static>>>,
    /// Each interface's declared native fan-out, cached at construction.
    ///
    /// Read here rather than at use: the receive arm holds a mutable borrow of
    /// `interfaces` through its `recv` futures, so the medium cannot be asked
    /// about itself while one of its frames is in hand. It is a property of the
    /// medium and fixed once the link is built, so one read is enough.
    fan_out: Vec<Option<NonZeroU8>>,
    /// The routing engine for this node, and the identity seed beside it,
    /// behind the lock the management reads share.
    ///
    /// Behind a lock rather than owned outright because sixteen of the
    /// nineteen management answers only *read* it, and serving those on this
    /// loop meant a dashboard's poll built its response `Vec`s between mesh
    /// frames. This loop takes the write guard — in short scopes, never across
    /// a link send — and a connection task reads through a
    /// [`RouterHandle`](wayfinder_server::RouterHandle).
    shared: Arc<RwLock<SharedRouter<R>>>,
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
    /// The command channel to the certificate-authority task, when this node
    /// runs one.
    ///
    /// `None` on every node that is not a provider, which is most of them — and
    /// is why a mesh renewal reaching such a node is traced and dropped rather
    /// than being a condition. Wired by
    /// [`attach_authority`](Self::attach_authority) alongside the receiving
    /// half, so the two cannot be half-connected.
    authority_tx: Option<wayfinder_server::AuthorityTx>,
    /// Receive scratchpad for frames read from the host device.
    rx_buffer: [u8; MAX_LINK_FRAME_LEN],
    /// Transmit scratchpad the router builds outgoing frames into.
    tx_buffer: [u8; MAX_LINK_FRAME_LEN],
    /// Where accepted security settings are recorded so they outlive a
    /// restart (set via [`set_settings_store`](Self::set_settings_store)).
    /// Absent ⇒ a runtime change applies in memory only.
    settings: Option<SettingsFile>,
    /// Paces the renewal check and holds the single in-flight slot.
    ///
    /// *Where* this node renews is not here: it is the provider its last
    /// enrollment recorded, held beside the router in
    /// [`SharedRouter::renewal_provider`] and read under the same guard as the
    /// certificate it is deciding about. A node that has never been told one
    /// reports its certificate as due and renews nothing, which is what every
    /// node did before renewal existed.
    renewal_gate: RenewalGate,
    /// Where a spawned renewal attempt reports back.
    ///
    /// Kept as a pair on the driver rather than plumbed through a `select!` arm
    /// because a renewal is not latency-sensitive: the result is applied on the
    /// next turn of the loop — at worst an hour away, on a node with no
    /// interfaces whose loop timer has nothing else to wake for, against a
    /// window that is a quarter of a certificate's life.
    renewal_tx: tokio::sync::mpsc::Sender<anyhow::Result<Renewed>>,
    /// The receiving half of [`renewal_tx`](Self::renewal_tx).
    renewal_rx: tokio::sync::mpsc::Receiver<anyhow::Result<Renewed>>,
    /// Where the certificate authority's answer to a renewal that arrived over
    /// the **mesh** comes back, paired with the node that asked.
    ///
    /// Design 24 §4.3's fork, and the one asymmetry that keeps this off the
    /// cert-reply path: a `CertReply` is built in the receive path from state
    /// the router already holds, while this answer is a round trip to another
    /// task. So the request is verified on one turn of the loop and answered on
    /// a later one, and a channel is what holds it across the gap.
    ///
    /// A separate pair from [`renewal_tx`](Self::renewal_tx) because the two
    /// are opposite directions of unrelated things: that one carries *this
    /// node's own* renewal home from a socket, this one carries *another
    /// node's* answer out onto the mesh.
    mesh_renewal_tx: tokio::sync::mpsc::Sender<(Mac, wayfinder_server::RenewalOutcome)>,
    /// The receiving half of [`mesh_renewal_tx`](Self::mesh_renewal_tx).
    mesh_renewal_rx: tokio::sync::mpsc::Receiver<(Mac, wayfinder_server::RenewalOutcome)>,
}

/// Whether `n` configured mesh links exceed router type `R`'s own interface
/// capacity ([`RouterOps::INTERFACES`]), not the fixed crate constant
/// [`wayfinder::MAX_INTERFACES`].
///
/// Pulled out of [`Driver::new`] as a pure function so the bound it checks —
/// which varies by capacity profile — is assertable directly, rather than
/// only observable by capturing the `warn!` line it gates.
fn links_beyond_capacity<R: RouterOps>(n: usize) -> bool {
    n > R::INTERFACES
}

/// Run `build` to completion on a short-lived thread whose stack is sized for a
/// value of `value_bytes`, and return what it produced.
///
/// For constructing a router at a large capacity profile. A `no_std` router
/// has no way to be built in place, so construction returns it by value, and
/// an unoptimized build keeps several copies of that value live on the stack
/// at once — for a `host` router, more than a whole default thread's worth.
/// The fix is to build somewhere with room and hand back something small (an
/// `Arc`), not to raise every thread's stack in the process: the router is
/// constructed once, and nothing after that moves it.
///
/// The stack is sixteen times the value. Measured at the `host` profile, a
/// debug build needs more than six times and no more than eight; a release
/// build needs a fraction of one, so the margin is for the build that is
/// slowest to notice. It is reserved address space, committed only as far as
/// construction actually reaches. A thread that cannot be spawned at all is a
/// node that cannot start, so that panics.
fn build_off_stack<T: Send>(value_bytes: usize, build: impl FnOnce() -> T + Send) -> T {
    const MIN_STACK: usize = 2 << 20;
    let stack = value_bytes.saturating_mul(16).max(MIN_STACK);
    std::thread::scope(|scope| {
        let builder = std::thread::Builder::new()
            .name("router-build".into())
            .stack_size(stack);
        match builder.spawn_scoped(scope, build) {
            Ok(handle) => handle
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            Err(e) => panic!("cannot spawn a {stack}-byte thread to build the router: {e}"),
        }
    })
}

impl<Local: FrameIo, R: RouterOps> Driver<Local, R> {
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
    ) -> Self
    where
        R: Send + Sync,
    {
        // Gated on the host's NTP verdict by default: a node whose clock
        // nothing is disciplining reports zero rather than a plausible wrong
        // time, and every certificate-validity check refuses on that sentinel.
        // `wayfinder-tap` overrides the policy from config.
        let clock = AuthClock::Host;
        let clock_trust = ClockTrust::default();
        let link_count = interfaces.len();
        // The router only tracks `R::INTERFACES` interfaces; links past that cap
        // are silently never OGM-scheduled *and* silently revert to full
        // participation (a `set_link_features` past the cap no-ops), so a link
        // configured as a read-only tap would still transmit. Warn rather than
        // ship that misconfiguration mutely. Checked against this router's own
        // capacity, not the fixed `default`-profile constant: a smaller profile
        // (`tiny_host`'s 2, say) must be flagged well below that constant, and
        // a larger one must not be flagged below it either.
        if links_beyond_capacity::<R>(link_count) {
            warn!(
                configured = link_count,
                max = R::INTERFACES,
                "more mesh links than the router supports; links past the cap are unscheduled and ungated"
            );
        }
        // Built — and configured — on a thread whose stack fits the router,
        // then handed back already behind its `Arc`. At the `host` profile a
        // router is ~1.8 MB, and a debug build copies it through
        // `with_capacities` and each wrapper on the way into the lock: done
        // here, on a 2 MiB tokio worker or test thread, that overflows the
        // stack. What comes back is a pointer, so nothing on this side ever
        // holds the router by value.
        let shared = build_off_stack(size_of::<SharedRouter<R>>(), move || {
            let mut router = R::with_capacities(mac);
            // Install each interface's adaptive OGM schedule and participation
            // features up front so the periodic loop and the egress gates have a
            // per-interface entry to consult from the start.  The Trickle timer is
            // armed on every interface regardless of `tx_ogm`; a `tx_ogm`-off link
            // simply has its emission suppressed at poll time, which keeps the
            // features runtime-toggleable without arming/disarming timers.
            for idx in 0..link_count {
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
            Arc::new(RwLock::new(SharedRouter::new(router)))
        });
        let fan_out = interfaces.iter().map(|i| i.fan_out()).collect();
        // Depth one: at most one renewal attempt is ever outstanding, so a
        // second result cannot exist to be queued behind the first.
        let (renewal_tx, renewal_rx) = tokio::sync::mpsc::channel(1);
        // A handful of slots rather than one: unlike this node's own renewal,
        // which is a single conversation, several boards can be inside their
        // renewal windows at once and each answer is independent. Still small —
        // the answers are drained on every turn of the loop, and a depth that
        // could absorb a flood would only be a buffer for one.
        let (mesh_renewal_tx, mesh_renewal_rx) = tokio::sync::mpsc::channel(8);
        Self {
            local,
            interfaces,
            fan_out,
            shared,
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
            authority_tx: None,
            renewal_gate: RenewalGate::default(),
            renewal_tx,
            mesh_renewal_tx,
            mesh_renewal_rx,
            renewal_rx,
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
    ///
    /// Both halves of the command channel are taken, not just the receiving
    /// one. Since design 24 this loop is itself a *sender*: a `RenewReq`
    /// arriving over the mesh is verified by the router and then has to reach
    /// the authority, which is exactly what this channel is for. Taking the
    /// sender here rather than through a second setter keeps the
    /// cannot-be-half-enabled property this method exists for — a driver wired
    /// with the receiver and not the sender would verify renewals and answer
    /// none of them, silently.
    pub fn attach_authority(
        &mut self,
        commands_tx: wayfinder_server::AuthorityTx,
        commands: wayfinder_server::AuthorityRx,
    ) -> wayfinder_server::AuthorityPorts {
        self.authority_tx = Some(commands_tx);
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

    /// Record `provider` as where this node renews the certificate it is
    /// already holding, as its last enrollment left it.
    ///
    /// For startup only: `wayfinder-tap` calls this with what it read out of the
    /// runtime settings store, so a node that enrolled on a previous run comes
    /// back up still knowing where to renew. Every *runtime* change to this
    /// record arrives with the credential it belongs to, through `SetAuth`.
    ///
    /// Pair it with [`set_settings_store`](Self::set_settings_store): without a
    /// store, an enrollment's provider — like the certificate it came with — is
    /// forgotten on restart, and the node comes back up with neither.
    pub async fn set_renewal_provider(&mut self, provider: Option<RenewalProviderData>) {
        self.shared.write().await.renewal_provider = provider;
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
    /// tracks the loop's `now` consistently. Only `set_auth_time`'s work is
    /// skipped when auth is disabled — it no-ops on its own — while both
    /// publications happen either way, and the auth-disabled case is precisely
    /// the one the authority needs told.
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
        // A short write guard, but no longer a free one: `set_auth_time`
        // reconciles the engine's next-hop proofs against the key cache as well
        // as storing the clock, and this runs on every frame. The reconciliation
        // is gated on a generation counter, so the steady-state cost is one
        // integer comparison and the scan happens only when a key was actually
        // evicted.
        let auth_present = {
            let mut guard = self.shared.write().await;
            // Through the router, never `auth_mut().set_time` — advancing the
            // clock can evict a lapsed peer's key, and the engine's next-hop
            // proofs have to be swept in the same breath or a route reports
            // healthy while every frame over it is dropped for want of that
            // key (design 09 §8.10).
            guard.router.set_auth_time(now, self.clock.wall(now));
            guard.router.auth().is_some()
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
}

/// The management-API surface: read/mutate the router directly, hand a shared
/// handle to the TLS server, and run the event loop.
///
/// Const-generic over `CentralRouter`'s eleven table capacities rather than
/// generic over `R: RouterOps` (design 26 phase 1 slice 3): `RouterAdapter`
/// and `RouterHandle` are themselves const-generic over those same eleven
/// capacities — same names, same order, same `wayfinder::default` defaults — not
/// generic over the trait, so a query-handling arm built against them still
/// cannot be written for an arbitrary `R` today. What this buys is every
/// *capacity profile* of `CentralRouter`, not only the default one: a driver
/// built at `wayfinder::router_for!(host)` gets a working management API
/// exactly as a `default`-profile one does.
impl<
    Local: FrameIo,
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
>
    Driver<
        Local,
        CentralRouter<
            ORIGINATORS,
            INTERFACES,
            MCAST_MEMBERS,
            LOCAL_MCAST,
            IDENT_TABLE,
            IDENT_LIVE,
            LINK_QUALITY,
            NEIGHBOR_KEYS,
            REVOKED,
            IN_FLIGHT_CERT_REQUESTS,
            PENDING_REPLIES,
        >,
    >
{
    /// Read the router under the shared lock.
    ///
    /// A scoped callback rather than a returned guard, so a caller cannot hold
    /// the lock across an `await` it did not think about — which on this type
    /// means stalling the mesh, since the event loop needs the write half for
    /// every frame it forwards.
    pub async fn with_router<T>(
        &self,
        f: impl FnOnce(
            &CentralRouter<
                ORIGINATORS,
                INTERFACES,
                MCAST_MEMBERS,
                LOCAL_MCAST,
                IDENT_TABLE,
                IDENT_LIVE,
                LINK_QUALITY,
                NEIGHBOR_KEYS,
                REVOKED,
                IN_FLIGHT_CERT_REQUESTS,
                PENDING_REPLIES,
            >,
        ) -> T,
    ) -> T {
        f(&self.shared.read().await.router)
    }

    /// Mutate the router under the shared lock — lets callers inject crafted
    /// frames with explicit link metrics that the message-oriented transports
    /// cannot carry.
    ///
    /// Scoped for the same reason as [`with_router`](Self::with_router), and
    /// more so: this takes the write half, which excludes every reader.
    pub async fn with_router_mut<T>(
        &self,
        f: impl FnOnce(
            &mut CentralRouter<
                ORIGINATORS,
                INTERFACES,
                MCAST_MEMBERS,
                LOCAL_MCAST,
                IDENT_TABLE,
                IDENT_LIVE,
                LINK_QUALITY,
                NEIGHBOR_KEYS,
                REVOKED,
                IN_FLIGHT_CERT_REQUESTS,
                PENDING_REPLIES,
            >,
        ) -> T,
    ) -> T {
        f(&mut self.shared.write().await.router)
    }

    /// A handle the management transport serves its *reads* through, so they
    /// run on the connection's own task rather than on this loop.
    ///
    /// Read-only by construction: [`RouterHandle`](wayfinder_server::RouterHandle)
    /// exposes no way to take the write guard, so wiring one up cannot move a
    /// mutation off this loop by accident.
    pub fn router_handle(
        &self,
    ) -> wayfinder_server::RouterHandle<
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    > {
        wayfinder_server::RouterHandle::new(Arc::clone(&self.shared), self.start)
            .with_enrollment_policy(Some(self.authority.enrollment_policy_rx()))
            .with_clock_trust(Some(self.clock_trusted_tx.subscribe()))
    }

    /// How long since this driver's reference instant — the same monotonic
    /// clock `run()` stamps every received record, emitted OGM and `record_tx`
    /// with, and the one [`router_handle`](Self::router_handle) hands the
    /// management transport.
    ///
    /// Exposed because a caller that reads the router's time-evaluated state
    /// (throughput rates, route ages) has to evaluate it against *this* clock;
    /// picking an instant of its own reads a decayed — often zero — value for
    /// state the driver stamped later than the instant asked about.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
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
                // And a running ping session's, for the same reason: a probe
                // that waits for the OGM deadline on a settled mesh has timed
                // out before its turn comes, so a working path would read as
                // totally lossy.
                .min(guard.router.next_ping_after(now).unwrap_or(Duration::MAX))
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
            fan_out,
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
            // Used by `poll_mesh_renewals` after `dispatch`, off this
            // destructure.
            authority_tx: _,
            // Serviced by `poll_cert_renewal` after `dispatch`, off this
            // destructure: a renewal is a network round trip, so it must not be
            // an arm that holds the loop.
            renewal_gate: _,
            renewal_tx: _,
            renewal_rx: _,
            // Serviced by `poll_mesh_renewals` after `dispatch`, off this
            // destructure, for the same reason the renewal slots above are: the
            // answer is a round trip to another task and must not be an arm
            // that holds the loop.
            mesh_renewal_tx: _,
            mesh_renewal_rx: _,
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
                        now, &mut shared.write().await.router, idx, result, tx_buffer, fan_out, &mut out,
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
                    let SharedRouter { router, identity_seed, renewal_provider } = &mut *guard;
                    let mut adapter = RouterAdapter::new(router, now)
                        .with_epoch_unix(epoch_offset)
                        .with_clock_trusted(clock_trusted)
                        .with_identity(identity_seed)
                        .with_renewal_provider(renewal_provider)
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
                    trace!("polling OGMs, keep-alives, next-hop challenges and probes");
                    let mut out = LoopOutput::none();
                    let mut guard = shared.write().await;
                    let router = &mut guard.router;
                    // Spelled out rather than `poll_due_all` because this arm
                    // holds a write guard it must not give up between calls.
                    // Every schedule the sleep above folded into `next_due`
                    // must appear here: one left out is a deadline that wakes
                    // the loop and is then not serviced, which for a probe
                    // session is a busy-spin — its deadline stays due forever.
                    wayfinder_driver_core::poll_due_ogms(router, now, tx_buffer, &mut out);
                    wayfinder_driver_core::poll_due_keepalives(router, now, tx_buffer, &mut out);
                    wayfinder_driver_core::poll_due_challenges(router, now, tx_buffer, &mut out);
                    wayfinder_driver_core::poll_due_pings(router, now, tx_buffer, &mut out);
                    drop(guard);
                    (now, out)
                }
            }
        };

        dispatch(local, interfaces, &shared, mac, now, output).await?;
        // The live loop's counterpart to `process_pending`'s call. Both drains
        // are needed: `run()` — which is what a real node runs — never goes
        // through `process_pending`, so wiring this only there left a
        // production node inert with no durable record and no alarm, exactly
        // the failure `record_self_revocation`'s own doc warns a missed call
        // site would cause.
        self.record_self_revocation().await;
        // Same call-site argument as `record_self_revocation` above: `run()` is
        // what a real node runs and never goes through `process_pending`, so a
        // check wired only there would leave a production node lapsing silently.
        self.poll_cert_renewal(now).await;
        // And the other direction: renewals *other* nodes asked this one for.
        // On a node that is not a certificate authority this is two channel
        // polls that find nothing.
        self.poll_mesh_renewals(now).await;
        Ok(())
    }

    /// Carry a mesh renewal through the fork design 13 forces: hand a verified
    /// request to the certificate authority, and put the answer back on the
    /// mesh.
    ///
    /// Both halves in one place because they are one cycle, and because the
    /// second is the only thing that makes the first mean anything.
    ///
    /// Runs off the `select!`, after dispatch, like
    /// [`poll_cert_renewal`](Self::poll_cert_renewal): the authority may be
    /// mid-Argon2id on somebody else's login when this asks, and the router loop
    /// never awaits that task (`authority_task`'s stated invariant).
    ///
    /// A node that is not a certificate authority normally does nothing here:
    /// a board only ever routes a `RenewReq` toward the provider its enrollment
    /// recorded, so nothing addresses one at a node that does not sign. That is
    /// what *honest* peers do, not an invariant — the router surfaces a
    /// verified request for any frame naming this node, so a peer can address
    /// one here deliberately. The `None` branch below is that case, and it is
    /// reachable rather than defensive.
    async fn poll_mesh_renewals(&mut self, now: Duration) {
        self.answer_finished_mesh_renewals(now).await;

        // **One**, not a loop. The router holds a single verified request and
        // displaces rather than queues, and nothing can refill that slot
        // between iterations here — so a second take is always `None`. A bound
        // of four read as though a burst were possible, which invited sizing it
        // against a threat the one-slot design makes unreachable.
        let Some(verified) = self.shared.write().await.router.take_renewal_request() else {
            return;
        };
        let Some(authority_tx) = self.authority_tx.clone() else {
            // Verified by the router and answerable by nobody: this node is
            // not a provider. Reachable only if a peer addressed a renewal
            // at a node that does not sign, which is a misconfiguration at
            // the *asking* end — so it is traced, not alarmed, and the
            // asker's retry budget is what bounds it.
            trace!(
                requester = ?verified.mac,
                "drop: a renewal reached this node, which is not a certificate authority"
            );
            return;
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        // Dropped rather than awaited either way — awaiting is the coupling
        // design 13 removed — but the two reasons are not the same
        // condition and must not read the same. A full queue is ordinary
        // backpressure and the asker retries; a *closed* one means the
        // authority task is gone, which renews nobody and lapses every
        // board on this mesh within a certificate lifetime.
        if let Err(e) = authority_tx.try_send(wayfinder_server::AuthorityCommand::RenewOverMesh {
            node_mac: verified.mac.0,
            ed_pubkey: verified.ed_pubkey,
            x_pubkey: verified.x_pubkey,
            reply: reply_tx,
        }) {
            match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => trace!(
                    requester = ?verified.mac,
                    "drop: the certificate authority is busy; the asker will retry"
                ),
                tokio::sync::mpsc::error::TrySendError::Closed(_) => error!(
                    requester = ?verified.mac,
                    "the certificate-authority task is gone: this node can no longer \
                     renew any board on its mesh"
                ),
            }
            return;
        }

        // Spawned so the answer can arrive on a later turn of the loop
        // without anything here waiting for it.
        let tx = self.mesh_renewal_tx.clone();
        let requester = verified.mac;
        tokio::spawn(async move {
            let Ok(outcome) = reply_rx.await else {
                // The authority dropped the reply channel mid-request: the
                // task has died or panicked. There is nothing to report to
                // the *asker* — it retries — but there is very much
                // something to report to this node's operator, because a CA
                // in this state renews nobody and every board on its mesh
                // lapses within a certificate lifetime.
                error!(
                    ?requester,
                    "the certificate-authority task dropped a mesh renewal without \
                     answering; this node can no longer renew any board"
                );
                return;
            };
            match outcome {
                Ok(outcome) => {
                    let _ = tx.send((requester, outcome)).await;
                }
                Err(e) => {
                    // Unserviceable, not refused — this node cannot issue
                    // at all, today only for want of a clock. Already
                    // `error!`ed by the authority task; nothing goes back on
                    // the mesh either way.
                    trace!(?requester, error = %e, "a mesh renewal was unserviceable");
                }
            }
        });
    }

    /// Put finished mesh renewals back on the mesh, if any have come back since
    /// the last turn.
    ///
    /// Non-blocking on purpose: this runs on the driver loop, and an
    /// outstanding renewal must not stall the mesh waiting for it.
    async fn answer_finished_mesh_renewals(&mut self, now: Duration) {
        loop {
            let Ok((requester, outcome)) = self.mesh_renewal_rx.try_recv() else {
                return;
            };
            let cert = match outcome {
                wayfinder_server::RenewalOutcome::Issued(bytes) => bytes,
                wayfinder_server::RenewalOutcome::Refused(why) => {
                    // Nothing goes back. A `RenewReply` carries a certificate or
                    // it does not exist, so a node that cannot be renewed hears
                    // silence and reads it off the gap in its own counters —
                    // honest, and one fewer message for an attacker to forge.
                    // Logged here, where the operator who can act on it is.
                    info!(
                        ?requester,
                        reason = %why,
                        "refused a membership renewal that arrived over the mesh"
                    );
                    continue;
                }
            };
            let Some(cert) = wayfinder::wayfinder_auth::MembershipCert::from_bytes(&cert) else {
                // This process signed it moments ago, so it is not a real
                // condition — but an `error!` rather than an `unwrap`, since the
                // authority going wrong must not take the router down.
                error!(
                    ?requester,
                    "the certificate authority produced a certificate this node cannot parse"
                );
                continue;
            };

            let mut output = LoopOutput::none();
            {
                let mut guard = self.shared.write().await;
                if let Some(frame) =
                    guard
                        .router
                        .send_renew_reply(now, requester, &cert, &mut self.tx_buffer)
                {
                    output.mesh.push(OutgoingFrame {
                        dst: frame.dst,
                        protocol: frame.protocol,
                        payload: frame.payload.to_vec(),
                        egress: wayfinder_driver_core::Egress::Auto,
                    });
                } else {
                    // The route the request arrived over has gone since. The
                    // certificate is issued and durable either way, and the
                    // asker's next attempt collects it — `renew_holder` is
                    // idempotent for a live holder.
                    trace!(
                        ?requester,
                        "no route back to a node whose renewal was just issued; it will retry"
                    );
                }
            }
            if !output.mesh.is_empty()
                && let Err(e) = self.dispatch_output(now, output).await
            {
                warn!(error = %e, "could not send a renewal answer onto the mesh");
            }
        }
    }

    /// Apply a finished renewal, and start a new one if this node's certificate
    /// has entered its renewal window.
    ///
    /// Both halves in one place because they are one cycle, and because the
    /// in-flight slot is released by the first and claimed by the second — split
    /// across two call sites, one of them eventually would not run.
    async fn poll_cert_renewal(&mut self, now: Duration) {
        self.apply_finished_renewal(now).await;

        if !self.renewal_gate.should_check(now) {
            return;
        }

        // Nothing below is decidable on a clock a credential may not be decided
        // against, and both halves of the cycle would get it wrong in opposite
        // directions. The *verdict* is taken from the router's own clock, which
        // is deliberately never gated (see `AuthClock::Host`) — an unset host
        // clock floors to a plausible-looking past, where a live certificate
        // reads `Fresh` and the arm below would *clear* a `CertExpiring` row
        // that is more true than ever. The *install* is gated: `epoch_offset`
        // fails closed to zero, so a certificate this node fetched would be
        // refused as not-yet-valid — a node that renews every interval, is
        // issued a certificate every interval, and throws each one away.
        //
        // So the answer to an untrusted clock is to make no judgement at all:
        // any alarm already standing stays standing, and nothing is spent at the
        // authority. At most four of these an hour, which is what makes it a
        // `warn!` rather than a `trace!`.
        if !clock_trusted(self.clock, self.clock_checked) {
            warn!(
                "not judging this node's certificate: the host clock is not \
                 synchronized, so neither its expiry nor a renewal issued against \
                 it can be trusted"
            );
            return;
        }

        // Everything the attempt needs, read once under a *read* guard: the
        // round trip below must not hold any guard, and a management read must
        // not be excluded to ask a question whose answer is almost always no.
        let Some((mac, ed_pubkey, x_pubkey, seed, provider, condition)) = ({
            let guard = self.shared.read().await;
            let seed = guard.identity_seed;
            // Read under the same guard as the certificate, so the authority
            // this node renews against is always the one that issued what it is
            // holding — the pairing an enrollment installs and every subsequent
            // one replaces.
            let provider = guard.renewal_provider.clone();
            guard.router.auth().map(|auth| {
                let cert = auth.own_cert();
                (
                    cert.node_mac,
                    cert.ed_pubkey,
                    cert.x_pubkey,
                    seed,
                    provider,
                    // Judged against the router's own credential clock — the one
                    // it verifies every peer certificate with — so this node
                    // cannot believe itself fresh on the tick its peers begin
                    // rejecting it.
                    crate::renew::cert_condition(cert, auth.now_unix()),
                )
            })
        }) else {
            // No certificate at all. Not a renewal question: an un-enrolled node
            // needs enrolling, which is an operator's act.
            return;
        };

        let subject = wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&mac));
        match condition {
            CertCondition::Fresh => {
                // Retired here rather than at the moment a renewal succeeds, so
                // the one place that decides the condition holds is also the one
                // that decides it has lifted. This covers every way a node can
                // leave the window — its own renewal, an operator's `csr
                // install`, a wholesale new identity — not only the one this
                // loop drove.
                wayfinder_alarm::clear(wayfinder_alarm::AlarmKind::CertExpiring, &subject);
                return;
            }
            CertCondition::DueRenewal => {
                // Raised whether or not this node can do anything about it, and
                // the two cases say different things. A node with no renewal
                // provider recorded will *never* act on this row, and an operator reading
                // "renewal due" beside a node that renews itself has no way to
                // tell the two apart — so the row says which one this is.
                // The distinguishing clause comes **first**. An alarm's detail
                // is truncated at `DETAIL_CAP` (64 bytes), and these two used to
                // differ only well past that boundary — so both rendered as the
                // same row and the distinction this branch exists to draw
                // reached nobody.
                if provider.is_some() {
                    wayfinder_alarm::alarm!(
                        wayfinder_alarm::Severity::Warning,
                        wayfinder_alarm::AlarmKind::CertExpiring,
                        subject,
                        "renewing against its provider: certificate in its last quarter"
                    );
                } else {
                    wayfinder_alarm::alarm!(
                        wayfinder_alarm::Severity::Warning,
                        wayfinder_alarm::AlarmKind::CertExpiring,
                        subject,
                        "no renewal provider recorded: certificate nearly expired"
                    );
                }
            }
            CertCondition::Expired => {
                // Escalated, never cleared. This is the state the warning above
                // exists to prevent, and it is invisible from outside: the node
                // keeps running, keeps its links up, and is refused by every
                // peer. Clearing the alarm here — which treating "not due
                // renewal" as one condition would do — would retire the only
                // record of why the node went quiet at the exact moment it
                // became true.
                wayfinder_alarm::alarm!(
                    wayfinder_alarm::Severity::Critical,
                    wayfinder_alarm::AlarmKind::CertExpiring,
                    subject,
                    "expired: peers reject this node's OGMs; it must be re-enrolled"
                );
                // Deliberately no attempt: past `not_after` a CSR is parked for
                // an operator's approval rather than re-issued, so retrying it
                // every interval would queue nothing and fix nothing.
                return;
            }
        }

        let Some(provider) = provider else {
            // Reported, not renewed. A node whose credential was installed
            // without a provider — an offline `csr install`, or an enrollment
            // that named none — has nowhere to ask, and reaching back to an
            // authority a previous credential came from is the one thing worse
            // than waiting for an operator. The `CertExpiring` alarm above is
            // how they find out.
            return;
        };
        if provider.target.address.is_empty() {
            // A provider with a pinned key and **no socket address**: the node
            // renews over the mesh (design 24), not over this API. Nothing to
            // dial, and nothing wrong — so this returns quietly rather than
            // failing a connection every fifteen minutes over an address that
            // was never meant to be one.
            trace!("this node's renewal provider names no address; it renews over the mesh");
            return;
        }
        let Some(seed) = seed else {
            // A node holding a certificate but no seed cannot prove possession
            // of the key that certificate names, so it could not complete the
            // handshake. An `error!` because it is a violated invariant of this
            // node's own identity state, not something a peer can cause.
            error!(
                "cannot renew this node's certificate: it holds a certificate but no \
                 identity seed to authenticate the renewal with"
            );
            return;
        };
        // An attempt that never came back has to be given up on, or the single
        // in-flight slot is held for the life of the process and this node never
        // renews again — silently, since every later check would take the early
        // return below. The attempt itself is bounded (see the `timeout` in the
        // task), so reaching here means something the timeout could not reach:
        // a panicked task whose result never arrives.
        if let Some(held) = self.renewal_gate.stuck_for(now) {
            error!(
                held_secs = held.as_secs(),
                "a renewal attempt never reported back; abandoning it and retrying"
            );
            self.renewal_gate.finish();
        }
        if !self.renewal_gate.begin(now) {
            // An attempt from a previous interval is still running, inside its
            // budget. Nothing to say: the next check picks it up.
            return;
        }

        let tx = self.renewal_tx.clone();
        tokio::spawn(async move {
            let address = provider.target.address.clone();
            // Bounded, because none of the client's stages has a deadline of its
            // own: a peer that completes the TCP handshake and then goes silent
            // — a black-holing firewall, a wedged provider — would otherwise
            // park this task forever holding the in-flight slot. The budget is
            // far under `RENEWAL_CHECK_INTERVAL`, so a timed-out attempt is
            // retried on the very next check rather than costing a whole cycle.
            let attempt = crate::renew::request_renewal(&provider, seed, mac, ed_pubkey, x_pubkey);
            let outcome = match tokio::time::timeout(RENEWAL_ATTEMPT_TIMEOUT, attempt).await {
                Ok(outcome) => {
                    outcome.map_err(|e| e.context(format!("renewing against {address}")))
                }
                Err(_) => Err(anyhow::anyhow!(
                    "the renewal provider at {address} did not answer within {}s; the \
                     attempt was abandoned and will be retried",
                    RENEWAL_ATTEMPT_TIMEOUT.as_secs()
                )),
            };
            // The receiver lives as long as the driver; a send that fails means
            // the node is shutting down, and there is nothing to report it to.
            let _ = tx.send(outcome).await;
        });
    }

    /// Install a renewed certificate, if an attempt has come back since the last
    /// turn of the loop.
    ///
    /// Non-blocking on purpose: this runs on the driver loop, and a renewal that
    /// is still outstanding must not stall the mesh waiting for it.
    async fn apply_finished_renewal(&mut self, now: Duration) {
        let Ok(outcome) = self.renewal_rx.try_recv() else {
            return;
        };
        // Before anything can fail below: the slot is released however the
        // attempt ended, or one unreachable provider wedges renewal for the life
        // of the process and the node lapses without ever retrying again.
        self.renewal_gate.finish();

        let renewed = match outcome {
            Ok(renewed) => renewed,
            Err(e) => {
                // `warn!`, not `error!`: an authority that is unreachable right
                // now is handled and retried on the next interval, and the
                // condition an operator has to act on is already latched as the
                // `CertExpiring` alarm.
                warn!(error = %e, "certificate renewal failed; will retry");
                return;
            }
        };

        // The node must still belong where this attempt started. An operator
        // moving it to another authority while a renewal was outstanding is the
        // one window in which the answer that comes back is worse than no
        // answer: it verifies (against its own mesh's anchor, which arrives with
        // it), it installs against the unchanged seed, and it would silently
        // return the node to the mesh it was just moved off — re-recording the
        // old provider over the operator's action. Discarded rather than
        // installed, and the next check renews against the authority the node
        // now belongs to.
        if self.shared.read().await.renewal_provider.as_ref() != Some(&renewed.provider) {
            warn!(
                provider = %renewed.provider.target.address,
                "discarding a renewal that landed after this node was re-enrolled elsewhere"
            );
            return;
        }

        // Installed through exactly the path `csr install` uses — `SetAuth` with
        // an empty seed — so a renewal certifies the identity this node already
        // holds and can never re-identify it. Every check that guards an
        // operator's install guards this one: the anchor verifies the
        // certificate, the certificate must name this node's key, and it must
        // name the address that key derives.
        let clock_trusted = clock_trusted(self.clock, self.clock_checked);
        let epoch_offset = epoch_offset(self.clock, clock_trusted, now);
        let mut guard = self.shared.write().await;
        let SharedRouter {
            router,
            identity_seed,
            renewal_provider,
        } = &mut *guard;
        let mut adapter = RouterAdapter::new(router, now)
            .with_epoch_unix(epoch_offset)
            .with_clock_trusted(clock_trusted)
            .with_identity(identity_seed)
            .with_renewal_provider(renewal_provider);
        if let Some(store) = self.settings.as_mut() {
            adapter = adapter.with_settings(store as &mut dyn SettingsStore);
        }
        // Re-installed with the certificate, not left standing beside it: an
        // install replaces the record, so passing the provider this renewal
        // came from is what keeps the node renewing where it just renewed.
        match adapter.set_auth(
            &[],
            &renewed.cert,
            &renewed.trust_anchor,
            Some(renewed.provider),
            // This node *is* the installer here, and it has no `WallClock` to
            // anchor — it reads its own host clock. `credential_unix` is
            // nonetheless the honest value to stamp: it is the same reading,
            // under the same trust gate, that every other credential decision
            // on this node is made against.
            credential_unix(self.clock, clock_trusted, now),
        ) {
            // `info!`: a lifecycle event an observer wants, once per certificate
            // lifetime rather than per frame.
            Ok(()) => info!("renewed this node's membership certificate"),
            // The certificate came back and could not be installed. The cause
            // is deliberately not attributed here: `set_auth` fails both for a
            // certificate this node refuses (not retryable — the next attempt
            // gets the same answer) and for a node that could not write its own
            // state file (retryable, and nothing to do with the authority).
            // Naming the authority in both cases sent an operator to audit a CA
            // when the fix was `df -h`.
            Err(e) => error!(
                error = %e,
                "a renewed certificate could not be installed; this node keeps retrying, \
                 but if the certificate itself is the cause the retries cannot help and \
                 an operator must re-issue it"
            ),
        }
    }
}

/// Back to the generic surface: planning and dispatch, expressible for any
/// `R: RouterOps` (see the concrete-only block above for why the
/// management-API methods cannot join them yet).
impl<Local: FrameIo, R: RouterOps> Driver<Local, R> {
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
}

/// Back to the concrete-only management surface (see above).
impl<
    Local: FrameIo,
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
>
    Driver<
        Local,
        CentralRouter<
            ORIGINATORS,
            INTERFACES,
            MCAST_MEMBERS,
            LOCAL_MCAST,
            IDENT_TABLE,
            IDENT_LIVE,
            LINK_QUALITY,
            NEIGHBOR_KEYS,
            REVOKED,
            IN_FLIGHT_CERT_REQUESTS,
            PENDING_REPLIES,
        >,
    >
{
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
                    &self.fan_out,
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
                    renewal_provider,
                } = &mut *guard;
                let mut adapter = RouterAdapter::new(router, now)
                    .with_epoch_unix(epoch_offset)
                    .with_clock_trusted(clock_trusted)
                    .with_identity(identity_seed)
                    .with_renewal_provider(renewal_provider)
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

            // Mesh renewals: verified requests waiting to reach the authority,
            // and its answers waiting to go back onto the mesh. Inside the
            // drain loop rather than after it, because a request that arrives
            // on an earlier pass must be handed on by the same sweep — and
            // because the answer arrives on a *later* one, which is the whole
            // reason this is a channel and not a return value.
            self.poll_mesh_renewals(self.start.elapsed()).await;

            if !progressed {
                break;
            }
        }
        self.record_self_revocation().await;
        Ok(())
    }
}

/// Back to the generic surface for the remaining helpers, which touch only
/// what [`RouterOps`] already covers.
impl<Local: FrameIo, R: RouterOps> Driver<Local, R> {
    /// Persist and alarm on a revocation of *this* node, if the router acted
    /// on one this iteration.
    ///
    /// The router has already gone inert by the time this runs — that part is
    /// the `no_std` core's and happens the instant the record verifies. What
    /// is left is everything the core cannot do: writing the record where the
    /// next boot will find it, and raising the alarm that tells an operator
    /// why the node went silent.
    ///
    /// Called once per loop iteration rather than from each arm that can
    /// trigger it, because three of them can (a flooded OGM, a management-API
    /// ingest, and the periodic timer arming a record that was held for its
    /// effective instant) and a missed one would leave the node inert with no
    /// durable record and no alarm — undone by the next restart, with nothing
    /// anywhere saying why.
    async fn record_self_revocation(&mut self) {
        // Shared borrow first: the answer is "nothing to do" on every
        // iteration but the one, and management reads are served through this
        // same lock off the driver loop — a write lock per iteration would
        // stall them to ask a question whose answer is almost always no.
        if !self.shared.read().await.router.self_revocation_pending() {
            return;
        }
        let Some(record) = self.shared.write().await.router.take_self_revocation() else {
            return;
        };
        wayfinder_alarm::alarm!(
            wayfinder_alarm::Severity::Critical,
            wayfinder_alarm::AlarmKind::SelfRevoked,
            wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&record.node_mac)),
            "mesh membership revoked; re-enroll this node to bring it back"
        );
        let Some(store) = self.settings.as_mut() else {
            error!(
                "this node's membership was revoked, but it has no settings store to \
                 record that in — a restart will bring it back under the revoked \
                 certificate"
            );
            return;
        };
        use zerocopy::IntoBytes;
        if let Err(e) = store.persist(wayfinder_server::NodeSettings {
            self_revocation: Some(record.as_bytes().to_vec()),
            ..Default::default()
        }) {
            error!(
                error = %e,
                "this node's membership was revoked, but the record could not be made \
                 durable — a restart will bring it back under the revoked certificate"
            );
        }
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
fn poll_due_ogms<R: RouterOps>(
    router: &mut R,
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
fn poll_due_keepalives<R: RouterOps>(
    router: &mut R,
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
fn ingest_signed_revocation<R: RouterOps>(
    router: &mut R,
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
    // node. It is not "nothing happened" any more — this node has just dropped
    // its own certificate and gone inert — but it is still a failure to
    // *flood*, which is what the authority asked for and what this reports.
    Err(
        "it names this node, which has therefore gone inert rather than flooding it; \
         no peer will learn of the revocation from here"
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
fn ingest_and_report<R: RouterOps>(
    router: &mut R,
    record: &wayfinder::wayfinder_auth::RevocationRecord,
    now: Duration,
    now_unix: u64,
    ack: tokio::sync::oneshot::Sender<Result<(), String>>,
) {
    let outcome = ingest_signed_revocation(router, record, now, now_unix);
    if let Err(reason) = &outcome {
        error!(
            reason,
            node_mac = ?record.node_mac,
            "revocation signed and durably recorded, but this node could not flood it"
        );
    }
    if ack.send(outcome).is_err() {
        warn!(
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
fn build_auth_snapshot<R: RouterOps>(router: &R, identity_seed: Option<[u8; 32]>) -> AuthSnapshot {
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

/// Collects the router's multicast destination groups into the owned
/// `OutgoingFrame`s this shell dispatches.
///
/// Unbounded on purpose: on a host the frames go into a `Vec`, so there is no
/// capacity to run out of and no group to lose. The engine still bounds how
/// many groups it produces.
struct OwnedFrameSink<'a>(&'a mut Vec<OutgoingFrame>);

impl FrameSink for OwnedFrameSink<'_> {
    fn push(&mut self, f: LinkFrameData<'_>) -> bool {
        self.0.push(OutgoingFrame {
            dst: f.dst,
            protocol: f.protocol,
            payload: f.payload.to_vec(),
            egress: Egress::Auto,
        });
        true
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
fn plan_host_frame<R: RouterOps>(
    now: Duration,
    router: &mut R,
    snooper: &mut McastSnooper,
    eth: &[u8],
    tx_buffer: &mut [u8],
) -> Vec<OutgoingFrame> {
    if snooper.observe(eth) {
        router.set_local_mcast_groups(now, &snooper.groups());
    }

    let mut mesh: Vec<OutgoingFrame> = Vec::new();
    if eth.len() < 14 {
        return mesh;
    }

    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&eth[0..6]);
    let dst = Mac(dst_mac);

    // Locally originated frames flood out every interface (no ingress to omit).
    let flood = |router: &mut R, mesh: &mut Vec<OutgoingFrame>, buf: &mut [u8]| {
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
                // One call with the whole listener set, not one call per
                // listener: the router groups them by next hop, so listeners
                // sharing one travel in a single frame and every hop they
                // share is paid for once rather than once per listener.
                let targets: Vec<Mac> = router.mcast_targets(dst).collect();
                if let Err(e) = router.handle_local_mcast(
                    now,
                    &targets,
                    eth,
                    tx_buffer,
                    &mut OwnedFrameSink(&mut mesh),
                ) {
                    // Nothing went out at all — no flood arm to fall back to
                    // on this branch, so record it rather than lose the host's
                    // frame silently.
                    trace!(?dst, ?e, "drop: local multicast unsendable");
                }
            }
            McastPlan::Flood => flood(router, &mut mesh, tx_buffer),
        }
    } else {
        match router.handle_local(now, dst, eth, tx_buffer) {
            Ok(f) => mesh.push(OutgoingFrame {
                dst: f.dst,
                protocol: f.protocol,
                payload: f.payload.to_vec(),
                egress: Egress::Auto,
            }),
            // Recorded for the same reason the multicast arm above records
            // its failure: the host's frame is gone and nothing else says so.
            //
            // This got sharper when next-hop proofs began being swept with the
            // keys they were answered with (design 09 §8.10). Before that, a
            // frame aimed at a lapsed neighbour was planned, reached
            // `tag_directed_into`, and was counted there by §7's
            // `untaggable_drop_rate`. Now the route is correctly gone first, so
            // it fails earlier and that counter never sees it — an improvement
            // in behaviour that was a regression in visibility until here.
            Err(e) => trace!(?dst, ?e, "drop: local unicast unsendable"),
        }
    }

    mesh
}

/// Deliver one unit of work: write any inner frame to the host device and
/// dispatch each outgoing frame onto the mesh via `get_egress_interface`.
async fn dispatch<Local: FrameIo, R: RouterOps>(
    local: &Local,
    interfaces: &mut [Box<DynLinkT<'static>>],
    shared: &RwLock<SharedRouter<R>>,
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
        payload.resize(body_len + MAX_TRAILER_LEN, 0);
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

    /// The router's wall-clock posture, pinned on both variants.
    ///
    /// Two deliberate policy decisions live in this two-line function and
    /// neither is obvious from reading it (design 20 §11): a `Host` reading is
    /// **not** gated on the NTP verdict, and an implausible one — or an
    /// unpinned `Epoch` — reports `Unknown` rather than an instant in 1970.
    #[test]
    fn auth_clock_reports_its_posture() {
        use wayfinder::wayfinder_auth::Clocked;

        // A pinned epoch is a value its caller chose, reported verbatim.
        assert_eq!(
            AuthClock::Epoch(1_000).wall(Duration::from_secs(5)),
            Clocked::At(1_005),
            "a chosen epoch is not floored — a test asking about second 1000 \
             must not silently be asked about something else"
        );

        // An unpinned one is the "no epoch" state, *not* a 1970 instant: as
        // `At`, `elapsed` seconds precedes every real `not_before` and would
        // refuse every peer as NotYetValid.
        assert_eq!(
            AuthClock::Epoch(0).wall(Duration::from_secs(5)),
            Clocked::Unknown
        );
        assert_eq!(AuthClock::Epoch(0).wall(Duration::ZERO), Clocked::Unknown);
    }
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
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(tx, rx);
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

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(tx, rx);

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
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(tx, rx);
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
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        drop(driver.attach_authority(tx, rx));
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

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(tx, rx);
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
        // The node routes under the address its identity key derives — a
        // certificate can name no other (design 09 §5), and `set_auth` refuses
        // one that does not match the address this router answers to.
        let mac_addr = kp.derived_mac();

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
        let mut driver: Driver<NeverIo> = Driver::new(
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
                        provider: None,
                        installer_unix: 0,
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

    /// An enrollment reaching the node over the management API records where
    /// that credential is renewed, and a later one re-points it — which is the
    /// whole reason the target travels with the credential instead of sitting in
    /// the node's configuration file.
    ///
    /// Asserted through `GetSecurityStatus` rather than by reaching into the
    /// driver, because the read path is the same one the renewal check uses: the
    /// slot beside the router. A record that persisted but never reached that
    /// slot would leave the running node renewing against its previous authority
    /// until it restarted.
    #[tokio::test]
    async fn an_enrollment_records_where_the_node_renews_and_a_later_one_re_points_it() {
        use zerocopy::IntoBytes;

        use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusRequest;
        use wayfinder_protos::wayfinder::v1alpha::RenewalProvider;
        use wayfinder_protos::wayfinder::v1alpha::SetAuthRequest;
        use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as RespKind;

        let seed = [3u8; 32];
        let kp = Keypair::from_seed(&seed);
        let mac_addr = kp.derived_mac();
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
        let mut driver: Driver<NeverIo> = Driver::new(
            mac_addr,
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );
        driver.set_identity_seed(seed).await;
        driver.set_epoch_unix(Duration::from_secs(1_700_000_000));

        // One helper for both requests: every one of them goes down the same
        // channel and is answered on the same `process_pending` sweep.
        async fn ask(
            driver: &mut Driver<NeverIo>,
            query_tx: &tokio::sync::mpsc::Sender<(
                WayfinderRequest,
                tokio::sync::oneshot::Sender<
                    wayfinder_protos::wayfinder::v1alpha::WayfinderResponse,
                >,
            )>,
            request: ReqKind,
        ) -> RespKind {
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            query_tx
                .send((
                    WayfinderRequest {
                        request: Some(request),
                    },
                    resp_tx,
                ))
                .await
                .unwrap();
            driver.process_pending().await.unwrap();
            resp_rx.await.unwrap().response.unwrap()
        }

        let enroll_with = |address: &str| {
            ReqKind::SetAuth(SetAuthRequest {
                seed: Vec::new(),
                cert: cert.clone(),
                trust_anchor: anchor.clone(),
                provider: Some(Box::new(RenewalProvider {
                    address: address.into(),
                    node_key: vec![9u8; 32],
                    enrollment_token: "s3cret".into(),
                })),
                installer_unix: 0,
            })
        };

        match ask(&mut driver, &query_tx, enroll_with("first.example:7700")).await {
            RespKind::Empty(_) => {}
            other => panic!("expected the enrollment to be accepted, got {other:?}"),
        }
        let status = match ask(
            &mut driver,
            &query_tx,
            ReqKind::GetSecurityStatus(GetSecurityStatusRequest {}),
        )
        .await
        {
            RespKind::SecurityStatus(status) => status,
            other => panic!("expected a security status, got {other:?}"),
        };
        assert_eq!(
            status.renewal_provider.map(|p| p.address),
            Some("first.example:7700".to_string()),
            "the node renews where the enrollment that certified it said"
        );

        // The un-register / re-register case: a second authority certifies this
        // node, and the first must stop being the one it asks.
        match ask(&mut driver, &query_tx, enroll_with("second.example:7700")).await {
            RespKind::Empty(_) => {}
            other => panic!("expected the re-enrollment to be accepted, got {other:?}"),
        }
        let status = match ask(
            &mut driver,
            &query_tx,
            ReqKind::GetSecurityStatus(GetSecurityStatusRequest {}),
        )
        .await
        {
            RespKind::SecurityStatus(status) => status,
            other => panic!("expected a security status, got {other:?}"),
        };
        assert_eq!(
            status.renewal_provider.map(|p| p.address),
            Some("second.example:7700".to_string()),
            "and follows the credential when the node is moved to another authority"
        );
    }

    /// A node whose certificate has entered its renewal window renews it
    /// against the provider its own record names, over real TLS, and comes out
    /// holding a later certificate — **with that provider still recorded**.
    ///
    /// The one end-to-end pass over the whole cycle: the condition verdict, the
    /// pinned connection, the empty credential the enrollment tier requires, the
    /// authority's holder match, and the install. Every piece of it is claimed in
    /// prose somewhere and each is a silent failure if wrong — a node that does
    /// not renew keeps routing, keeps its links up, reports itself healthy, and
    /// is dropped by every peer weeks later.
    ///
    /// The provider record surviving the install is worth its own assertion: the
    /// install path is `set_auth`, where an absent provider *clears* the record,
    /// so passing `None` there would make the first renewal succeed and every
    /// later one impossible, permanently and silently.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_due_certificate_is_renewed_against_the_recorded_provider() {
        use zerocopy::IntoBytes;

        use wayfinder::wayfinder_auth::MembershipCert;
        use wayfinder_protos::service::RenewalProviderData;
        use wayfinder_protos::service::RenewalTargetData;
        use wayfinder_protos::service::SharedSecret;

        // The node's certificate is issued at T0 for 10_000s, so its last
        // quarter opens at T0+7_500. Everything below runs at T0+8_000: inside
        // the window, and still a live holder as far as the authority is
        // concerned (`now <= not_after`), which is the state renewal exists to
        // act in.
        const T0: u64 = 1_700_000_000;
        const TTL: u64 = 10_000;
        const NOW: u64 = T0 + 8_000;
        const TOKEN: &str = "s3cret";

        let seed = [3u8; 32];
        let kp = Keypair::from_seed(&seed);
        let mac_addr = kp.derived_mac();

        // The authority, and the node's *first* certificate from it — issued
        // directly, so the holder record the renewal will match against exists.
        let mut ca = CertAuthority::new(&[9u8; 32], 0xABCD, TTL, Some(TOKEN.into()), true);
        ca.set_now_unix(T0);
        let first = match ca
            .submit_csr(mac_addr.as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey(), TOKEN)
            .unwrap()
        {
            wayfinder_protos::service::CsrOutcome::Issued(issued) => issued,
            other => panic!("expected the first certificate to be issued, got {other:?}"),
        };
        // The authority moves on to `NOW` before it serves anything, so what a
        // renewal is issued differs from what the node holds and the renewal is
        // observable at all. Its clock is its own — since the authority moved
        // off the router loop it takes none from the router — so this is the
        // only thing that sets it.
        ca.set_now_unix(NOW);
        let anchor_bytes = ca.trust_anchor_bytes();
        let first_cert = MembershipCert::from_bytes(&first.cert).unwrap();
        assert!(
            first_cert.due_renewal(NOW) && !first_cert.expired(NOW),
            "the fixture must start inside the renewal window, or this test measures nothing"
        );

        // The provider, reachable over real TLS on a loopback port. Its own
        // identity key is what the node pins; nothing here is trusted on the
        // strength of the address.
        let provider_seed = [11u8; 32];
        let provider_key = Keypair::from_seed(&provider_seed).ed_pubkey();
        let mut comms = wayfinder_server::AuthorityComms::new(NOW);
        let (authority_tx, authority_rx) = tokio::sync::mpsc::channel(8);
        let ports = comms.attach(authority_rx);
        // Published *after* the attach, so the authority observes it as a
        // change: this is the router loop's certificate-validity clock, and an
        // authority that never sees one keeps the instant it was built with —
        // here, the instant the node's first certificate was issued, which
        // would re-issue an identical window and make a renewal indetectable.
        comms.publish(wayfinder_server::RouterFacts {
            unix_secs: NOW,
            auth_present: true,
        });
        tokio::spawn(wayfinder_server::serve_authority(ca, ports));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider_addr = listener.local_addr().unwrap().to_string();
        let (snapshot_tx, mut snapshot_rx) =
            tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<AuthSnapshot>>(4);
        tokio::spawn(async move {
            // An un-enrolled provider: no anchor, so the transport admits a
            // stranger at the enrollment tier — which is exactly what a node
            // presenting no certificate is.
            while let Some(reply) = snapshot_rx.recv().await {
                let _ = reply.send(AuthSnapshot {
                    own_key: Some(provider_key),
                    anchor: None,
                    revoked: Vec::new(),
                    own_mac: wayfinder_server::Mac([2, 0, 0, 0, 0, 1]),
                });
            }
        });
        // Router requests have nowhere to go on this listener and none are sent;
        // the receiver is held so the channel does not close under the server.
        let (query_tx, _provider_query_rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(wayfinder_server::serve_tls_server_with_vpn(
            listener,
            provider_seed,
            snapshot_tx,
            query_tx,
            wayfinder_server::ServerServices {
                authority_tx: Some(authority_tx),
                ..Default::default()
            },
        ));

        // The node: running under that first certificate, and told where it
        // came from.
        let (_query_tx, query_rx) = tokio::sync::mpsc::channel(4);
        let mut driver: Driver<NeverIo> = Driver::new(
            mac_addr,
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );
        driver.set_identity_seed(seed).await;
        driver.set_epoch_unix(Duration::from_secs(NOW));
        let anchor = wayfinder::wayfinder_auth::TrustAnchor::from_bytes(&anchor_bytes).unwrap();
        driver
            .with_router_mut(|r| {
                r.set_auth(wayfinder::auth::OgmAuth::new(
                    Keypair::from_seed(&seed),
                    first_cert,
                    anchor,
                ));
                // After `set_auth`, not before: installing auth brings its own
                // clock, so a time set first is discarded and the certificate
                // reads as fresh against a zero clock.
                r.set_auth_time(Duration::ZERO, wayfinder::wayfinder_auth::Clocked::At(NOW));
            })
            .await;
        let recorded = RenewalProviderData {
            target: RenewalTargetData {
                address: provider_addr.clone(),
                node_key: provider_key,
            },
            enrollment_token: SharedSecret::new(TOKEN),
        };
        driver.set_renewal_provider(Some(recorded.clone())).await;

        // Drive the cycle: one pass starts the attempt, later passes apply
        // whatever has come back. Polled rather than slept on, so the test is
        // bounded by the work rather than by a guessed duration.
        let mut renewed_not_after = None;
        for _ in 0..500 {
            driver.poll_cert_renewal(Duration::ZERO).await;
            let not_after = driver
                .with_router(|r| r.auth().map(|a| a.own_cert().not_after.get()))
                .await;
            if not_after != Some(first_cert.not_after.get()) {
                renewed_not_after = not_after;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(
            renewed_not_after,
            Some(NOW + TTL),
            "the node installed a certificate re-issued for the lifetime it was admitted for"
        );
        assert_eq!(
            driver.shared.read().await.renewal_provider.as_ref(),
            Some(&recorded),
            "and still knows where to renew: an install that dropped the provider would \
             make this the last renewal this node ever performs"
        );
        assert_eq!(
            driver.with_router(|r| r.self_ident()).await,
            mac_addr,
            "a renewal certifies the identity the node already had; it never re-identifies it"
        );
    }

    /// Build a driver holding a certificate valid `[issued, issued + ttl]`, with
    /// `provider` recorded as where it renews.
    ///
    /// Shared by the condition tests below, which differ only in the instant
    /// they judge that certificate at.
    async fn driver_holding_cert(
        issued: u64,
        ttl: u64,
        judged_at: u64,
        provider: Option<wayfinder_protos::service::RenewalProviderData>,
    ) -> Driver<NeverIo> {
        use zerocopy::IntoBytes;

        use wayfinder::wayfinder_auth::MembershipCert;
        use wayfinder::wayfinder_auth::TrustAnchor;

        let seed = [3u8; 32];
        let kp = Keypair::from_seed(&seed);
        let mac_addr = kp.derived_mac();
        let mut ca = CertAuthority::new(&[9u8; 32], 0xABCD, ttl, None, true);
        ca.set_now_unix(issued);
        let cert = match ca
            .submit_csr(mac_addr.as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey(), "")
            .unwrap()
        {
            wayfinder_protos::service::CsrOutcome::Issued(issued) => issued.cert,
            other => panic!("expected the certificate to be issued, got {other:?}"),
        };
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();

        let (_query_tx, query_rx) = tokio::sync::mpsc::channel(4);
        let mut driver: Driver<NeverIo> = Driver::new(
            mac_addr,
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );
        driver.set_identity_seed(seed).await;
        driver.set_epoch_unix(Duration::from_secs(judged_at));
        driver
            .with_router_mut(|r| {
                r.set_auth(wayfinder::auth::OgmAuth::new(
                    Keypair::from_seed(&seed),
                    MembershipCert::from_bytes(&cert).unwrap(),
                    anchor,
                ));
                // After `set_auth`: installing auth brings its own clock, so a
                // time set before it is discarded and every certificate reads
                // fresh against a zero clock.
                r.set_auth_time(
                    Duration::ZERO,
                    wayfinder::wayfinder_auth::Clocked::At(judged_at),
                );
            })
            .await;
        driver.set_renewal_provider(provider).await;
        driver
    }

    /// A certificate past `not_after` escalates to a critical alarm, and no
    /// renewal is attempted.
    ///
    /// Both halves matter. The alarm is the *only* outward sign of this state —
    /// the node keeps running and keeps its links up while every peer rejects it
    /// — so folding `Expired` in with `Fresh`, which is what a two-way "is it
    /// due?" would do, retires the warning at the instant it becomes true. And
    /// an attempt here would be spent for nothing: past `not_after` the
    /// authority no longer matches a live holder, so it parks the request rather
    /// than issuing.
    #[tokio::test]
    async fn an_expired_certificate_escalates_and_is_not_renewed() {
        let board = Arc::new(wayfinder_alarm::SharedBoard::new());
        let provider = wayfinder_protos::service::RenewalProviderData {
            target: wayfinder_protos::service::RenewalTargetData {
                address: "ca.example:7700".into(),
                node_key: [9u8; 32],
            },
            enrollment_token: wayfinder_protos::service::SharedSecret::new(""),
        };
        // Judged an hour past a certificate that expired at 1_000_000 + 100.
        let mut driver =
            driver_holding_cert(1_000_000, 100, 1_000_000 + 3_600, Some(provider)).await;

        wayfinder_alarm::with_board(&board, || {
            futures::executor::block_on(driver.poll_cert_renewal(Duration::ZERO));
        });

        let snapshot = board.snapshot();
        let row = snapshot
            .alarms
            .iter()
            .find(|a| a.kind == wayfinder_alarm::AlarmKind::CertExpiring)
            .expect("an expired certificate is on the board, not silently absent");
        assert_eq!(
            row.severity,
            wayfinder_alarm::Severity::Critical,
            "expired is not the same condition as due, and must not read as one"
        );
        assert!(
            driver.renewal_gate.begin(Duration::ZERO),
            "the in-flight slot is untouched: no attempt is spent on a certificate the \
             authority can only park"
        );
    }

    /// On a clock this node may not make a credential decision against, it
    /// judges nothing: no alarm is retired, and no attempt is made.
    ///
    /// The hazard is specific. The verdict is taken from the router's own clock,
    /// which is deliberately never gated, so an unsynchronized host — one whose
    /// clock floors to a plausible-looking past — reads a live certificate as
    /// `Fresh` and would *clear* a `CertExpiring` row that is more true than
    /// ever. The install is gated the other way, so a certificate fetched on
    /// such a clock would be refused as not-yet-valid: the node would renew
    /// every interval and throw every answer away.
    #[tokio::test]
    async fn nothing_is_judged_on_an_untrusted_clock() {
        let board = Arc::new(wayfinder_alarm::SharedBoard::new());
        let mut driver = driver_holding_cert(1_000_000, 10_000, 1_000_000 + 9_000, None).await;
        // The default host clock with no check behind it — what a node has
        // before NTP has been established, and what `clock_trusted` reports as
        // untrusted.
        driver.clock = AuthClock::Host;
        driver.clock_checked = None;
        let subject = wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&driver.mac.0));

        wayfinder_alarm::with_board(&board, || {
            // A row already standing, exactly as a previous check would have
            // left it while the clock was still good.
            wayfinder_alarm::alarm!(
                wayfinder_alarm::Severity::Warning,
                wayfinder_alarm::AlarmKind::CertExpiring,
                subject,
                "raised while the clock was still trustworthy"
            );
            futures::executor::block_on(driver.poll_cert_renewal(Duration::ZERO));
        });

        assert!(
            board
                .snapshot()
                .alarms
                .iter()
                .any(|a| a.kind == wayfinder_alarm::AlarmKind::CertExpiring),
            "the standing row survives: a clock that cannot be trusted cannot retire it"
        );
    }

    /// A failed attempt releases the in-flight slot, so the next check tries
    /// again.
    ///
    /// The slot is the whole of this feature's backpressure, and nothing but the
    /// attempt's result releases it — so an early return on the failure path
    /// would wedge renewal for the life of the process, and the node would lapse
    /// without ever retrying. Driven through the real channel rather than by
    /// calling the gate, because the gate's own test cannot see that call site.
    #[tokio::test]
    async fn a_failed_attempt_releases_the_slot_for_the_next_check() {
        let mut driver = driver_holding_cert(1_000_000, 10_000, 1_000_000 + 9_000, None).await;
        assert!(driver.renewal_gate.begin(Duration::ZERO), "claim the slot");

        driver
            .renewal_tx
            .send(Err(anyhow::anyhow!("the provider was unreachable")))
            .await
            .unwrap();
        driver.apply_finished_renewal(Duration::ZERO).await;

        assert!(
            driver.renewal_gate.begin(Duration::ZERO),
            "the slot is free again after a failure, so renewal is retried rather than \
             wedged for the life of the process"
        );
    }

    /// A renewal that lands after the node has been re-enrolled elsewhere is
    /// discarded rather than installed.
    ///
    /// The window is small and the consequence is not: the answer verifies
    /// against its own mesh's anchor and installs against an unchanged seed, so
    /// installing it would return the node to the authority an operator has just
    /// moved it off — and re-record that authority over their action.
    #[tokio::test]
    async fn a_renewal_that_lands_after_a_re_enrollment_is_discarded() {
        use wayfinder_protos::service::RenewalProviderData;
        use wayfinder_protos::service::RenewalTargetData;
        use wayfinder_protos::service::SharedSecret;

        let second = RenewalProviderData {
            target: RenewalTargetData {
                address: "second.example:7700".into(),
                node_key: [2u8; 32],
            },
            enrollment_token: SharedSecret::new(""),
        };
        let mut driver =
            driver_holding_cert(1_000_000, 10_000, 1_000_000 + 9_000, Some(second)).await;
        let held = driver
            .with_router(|r| r.auth().map(|a| a.own_cert().not_after.get()))
            .await;

        // An answer from the authority the node used to belong to, carrying a
        // certificate that is perfectly valid — for the mesh it has left.
        driver
            .renewal_tx
            .send(Ok(Renewed {
                cert: Vec::new(),
                trust_anchor: Vec::new(),
                provider: RenewalProviderData {
                    target: RenewalTargetData {
                        address: "first.example:7700".into(),
                        node_key: [1u8; 32],
                    },
                    enrollment_token: SharedSecret::new(""),
                },
            }))
            .await
            .unwrap();
        driver.apply_finished_renewal(Duration::ZERO).await;

        assert_eq!(
            driver
                .with_router(|r| r.auth().map(|a| a.own_cert().not_after.get()))
                .await,
            held,
            "the node keeps the credential its current authority gave it"
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
        let mut driver: Driver<NeverIo> = Driver::new(
            mac(1),
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );

        let (authority_tx, authority_rx) = tokio::sync::mpsc::channel(4);
        let ports = driver.attach_authority(authority_tx.clone(), authority_rx);

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

    // ---- design 26 phase 1 slice 2: the host driver at a non-default profile --

    wayfinder::define_profile! {
        /// A capacity profile smaller than `default` in every dimension, so a test
        /// exercising it cannot pass merely because it happens to coincide with
        /// the router's built-in defaults.
        pub tiny_host {
            originators: 16,
            interfaces: 2,
            mcast_members: 8,
            local_mcast: 4,
            ident_table: 16,
            ident_live: 12,
            link_quality: 16,
            neighbor_keys: 8,
            revoked: 4,
            in_flight_cert_requests: 2,
            pending_replies: 2,
            max_frame_len: 256,
        }
    }

    /// The concrete router type for [`tiny_host`] — a stand-in for the `host`
    /// profile design 26 itself adds, at a size cheap enough for a unit test.
    type TinyRouter = wayfinder::router_for!(tiny_host);

    /// A mesh interface that only ever captures what is sent on it, so a test
    /// can observe that the driver's periodic loop actually produced and
    /// dispatched an OGM rather than merely type-checking.
    struct CapturingLink(Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

    impl LinkT for CapturingLink {
        async fn send(
            &mut self,
            _origin: Mac,
            data: &LinkFrameData<'_>,
        ) -> Result<usize, interfaces::link::LinkError> {
            let payload = data.payload.to_vec();
            let len = payload.len();
            #[expect(clippy::unwrap_used, reason = "test harness: an uncontended mutex")]
            self.0.lock().unwrap().push(payload);
            Ok(len)
        }

        async fn recv<'a>(
            &'a mut self,
        ) -> Result<wayfinder::link::Received<'a>, interfaces::link::LinkError> {
            std::future::pending().await
        }
    }

    /// `Driver::new` must warn about a link count past the router's own
    /// capacity, not past the fixed crate constant `wayfinder::MAX_INTERFACES`.
    ///
    /// `wayfinder::MAX_INTERFACES` is `batman::MAX_INTERFACES` (8) — the
    /// `default` profile's own interface count, but not every profile's.
    /// `tiny_host` has only 2, so 3 links must be flagged there even though
    /// 3 is nowhere near the fixed constant. Conversely the `default` profile's
    /// 8 links is exactly at its own capacity, not past it, and must not be
    /// flagged. Checked through the pure helper rather than `Driver::new`
    /// itself so the assertion does not need to capture a `warn!` line.
    #[test]
    fn links_beyond_capacity_checks_the_routers_own_interface_bound() {
        assert!(
            links_beyond_capacity::<TinyRouter>(3),
            "tiny_host has only 2 interfaces, so 3 links is past its capacity"
        );
        assert!(
            !links_beyond_capacity::<CentralRouter>(8),
            "the default profile's own capacity is 8, so 8 links is at capacity, not past it"
        );
        // And the other side of each boundary, so an off-by-one fails.
        assert!(!links_beyond_capacity::<TinyRouter>(2));
        assert!(links_beyond_capacity::<CentralRouter>(9));
    }

    /// The whole point of this slice: the host driver, generic over `R:
    /// RouterOps`, runs its real event loop — construction, per-interface
    /// Trickle scheduling, and dispatch — at a capacity profile other than the
    /// `default` one, and actually emits an OGM onto a link. Before this
    /// slice `Driver<Local>` named `CentralRouter` outright, so a router of
    /// another profile could not be handed to it at all — this test could not
    /// even be *written*, let alone pass.
    #[tokio::test]
    async fn the_host_driver_runs_at_a_non_default_router_profile() {
        let sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Box<DynLinkT<'static>> = DynLinkT::new_box(CapturingLink(sent.clone()));

        let (_query_tx, query_rx) = tokio::sync::mpsc::channel(4);
        let mut driver: Driver<NeverIo, TinyRouter> = Driver::new(
            mac(1),
            NeverIo,
            vec![link],
            vec![TrickleConfig::default()],
            vec![LinkFeatures::default()],
            Vec::new(),
            query_rx,
        );

        // Advance until the one interface's Trickle timer is due — the exact
        // instant is Trickle's own choice, not this test's, exactly as
        // `wayfinder::router_ops`'s own `drive_one_ogm` test helper does.
        let mut now = Duration::ZERO;
        while sent.lock().expect("uncontended mutex").is_empty() && now < Duration::from_secs(60) {
            driver.poll_due(now).await.expect("poll_due does not fail");
            now += Duration::from_millis(100);
        }

        assert!(
            !sent.lock().expect("uncontended mutex").is_empty(),
            "the driver must emit an OGM on its one interface even at a non-default \
             capacity profile"
        );
    }

    /// The management-API surface (`router_handle`, `with_router*`,
    /// `run`/`run_once`/`process_pending`) reaches every capacity profile, not
    /// only `default`: it is const-generic over `CentralRouter`'s eleven table
    /// capacities, as `RouterAdapter`/`RouterHandle` are. When it lived only on
    /// the default-profile `CentralRouter`, calling `router_handle` on a
    /// `TinyRouter`-backed driver did not compile.
    #[tokio::test]
    async fn a_non_default_router_profile_serves_a_management_read() {
        let (_query_tx, query_rx) = tokio::sync::mpsc::channel(4);
        let driver: Driver<NeverIo, TinyRouter> = Driver::new(
            mac(9),
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );

        let handle = driver.router_handle();
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
            )) => {
                assert_eq!(
                    info.node_id,
                    mac(9).0.to_vec(),
                    "a management read on a non-default router profile must answer from \
                     that same router, not a default-profile stand-in"
                );
            }
            other => panic!("expected NodeInfo, got {other:?}"),
        }
    }

    // ---- design 26 phase 1: the `host` profile itself --------------------

    /// The router type `wayfinder-tap` runs every node at.
    type HostRouter = wayfinder::router_for!(wayfinder::host);

    /// A `host` router is about 1.8 MB, well past a 2 MiB thread's stack once
    /// a debug build has copied it through a constructor or two — which is how
    /// every host path used to build one. `Driver::new` must therefore put it
    /// on the heap without ever holding it by value on the caller's stack: this
    /// test runs on an ordinary test thread, so building the router inline
    /// aborts the process with a stack overflow rather than failing an assert.
    #[tokio::test]
    async fn a_host_profile_driver_builds_on_an_ordinary_thread() {
        let (_query_tx, query_rx) = tokio::sync::mpsc::channel(1);
        let driver: Driver<NeverIo, HostRouter> = Driver::new(
            mac(1),
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );

        let occupancy = driver.with_router(|r| r.originator_occupancy()).await;
        assert_eq!(
            occupancy,
            (0, wayfinder::host::ORIGINATORS),
            "the driver must be running the host profile it was asked for"
        );
    }

    /// A `host` node does per-frame work on an ordinary thread, and its
    /// management API reports that work against the `host` capacities.
    ///
    /// The other `host` tests only build a router or install a credential; this
    /// drives one real OGM from one `host` driver into another over a datagram
    /// pair, on a 2 MiB test thread, so a router- or `OgmAuth`-sized value
    /// (1.8 MB / 548 KB, copied a few times in a debug build) moved onto the
    /// stack anywhere on the receive path overflows here. It then reads
    /// `GetMetrics` through the type-erased handle, where a fallback to
    /// `default`'s constants would report 128 rather than 4096.
    ///
    /// Not a guard against per-frame *cost*: `IdentTable::clear` once built a
    /// >100 KB temporary on every frame, which fits a 2 MiB stack and passes
    /// here. Only `wayfinder-bench`'s `host` suite sees that kind of
    /// regression.
    #[tokio::test]
    async fn a_host_profile_driver_learns_a_peer_and_reports_it_at_host_capacity() {
        let (a_sock, b_sock) = tokio::net::UnixDatagram::pair().expect("socketpair");
        let link_a: Box<DynLinkT<'static>> = DynLinkT::new_box(crate::Link::new(a_sock));
        let link_b: Box<DynLinkT<'static>> = DynLinkT::new_box(crate::Link::new(b_sock));

        let (_a_query_tx, a_query_rx) = tokio::sync::mpsc::channel(1);
        let mut a: Driver<NeverIo, HostRouter> = Driver::new(
            mac(1),
            NeverIo,
            vec![link_a],
            vec![TrickleConfig::default()],
            vec![LinkFeatures::default()],
            Vec::new(),
            a_query_rx,
        );
        let (_b_query_tx, b_query_rx) = tokio::sync::mpsc::channel(1);
        let mut b: Driver<NeverIo, HostRouter> = Driver::new(
            mac(2),
            NeverIo,
            vec![link_b],
            vec![TrickleConfig::default()],
            vec![LinkFeatures::default()],
            Vec::new(),
            b_query_rx,
        );

        // Tick `b` until its Trickle timer emits, and let `a` drain each tick.
        let mut now = Duration::ZERO;
        while a.with_router(|r| r.originator_occupancy().0).await == 0
            && now < Duration::from_secs(60)
        {
            b.poll_due(now).await.expect("poll_due does not fail");
            a.process_pending()
                .await
                .expect("process_pending does not fail");
            now += Duration::from_millis(100);
        }
        assert_eq!(
            a.with_router(|r| r.originator_occupancy()).await,
            (1, wayfinder::host::ORIGINATORS),
            "a host node must learn its peer from a received OGM"
        );

        let response = a
            .router_handle()
            .serve_read(wayfinder_protos::wayfinder::v1alpha::WayfinderRequest {
                request: Some(
                    wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request::GetMetrics(
                        wayfinder_protos::wayfinder::v1alpha::GetMetricsRequest {},
                    ),
                ),
            })
            .await
            .expect("GetMetrics is a router read");
        match response.response {
            Some(wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response::Metrics(
                metrics,
            )) => {
                let originators = metrics
                    .originators
                    .expect("originator occupancy is reported");
                assert_eq!(
                    (originators.used, originators.capacity),
                    (1, wayfinder::host::ORIGINATORS as u32),
                    "GetMetrics must report the host profile's capacity, not default's"
                );
            }
            other => panic!("expected Metrics, got {other:?}"),
        }
    }

    /// Installing a credential is the other place auth state crosses the stack
    /// by value: `SetAuth` builds an `OgmAuth` and hands it to the router, and
    /// at the `host` profile's 1024 neighbour keys and 1024 revocations that
    /// value alone is ~548 KB. A `no_std` value cannot be built in place, so
    /// an unoptimized build holds a few copies across `RouterAdapter::set_auth`
    /// and `CentralRouter::set_auth` — about 2.1 MB, measured, just past a
    /// 2 MiB test thread (a release build fits in a fraction of that).
    ///
    /// So this pins the install on the thread `wayfinder-tap` actually runs
    /// its loop on: `driver.run()` is awaited on the main thread, which gets
    /// the platform's 8 MiB default rather than a spawned thread's 2 MiB.
    #[test]
    fn a_host_profile_driver_installs_a_credential_over_set_auth() {
        const MAIN_THREAD_STACK: usize = 8 << 20;
        std::thread::Builder::new()
            .stack_size(MAIN_THREAD_STACK)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(install_a_credential_on_a_host_driver());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn install_a_credential_on_a_host_driver() {
        let seed = [3u8; 32];
        let kp = Keypair::from_seed(&seed);
        let mac_addr = kp.derived_mac();

        let mut ca = CertAuthority::new(&[9u8; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_700_000_000);
        let cert = match ca
            .submit_csr(
                zerocopy::IntoBytes::as_bytes(&mac_addr),
                &kp.ed_pubkey(),
                &kp.x_pubkey(),
                "",
            )
            .unwrap()
        {
            wayfinder_protos::service::CsrOutcome::Issued(issued) => issued.cert,
            other => panic!("expected the CSR to be issued outright, got {other:?}"),
        };
        let anchor = ca.trust_anchor_bytes();

        let (query_tx, query_rx) = tokio::sync::mpsc::channel(1);
        let mut driver: Driver<NeverIo, HostRouter> = Driver::new(
            mac_addr,
            NeverIo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            query_rx,
        );
        driver.set_identity_seed(seed).await;
        driver.set_epoch_unix(Duration::from_secs(1_700_000_000));

        let request = wayfinder_protos::wayfinder::v1alpha::WayfinderRequest {
            request: Some(
                wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request::SetAuth(
                    wayfinder_protos::wayfinder::v1alpha::SetAuthRequest {
                        seed: Vec::new(),
                        cert,
                        trust_anchor: anchor,
                        provider: None,
                        installer_unix: 0,
                    },
                ),
            ),
        };
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        query_tx.send((request, resp_tx)).await.unwrap();
        driver.process_pending().await.unwrap();

        match resp_rx.await.unwrap().response {
            Some(wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response::Empty(_)) => {}
            other => panic!("expected SetAuth to install on a host router, got {other:?}"),
        }
        assert!(
            driver.with_router(|r| r.auth().is_some()).await,
            "the credential must actually be installed"
        );
    }
}
