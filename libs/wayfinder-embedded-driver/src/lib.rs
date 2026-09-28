//! A `no_std`, HAL-agnostic driver that runs the wayfinder router's event loop
//! on bare metal.
//!
//! This is the embedded counterpart to `wayfinder-driver` (the tokio/`std`
//! loop).  Both share the same synchronous planning logic in
//! [`wayfinder-driver-core`]; the difference is the loop around it.  Here the
//! loop is a plain `async fn` — the board's executor (embassy, RTIC, …) drives
//! [`Driver::run`] — and it races each mesh link's `recv` against a periodic
//! OGM timer with [`embassy_futures::select`], staging outgoing frames into a
//! fixed [`heapless`] buffer instead of a heap `Vec`.
//!
//! The driver depends on **no vendor HAL and no concrete time driver**: a board
//! supplies the concrete mesh links ([`LinkT`]) and a [`Clock`], so the same
//! code runs on the nRF52840 and on any Cortex-M.
//!
//! # Milestone scope
//!
//! At its core this is a **radio relay**: it drives the mesh interfaces (OGM
//! exchange, forwarding, per-link Trickle timers).  There is no local host
//! device or IGMP snoop yet.  Authentication *time* is wired — the driver owns
//! a [`WallClock`] and feeds the router its posture on every pass, so a board
//! judges certificate windows to whatever extent it can prove them (design 20
//! §4.4) — and since design 22 that clock's checkpoint survives a reset,
//! alongside the credential and in the same durable record ([`identity`]).
//! A board calls [`Driver::restore`] once at bring-up to come back from it, and
//! the loop rewrites the checkpoint every [`CHECKPOINT_INTERVAL`].  A board can
//! also enable auth directly via [`Driver::router_mut`].  The optional `mgmt`
//! feature adds a management-API arm to the event loop (`run_with_mgmt`) that
//! serves read-only/config queries forwarded from a `wayfinder-server` `serve`
//! loop, so an embedded node is inspectable over a debug transport (e.g. a UART)
//! exactly like a host node — and, given a [`NodeStore`], a `SetAuth` over that
//! port is durable rather than lost on the next reset.
//!
//! [`wayfinder-driver-core`]: https://docs.rs/wayfinder-driver-core
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use core::num::NonZeroU8;
use core::time::Duration;

use embassy_futures::select::Either;
use embassy_futures::select::select;
use embassy_futures::select::select_array;
use heapless::Vec as HVec;
use interfaces::link::LinkError;
use tracing::trace;
use tracing::warn;
use wayfinder::CentralRouter;
use wayfinder::auth::MAX_TRAILER_LEN;
use wayfinder::features::LinkFeatures;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::link::LinkT;
use wayfinder::router_ops::RouterAuthOps;
use wayfinder::router_ops::RouterOps;
use wayfinder::wayfinder_auth::WallClock;
use wayfinder_alarm::AlarmKind;
use wayfinder_alarm::NodeId;
use wayfinder_alarm::Severity;
use wayfinder_alarm::Subject;
use wayfinder_alarm::alarm;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::MeshSink;
use wayfinder_driver_core::OutgoingFrame;
use wayfinder_driver_core::handle_link_result;
use wayfinder_driver_core::plan_dispatch;
use wayfinder_driver_core::poll_due_all;
use wayfinder_driver_core::poll_due_renewal;

pub mod identity;

// `NodeSettings` is `alloc`-based, and so is the `RouterAdapter` that writes
// through it. Not a cost this crate is choosing: every board already links an
// allocator, because `tracing-core` does an unconditional `extern crate
// alloc` and every board logs.
extern crate alloc;

pub mod settings;

/// How much wall-clock time a board lets accumulate before rewriting its
/// durable clock checkpoint.
///
/// A **wear** figure, not a correctness one — design 20 settled that a coarser
/// interval only widens the deficit on restore and can never make the clock
/// wrong in the other direction, because the posture is a floor. The
/// arithmetic behind six hours (design 22 §4.5): the nRF52840's two 4 KiB
/// pages sustain roughly 10 000 erase cycles each and are written
/// alternately, so the pair is good for ~20 000 checkpoints; at this interval
/// that is 1 461 a year, or ~13.7 years. An hourly checkpoint would be 2.3
/// years, which is not a service life; a daily one buys 55 and costs a wider
/// deficit for nothing.
pub const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// What [`Driver::restore`] did with the record it was handed.
///
/// Returned rather than logged internally so a board can report it through
/// whatever it has — an `info!` on a DK with a probe, the bounded log ring on
/// a dongle with none — and so a test can assert it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restored {
    /// The record held no credential. The node routes unauthenticated, which
    /// is every board's state before it is first enrolled.
    Unauthenticated,
    /// The credential in the record was installed.
    Authenticated,
    /// The record held something credential-shaped that could not be used. The
    /// node routes unauthenticated.
    ///
    /// Distinct from [`Unauthenticated`](Self::Unauthenticated) because the two
    /// look identical from outside and mean very different things: one is a
    /// board waiting to be enrolled, the other is a board whose enrolment is
    /// on the medium and unusable.
    Refused(RefusalReason),
}

/// Why [`Driver::restore`] would not arm a credential the record held.
///
/// An enum rather than a message, because one of these is a *latchable
/// condition* and not merely a line to print: a board still reporting a
/// certified-address mismatch after a restart is design 22 §7's genuinely bad
/// case — a credential it can never use — and the caller has to be able to pick
/// it out to raise an alarm for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The record holds a root-signed revocation of this node's own
    /// membership.
    SelfRevoked,
    /// A certificate without its anchor, or an anchor with no certificate.
    /// Neither half is a credential on its own.
    IncompleteCredential,
    /// The stored certificate or trust anchor did not parse.
    Unparseable,
    /// The stored certificate names a MAC this node does not run under.
    ///
    /// Unreachable through `SetAuth`, which checks the certificate against the
    /// seed it installs — so a record in this state was written by a build
    /// predating that rule, and **it does not clear itself**. Every boot will
    /// refuse the same credential.
    CertifiedAddressMismatch,
}

impl RefusalReason {
    /// A short static phrase for a log line.
    pub fn as_str(self) -> &'static str {
        match self {
            RefusalReason::SelfRevoked => "this node holds a revocation of its own membership",
            RefusalReason::IncompleteCredential => {
                "the stored credential is missing its certificate or its anchor"
            }
            RefusalReason::Unparseable => "the stored certificate or trust anchor does not parse",
            RefusalReason::CertifiedAddressMismatch => {
                "the stored certificate names a MAC this node does not run under"
            }
        }
    }
}

/// The durable state a board hands its driver: the settings the management API
/// writes through, plus the clock checkpoint that lives beside them.
///
/// One trait rather than two parameters because they are one blob — design 20
/// §4.5 requires the checkpoint be written, loaded and erased with the
/// credential, and a driver holding two independent handles could not honour
/// that. `&mut dyn` rather than a type parameter because [`Driver`] is already
/// const-generic over fourteen parameters and this is a once-per-loop virtual
/// call on a path that does I/O anyway.
///
/// [`settings::RecordSettings`] is the implementation; a board whose durable
/// medium is unusable supplies [`NullStore`] instead.
pub trait NodeStore: wayfinder_server::SettingsStore {
    /// The clock high-water mark currently on the medium, or `None` for a
    /// store that keeps none at all.
    ///
    /// `None` and `Some(0)` are different answers and both occur: a board with
    /// no usable medium ([`NullStore`]) can never checkpoint, while a board
    /// with a fresh record has simply not checkpointed *yet* and should do so
    /// as soon as it is anchored. An earlier version of this returned a plain
    /// `u64` with `u64::MAX` standing in for the first case, which read as
    /// "never due" and was not: the due test adds an interval to it, and
    /// `u64::MAX + 21_600` panics in a dev build and wraps in a release one —
    /// making a store-less board attempt a checkpoint, which is the opposite
    /// of what the sentinel was for.
    fn stored_checkpoint(&self) -> Option<u64>;

    /// Durably record a new high-water mark.
    fn checkpoint(&mut self, unix: u64) -> Result<(), alloc::string::String>;
}

/// The store a board falls back to when it has no usable durable medium —
/// misconfigured flash geometry, or a device that will not write.
///
/// Every write is refused with a stated reason rather than silently accepted,
/// which is the honest answer: such a board has nowhere to keep a credential,
/// so `SetAuth` against it must fail rather than appear to work until the next
/// reset. It is also the posture design 22 §4.3 gives a board with no seed at
/// all — it cannot hold a credential, so refusing to pretend is correct.
#[derive(Default)]
pub struct NullStore {
    empty: wayfinder_server::NodeSettings,
}

impl wayfinder_server::SettingsStore for NullStore {
    fn settings(&self) -> &wayfinder_server::NodeSettings {
        &self.empty
    }

    fn persist(
        &mut self,
        _update: wayfinder_server::NodeSettings,
    ) -> Result<(), alloc::string::String> {
        Err(alloc::string::String::from(
            "this node has no usable durable store, so nothing set over the management API \
             would survive a reset; it is refused rather than accepted and lost",
        ))
    }
}

impl NodeStore for NullStore {
    /// `None`: there is no medium, so no checkpoint is ever due.
    fn stored_checkpoint(&self) -> Option<u64> {
        None
    }

    fn checkpoint(&mut self, _unix: u64) -> Result<(), alloc::string::String> {
        Err(alloc::string::String::from(
            "this node has no durable store",
        ))
    }
}

/// Build the concrete [`Driver`] type for a capacity profile declared with
/// [`define_profile!`](wayfinder::define_profile).
///
/// A `Driver` names its link type, clock, link count, frame buffer and router
/// type; the last two both follow from the capacity profile, so the mapping
/// lives here rather than at a board's call site:
///
/// ```ignore
/// type NrfDriver = wayfinder_embedded_driver::driver_for!(RadioLink, BoardClock, 2, embedded);
/// ```
///
/// `$n` is the number of mesh links, which should match the profile's
/// `interfaces`; the profile is named by an ident path, since a `$p:path`
/// capture is opaque to `::CONST`.
#[macro_export]
macro_rules! driver_for {
    ($link:ty, $clock:ty, $n:expr, $($p:ident)::+) => {
        $crate::Driver<
            $link,
            $clock,
            $n,
            { $($p)::+::MAX_FRAME_LEN },
            ::wayfinder::router_for!($($p)::+),
        >
    };
}

use embassy_futures::select::Either3;
use embassy_futures::select::select3;
use wayfinder_protos::service::audit_request;
use wayfinder_protos::service::handle_router;
use wayfinder_server::EmbeddedQueryRx;
use wayfinder_server::RouterAdapter;

/// A monotonic clock plus an async delay — the one piece of platform the driver
/// can't provide itself.
///
/// A board implements this over its executor's timer (e.g. `embassy_time`):
/// [`now`](Self::now) reads the monotonic time since boot as a
/// [`core::time::Duration`] (the same clock the router ages routes against), and
/// [`sleep`](Self::sleep) completes after `duration` has elapsed.
// A native `async fn` in a trait, driven by static dispatch on embedded — the
// same shape (and same lint waiver) as [`LinkT`]; no `Send` bound is needed on
// a single-core embedded executor.
#[allow(async_fn_in_trait)]
pub trait Clock {
    /// The monotonic time since a fixed reference (typically boot).
    fn now(&self) -> Duration;

    /// Complete after `duration` has elapsed on this clock.
    async fn sleep(&self, duration: Duration);
}

/// One mesh interface's adaptive (Trickle) OGM schedule: emission starts at
/// `i_min` and backs off (doubling) toward `i_max` while the topology is stable,
/// snapping back to `i_min` on any change.  The `no_std` counterpart to
/// `wayfinder::config::TrickleConfig` (which is `alloc`-gated by its YAML
/// parsing) — a board hardcodes these rather than parsing a config file.
#[derive(Debug, Clone, Copy)]
pub struct TrickleParams {
    /// Minimum OGM interval — how quickly a link reconverges after a change.
    pub i_min: Duration,
    /// Maximum OGM interval — how quiet a stable link becomes.
    pub i_max: Duration,
}

impl Default for TrickleParams {
    /// `i_min = 1 s`, `i_max = 128 s` — the same defaults as
    /// `wayfinder::config::TrickleConfig`.
    fn default() -> Self {
        Self {
            i_min: Duration::from_secs(1),
            i_max: Duration::from_secs(128),
        }
    }
}

/// One outgoing frame staged between synchronous planning and async dispatch,
/// owning its payload so the transmit scratchpad can be reused immediately.
struct Staged<const FRAME_LEN: usize> {
    dst: Mac,
    protocol: u16,
    payload: HVec<u8, FRAME_LEN>,
    egress: Egress,
}

impl<const FRAME_LEN: usize> Staged<FRAME_LEN> {
    /// The widest payload this staging slot can hold, in bytes — the profile's
    /// `max_frame_len`. Exposed so a test can pin that the buffers really did
    /// follow the profile rather than the crate-wide default.
    #[cfg(test)]
    const fn payload_capacity() -> usize {
        FRAME_LEN
    }
}

/// A [`MeshSink`] that stages planned frames into a fixed [`heapless`] buffer
/// (no heap), to be drained by the async dispatch step.
struct StageSink<const STAGE: usize, const FRAME_LEN: usize> {
    frames: HVec<Staged<FRAME_LEN>, STAGE>,
}

impl<const STAGE: usize, const FRAME_LEN: usize> Default for StageSink<STAGE, FRAME_LEN> {
    fn default() -> Self {
        Self {
            frames: HVec::new(),
        }
    }
}

impl<const STAGE: usize, const FRAME_LEN: usize> MeshSink for StageSink<STAGE, FRAME_LEN> {
    /// Reports refusals, because this is the shell whose staging is bounded:
    /// a collapsed multicast is the largest frame the planner produces, so it
    /// is the first to be refused here, and the caller has directed copies to
    /// fall back to only if it is told.
    fn emit(&mut self, frame: OutgoingFrame<'_>) -> bool {
        let mut payload = HVec::new();
        if payload.extend_from_slice(frame.payload).is_err() {
            warn!(
                len = frame.payload.len(),
                "drop: staged payload exceeds frame buffer"
            );
            return false;
        }
        let staged = Staged {
            dst: frame.dst,
            protocol: frame.protocol,
            payload,
            egress: frame.egress,
        };
        if self.frames.push(staged).is_err() {
            warn!("drop: staging buffer full");
            return false;
        }
        true
    }
    // `deliver_local` keeps its default no-op: a radio relay has no host device.
}

/// The embedded router event loop and the state it owns.
///
/// `L` is the mesh-link type (a single concrete link, or a board-defined `enum`
/// dispatching across mixed media); `C` is the board's [`Clock`]; `N` is the
/// number of mesh interfaces.  All state is fixed-capacity, so a `Driver` is a
/// single long-lived value (typically a `static` or held in the executor task).
pub struct Driver<
    L,
    C,
    const N: usize,
    const FRAME_LEN: usize = { wayfinder::host::MAX_FRAME_LEN },
    R = CentralRouter,
> {
    router: R,
    links: [L; N],
    clock: C,
    mac: Mac,
    tx_buffer: [u8; FRAME_LEN],
    stage: StageSink<N, FRAME_LEN>,
    /// The node's monotone floor on absolute time.
    ///
    /// A board has no RTC and no NTP, so this is the whole of what it knows
    /// about the year: an anchor an installer stamped (`SetAuth`'s
    /// `installer_unix`, or `SetTime`) plus elapsed monotonic time, and
    /// [`Clocked::Unknown`](wayfinder::wayfinder_auth::Clocked) until one
    /// arrives. Fed to the router on every pass of the loop, so certificate
    /// validity is judged under a posture that says what the node can actually
    /// prove rather than against a counter that reads 1970 (design 20 §4.4).
    wall: WallClock,
    /// Monotonic instant of the last clock-checkpoint *attempt*, or `None`
    /// before the first.
    ///
    /// Attempts rather than successes: a store that cannot write leaves the
    /// stored checkpoint where it is, so a success-only guard would have the
    /// loop ask again on every pass. See
    /// [`write_checkpoint_if_due`](Driver::write_checkpoint_if_due).
    checkpoint_attempted: Option<Duration>,
    /// The identity seed this node runs under, as the adapter's write-back
    /// slot.
    ///
    /// `SetAuth`'s *certify the identity I already have* branch reads it, and
    /// writes back through it when an install rotates the seed — so the value
    /// here is the one the record holds, not a stale copy. Without it that
    /// branch refuses with "this node has no identity to certify" on a board
    /// that plainly has one, which is the only shape of enrolment a board with
    /// no debugger can use: the wholesale path needs a reboot to take effect,
    /// and a dongle cannot be reset from the host.
    ///
    /// Set by [`restore`](Driver::restore); `None` on a board whose durable
    /// store is unusable, which has no seed to certify either.
    identity_seed: Option<[u8; 32]>,
    /// Each link's declared native fan-out, cached at construction.
    ///
    /// Read here rather than at use: the receive arm holds a borrow of `links`
    /// through its `recv` futures, so the medium cannot be asked about itself
    /// while one of its frames is in hand. It is a property of the medium and
    /// does not change once the link is built, so one read is enough.
    fan_out: [Option<NonZeroU8>; N],
}

/// Constructor at the default (host) capacities.
///
/// Kept on the fully-defaulted type rather than the generic impl below: a
/// struct's default const parameters do not drive inference in expression
/// position, so a generic `Driver::new` would force every board to name all
/// fourteen (`E0284`). A constrained board builds one with
/// [`with_capacities`](Driver::with_capacities), usually via
/// [`driver_for!`](crate::driver_for).
impl<L: LinkT, C: Clock, const N: usize> Driver<L, C, N> {
    /// Build a driver for node `mac` over the given mesh `links` and `clock`,
    /// at the default capacities. See
    /// [`with_capacities`](Driver::with_capacities) for the arguments.
    /// `#[inline(never)]` for the reason given on
    /// [`with_capacities`](Driver::with_capacities): this returns the same
    /// oversized value and must not be built in a caller's poll frame.
    #[inline(never)]
    pub fn new(
        mac: Mac,
        links: [L; N],
        clock: C,
        trickle: &[TrickleParams],
        features: &[LinkFeatures],
        names: &[&str],
    ) -> Self {
        Self::with_capacities(mac, links, clock, trickle, features, names)
    }
}

impl<L: LinkT, C: Clock, const N: usize, const FRAME_LEN: usize, R: RouterAuthOps>
    Driver<L, C, N, FRAME_LEN, R>
{
    /// A board must not hand the driver more mesh links than its profile's
    /// `interfaces` capacity.
    ///
    /// The router only tracks `INTERFACES` of them, so a surplus link would
    /// never be scheduled for an OGM (`configure_interface_ogm` no-ops past
    /// the bound) and the node would be silently mute on a link it believes is
    /// up. This is a compile-time check rather than the `debug_assert!` it
    /// replaces: that one compiled out of the `--release` images boards
    /// actually flash, and compared `N` against the crate-wide default instead
    /// of the profile, so it passed for exactly the profiles that needed it.
    const _LINKS_FIT_PROFILE: () = assert!(
        N <= R::INTERFACES,
        "more mesh links than the profile's `interfaces` capacity"
    );

    /// Build a driver for node `mac` over the given mesh `links` and `clock`.
    /// `trickle` supplies each interface's adaptive OGM bounds
    /// ([`TrickleParams`]), `features` its per-link participation gates, and
    /// `names` its human-readable label, all in interface order; interfaces
    /// without an entry fall back to [`TrickleParams::default`] /
    /// [`LinkFeatures::default`] (full participation) / unnamed.
    ///
    /// [`LinkFeatures::default`]: wayfinder::features::LinkFeatures
    /// `#[inline(never)]` is load-bearing on a board, not a codegen hint. A
    /// `Driver` is tens of kilobytes (it owns the router and every link), and
    /// a board builds one inside its `async` main. Inlined, the constructor's
    /// result is materialised in a *stack temporary* that the enclosing
    /// coroutine's poll prologue reserves — and an executor holds a task's
    /// poll frame for the task's whole life, so that temporary becomes
    /// permanently-reserved stack rather than transient. Out of line, the
    /// caller passes the coroutine's own slot as the return pointer and no
    /// temporary exists. Under LTO this was worth 13 KB of the STM32F411's
    /// stack, enough to fail `scripts/stack-budget.py`.
    #[inline(never)]
    pub fn with_capacities(
        mac: Mac,
        links: [L; N],
        clock: C,
        trickle: &[TrickleParams],
        features: &[LinkFeatures],
        names: &[&str],
    ) -> Self {
        let () = Self::_LINKS_FIT_PROFILE;
        let mut router = R::with_capacities(mac);
        // Install each interface's adaptive OGM schedule and participation
        // features up front so the periodic timer and egress gates have a
        // per-interface entry from the start. The Trickle timer is armed on
        // every interface regardless of `tx_ogm`; a `tx_ogm`-off link has its
        // emission suppressed at poll time, keeping the features runtime-
        // toggleable without arming/disarming timers.
        for idx in 0..N {
            let cfg = trickle.get(idx).copied().unwrap_or_default();
            router.configure_interface_ogm(idx, cfg.i_min, cfg.i_max, Duration::ZERO);
            let link_features = features.get(idx).copied().unwrap_or_default();
            router.set_link_features(idx, link_features);
            if let Some(name) = names.get(idx) {
                router.set_interface_name(idx, name);
            }
            // Keep-alive rides on the same per-link `features` entry (no
            // separate constructor parameter) — its `tx_keepalive` supplies
            // the schedule, `None` leaving that interface's timer unarmed.
            router.configure_interface_keepalive(
                idx,
                link_features.tx_keepalive.map(|c| c.interval()),
                Duration::ZERO,
            );
        }
        let fan_out = core::array::from_fn(|i| links[i].fan_out());
        Self {
            router,
            links,
            clock,
            mac,
            wall: WallClock::new(),
            checkpoint_attempted: None,
            identity_seed: None,
            tx_buffer: [0u8; FRAME_LEN],
            stage: StageSink::default(),
            fan_out,
        }
    }

    /// Run the event loop forever.  Never returns; the board spawns this on its
    /// executor.
    pub async fn run(&mut self) -> ! {
        loop {
            self.run_once().await;
        }
    }

    /// Run a single iteration: race each mesh link's `recv` against the periodic
    /// OGM timer, plan the winner into staged frames, then dispatch them onto
    /// the mesh.
    pub async fn run_once(&mut self) {
        let now = self.clock.now();
        // When the soonest interface is next due to emit an OGM or a
        // keep-alive, or the soonest next-hop proof challenge falls due.
        // Recomputed every iteration, so a timer reset by the frame just
        // processed shortens the next sleep automatically.
        //
        // The challenge deadline has to be in this `min`, not left to ride the
        // OGM timer: a newly discovered originator would otherwise wait for the
        // next Trickle deadline — up to a full `i_max` on a settled mesh —
        // before it was challenged at all, and carry no traffic until then.
        let due = self
            .router
            .next_broadcast_after(now)
            .min(self.router.next_keepalive_after(now))
            .min(
                self.router
                    .next_challenge_after(now)
                    .unwrap_or(core::time::Duration::MAX),
            )
            // A running ping session's deadline. Same requirement as the
            // challenge one above: a probe left riding the OGM schedule waits
            // up to a full `i_max` on a settled mesh, by which time it has
            // already timed out and a working path reads as totally lossy.
            .min(
                self.router
                    .next_ping_after(now)
                    .unwrap_or(core::time::Duration::MAX),
            );
        // **No renewal deadline here, and no renewal poll below.** This loop
        // has no store: it is `run()`, the arm a board takes when it has no
        // management port. A renewal it could not make durable would install a
        // certificate, report success through `renewal_replies_accepted`, and
        // be lost at the next reset — a board that reads healthy and comes back
        // stale, which is worse than one that never renewed. Renewal lives in
        // `run_once_with_mgmt`, which holds the store that finishes the job.
        trace!(?now, ?due, "run_once");

        // Destructure into disjoint field borrows so the planning step can hold
        // a borrow of `links` (via the recv futures) alongside `router`/`stage`.
        let Driver {
            router,
            links,
            fan_out,
            clock,
            mac,
            wall,
            tx_buffer,
            stage,
            ..
        } = self;
        // Advanced before anything reads it, and through the router rather than
        // straight at the auth state: advancing the clock can evict a lapsed
        // peer's key, and the engine's next-hop proofs were answered *with*
        // that key, so the two must move together (design 09 §8.10). Until an
        // installer anchors this node the posture is `Unknown` — every
        // signature is still checked, no validity window is judged, and the
        // node routes (design 20 §4.2).
        router.set_auth_time(now, wall.posture(now));
        stage.frames.clear();

        // Build one `recv` future per link and race them against the OGM timer.
        // `select_array` reports which link fired; an empty link set (`N == 0`)
        // is pending forever, so the timer arm still drives OGM emission.
        let recv_futs = links.each_mut().map(|link| link.recv());
        match select(select_array(recv_futs), clock.sleep(due)).await {
            Either::First((result, idx)) => {
                handle_link_result(now, router, idx, result, tx_buffer, fan_out, stage)
            }
            Either::Second(()) => poll_due_all(router, now, tx_buffer, stage),
        }

        // The select's futures are dropped here, freeing `links` to be borrowed
        // mutably again for dispatch.
        dispatch(links, router, *mac, now, stage).await;
    }
}

/// The management arm is the one place still spelling the capacities out.
///
/// `wayfinder-server`'s `RouterAdapter` is itself const-generic over all eleven
/// (it projects the router's full observability surface onto
/// `WayfinderDataProvider`), so it cannot accept an opaque `R: RouterOps`. This
/// `impl` is therefore specialised to a concrete `CentralRouter` rather than
/// growing `RouterOps` by the ~25 read-only accessors the adapter needs, which
/// would create a second near-copy of `WayfinderDataProvider` to keep in step.
/// No practical loss: `R` is always a `CentralRouter` today. Making
/// `RouterAdapter` generic over `RouterOps` would retire this block.
impl<
    L: LinkT,
    C: Clock,
    const N: usize,
    const FRAME_LEN: usize,
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
        L,
        C,
        N,
        FRAME_LEN,
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
    /// Run the event loop forever, additionally serving management-API queries.
    ///
    /// The same mesh loop as [`run`](Self::run), plus a third `select` arm that
    /// answers requests forwarded from a `wayfinder-server` `serve` loop over
    /// `mgmt` (the router-loop half of an
    /// [`EmbeddedQueryChannel`](wayfinder_server::EmbeddedQueryChannel)). The
    /// serve loop owns the management byte stream (a UART) on its own task; this
    /// loop owns the router, so a query is serviced synchronously here — against
    /// a fresh [`RouterAdapter`] at the current instant — and never shares the
    /// router across tasks. Never returns; the board spawns this on its executor.
    pub async fn run_with_mgmt(
        &mut self,
        mgmt: &EmbeddedQueryRx<'_>,
        store: &mut dyn NodeStore,
    ) -> ! {
        loop {
            self.run_once_with_mgmt(mgmt, store).await;
        }
    }

    /// Bring this driver up from the record the board loaded: restore the
    /// clock checkpoint, then install the credential the record holds.
    ///
    /// Call it once, before [`run_with_mgmt`](Self::run_with_mgmt).
    ///
    /// # The clock comes from the checkpoint and nothing else
    ///
    /// Design 20 §4.4 states this in bold and it is the rule most easily
    /// broken by being helpful: a restored certificate's `not_before` looks
    /// like a perfectly good lower bound on the current time, and using it
    /// resets the expiry clock on **every power cycle**, by an amount that
    /// grows with the certificate's age, triggerable by anyone who can pull
    /// the cable. The damage is not mainly to this node's own credential —
    /// clocked peers reject that anyway — but to its judgement of *everyone
    /// else's*: a board with a one-year certificate rebooting at month eleven
    /// would believe it is month zero and honour peer certificates revoked by
    /// expiry ten months earlier.
    ///
    /// The checkpoint is handed to [`WallClock::anchor`], so it goes through
    /// that method's `max` and its plausibility floor: a stale page cannot
    /// pull a corrected estimate back, and a checkpoint of zero — a board that
    /// was never anchored — leaves the node `Unknown`, which is a supported
    /// state it keeps routing in.
    ///
    /// # The credential is not re-verified
    ///
    /// Its signature was checked by the `SetAuth` that stored it, and
    /// `wayfinder-tap`'s boot path makes the same choice for the same reason.
    /// What *is* checked here is the binding that a stored record could
    /// violate: the certificate must name the address this node runs under.
    /// It cannot fail on a record this build wrote — the address is derived
    /// from the seed the certificate names — but a record from a build
    /// predating that rule could hold one, and arming from it would have the
    /// board sign OGMs no peer attributes to it (#60).
    pub fn restore(&mut self, record: &crate::identity::NodeRecord) -> Restored {
        use wayfinder::auth::OgmAuth;
        use wayfinder::wayfinder_auth::MembershipCert;
        use wayfinder::wayfinder_auth::TrustAnchor;

        // Handed to the adapter so `SetAuth` can certify this identity in
        // place rather than only replace it. Set before any early return: a
        // board whose credential is refused below still has a seed, and
        // certifying it is exactly how an operator fixes that.
        self.identity_seed = Some(record.seed);

        let now = self.clock.now();
        // First, so anything below is judged under the restored posture — and
        // from the checkpoint alone. See the doc above.
        if record.checkpoint_unix != 0 && !self.wall.anchor(record.checkpoint_unix, now) {
            warn!(
                checkpoint = record.checkpoint_unix,
                "the stored clock checkpoint was refused as implausible; this node cannot \
                 judge validity windows"
            );
        }

        // Fail closed on a revocation of this node. Nothing on a board writes
        // one today — the record carries the field so a `SetAuth` that
        // *clears* it round-trips — so finding one means either a future
        // build wired the write, or the record is not what this build thinks.
        // Arming and hoping is the single outcome design 16 exists to
        // prevent; judging its window properly belongs with whatever wires
        // self-revocation on embedded.
        if record.self_revocation.is_some() {
            return Restored::Refused(RefusalReason::SelfRevoked);
        }

        let (Some(cert_bytes), Some(anchor_bytes)) = (&record.cert, &record.trust_anchor) else {
            // A certificate with no anchor to chain to is not a credential,
            // and neither is an anchor with nothing under it.
            return if record.cert.is_some() || record.trust_anchor.is_some() {
                Restored::Refused(RefusalReason::IncompleteCredential)
            } else {
                Restored::Unauthenticated
            };
        };
        let Some(cert) = MembershipCert::from_bytes(cert_bytes) else {
            return Restored::Refused(RefusalReason::Unparseable);
        };
        let Some(anchor) = TrustAnchor::from_bytes(anchor_bytes) else {
            return Restored::Refused(RefusalReason::Unparseable);
        };
        if cert.node_mac != record.mac().0 {
            return Restored::Refused(RefusalReason::CertifiedAddressMismatch);
        }

        let mut auth = OgmAuth::with_capacities(record.keypair(), cert, anchor);
        // Where this board renews, derived from the pinned provider key the
        // record keeps — the same derivation `RouterAdapter::set_auth` makes
        // when the credential is first installed, so a reboot inside the
        // renewal window carries on renewing rather than waiting for an
        // operator with a serial cable (design 24 §4.4).
        auth.set_renewal_authority(record.renewal_provider_key.as_ref());
        self.router.set_auth(auth);
        Restored::Authenticated
    }

    /// Write a certificate a renewal just installed back to `store`, if one is
    /// waiting.
    ///
    /// The shell's half of a split the `no_std` core cannot close: it can
    /// change the credential this node runs under, but it cannot write flash.
    /// Without this a renewed board keeps routing until somebody power-cycles
    /// it and then comes back under the certificate it renewed away from —
    /// which by then is the one that has lapsed.
    ///
    /// Costs nothing when there is nothing to write, which is every turn of the
    /// loop but a handful per certificate lifetime.
    ///
    /// A failed write is reported and **not retried**. The node keeps running
    /// under the renewed certificate either way, and re-attempting a store that
    /// just refused would spend the erase budget design 22 §4.5 sizes on a
    /// write that is failing for a reason another attempt will not change. The
    /// alarm is the operator-facing half: what it says is that this board will
    /// come back stale, which is a thing to fix before the reset rather than
    /// after.
    fn persist_renewed_cert(&mut self, store: &mut dyn NodeStore) {
        let Some(cert) = self.router.take_renewed_cert() else {
            return;
        };
        // Every field but the certificate carried over from what is stored:
        // this write replaces one blob, and rebuilding the identity from
        // anything else would be a chance to drop the seed or the anchor that
        // certificate chains to.
        let Some(mut identity) = store.settings().identity.clone() else {
            // Unreachable in the direction that matters: a renewal only ever
            // answers a request a credentialed node made. Reported rather than
            // ignored, because reaching it means the record and the running
            // auth state disagree about whether this node has an identity.
            warn!(
                "a renewed certificate has nowhere to be written: this node holds no \
                 stored identity to replace"
            );
            return;
        };
        identity.cert = cert.to_bytes().to_vec();
        if let Err(e) = store.persist(wayfinder_server::NodeSettings {
            identity: Some(identity),
            ..Default::default()
        }) {
            warn!(
                error = %e,
                "could not make a renewed certificate durable; this node is running under it \
                 but will come back to the previous one after a reset"
            );
            // `CertNotDurable`, **not** `CertExpiring`. The renewal-window row
            // is cleared by the poll that finds this node no longer due — which
            // is exactly what a successful renewal produces — so raising this
            // under that kind would have the renewal retire the one row saying
            // the renewal was not made durable. The board would then read as
            // healthy right up until somebody power-cycled it.
            alarm!(
                Severity::Warning,
                AlarmKind::CertNotDurable,
                Subject::Node(NodeId::new(&self.router.self_ident().0)),
                "renewed certificate not written to storage; a reset loses it"
            );
        }
    }

    /// Write the clock's current estimate back to `store`, if enough of it has
    /// accumulated to be worth an erase.
    ///
    /// Called at the top of every pass of the loop rather than on a timer of
    /// its own: a board wakes far more often than [`CHECKPOINT_INTERVAL`] — an
    /// interface's `i_max` is at most a couple of minutes — so a plain check
    /// here fires on time without another deadline in the `select`'s `min`.
    ///
    /// Three guards, all of them about flash wear ([`CHECKPOINT_INTERVAL`]):
    ///
    /// - An **unanchored** board writes nothing. It has nothing to say.
    /// - The estimate must have run at least an interval past what is stored.
    ///   This is what makes a plain reboot free — the restored estimate starts
    ///   *at* the stored value — while still writing promptly after a
    ///   `SetAuth`, whose anchor lands a whole unix epoch past a fresh board's
    ///   zero.
    /// - Attempts, not just successes, are rate-limited on the monotonic
    ///   clock. A store that cannot write leaves the stored checkpoint where
    ///   it was, so without this it would be asked again on every pass.
    fn write_checkpoint_if_due(&mut self, store: &mut dyn NodeStore) {
        let now = self.clock.now();
        let Some(estimate) = self.wall.estimate(now) else {
            return;
        };
        // A store that keeps no checkpoint is never due — and says so as an
        // absence rather than as a large number, so there is nothing here to
        // overflow.
        let Some(stored) = store.stored_checkpoint() else {
            return;
        };
        // Saturating, because `stored` is whatever was last checkpointed and
        // the clock takes any plausible instant an operator hands it: a
        // `SetTime` far into the future is checkpointed like any other, and
        // adding an interval to it must not wrap.
        if estimate < stored.saturating_add(CHECKPOINT_INTERVAL.as_secs()) {
            return;
        }
        if self
            .checkpoint_attempted
            .is_some_and(|last| now.saturating_sub(last) < CHECKPOINT_INTERVAL)
        {
            return;
        }
        self.checkpoint_attempted = Some(now);
        if let Err(e) = store.checkpoint(estimate) {
            warn!(
                error = %e,
                "could not write the clock checkpoint; this node will come back undated \
                 after its next reset"
            );
        }
    }

    /// One iteration of [`run_with_mgmt`](Self::run_with_mgmt): race each link's
    /// `recv`, the periodic OGM/keep-alive timer, and an inbound management
    /// query; plan the winner; then dispatch any staged frames. A served query
    /// stages nothing, so its dispatch is a no-op.
    async fn run_once_with_mgmt(&mut self, mgmt: &EmbeddedQueryRx<'_>, store: &mut dyn NodeStore) {
        // Here rather than on a deadline of its own: the interval is hours and
        // this loop wakes every few seconds, so a check costs nothing and
        // keeps the `select`'s `min` about the mesh.
        self.write_checkpoint_if_due(store);
        // Beside the checkpoint, and on the same argument: this is a write that
        // only ever happens when there is something new to say, and the thing
        // it says — the certificate this node is now running under — is lost at
        // the next reset if nothing writes it. It is the mgmt-arm loop rather
        // than `run_once` that does so because this is where the store is.
        self.persist_renewed_cert(store);

        let now = self.clock.now();
        // Same five deadlines as `run_once`, and for the same reasons.
        let due = self
            .router
            .next_broadcast_after(now)
            .min(self.router.next_keepalive_after(now))
            .min(
                self.router
                    .next_challenge_after(now)
                    .unwrap_or(core::time::Duration::MAX),
            )
            // A running ping session's deadline. Same requirement as the
            // challenge one above: a probe left riding the OGM schedule waits
            // up to a full `i_max` on a settled mesh, by which time it has
            // already timed out and a working path reads as totally lossy.
            .min(
                self.router
                    .next_ping_after(now)
                    .unwrap_or(core::time::Duration::MAX),
            )
            // The renewal check. Folded in here and not in `run_once` because
            // this is the loop that holds the store, and so the only one that
            // can finish a renewal by making it durable.
            .min(
                self.router
                    .next_renewal_after(now)
                    .unwrap_or(core::time::Duration::MAX),
            );

        let Driver {
            router,
            links,
            fan_out,
            clock,
            mac,
            wall,
            tx_buffer,
            stage,
            identity_seed,
            ..
        } = self;
        // Same reason as `run_once`: advanced before anything reads it, and
        // through the router so an eviction and the proofs behind it move
        // together.
        router.set_auth_time(now, wall.posture(now));
        stage.frames.clear();

        let recv_futs = links.each_mut().map(|link| link.recv());
        match select3(select_array(recv_futs), clock.sleep(due), mgmt.recv()).await {
            Either3::First((result, idx)) => {
                handle_link_result(now, router, idx, result, tx_buffer, fan_out, stage)
            }
            Either3::Second(()) => {
                poll_due_all(router, now, tx_buffer, stage);
                // Explicit, because `poll_due_all` deliberately excludes it:
                // renewal is only safe to start on a shell that can make the
                // answer durable, and this is that shell.
                poll_due_renewal(router, now, tx_buffer, stage);
            }
            Either3::Third(request) => {
                trace!("servicing forwarded management query");
                // Build the response against a fresh adapter at `now`, then hand
                // it back to the waiting serve loop. `None` — an embedded node is
                // never a provider-mode certificate authority.
                //
                // No `.with_epoch_unix(...)`: `Clock` (above) is monotonic
                // only, with no wall-clock source to supply one from. What
                // goes in instead is `with_wall_clock`, the node's own
                // monotone floor — so `SetAuth` verifies the certificate under
                // `Clocked::AtLeast`/`Unknown` (signature, mesh id and key↔MAC
                // binding all checked; the window judged only where the floor
                // proves it) and then *anchors* that floor from the
                // installer's stamp and the certificate's own `not_before`.
                // Before design 20 this path rejected every certificate ever
                // issued as not-yet-valid, which is why `SetAuth` over a
                // board's management port was not wired up at all.
                // `handle_router`, not the combined service: an embedded node
                // has no certificate authority, so the router half is all it
                // can answer. The audit record is emitted explicitly because
                // `WayfinderService::handle` used to emit it and no longer runs
                // on this path.
                audit_request(&request);
                // No `with_renewal_provider` slot, which is now only about
                // *reporting*. A board does renew itself — over the mesh, since
                // design 24 — and the `SetAuth` below does record where: it
                // reaches `RecordSettings` through `with_settings`, which
                // persists the provider's pinned key, and `set_auth` arms the
                // router from it.
                //
                // What is missing is the adapter's live slot, which is what
                // `GetSecurityStatus` reads its `renewal_provider` field from.
                // So a board reports no provider while renewing perfectly well,
                // and an operator sees a non-zero `renewal_requests_sent`
                // beside an empty target. Wire the slot through to fix the
                // report; nothing about the renewal itself depends on it.
                let response = handle_router(
                    &mut RouterAdapter::new(&mut *router, now)
                        .with_wall_clock(wall)
                        // The seed this node runs under, so `SetAuth` can
                        // certify it in place. Also what earns a client the
                        // self-key access tier, which a board could not offer
                        // before it had a durable seed to compare against.
                        .with_identity(identity_seed)
                        // The board's durable record. Without it a `SetAuth`
                        // over this port installed a credential that lived
                        // until the next reset and no further, which is what
                        // design 22 exists to fix.
                        .with_settings(store),
                    request,
                )
                // An embedded node runs no certificate authority, so an
                // authority request gets the same "not a certificate-authority
                // provider" a router-only host gives, which clients render as
                // such. Anything else (a repeated `Authenticate`, an empty
                // request) keeps its own protocol-error answer.
                .unwrap_or_else(wayfinder_protos::service::handle_without_authority);
                mgmt.reply(response).await;
            }
        }

        dispatch(links, router, *mac, now, stage).await;
    }
}

/// Drain the staged frames onto the mesh: authenticate each directed frame with
/// a pairwise tag (when auth is on), then send it out the interface(s) the
/// egress plan selects, recording the transmit for throughput accounting.
async fn dispatch<
    L: LinkT,
    const N: usize,
    const STAGE: usize,
    const FRAME_LEN: usize,
    R: RouterOps,
>(
    links: &mut [L; N],
    router: &mut R,
    mac: Mac,
    now: Duration,
    stage: &mut StageSink<STAGE, FRAME_LEN>,
) {
    for i in 0..stage.frames.len() {
        let dst = stage.frames[i].dst;
        let protocol = stage.frames[i].protocol;
        let egress = stage.frames[i].egress;
        let body_len = stage.frames[i].payload.len();

        // Reserve the trailer bytes so the shared planner can write a pairwise
        // tag into them when this directed frame needs one.
        if stage.frames[i]
            .payload
            .resize(body_len + MAX_TRAILER_LEN, 0)
            .is_err()
        {
            warn!("drop: no room for auth trailer");
            continue;
        }
        let Some(plan) = plan_dispatch(
            router,
            now,
            dst,
            protocol,
            egress,
            body_len,
            &mut stage.frames[i].payload,
            N,
        ) else {
            continue; // auth on but untaggable — drop rather than emit in clear
        };

        let data = LinkFrameData {
            dst,
            protocol,
            payload: plan.payload(),
        };

        for idx in plan.targets().iter() {
            send_on(links, router, idx, mac, &data, now).await;
        }
    }
}

/// Send one framed datagram out interface `idx`, folding the byte count into the
/// interface's transmit-rate estimator; a send error is logged and dropped
/// (fire-and-forget, matching the tokio driver's `LinkError` handling on radios).
async fn send_on<L: LinkT, const N: usize, R: RouterOps>(
    links: &mut [L; N],
    router: &mut R,
    idx: usize,
    mac: Mac,
    data: &LinkFrameData<'_>,
    now: Duration,
) {
    if let Some(link) = links.get_mut(idx) {
        match link.send(mac, data).await {
            Ok(sent) => router.record_tx(idx, sent, now),
            // No radio in this slot: expected on a board whose link array is
            // sized for hardware it may not have, so not a warning — and
            // deliberately not recorded, since `record_tx` would touch the
            // index into the interface table and publish an interface that
            // physically isn't there.
            Err(LinkError::NotPresent) => {
                trace!(iface = idx, "drop: no radio on this link")
            }
            // A contended medium is not an operator-actionable event, and it
            // is reachable from ambient RF: with carrier-sense CCA, any
            // neighbour transmitting — or a co-channel Wi-Fi AP, or a
            // microwave — makes `try_send` report the channel busy. `warn!`
            // here would evict the rest of the bounded log ring, which on a
            // probe-less board is the only observability there is. The
            // persistent case is the alarm board's job, not the log's.
            Err(LinkError::TransmitFailed) => {
                trace!(iface = idx, "drop: medium busy")
            }
            Err(e) => warn!(iface = idx, error = ?e, "drop: link send failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use interfaces::link::LinkError;
    use interfaces::link::LinkMetrics;
    use wayfinder::batman::wire::BATMAN_VERSION;
    use wayfinder::batman::wire::BatmanOgmPacket;
    use wayfinder::batman::wire::BatmanPacketType;
    use wayfinder::interfaces::frame::LinkFrame;
    use wayfinder::link::Received;
    use zerocopy::FromBytes;
    use zerocopy::IntoBytes;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// The raw bytes of a bare 1-hop OGM from `orig` — BATMAN header only, no
    /// TVLVs (auth-off), enough for the engine to re-flood it.
    fn bare_ogm_bytes(orig: Mac, seqno: u32, ttl: u8) -> Vec<u8> {
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: BATMAN_VERSION,
            ttl,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        ogm.as_bytes().to_vec()
    }

    /// The raw bytes of a link frame: `[dst][src][protocol be][payload]`.
    fn link_frame_bytes(dst: Mac, src: Mac, protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(dst.as_bytes());
        raw.extend_from_slice(src.as_bytes());
        raw.extend_from_slice(&protocol.to_be_bytes());
        raw.extend_from_slice(payload);
        raw
    }

    /// A fake mesh link: `send` records the framed datagram. `recv` yields the
    /// frame staged in `to_recv` (parked forever once `None`), so a test can feed
    /// exactly one received frame and observe how it is dispatched.
    #[derive(Default)]
    pub(crate) struct FakeLink {
        pub(crate) sent: Vec<(Mac, u16, Vec<u8>)>,
        to_recv: Option<Vec<u8>>,
    }

    impl LinkT for FakeLink {
        async fn send(
            &mut self,
            _origin: Mac,
            data: &LinkFrameData<'_>,
        ) -> Result<usize, LinkError> {
            self.sent
                .push((data.dst, data.protocol, data.payload.to_vec()));
            Ok(data.payload.len())
        }

        async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
            match self.to_recv.as_deref() {
                Some(bytes) => Ok(Received {
                    frame: LinkFrame::ref_from_bytes(bytes).expect("valid staged frame"),
                    metrics: LinkMetrics::default(),
                }),
                None => core::future::pending().await,
            }
        }
    }

    /// A link standing in for a radio slot that carries no hardware — the
    /// `MeshLink::Absent` shape a board uses to keep its link array a fixed
    /// size when a module isn't wired (see `bins/wayfinder-nrf52840`).
    #[derive(Default)]
    struct AbsentLink;

    impl LinkT for AbsentLink {
        async fn send(
            &mut self,
            _origin: Mac,
            _data: &LinkFrameData<'_>,
        ) -> Result<usize, LinkError> {
            Err(LinkError::NotPresent)
        }

        async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
            core::future::pending().await
        }
    }

    /// A slot with no radio behind it must not report transmitted frames.
    ///
    /// `record_tx` feeds the interface's transmit-rate estimator, and
    /// `RateEstimator::observe` counts a *frame* regardless of its byte count —
    /// so treating an absent link's `send` as a successful zero-byte
    /// transmission publishes a non-zero `tx_fps` for hardware that isn't
    /// attached. The interface still appears in `num_interfaces()` either way,
    /// since it is configured for OGM emission; the throughput is what lies.
    #[test]
    fn absent_link_reports_no_transmitted_frames() {
        let now = Duration::from_secs(30);
        let trickle = [TrickleParams::default()];
        let clock = ImmediateClock { now };
        let mut driver = Driver::new(mac(1), [AbsentLink], clock, &trickle, &[], &[]);

        futures::executor::block_on(driver.run_once());

        let throughput = driver
            .router
            .interface_throughput(0, now + Duration::from_secs(1))
            .expect("interface is configured for OGM emission");
        assert_eq!(
            throughput.tx_fps, 0.0,
            "an absent radio must not report transmitting frames"
        );
        assert_eq!(throughput.tx_bps, 0.0);
    }

    /// A clock frozen at a chosen instant whose `sleep` returns immediately, so
    /// a single `run_once` deterministically takes the periodic-OGM arm.
    pub(crate) struct ImmediateClock {
        pub(crate) now: Duration,
    }

    impl Clock for ImmediateClock {
        fn now(&self) -> Duration {
            self.now
        }
        async fn sleep(&self, _duration: Duration) {}
    }

    /// A clock whose `sleep` never completes, so a ready `recv` always wins the
    /// `select` — used to drive the received-frame (forwarding) arm of the loop
    /// deterministically, rather than the periodic-OGM timer arm.
    pub(crate) struct RecvClock {
        pub(crate) now: Duration,
    }

    impl Clock for RecvClock {
        fn now(&self) -> Duration {
            self.now
        }
        async fn sleep(&self, _duration: Duration) {
            core::future::pending().await
        }
    }

    /// One `run_once` at an instant where the single interface is due emits an
    /// OGM broadcast out that interface — the full embedded path: clock →
    /// `poll_due_ogms` → stage → dispatch → `LinkT::send`.
    #[test]
    fn run_once_emits_due_ogm_out_the_interface() {
        let trickle = [TrickleParams::default()];
        let clock = ImmediateClock {
            now: Duration::from_secs(30),
        };
        let mut driver = Driver::new(mac(1), [FakeLink::default()], clock, &trickle, &[], &[]);

        futures::executor::block_on(driver.run_once());

        let sent = &driver.links[0].sent;
        assert_eq!(sent.len(), 1, "one due interface => one OGM emission");
        let (dst, protocol, _payload) = &sent[0];
        assert_eq!(*dst, Mac::BROADCAST);
        assert_eq!(*protocol, wayfinder::DEFAULT_BATMAN_ETHER_TYPE);
    }

    /// A received OGM re-floods onto **both** interfaces, the ingress one
    /// included, across the full recv → handle → stage → dispatch path. The
    /// echo out interface 0 is deliberate; see `driver_core::Egress::Auto`.
    #[test]
    fn run_once_reforwards_received_ogm_onto_every_interface() {
        let ogm = link_frame_bytes(
            Mac::BROADCAST,
            mac(2),
            wayfinder::DEFAULT_BATMAN_ETHER_TYPE,
            &bare_ogm_bytes(mac(2), 1, 50),
        );
        let link0 = FakeLink {
            to_recv: Some(ogm),
            ..Default::default()
        };
        let link1 = FakeLink::default();
        // `RecvClock` keeps the OGM timer from firing, so the ready recv wins.
        let clock = RecvClock {
            now: Duration::from_secs(1),
        };
        let trickle = [TrickleParams::default(), TrickleParams::default()];
        let mut driver = Driver::new(mac(1), [link0, link1], clock, &trickle, &[], &[]);

        futures::executor::block_on(driver.run_once());

        assert_eq!(
            driver.links[0].sent.len(),
            1,
            "the re-flood returns out the ingress interface too"
        );
        assert_eq!(
            driver.links[1].sent.len(),
            1,
            "the OGM is re-flooded out the other interface"
        );
        let (dst, protocol, _payload) = &driver.links[1].sent[0];
        assert_eq!(*dst, Mac::BROADCAST);
        assert_eq!(*protocol, wayfinder::DEFAULT_BATMAN_ETHER_TYPE);
    }

    /// A management query forwarded over the channel while neither the OGM timer
    /// nor a link recv is ready is served against the router: the response is a
    /// `NodeInfo` whose node id is this driver's own MAC — the full embedded
    /// mgmt path: channel → `run_once_with_mgmt` → `RouterAdapter` → reply.
    #[test]
    fn run_once_with_mgmt_serves_a_node_info_query() {
        use wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest;
        use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as RespKind;
        use wayfinder_server::EmbeddedQueryChannel;

        let channel = EmbeddedQueryChannel::new();
        let (tx, rx) = channel.split();

        // `RecvClock` never completes its sleep and `FakeLink` never receives, so
        // the management arm is the only one that can fire this iteration.
        let clock = RecvClock {
            now: Duration::from_secs(1),
        };
        let trickle = [TrickleParams::default()];
        let mut driver = Driver::new(mac(1), [FakeLink::default()], clock, &trickle, &[], &[]);

        let client = async {
            tx.query(WayfinderRequest {
                request: Some(ReqKind::GetNodeInfo(GetNodeInfoRequest {})),
            })
            .await
        };

        let (_, response) = futures::executor::block_on(futures::future::join(
            driver.run_once_with_mgmt(&rx, &mut NullStore::default()),
            client,
        ));

        match response.response {
            Some(RespKind::NodeInfo(info)) => {
                assert_eq!(
                    info.node_id,
                    mac(1).as_bytes().to_vec(),
                    "the served NodeInfo carries this node's own MAC"
                );
                // The case the whole feature exists for: a board with no
                // filesystem and possibly no probe still says which build it
                // is. Nothing on this path injects it, so a board cannot be
                // built that answers without it.
                let build = info
                    .build_info
                    .expect("a board reports the build it was flashed with");
                assert_eq!(build.version, wayfinder_version::VERSION);
            }
            other => panic!("expected a NodeInfo response, got {other:?}"),
        }
        assert!(
            driver.links[0].sent.is_empty(),
            "a served query stages nothing to send: dispatch is a no-op"
        );
    }

    /// When a link `recv` and a management query are both ready in the same
    /// iteration, `select3` polls its arms left-to-right, so the link arm — not
    /// the management arm — wins: sustained mesh traffic can starve a pending
    /// management query indefinitely. This pins down that current behavior as a
    /// deliberate, verified property rather than an unverified implementation
    /// detail of `select3`'s poll order; it is not yet mitigated (no fairness /
    /// round-robin between the two).
    #[test]
    fn run_once_with_mgmt_prefers_ready_link_traffic_over_a_pending_query() {
        use futures::FutureExt;
        use wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest;
        use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;
        use wayfinder_server::EmbeddedQueryChannel;

        let channel = EmbeddedQueryChannel::new();
        let (tx, rx) = channel.split();

        // Enqueue a request without waiting for its reply: `query`'s send half
        // completes synchronously (the channel has a free slot), so polling it
        // once via `now_or_never` runs that far and leaves `mgmt.recv()` ready;
        // the reply half then blocks forever (no router loop is running yet),
        // which `now_or_never` correctly reports as `None`.
        let seed = tx.query(WayfinderRequest {
            request: Some(ReqKind::GetNodeInfo(GetNodeInfoRequest {})),
        });
        assert!(
            core::pin::pin!(seed).now_or_never().is_none(),
            "the reply half blocks forever with no router loop running yet"
        );

        // A link with a frame already staged is ready on the very first poll,
        // same as the mgmt arm seeded above.
        let ogm = link_frame_bytes(
            Mac::BROADCAST,
            mac(2),
            wayfinder::DEFAULT_BATMAN_ETHER_TYPE,
            &bare_ogm_bytes(mac(2), 1, 50),
        );
        let link0 = FakeLink {
            to_recv: Some(ogm),
            ..Default::default()
        };
        let clock = RecvClock {
            now: Duration::from_secs(1),
        };
        let trickle = [TrickleParams::default()];
        let mut driver = Driver::new(mac(1), [link0], clock, &trickle, &[], &[]);

        futures::executor::block_on(driver.run_once_with_mgmt(&rx, &mut NullStore::default()));

        // Had the mgmt arm won, `run_once_with_mgmt` would have drained the
        // request via `mgmt.recv()`, leaving the channel empty. It's still
        // there: the ready link arm won instead, starving the query this
        // iteration.
        assert!(
            core::pin::pin!(rx.recv()).now_or_never().is_some(),
            "the request enqueued before run_once_with_mgmt is still waiting to \
             be received: the ready link arm won this iteration over the ready \
             management arm"
        );
    }
}

#[cfg(test)]
mod capacity_tests {
    extern crate std;

    use core::mem::size_of;

    use super::*;
    use crate::tests::FakeLink;
    use crate::tests::ImmediateClock;

    wayfinder::define_profile! {
        /// A constrained board: two radios, BLE-sized frames.
        pub embedded {
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

    /// A driver on the constrained profile, over two fake links.
    type TinyDriver = crate::driver_for!(FakeLink, ImmediateClock, 2, embedded);

    /// The driver's own buffers dominate its footprint: today it stages
    /// `MAX_INTERFACES` frames of `MAX_LINK_FRAME_LEN` each (8 × 2048) plus a
    /// 2 KB transmit scratchpad, regardless of what the radios can carry.
    #[test]
    fn tiny_driver_is_substantially_smaller() {
        let tiny = size_of::<TinyDriver>();
        let host = size_of::<Driver<FakeLink, ImmediateClock, 2>>();
        assert!(
            tiny * 4 < host,
            "tiny driver ({tiny} B) should be well under a quarter of host ({host} B)"
        );
    }

    /// The staging buffers must follow the profile's frame length, not the
    /// 2 KB a host tap link needs.
    #[test]
    fn staged_frame_capacity_follows_the_profile() {
        assert_eq!(Staged::<256>::payload_capacity(), 256);
        assert_eq!(
            Staged::<{ wayfinder::host::MAX_FRAME_LEN }>::payload_capacity(),
            2048
        );
    }

    /// A profiled driver still emits a due OGM: the capacities are a memory
    /// decision, and the event loop is unchanged.
    #[test]
    fn tiny_driver_still_emits_a_due_ogm() {
        let trickle = [TrickleParams::default(), TrickleParams::default()];
        let clock = ImmediateClock {
            now: Duration::from_secs(30),
        };
        let mut driver: TinyDriver = Driver::with_capacities(
            mac(1),
            [FakeLink::default(), FakeLink::default()],
            clock,
            &trickle,
            &[],
            &[],
        );

        futures::executor::block_on(driver.run_once());

        let sent: usize = driver.links.iter().map(|l| l.sent.len()).sum();
        assert!(sent > 0, "a due interface must emit an OGM");
    }

    // Map a compact `u8` test identifier to a full MAC.
    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }
}

/// What a board does with the record it loaded, and what it writes back.
///
/// Design 22 §4.5/§4.6. The load-bearing test here is
/// [`restore_never_anchors_from_the_certificate`]: that is design 20 §4.4's
/// bold rule, and getting it wrong resets the expiry clock on every power
/// cycle for anyone who can pull the cable.
#[cfg(test)]
mod restore_tests {
    extern crate std;
    use std::rc::Rc;
    use std::vec::Vec;

    use super::tests::FakeLink;
    use super::tests::ImmediateClock;
    use super::*;
    use core::cell::RefCell;
    use wayfinder::wayfinder_auth::Clocked;
    use wayfinder::wayfinder_auth::Keypair;
    use wayfinder::wayfinder_auth::MIN_PLAUSIBLE_UNIX;
    use wayfinder::wayfinder_auth::MembershipCert;
    use wayfinder::wayfinder_auth::RevocationRecord;
    use wayfinder::wayfinder_auth::TrustAnchor;
    use wayfinder_storage::DurableStore;
    use zerocopy::IntoBytes;

    use crate::identity::NodeRecord;
    use crate::settings::RecordSettings;

    const MESH_ID: u32 = 0x4849_4C00;

    fn seed(n: u8) -> [u8; Keypair::SEED_LEN] {
        [n; Keypair::SEED_LEN]
    }

    /// An in-memory store, so a test can see what the driver wrote back.
    #[derive(Default, Clone)]
    struct MemStore {
        blob: Rc<RefCell<Option<Vec<u8>>>>,
        saves: Rc<RefCell<usize>>,
    }

    impl DurableStore for MemStore {
        type Error = core::convert::Infallible;

        fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            Ok(self.blob.borrow().as_ref().map(|b| {
                out[..b.len()].copy_from_slice(b);
                b.len()
            }))
        }

        fn save(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            *self.saves.borrow_mut() += 1;
            *self.blob.borrow_mut() = Some(data.to_vec());
            Ok(())
        }

        fn erase(&mut self) -> Result<(), Self::Error> {
            *self.blob.borrow_mut() = None;
            Ok(())
        }
    }

    /// A settings store already holding `record`.
    fn store_holding(record: NodeRecord) -> (RecordSettings<MemStore>, MemStore) {
        let medium = MemStore::default();
        let settings = RecordSettings::new(wayfinder_storage::Persisted::new(
            record,
            medium.clone(),
            crate::identity::RecordCodec,
        ));
        (settings, medium)
    }

    /// A certificate binding `keypair` to the address that keypair derives —
    /// the shape design 09 §5 requires, built by hand because minting a signed
    /// one needs the `std` `Authority` this crate does not link.
    ///
    /// Unsigned, which is fine here for the same reason it is fine on the
    /// host's own boot path: restoring a stored credential does not re-verify
    /// the signature (see [`Driver::restore`]).
    fn cert_for(keypair: &Keypair, not_before: u64) -> [u8; MembershipCert::SERIALIZED_LEN] {
        let cert = MembershipCert {
            version: 1,
            flags: 0,
            mesh_id: MESH_ID.into(),
            node_mac: keypair.derived_mac().0,
            ed_pubkey: keypair.ed_pubkey(),
            x_pubkey: keypair.x_pubkey(),
            not_before: not_before.into(),
            not_after: (not_before + 365 * 86_400).into(),
            signature: [0u8; 64],
        };
        cert.as_bytes()
            .try_into()
            .expect("a certificate is a fixed-size struct")
    }

    fn anchor_bytes() -> [u8; TrustAnchor::SERIALIZED_LEN] {
        TrustAnchor {
            mesh_id: MESH_ID,
            root_pubkey: [0x0B; 32],
        }
        .to_bytes()
    }

    /// A record holding a credential for its own seed, and `checkpoint`.
    fn credentialed(seed_byte: u8, checkpoint: u64, cert_not_before: u64) -> NodeRecord {
        let seed = seed(seed_byte);
        NodeRecord {
            checkpoint_unix: checkpoint,
            cert: Some(cert_for(&Keypair::from_seed(&seed), cert_not_before)),
            trust_anchor: Some(anchor_bytes()),
            ..NodeRecord::fresh(seed)
        }
    }

    fn driver_at(now: Duration, mac: Mac) -> Driver<FakeLink, ImmediateClock, 1> {
        Driver::new(
            mac,
            [FakeLink::default()],
            ImmediateClock { now },
            &[TrickleParams::default()],
            &[],
            &[],
        )
    }

    /// A board that has never been anchored comes back `Unknown` and
    /// unauthenticated — the state design 20 says it must keep routing in.
    #[test]
    fn restoring_an_empty_record_leaves_the_board_unclocked() {
        let now = Duration::from_secs(30);
        let record = NodeRecord::fresh(seed(0x01));
        let mut driver = driver_at(now, record.mac());

        assert_eq!(driver.restore(&record), Restored::Unauthenticated);
        assert_eq!(driver.wall.posture(now), Clocked::Unknown);
    }

    /// A stored checkpoint is what the clock comes back from.
    #[test]
    fn a_checkpoint_restores_the_clock_as_a_floor() {
        let now = Duration::from_secs(30);
        let record = NodeRecord {
            checkpoint_unix: 1_800_000_000,
            ..NodeRecord::fresh(seed(0x02))
        };
        let mut driver = driver_at(now, record.mac());

        driver.restore(&record);

        assert_eq!(
            driver.wall.posture(now),
            Clocked::AtLeast(1_800_000_000),
            "a restored board reports a floor, never a reading: it cannot measure how \
             long it was powered off"
        );
    }

    /// **Design 20 §4.4's bold rule, and the reason this design exists.**
    ///
    /// A board restores its clock from the checkpoint and *nothing else*. In
    /// particular never from its own certificate's `not_before`: that resets
    /// the expiry clock on every power cycle, by an amount that grows with the
    /// certificate's age, and anyone who can pull the cable triggers it. The
    /// damage is not mainly to its own credential — clocked peers reject that
    /// anyway — but to its judgement of *everyone else's*.
    #[test]
    fn restore_never_anchors_from_the_certificate() {
        let now = Duration::from_secs(30);
        // A credential whose window opened long ago, and no checkpoint.
        let record = credentialed(0x03, 0, 1_800_000_000);
        let mut driver = driver_at(now, record.mac());

        assert_eq!(driver.restore(&record), Restored::Authenticated);

        assert_eq!(
            driver.wall.posture(now),
            Clocked::Unknown,
            "the certificate's not_before must not reach the clock; a board that was \
             never checkpointed comes back undated even while credentialed"
        );
    }

    /// A checkpoint below the plausibility floor is refused by the clock, the
    /// same as any other implausible anchor — a board that has never been
    /// powered in 1970.
    #[test]
    fn an_implausible_checkpoint_is_refused() {
        let now = Duration::from_secs(30);
        let record = NodeRecord {
            checkpoint_unix: MIN_PLAUSIBLE_UNIX - 1,
            ..NodeRecord::fresh(seed(0x04))
        };
        let mut driver = driver_at(now, record.mac());

        driver.restore(&record);

        assert_eq!(driver.wall.posture(now), Clocked::Unknown);
    }

    /// A stored credential is installed, so the board comes back
    /// authenticated rather than having to be re-enrolled after every reset.
    #[test]
    fn a_stored_credential_is_installed_at_boot() {
        let now = Duration::from_secs(30);
        let record = credentialed(0x05, 1_800_000_000, 1_800_000_000);
        let mut driver = driver_at(now, record.mac());

        assert_eq!(driver.restore(&record), Restored::Authenticated);
        assert!(driver.router.auth_mut().is_some());
    }

    /// A certificate naming a MAC the board does not run under is refused.
    ///
    /// Unreachable through `SetAuth`, which checks the key against the seed it
    /// installs — but a record written by a build predating the seed-derived
    /// address could hold one, and arming from it would have the board sign
    /// OGMs no peer attributes to it. #60, refused rather than run.
    #[test]
    fn a_credential_for_another_mac_is_refused() {
        let now = Duration::from_secs(30);
        let record = NodeRecord {
            // A certificate for a *different* key's address.
            cert: Some(cert_for(&Keypair::from_seed(&seed(0xFF)), 1_800_000_000)),
            trust_anchor: Some(anchor_bytes()),
            ..NodeRecord::fresh(seed(0x06))
        };
        let mut driver = driver_at(now, record.mac());

        assert!(matches!(driver.restore(&record), Restored::Refused(_)));
        assert!(
            driver.router.auth_mut().is_none(),
            "a board must not arm under an address its credential does not name"
        );
    }

    /// A certificate with no anchor to chain to is not a credential.
    #[test]
    fn a_certificate_without_its_anchor_is_refused() {
        let now = Duration::from_secs(30);
        let seed = seed(0x07);
        let record = NodeRecord {
            cert: Some(cert_for(&Keypair::from_seed(&seed), 1_800_000_000)),
            trust_anchor: None,
            ..NodeRecord::fresh(seed)
        };
        let mut driver = driver_at(now, record.mac());

        assert!(matches!(driver.restore(&record), Restored::Refused(_)));
    }

    /// A record holding a revocation of this node does not arm, whatever else
    /// it holds. Nothing on a board writes one today; refusing is the
    /// fail-closed reading of finding one, and the alternative — arming and
    /// hoping — is the one outcome design 16 exists to prevent.
    #[test]
    fn a_held_self_revocation_refuses_to_arm() {
        let now = Duration::from_secs(30);
        let record = NodeRecord {
            self_revocation: Some([0x9E; RevocationRecord::SERIALIZED_LEN]),
            ..credentialed(0x08, 1_800_000_000, 1_800_000_000)
        };
        let mut driver = driver_at(now, record.mac());

        assert!(matches!(driver.restore(&record), Restored::Refused(_)));
        assert!(driver.router.auth_mut().is_none());
    }

    /// A record credentialed by a real authority, so the renewal path — which
    /// verifies every certificate it installs against the anchor — can be
    /// driven end to end. The rest of this module's fixtures hand-build an
    /// unsigned certificate, which `restore` accepts and `ingest_renew_reply`
    /// rightly does not.
    fn ca_credentialed(seed_byte: u8) -> (wayfinder::wayfinder_auth::Authority, NodeRecord) {
        let ca = wayfinder::wayfinder_auth::Authority::from_seed(&[0x5A; 32], MESH_ID);
        let seed = seed(seed_byte);
        let kp = Keypair::from_seed(&seed);
        let cert = ca.issue_cert(
            kp.derived_mac(),
            kp.ed_pubkey(),
            kp.x_pubkey(),
            1_700_000_000,
            1_800_000_100,
        );
        let record = NodeRecord {
            checkpoint_unix: 1_800_000_000,
            cert: Some(*cert.as_bytes().first_chunk().expect("fixed-size cert")),
            trust_anchor: Some(ca.trust_anchor().to_bytes()),
            renewal_provider_key: Some([0x0B; 32]),
            ..NodeRecord::fresh(seed)
        };
        (ca, record)
    }

    /// A certificate a renewal installed is made **durable**, or the board
    /// comes back at its next reset under the credential it renewed away from
    /// — which by then is the one that has lapsed.
    ///
    /// The router can change the credential it runs under; it cannot write
    /// flash. This is the shell's half of that split, and it is the half that
    /// turns design 24 from "a board keeps routing until someone power-cycles
    /// it" into a board that stays a member.
    #[test]
    fn a_renewed_certificate_is_made_durable() {
        let now = Duration::from_secs(30);
        let (ca, record) = ca_credentialed(0x30);
        let (mut settings, medium) = store_holding(record.clone());
        let mut driver = driver_at(now, record.mac());
        driver.restore(&record);
        let before = *medium.saves.borrow();

        // The exchange, driven through auth state rather than over a frame:
        // the relay and delivery halves are `wayfinder`'s tests, and what is
        // being pinned here is that the *shell* writes what they produce.
        let mut buf = [0u8; 512];
        driver
            .router
            .auth_mut()
            .unwrap()
            .build_renewal_request(&mut buf)
            .expect("the record names an authority to renew against");
        let kp = Keypair::from_seed(&seed(0x30));
        let renewed = ca.issue_cert(
            kp.derived_mac(),
            kp.ed_pubkey(),
            kp.x_pubkey(),
            1_700_000_000,
            1_900_000_000,
        );
        assert!(
            driver
                .router
                .auth_mut()
                .unwrap()
                .ingest_renew_reply(renewed.as_bytes())
        );

        driver.persist_renewed_cert(&mut settings);

        assert_eq!(*medium.saves.borrow(), before + 1);
        assert_eq!(
            settings.record().cert.as_ref().map(|c| &c[..]),
            Some(renewed.as_bytes()),
            "the record now holds the certificate the node is running under"
        );
        assert_eq!(
            settings.record().checkpoint_unix,
            1_800_000_000,
            "and the clock checkpoint beside it is untouched"
        );
        assert_eq!(
            settings.record().renewal_provider_key,
            Some([0x0B; 32]),
            "as is the authority it renews against"
        );
    }

    /// With nothing renewed there is nothing to write. A board's erase budget
    /// is the thing design 22 §4.5 sizes, and a write per loop turn would spend
    /// it on saying nothing.
    #[test]
    fn a_board_with_no_renewal_to_record_spends_no_flash_wear() {
        let now = Duration::from_secs(30);
        let (_, record) = ca_credentialed(0x31);
        let (mut settings, medium) = store_holding(record.clone());
        let mut driver = driver_at(now, record.mac());
        driver.restore(&record);
        let before = *medium.saves.borrow();

        driver.persist_renewed_cert(&mut settings);

        assert_eq!(*medium.saves.borrow(), before);
    }

    /// An unanchored board writes no checkpoint at all — it has nothing to
    /// write, and design 22 §4.5's whole budget is spent on writes that say
    /// something.
    #[test]
    fn an_unanchored_board_spends_no_flash_wear() {
        let now = Duration::from_secs(30);
        let record = NodeRecord::fresh(seed(0x09));
        let (mut settings, medium) = store_holding(record.clone());
        let mut driver = driver_at(now, record.mac());
        driver.restore(&record);

        driver.write_checkpoint_if_due(&mut settings);

        assert_eq!(*medium.saves.borrow(), 0);
    }

    /// A board anchored well past its stored checkpoint writes one promptly.
    ///
    /// This is the `SetAuth` case: a fresh board's stored checkpoint is zero
    /// and the installer's anchor is a real unix second, so the gap exceeds
    /// the interval immediately. Without it, a credential installed and then
    /// reset within six hours would come back `Unknown` — which is exactly the
    /// hardware test design 21 §5.3 says to flip.
    #[test]
    fn a_freshly_anchored_board_checkpoints_at_once() {
        let now = Duration::from_secs(30);
        let record = NodeRecord::fresh(seed(0x0A));
        let (mut settings, medium) = store_holding(record.clone());
        let mut driver = driver_at(now, record.mac());
        driver.restore(&record);
        driver.wall.anchor(1_800_000_000, now);

        driver.write_checkpoint_if_due(&mut settings);

        assert_eq!(*medium.saves.borrow(), 1);
        assert_eq!(settings.record().checkpoint_unix, 1_800_000_000);
    }

    /// ...and does not write again on the next pass of the loop. A board wakes
    /// far more often than every six hours, so an unguarded write here would
    /// burn the two-page erase budget in minutes.
    #[test]
    fn a_checkpoint_is_not_rewritten_on_every_pass() {
        let now = Duration::from_secs(30);
        let record = NodeRecord::fresh(seed(0x0B));
        let (mut settings, medium) = store_holding(record.clone());
        let mut driver = driver_at(now, record.mac());
        driver.restore(&record);
        driver.wall.anchor(1_800_000_000, now);

        for _ in 0..100 {
            driver.write_checkpoint_if_due(&mut settings);
        }

        assert_eq!(*medium.saves.borrow(), 1);
    }

    /// A board restored from a checkpoint does not immediately rewrite it: the
    /// restored estimate starts *at* the stored value, so there is nothing to
    /// advance. Otherwise every boot would cost an erase, and a board that
    /// reboots often would exhaust the budget long before its service life.
    #[test]
    fn a_reboot_alone_costs_no_erase() {
        let now = Duration::from_secs(30);
        let record = NodeRecord {
            checkpoint_unix: 1_800_000_000,
            ..NodeRecord::fresh(seed(0x0C))
        };
        let (mut settings, medium) = store_holding(record.clone());
        let mut driver = driver_at(now, record.mac());
        driver.restore(&record);

        driver.write_checkpoint_if_due(&mut settings);

        assert_eq!(*medium.saves.borrow(), 0);
    }

    /// Six hours of free-running later, the checkpoint advances.
    #[test]
    fn the_checkpoint_advances_once_the_interval_has_elapsed() {
        let boot = Duration::from_secs(30);
        let record = NodeRecord {
            checkpoint_unix: 1_800_000_000,
            ..NodeRecord::fresh(seed(0x0D))
        };
        let (mut settings, medium) = store_holding(record.clone());
        let mut driver = driver_at(boot, record.mac());
        driver.restore(&record);
        driver.write_checkpoint_if_due(&mut settings);
        assert_eq!(*medium.saves.borrow(), 0);

        driver.clock.now = boot + CHECKPOINT_INTERVAL;
        driver.write_checkpoint_if_due(&mut settings);

        assert_eq!(*medium.saves.borrow(), 1);
        assert_eq!(
            settings.record().checkpoint_unix,
            1_800_000_000 + CHECKPOINT_INTERVAL.as_secs()
        );
    }

    /// Six hours is the interval design 22 §4.5 settles on, and the number is
    /// pinned here because it is a **wear** decision with arithmetic behind it:
    /// two 4 KiB pages at ~10 000 erase cycles, alternating, is ~20 000 writes;
    /// at this interval that is ~13.7 years. An hour would be 2.3.
    #[test]
    fn the_checkpoint_interval_is_six_hours() {
        assert_eq!(CHECKPOINT_INTERVAL, Duration::from_secs(6 * 60 * 60));
    }

    /// **An anchored board with no durable medium must not fault.**
    ///
    /// A board that fell back to `NullStore` still serves its management port,
    /// and `SetTime` anchors the wall clock without going near a store — so
    /// `estimate` becomes `Some` and the due test runs against a store that
    /// keeps no checkpoint at all. That combination has to be a quiet no-op.
    #[test]
    fn an_anchored_board_with_no_store_never_checkpoints() {
        let now = Duration::from_secs(30);
        let mut driver = driver_at(now, NodeRecord::fresh(seed(0x0E)).mac());
        driver.wall.anchor(1_800_000_000, now);

        // Deliberately many passes: the loop calls this every time round.
        for _ in 0..10 {
            driver.write_checkpoint_if_due(&mut NullStore::default());
        }
    }

    /// **`NullStore` refuses every write, with a reason** — the entire
    /// justification for the type existing (design 22 §11.2). A board with no
    /// usable medium must fail a `SetAuth` rather than appear to accept one
    /// and lose it at the next reset.
    #[test]
    fn a_board_with_no_store_refuses_writes_and_says_why() {
        use wayfinder_server::SettingsStore;

        let mut store = NullStore::default();
        assert!(store.settings().is_empty());

        let err = store
            .persist(wayfinder_server::NodeSettings {
                require_auth: Some(true),
                ..Default::default()
            })
            .expect_err("a store-less board cannot make anything durable");
        assert!(
            err.contains("durable"),
            "the refusal must say what is wrong, not just refuse: {err}"
        );
        assert!(
            store.settings().is_empty(),
            "and it must not be applied in memory either"
        );
    }

    /// A store that keeps a checkpoint but cannot write one, counting the
    /// attempts. Models flash that has stopped accepting writes.
    #[derive(Default)]
    struct FailingCheckpointStore {
        attempts: Rc<RefCell<usize>>,
        empty: wayfinder_server::NodeSettings,
    }

    impl wayfinder_server::SettingsStore for FailingCheckpointStore {
        fn settings(&self) -> &wayfinder_server::NodeSettings {
            &self.empty
        }

        fn persist(
            &mut self,
            _update: wayfinder_server::NodeSettings,
        ) -> Result<(), alloc::string::String> {
            Err(alloc::string::String::from("flash is not accepting writes"))
        }
    }

    impl NodeStore for FailingCheckpointStore {
        /// A real store holding no checkpoint yet — `Some(0)`, not `None`, so
        /// the due test is met and the attempt guard is what has to bound it.
        fn stored_checkpoint(&self) -> Option<u64> {
            Some(0)
        }

        fn checkpoint(&mut self, _unix: u64) -> Result<(), alloc::string::String> {
            *self.attempts.borrow_mut() += 1;
            Err(alloc::string::String::from("flash is not accepting writes"))
        }
    }

    /// **A store that cannot write is asked at most once per interval.**
    ///
    /// The advance guard alone cannot bound this: a failed `checkpoint` leaves
    /// the stored value where it was, so `estimate >= stored + interval` stays
    /// true and the loop — which runs every few seconds — would retry forever,
    /// warning each time. That is what `checkpoint_attempted` is for, and
    /// without this test deleting it left the suite green.
    #[test]
    fn a_store_that_cannot_write_is_not_asked_on_every_pass() {
        let boot = Duration::from_secs(30);
        let record = NodeRecord::fresh(seed(0x10));
        let mut settings = FailingCheckpointStore::default();
        let mut driver = driver_at(boot, record.mac());
        driver.restore(&record);
        driver.wall.anchor(1_800_000_000, boot);

        for _ in 0..50 {
            driver.write_checkpoint_if_due(&mut settings);
        }
        assert_eq!(*settings.attempts.borrow(), 1, "one attempt per interval");

        driver.clock.now = boot + CHECKPOINT_INTERVAL;
        driver.write_checkpoint_if_due(&mut settings);
        assert_eq!(
            *settings.attempts.borrow(),
            2,
            "and it does try again once the interval has passed"
        );
    }
    /// A restored credential arms renewal against the authority its enrollment
    /// recorded — derived from the provider key the record keeps, so a board
    /// that reboots inside its renewal window carries on renewing rather than
    /// waiting for an operator with a serial cable.
    #[test]
    fn a_restored_credential_arms_renewal_against_its_recorded_authority() {
        let now = Duration::from_secs(30);
        let record = NodeRecord {
            renewal_provider_key: Some([0x0B; 32]),
            ..credentialed(0x21, 0, 1_800_000_000)
        };
        let mut driver = driver_at(now, record.mac());

        assert_eq!(driver.restore(&record), Restored::Authenticated);
        assert_eq!(
            driver.router.auth().unwrap().renewal_authority(),
            Some(wayfinder::wayfinder_auth::derive_mac(&[0x0B; 32])),
        );
    }

    /// A record with no provider arms no renewal: the board asks nobody rather
    /// than reaching back to an authority it may have left.
    #[test]
    fn a_restored_credential_with_no_provider_arms_no_renewal() {
        let now = Duration::from_secs(30);
        let record = credentialed(0x22, 0, 1_800_000_000);
        let mut driver = driver_at(now, record.mac());

        assert_eq!(driver.restore(&record), Restored::Authenticated);
        assert_eq!(driver.router.auth().unwrap().renewal_authority(), None);
    }

    /// **A board hands the adapter the seed it holds**, so `SetAuth` can
    /// *certify the identity the node already runs under* — the empty-seed
    /// branch — rather than only installing a wholesale new one.
    ///
    /// This is the difference between a node that can be enrolled and one that
    /// can only be replaced. The wholesale path gives a node an address it
    /// adopts on its next boot, which is fine for a board with a debugger and
    /// impossible for one without: a dongle cannot be reset from the host, so
    /// a credential it will not use until a reboot is a credential it never
    /// uses. Certifying in place keeps the address and needs no reboot.
    ///
    /// It was unreachable on a board until design 22 gave one a durable seed —
    /// there was nothing to certify — and then stayed unreachable because the
    /// driver never passed it. `current_identity_seed` returning `None` makes
    /// `SetAuth` refuse with "this node has no identity to certify", on a node
    /// that plainly has one.
    ///
    /// Also the end-to-end test of the `mgmt` seam that nothing else covers:
    /// a real request, through the loop, landing in the durable record.
    #[test]
    fn a_set_auth_certifies_the_identity_the_board_already_holds() {
        use wayfinder_auth::Authority;
        use wayfinder_protos::wayfinder::v1alpha::SetAuthRequest;
        use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;
        use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as RespKind;
        use wayfinder_server::EmbeddedQueryChannel;
        use zerocopy::IntoBytes;

        const MESH: u32 = 0x4849_4C00;
        let record = NodeRecord::fresh(seed(0x21));
        let keypair = record.keypair();

        // Issued for the key the board already holds, naming the address that
        // key derives — which is the address the board is already running
        // under. That equality is the whole point of the path.
        let ca = Authority::from_seed(&[0x5C; 32], MESH);
        let cert = ca.issue_cert(
            keypair.derived_mac(),
            keypair.ed_pubkey(),
            keypair.x_pubkey(),
            MIN_PLAUSIBLE_UNIX,
            MIN_PLAUSIBLE_UNIX + 365 * 86_400,
        );

        let (mut settings, medium) = store_holding(record.clone());
        let channel = EmbeddedQueryChannel::new();
        let (tx, rx) = channel.split();
        let mut driver = Driver::new(
            record.mac(),
            [FakeLink::default()],
            crate::tests::RecvClock {
                now: Duration::from_secs(1),
            },
            &[TrickleParams::default()],
            &[],
            &[],
        );
        driver.restore(&record);

        let client = async {
            tx.query(WayfinderRequest {
                request: Some(ReqKind::SetAuth(SetAuthRequest {
                    // Empty: certify what the node has, do not replace it.
                    seed: Vec::new(),
                    cert: cert.as_bytes().to_vec(),
                    trust_anchor: ca.trust_anchor().to_bytes().to_vec(),
                    installer_unix: MIN_PLAUSIBLE_UNIX,
                    ..Default::default()
                })),
            })
            .await
        };

        let (_, response) = futures::executor::block_on(futures::future::join(
            driver.run_once_with_mgmt(&rx, &mut settings),
            client,
        ));

        // `SetAuth` carries nothing back, so success is `Empty` and failure is
        // an `Error` whose message is the interesting part of a red run.
        match response.response {
            Some(RespKind::Empty(_)) => {}
            Some(RespKind::Error(e)) => panic!(
                "certifying the identity the board already holds was refused: {}",
                e.message
            ),
            other => panic!("expected an Empty response, got {other:?}"),
        }

        assert!(
            driver.router.auth_mut().is_some(),
            "the credential should be live on the router"
        );
        // And durable: the medium, not just memory. Nothing else tests the
        // `.with_settings(...)` wiring end to end.
        let mut buf = [0u8; crate::identity::RECORD_READ_BUF_LEN];
        let (reloaded, _) = crate::identity::load_or_init_record(
            medium,
            || panic!("already provisioned"),
            &mut buf,
        )
        .unwrap();
        assert_eq!(
            reloaded.get().seed,
            seed(0x21),
            "certifying in place must not change the seed -- that is the whole difference \
             from a wholesale install"
        );
        assert!(reloaded.get().cert.is_some(), "and the cert is durable");
    }

    /// A checkpoint near the top of the range must not overflow the due test
    /// either.
    ///
    /// Reachable, not theoretical: `WallClock::anchor` accepts any plausible
    /// instant, so an operator (or anyone with the cable — the port is
    /// unauthenticated, #59) can `SetTime` a board to the far future,
    /// and that estimate is then what gets checkpointed and restored.
    #[test]
    fn a_checkpoint_near_the_end_of_time_does_not_overflow() {
        let now = Duration::from_secs(30);
        let record = NodeRecord {
            checkpoint_unix: u64::MAX - 1,
            ..NodeRecord::fresh(seed(0x0F))
        };
        let (mut settings, _) = store_holding(record.clone());
        let mut driver = driver_at(now, record.mac());
        driver.restore(&record);

        driver.write_checkpoint_if_due(&mut settings);
    }
}
