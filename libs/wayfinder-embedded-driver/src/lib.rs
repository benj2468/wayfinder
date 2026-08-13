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
//! device or IGMP snoop yet, and OGM authentication time is not wired (a board
//! can still enable auth via [`Driver::router_mut`]).  The optional `mgmt`
//! feature adds a management-API arm to the event loop (`run_with_mgmt`) that
//! serves read-only/config queries forwarded from a `wayfinder-server` `serve`
//! loop, so an embedded node is inspectable over a debug transport (e.g. a UART)
//! exactly like a host node.
//!
//! [`wayfinder-driver-core`]: https://docs.rs/wayfinder-driver-core
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use core::time::Duration;

use embassy_futures::select::Either;
use embassy_futures::select::select;
use embassy_futures::select::select_array;
use heapless::Vec as HVec;
use interfaces::link::LinkError;
use tracing::trace;
use tracing::warn;
use wayfinder::CentralRouter;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::features::LinkFeatures;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::link::LinkT;
use wayfinder::router_ops::RouterOps;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::MeshSink;
use wayfinder_driver_core::OutgoingFrame;
use wayfinder_driver_core::handle_link_result;
use wayfinder_driver_core::plan_dispatch;
use wayfinder_driver_core::poll_due_all;

pub mod identity;

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

#[cfg(feature = "mgmt")]
use embassy_futures::select::Either3;
#[cfg(feature = "mgmt")]
use embassy_futures::select::select3;
#[cfg(feature = "mgmt")]
use wayfinder_protos::service::WayfinderService;
#[cfg(feature = "mgmt")]
use wayfinder_server::EmbeddedQueryRx;
#[cfg(feature = "mgmt")]
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
    fn emit(&mut self, frame: OutgoingFrame<'_>) {
        let mut payload = HVec::new();
        if payload.extend_from_slice(frame.payload).is_err() {
            warn!(
                len = frame.payload.len(),
                "drop: staged payload exceeds frame buffer"
            );
            return;
        }
        let staged = Staged {
            dst: frame.dst,
            protocol: frame.protocol,
            payload,
            egress: frame.egress,
        };
        if self.frames.push(staged).is_err() {
            warn!("drop: staging buffer full");
        }
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

impl<L: LinkT, C: Clock, const N: usize, const FRAME_LEN: usize, R: RouterOps>
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
        Self {
            router,
            links,
            clock,
            mac,
            tx_buffer: [0u8; FRAME_LEN],
            stage: StageSink::default(),
        }
    }

    /// The underlying router, for inspecting routing state (originator tables,
    /// link quality, route resolution).
    pub fn router(&self) -> &R {
        &self.router
    }

    /// The underlying router, mutably — lets a board enable OGM authentication
    /// or inject crafted state before/while running the loop.
    pub fn router_mut(&mut self) -> &mut R {
        &mut self.router
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
        // keep-alive.  Recomputed every iteration, so a timer reset by the
        // frame just processed shortens the next sleep automatically.
        let due = self
            .router
            .next_broadcast_after(now)
            .min(self.router.next_keepalive_after(now));
        trace!(?now, ?due, "run_once");

        // Destructure into disjoint field borrows so the planning step can hold
        // a borrow of `links` (via the recv futures) alongside `router`/`stage`.
        let Driver {
            router,
            links,
            clock,
            mac,
            tx_buffer,
            stage,
        } = self;
        stage.frames.clear();

        // Build one `recv` future per link and race them against the OGM timer.
        // `select_array` reports which link fired; an empty link set (`N == 0`)
        // is pending forever, so the timer arm still drives OGM emission.
        let recv_futs = links.each_mut().map(|link| link.recv());
        match select(select_array(recv_futs), clock.sleep(due)).await {
            Either::First((result, idx)) => {
                handle_link_result(now, router, idx, result, tx_buffer, stage)
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
#[cfg(feature = "mgmt")]
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
    pub async fn run_with_mgmt(&mut self, mgmt: &EmbeddedQueryRx<'_>) -> ! {
        loop {
            self.run_once_with_mgmt(mgmt).await;
        }
    }

    /// One iteration of [`run_with_mgmt`](Self::run_with_mgmt): race each link's
    /// `recv`, the periodic OGM/keep-alive timer, and an inbound management
    /// query; plan the winner; then dispatch any staged frames. A served query
    /// stages nothing, so its dispatch is a no-op.
    async fn run_once_with_mgmt(&mut self, mgmt: &EmbeddedQueryRx<'_>) {
        let now = self.clock.now();
        let due = self
            .router
            .next_broadcast_after(now)
            .min(self.router.next_keepalive_after(now));

        let Driver {
            router,
            links,
            clock,
            mac,
            tx_buffer,
            stage,
        } = self;
        stage.frames.clear();

        let recv_futs = links.each_mut().map(|link| link.recv());
        match select3(select_array(recv_futs), clock.sleep(due), mgmt.recv()).await {
            Either3::First((result, idx)) => {
                handle_link_result(now, router, idx, result, tx_buffer, stage)
            }
            Either3::Second(()) => poll_due_all(router, now, tx_buffer, stage),
            Either3::Third(request) => {
                trace!("servicing forwarded management query");
                // Build the response against a fresh adapter at `now`, then hand
                // it back to the waiting serve loop. `None` — an embedded node is
                // never a provider-mode certificate authority.
                let response = WayfinderService::new(RouterAdapter::new(&mut *router, None, now))
                    .handle(request);
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
            .resize(body_len + DIRECTED_TRAILER_LEN, 0)
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
            version: 5,
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
    struct RecvClock {
        now: Duration,
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

    /// A `run_once` where a received OGM (on interface 0) is re-flooded exercises
    /// the embedded dispatch's `Egress::Auto` fan-out: the OGM goes out the
    /// *other* interface (1) and not back out the ingress interface (0) —
    /// split-horizon across the full recv → handle → stage → dispatch path.
    #[test]
    fn run_once_reforwards_received_ogm_to_other_interface_only() {
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

        assert!(
            driver.links[0].sent.is_empty(),
            "split-horizon: no re-flood back out the ingress interface"
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
    #[cfg(feature = "mgmt")]
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
            driver.run_once_with_mgmt(&rx),
            client,
        ));

        match response.response {
            Some(RespKind::NodeInfo(info)) => {
                assert_eq!(
                    info.node_id,
                    mac(1).as_bytes().to_vec(),
                    "the served NodeInfo carries this node's own MAC"
                );
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
    #[cfg(feature = "mgmt")]
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

        futures::executor::block_on(driver.run_once_with_mgmt(&rx));

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
