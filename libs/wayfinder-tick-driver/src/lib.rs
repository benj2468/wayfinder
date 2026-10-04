//! A synchronous, tick-based driver shell atop [`wayfinder_driver_core`].
//!
//! `wayfinder-driver` (tokio) and `wayfinder-embedded-driver` (embassy) both
//! race a real mesh link's `recv()` against a periodic-OGM sleep, driving an
//! event loop that *waits* for something to happen. This crate is a third
//! shell over the same shared planning logic, for a caller that instead
//! drives its own clock and wants a **non-blocking** "check what's due right
//! now" call each step — a tick-based simulation (e.g. a Python-driven
//! physics simulation) rather than a live host.
//!
//! There is no [`LinkT`](wayfinder::link::LinkT) here at all: interfaces are
//! plain queues. A caller [`push_rx`](Driver::push_rx)es received frames onto
//! whichever interface index carried them, optionally
//! [`queue_local_send`](Driver::queue_local_send)s host-originated data, then
//! calls [`tick`](Driver::tick) once per step — which drains everything
//! queued, runs the same egress-resolution/gating/auth-tagging logic
//! the real drivers use, and stages the results into each interface's egress
//! queue (or the local-delivery queue) for the caller to
//! [`poll_egress`](Driver::poll_egress)/[`poll_local`](Driver::poll_local)
//! out and carry over whatever physical/simulated medium it likes.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use interfaces::engine::FrameSink;
use interfaces::link::LinkMetrics;
use tracing::trace;
use tracing::warn;
use wayfinder::CentralRouter;
use wayfinder::MAX_INTERFACES;
use wayfinder::McastPlan;
use wayfinder::auth::MAX_TRAILER_LEN;
use wayfinder::auth::VerifiedRenewal;
use wayfinder::config::TrickleConfig;
use wayfinder::features::LinkFeatures;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN;
use wayfinder::interfaces::frame::Mac;
use wayfinder::link::FanOut;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::MeshSink;
use wayfinder_driver_core::OutgoingFrame;
use wayfinder_driver_core::handle_mesh_frame;
use wayfinder_driver_core::plan_dispatch;
use wayfinder_driver_core::poll_due_challenges;
use wayfinder_driver_core::poll_due_keepalives;
use wayfinder_driver_core::poll_due_ogms;
use wayfinder_driver_core::poll_due_pings;
use wayfinder_driver_core::poll_due_renewal;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// A received frame queued on interface `idx`, awaiting the next [`Driver::tick`].
struct QueuedRx {
    idx: usize,
    metrics: LinkMetrics,
    /// Owned wire bytes (`[dst][src][protocol be][payload]`), already
    /// validated to parse as a [`LinkFrame`] when it was queued.
    frame: Vec<u8>,
}

/// One frame planned by [`wayfinder_driver_core`], staged until the current
/// [`Driver::tick`]'s planning pass finishes so its egress can be resolved
/// without holding a borrow of the router's transmit scratchpad.
struct StagedFrame {
    dst: Mac,
    protocol: u16,
    payload: Vec<u8>,
    egress: Egress,
}

/// A [`MeshSink`] that copies each planned frame into an owned [`StagedFrame`]
/// (and each local delivery into an owned `Vec<u8>`), so the borrow of the
/// caller's transmit scratchpad ends before the frames are dispatched.
#[derive(Default)]
struct StageSink {
    frames: Vec<StagedFrame>,
    local: Vec<Vec<u8>>,
}

/// Bridges the router's [`FrameSink`] onto this shell's staging buffer, so the
/// destination groups a local multicast is split into are staged like any other
/// outgoing frame.
///
/// Unbounded: the stage is a `Vec` here, so there is no capacity to run out of
/// and no group to lose. The router still bounds how many groups it produces.
struct StageFrameSink<'a>(&'a mut StageSink);

impl FrameSink for StageFrameSink<'_> {
    fn push(&mut self, f: wayfinder::interfaces::frame::LinkFrameData<'_>) -> bool {
        let _ = self.0.emit(OutgoingFrame {
            dst: f.dst,
            protocol: f.protocol,
            payload: f.payload,
            egress: Egress::Auto,
        });
        true
    }
}

impl MeshSink for StageSink {
    /// Always accepts: the stage is a `Vec`, so there is no capacity to run
    /// out of and no frame to lose.
    fn emit(&mut self, frame: OutgoingFrame<'_>) -> bool {
        self.frames.push(StagedFrame {
            dst: frame.dst,
            protocol: frame.protocol,
            payload: frame.payload.to_vec(),
            egress: frame.egress,
        });
        true
    }

    fn deliver_local(&mut self, inner: &[u8]) {
        self.local.push(inner.to_vec());
    }
}

/// `frame` does not parse as a well-formed [`LinkFrame`] (too short for the
/// fixed `[dst][src][protocol]` header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedFrameError;

impl fmt::Display for MalformedFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("frame does not parse as a well-formed LinkFrame")
    }
}

/// A tick-based, queue-backed mesh router: the same
/// [`wayfinder_driver_core`] planning logic the real drivers use, but with
/// plain queues standing in for live [`LinkT`](wayfinder::link::LinkT) links
/// and no event loop of its own — the caller supplies `now` and drives every
/// step.
///
/// Interface indices run `0..num_interfaces()`, fixed at construction (the
/// length of the `trickle` slice passed to [`Driver::new`], capped at
/// [`MAX_INTERFACES`] — the router holds no more than that, so neither does
/// this driver).
pub struct Driver {
    router: CentralRouter,
    mac: Mac,
    tx_buffer: [u8; MAX_LINK_FRAME_LEN],
    rx_queue: VecDeque<QueuedRx>,
    local_tx_queue: VecDeque<(Mac, Vec<u8>)>,
    /// One outgoing queue per interface index.
    egress: Vec<VecDeque<Vec<u8>>>,
    local_rx: VecDeque<Vec<u8>>,
    /// Each interface's declared native fan-out: the number of destinations
    /// at which one send on that medium beats one directed copy each, or
    /// `None` when a send reaches one peer and N copies genuinely cost N.
    ///
    /// There is no `LinkT` here to ask, so a caller modelling a shared medium
    /// declares it with [`set_fan_out`](Self::set_fan_out). `None` everywhere
    /// by default, which is the safe answer: over-claiming a fan-out is a
    /// correctness bug, not a missed optimisation — a medium that says one send
    /// reaches every neighbour when it does not drops every destination but
    /// one.
    fan_out: Vec<Option<FanOut>>,
    /// Wall-clock unix time (seconds) that `now == 0` corresponds to.
    ///
    /// Certificate validity is judged against unix time, but a tick-driven
    /// caller supplies a monotonic `now` starting at zero — so each [`tick`]
    /// sets the auth clock to `epoch_unix + now`. Left at 0 the driver reports
    /// [`Clocked::Unknown`](wayfinder_auth::Clocked) — a node with no usable
    /// wall clock, which routes but judges no certificate validity window. Set
    /// it with [`set_epoch_unix`](Self::set_epoch_unix).
    ///
    /// [`tick`]: Self::tick
    epoch_unix: u64,
}

impl Driver {
    /// Build a driver for node `mac` with `trickle.len()` interfaces, or
    /// [`MAX_INTERFACES`] of them if that is fewer — a surplus is dropped with
    /// a warning rather than kept as an interface the router will never
    /// schedule or gate.
    /// `trickle[idx]` supplies that interface's adaptive OGM schedule;
    /// `features[idx]` its participation gates, defaulting to full
    /// participation ([`LinkFeatures::default`]) for any interface `features`
    /// doesn't cover. `features[idx].tx_keepalive` additionally arms that
    /// interface's fixed-cadence keep-alive schedule, left unarmed (`None`)
    /// by default. `names[idx]` labels the interface for the management API,
    /// leaving it unnamed when absent.
    pub fn new(
        mac: Mac,
        trickle: &[TrickleConfig],
        features: &[LinkFeatures],
        names: &[&str],
    ) -> Self {
        // The router only tracks `MAX_INTERFACES` interfaces; an index past
        // that is silently ignored, so a surplus interface is never
        // OGM-scheduled *and* never gated (a `set_link_features` past the cap
        // no-ops, so a link configured as a read-only tap would transmit
        // anyway). Say so, and hold this driver's own interface count to what
        // the router will actually act on rather than handing back queues
        // nothing drains. This replaces a `debug_assert!`, which compiled out
        // of exactly the release builds — the Python extension among them —
        // where the divergence was invisible.
        let n = trickle.len().min(MAX_INTERFACES);
        if trickle.len() > MAX_INTERFACES {
            warn!(
                configured = trickle.len(),
                max = MAX_INTERFACES,
                "more mesh interfaces than the router supports; interfaces past the cap are dropped"
            );
        }
        let mut router = CentralRouter::new(mac);
        for (idx, cfg) in trickle.iter().take(n).enumerate() {
            router.configure_interface_ogm(idx, cfg.i_min(), cfg.i_max(), Duration::ZERO);
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
            mac,
            tx_buffer: [0u8; MAX_LINK_FRAME_LEN],
            rx_queue: VecDeque::new(),
            local_tx_queue: VecDeque::new(),
            egress: (0..n).map(|_| VecDeque::new()).collect(),
            local_rx: VecDeque::new(),
            fan_out: (0..n).map(|_| None).collect(),
            epoch_unix: 0,
        }
    }

    /// Declare interface `idx`'s native fan-out: the destination count at
    /// which one send on that medium beats one directed copy each.
    ///
    /// The stand-in for `LinkT::fan_out` on a driver that has no links — a
    /// simulated shared segment (one radio every neighbour hears) declares
    /// `Some(2)`, a point-to-point queue leaves it `None`. Out-of-range indices
    /// are ignored, like every other per-interface setter here.
    pub fn set_fan_out(&mut self, idx: usize, fan_out: Option<FanOut>) {
        if let Some(slot) = self.fan_out.get_mut(idx) {
            *slot = fan_out;
        }
    }

    /// The number of mesh interfaces this driver was constructed with.
    pub fn num_interfaces(&self) -> usize {
        self.egress.len()
    }

    /// The underlying router, for inspecting routing state (originator
    /// tables, link quality, route resolution).
    pub fn router(&self) -> &CentralRouter {
        &self.router
    }

    /// The underlying router, mutably — enables OGM authentication or injects
    /// crafted state before/between ticks.
    pub fn router_mut(&mut self) -> &mut CentralRouter {
        &mut self.router
    }

    /// Pin the wall-clock unix time that `now == 0` corresponds to, so
    /// certificate validity is judged against a real clock while the caller
    /// keeps driving a monotonic `now` from zero.
    ///
    /// Each [`tick`](Self::tick) then advances the auth clock to
    /// `epoch_unix + now`. Set this whenever OGM authentication is enabled;
    /// without it the node reports [`Clocked::Unknown`](wayfinder_auth::Clocked)
    /// and judges no validity window.
    pub fn set_epoch_unix(&mut self, epoch_unix: u64) {
        self.epoch_unix = epoch_unix;
    }

    /// This driver's wall-clock posture at `now`.
    ///
    /// A pinned epoch is a value its caller chose, so it is reported as
    /// [`Clocked::At`](wayfinder_auth::Clocked::At) verbatim rather than
    /// floored by `MIN_PLAUSIBLE_UNIX` — flooring it would make a simulation
    /// asking about second 1000 silently ask about something else. The floor
    /// exists for the reading nobody chose; zero is the "no epoch pinned"
    /// state and is the one value that means there is no clock here.
    fn wall(&self, now: Duration) -> wayfinder_auth::Clocked {
        if self.epoch_unix == 0 {
            wayfinder_auth::Clocked::Unknown
        } else {
            wayfinder_auth::Clocked::At(self.epoch_unix.saturating_add(now.as_secs()))
        }
    }

    /// Enqueue a frame received on interface `idx` (with its carrier's
    /// physical-layer `metrics`), to be processed on the next [`tick`](Self::tick).
    /// Validates that `frame` parses as a [`LinkFrame`] immediately, so a
    /// caller's mistake surfaces at the point of the call rather than being
    /// silently dropped later.
    pub fn push_rx(
        &mut self,
        idx: usize,
        metrics: LinkMetrics,
        frame: &[u8],
    ) -> Result<(), MalformedFrameError> {
        LinkFrame::ref_from_bytes(frame).map_err(|_| MalformedFrameError)?;
        self.rx_queue.push_back(QueuedRx {
            idx,
            metrics,
            frame: frame.to_vec(),
        });
        Ok(())
    }

    /// Enqueue host-originated data destined for `dest` (or [`Mac::BROADCAST`]
    /// to flood), to be processed on the next [`tick`](Self::tick).
    pub fn queue_local_send(&mut self, dest: Mac, payload: &[u8]) {
        self.local_tx_queue.push_back((dest, payload.to_vec()));
    }

    /// Non-blocking: drain every currently queued received frame and local
    /// send, run whatever per-interface OGM and keep-alive maintenance is due
    /// as of `now`, and stage the results into each interface's egress queue
    /// (or the local-delivery queue). Call once per simulation step; never blocks and
    /// never waits for anything to arrive.
    pub fn tick(&mut self, now: Duration) {
        self.tick_schedules(now, true, true);
    }

    /// Advance to `now` servicing only the selected periodic schedules.
    ///
    /// [`tick`](Self::tick) is this with both enabled, and is what a normal
    /// caller wants. The split exists because the two schedules are
    /// independently observable failure modes: a node whose keep-alives have
    /// stopped while its OGMs still flow is a real fault, and driving
    /// `keepalives = false` is how a caller reproduces it. The async driver
    /// exposes the same split as separate `poll_due` / `poll_due_keepalive`
    /// methods.
    ///
    /// Received frames, queued host sends and the auth clock are serviced
    /// regardless — only the two emission schedules are gated.
    pub fn tick_schedules(&mut self, now: Duration, ogms: bool, keepalives: bool) {
        // Advance the auth clock before anything reads it: cert validity is
        // judged in unix seconds, and this is the only place the monotonic
        // `now` is mapped onto that clock.
        // Through the router rather than straight at the auth state: setting
        // the clock can evict a lapsed peer's key, and the engine's next-hop
        // proofs must be reconciled with that in the same call (design 09
        // §8.10).
        self.router.set_auth_time(now, self.wall(now));

        let mut stage = StageSink::default();

        while let Some(queued) = self.rx_queue.pop_front() {
            if let Ok(frame) = LinkFrame::ref_from_bytes(&queued.frame) {
                handle_mesh_frame(
                    now,
                    &mut self.router,
                    queued.idx,
                    frame,
                    queued.metrics,
                    &mut self.tx_buffer,
                    &self.fan_out,
                    &mut stage,
                );
            }
        }

        while let Some((dest, payload)) = self.local_tx_queue.pop_front() {
            // A group destination gets the multicast plan, not the unicast
            // path. Without this a group MAC went to `handle_local`, found no
            // route (nothing ever originates a group address) and was dropped
            // — so a tick-driven node could not send multicast at all.
            if dest.is_multicast() && !dest.is_broadcast() {
                match self.router.mcast_plan(dest) {
                    McastPlan::Unicast => {
                        let targets: Vec<Mac> = self.router.mcast_targets(dest).collect();
                        // One call with the whole listener set: the router
                        // groups them by next hop, so listeners sharing one
                        // travel in a single frame.
                        if let Err(e) = self.router.handle_local_mcast(
                            now,
                            &targets,
                            &payload,
                            &mut self.tx_buffer,
                            &mut StageFrameSink(&mut stage),
                        ) {
                            // Nothing went out at all. The plan said unicast,
                            // so there is no flood arm to fall back to here —
                            // say so rather than let the host's frame vanish
                            // without a record.
                            trace!(?dest, ?e, "drop: local multicast unsendable");
                        }
                    }
                    // Past the fan-out threshold, or no known listeners: flood
                    // it, exactly as the tokio shell does.
                    McastPlan::Flood => {
                        if let Ok(f) = self.router.handle_local(
                            now,
                            Mac::BROADCAST,
                            &payload,
                            &mut self.tx_buffer,
                        ) {
                            let _ = stage.emit(OutgoingFrame {
                                dst: f.dst,
                                protocol: f.protocol,
                                payload: f.payload,
                                egress: Egress::Auto,
                            });
                        }
                    }
                }
                continue;
            }
            match self
                .router
                .handle_local(now, dest, &payload, &mut self.tx_buffer)
            {
                Ok(f) => {
                    let _ = stage.emit(OutgoingFrame {
                        dst: f.dst,
                        protocol: f.protocol,
                        payload: f.payload,
                        egress: Egress::Auto,
                    });
                }
                // As in the multicast arm above, and for the same reason the
                // tokio shell records it: the host's frame is gone and nothing
                // downstream will say so. See design 09 §8.10 for why this arm
                // became reachable where §7's counter used to catch it.
                Err(e) => trace!(?dest, ?e, "drop: local unicast unsendable"),
            }
        }

        if ogms {
            poll_due_ogms(&mut self.router, now, &mut self.tx_buffer, &mut stage);
        }
        if keepalives {
            poll_due_keepalives(&mut self.router, now, &mut self.tx_buffer, &mut stage);
        }
        // Unconditional, unlike the two schedules above: a next-hop challenge
        // is not on a timer the caller steps, it is owed to whichever
        // neighbours are currently unproven. The router spaces retries per
        // neighbour, so ticking often does not mean challenging often.
        poll_due_challenges(&mut self.router, now, &mut self.tx_buffer, &mut stage);
        // Unconditional for the same reason: a probe is owed to a session the
        // caller started, not to a schedule the caller steps. The router paces
        // it from `now`, so ticking often does not mean probing often.
        poll_due_pings(&mut self.router, now, &mut self.tx_buffer, &mut stage);
        // And unconditional again: a renewal is owed to the credential this
        // node holds, not to anything the caller steps. The router paces it at
        // `RENEWAL_POLL_INTERVAL` and answers `None` outside the window, so a
        // node with no credential — which is most of a simulation — pays two
        // comparisons per tick.
        poll_due_renewal(&mut self.router, now, &mut self.tx_buffer, &mut stage);

        for staged in stage.frames.drain(..) {
            self.dispatch_one(now, staged);
        }
        self.local_rx.extend(stage.local.drain(..));
    }

    /// Answer every membership renewal this node has verified and not yet
    /// replied to, deciding each with `issue`.
    ///
    /// The synchronous counterpart of `wayfinder-driver`'s
    /// `poll_mesh_renewals` — the provider end of design 24's exchange, for a
    /// caller that drives its own clock. The router has already done
    /// everything decidable without policy: the requester's certificate
    /// verified against the trust anchor, is not revoked, and its holder proved
    /// possession of the key it names. What `issue` decides is the part this
    /// crate must not know about — whether this node is an authority at all,
    /// and whether that identity is still a holder it will re-issue for.
    ///
    /// A closure rather than a certificate-authority argument, deliberately.
    /// This crate is `no_std` + `alloc` and a `CertAuthority` is a host type
    /// that persists to a filesystem; taking one would put the whole authority
    /// in the dependency graph of a simulation that mostly does not run one.
    ///
    /// `issue` returning `None` sends nothing. A `RenewReply` carries a
    /// certificate or it does not exist, so a refusal reaches the asker as
    /// silence and then as the gap between its own counters.
    pub fn serve_mesh_renewals(
        &mut self,
        now: Duration,
        mut issue: impl FnMut(&VerifiedRenewal) -> Option<MembershipCert>,
    ) {
        // One, not a loop: the router holds a single verified request and
        // displaces rather than queues, and nothing refills that slot between
        // iterations here — so a second take would always be `None`.
        let Some(verified) = self.router.take_renewal_request() else {
            return;
        };
        let Some(cert) = issue(&verified) else {
            return;
        };
        let staged = {
            let Some(frame) =
                self.router
                    .send_renew_reply(now, verified.mac, &cert, &mut self.tx_buffer)
            else {
                // The route the request arrived over has gone since. The
                // certificate is issued either way and the asker retries.
                trace!(requester = ?verified.mac, "drop: no route back to a renewing node");
                return;
            };
            StagedFrame {
                dst: frame.dst,
                protocol: frame.protocol,
                payload: frame.payload.to_vec(),
                egress: Egress::Auto,
            }
        };
        self.dispatch_one(now, staged);
    }

    /// Resolve one staged frame's egress (tagging it for pairwise auth first,
    /// when enabled) and push its wire bytes onto each selected interface's
    /// egress queue — the synchronous counterpart of the embedded/tokio
    /// drivers' `dispatch`, minus the actual link I/O.
    fn dispatch_one(&mut self, now: Duration, mut staged: StagedFrame) {
        let body_len = staged.payload.len();
        staged.payload.resize(body_len + MAX_TRAILER_LEN, 0);
        let num_interfaces = self.egress.len();
        let Some(plan) = plan_dispatch(
            &mut self.router,
            now,
            staged.dst,
            staged.protocol,
            staged.egress,
            body_len,
            &mut staged.payload,
            num_interfaces,
        ) else {
            return; // auth on but untaggable — drop rather than emit in the clear
        };
        // Collect before sending: the plan borrows `staged.payload`, and
        // `send_on` needs `&mut self`.
        let targets = plan.targets();
        let send_len = plan.payload().len();
        staged.payload.truncate(send_len);

        for idx in targets.iter() {
            self.send_on(idx, staged.dst, staged.protocol, &staged.payload, now);
        }
    }

    /// Frame `dst`/`protocol`/`payload` as on-wire bytes
    /// (`[dst][src][protocol be][payload]`, `src` this driver's own `mac`),
    /// push them onto interface `idx`'s egress queue, and fold the byte count
    /// into that interface's transmit-rate estimator.
    fn send_on(&mut self, idx: usize, dst: Mac, protocol: u16, payload: &[u8], now: Duration) {
        if idx >= self.egress.len() {
            return;
        }
        let mut wire = Vec::with_capacity(dst.as_bytes().len() * 2 + 2 + payload.len());
        wire.extend_from_slice(dst.as_bytes());
        wire.extend_from_slice(self.mac.as_bytes());
        wire.extend_from_slice(&protocol.to_be_bytes());
        wire.extend_from_slice(payload);
        let sent = wire.len();
        self.egress[idx].push_back(wire);
        self.router.record_tx(idx, sent, now);
    }

    /// Pop the next frame staged for transmission on interface `idx`, if any
    /// (on-wire bytes: `[dst][src][protocol be][payload]`).
    pub fn poll_egress(&mut self, idx: usize) -> Option<Vec<u8>> {
        self.egress.get_mut(idx)?.pop_front()
    }

    /// Pop the next payload delivered to the local host, if any.
    pub fn poll_local(&mut self) -> Option<Vec<u8>> {
        self.local_rx.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
    use wayfinder::batman::wire::BATMAN_VERSION;
    use wayfinder::batman::wire::BatmanOgmPacket;
    use wayfinder::batman::wire::BatmanPacketType;

    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// The raw bytes of a link frame: `[dst][src][protocol be][payload]`.
    fn frame_bytes(dst: Mac, src: Mac, protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(dst.as_bytes());
        raw.extend_from_slice(src.as_bytes());
        raw.extend_from_slice(&protocol.to_be_bytes());
        raw.extend_from_slice(payload);
        raw
    }

    /// The bytes of a bare 1-hop OGM from `orig` — BATMAN header only, no
    /// TVLVs (auth off) — enough for the engine to re-flood it.
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

    /// More interfaces than the router can hold must not leave the driver
    /// reporting interfaces the router will never schedule or gate.
    ///
    /// The router silently ignores an index at or past its capacity, so a
    /// surplus interface gets no OGM timer and no `LinkFeatures` entry — it is
    /// mute, and a read-only tap configured there would transmit anyway. The
    /// driver must agree with the router about how many interfaces it has, so
    /// a caller sees the truncation instead of addressing a queue nothing
    /// drains.
    #[test]
    fn interfaces_past_the_router_capacity_are_not_silently_kept() {
        let trickle = vec![TrickleConfig::default(); MAX_INTERFACES + 4];
        let mut driver = Driver::new(mac(1), &trickle, &[], &[]);

        assert_eq!(driver.router().num_interfaces(), MAX_INTERFACES);
        assert_eq!(driver.num_interfaces(), driver.router().num_interfaces());
        assert!(driver.poll_egress(MAX_INTERFACES).is_none());
    }

    /// One due interface's `tick` stages exactly one OGM broadcast into that
    /// interface's egress queue.
    #[test]
    fn tick_emits_due_ogm_into_its_interface_egress_queue() {
        let trickle = [TrickleConfig::default()];
        let mut driver = Driver::new(mac(1), &trickle, &[], &[]);

        // Advance to whenever interface 0 first becomes due (Trickle jitters
        // the exact instant), so the test doesn't hard-code the schedule.
        let mut now = Duration::ZERO;
        while driver.router().due_interface(now).is_none() && now < Duration::from_secs(60) {
            now += Duration::from_millis(50);
        }
        assert!(
            driver.router().due_interface(now).is_some(),
            "interface never came due"
        );

        driver.tick(now);

        let frame = driver
            .poll_egress(0)
            .expect("one due interface stages one OGM");
        assert!(
            driver.poll_egress(0).is_none(),
            "only one OGM for one due interface"
        );
        let parsed = LinkFrame::ref_from_bytes(&frame).expect("valid on-wire link frame");
        assert_eq!(parsed.dst, Mac::BROADCAST);
        assert_eq!(parsed.protocol.get(), DEFAULT_BATMAN_ETHER_TYPE);
        assert_eq!(parsed.src, mac(1), "src is stamped with this driver's mac");
    }

    /// A received OGM pushed on interface 0 is re-flooded into **both**
    /// interfaces' egress queues, the ingress one included — there is no
    /// interface-level split-horizon (see `driver_core::Egress::Auto`). Ticks
    /// at `now = ZERO`, before either interface's own Trickle timer can be due
    /// (armed within `[i_min/2, i_min)` after construction), so the only thing
    /// in either queue is the re-flood.
    #[test]
    fn tick_reforwards_received_ogm_onto_every_interface() {
        let trickle = [TrickleConfig::default(), TrickleConfig::default()];
        let mut driver = Driver::new(mac(1), &trickle, &[], &[]);

        let ogm = bare_ogm_bytes(mac(2), 1, 50);
        let wire = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        driver
            .push_rx(0, LinkMetrics::default(), &wire)
            .expect("well-formed frame");

        driver.tick(Duration::ZERO);

        let echoed = driver
            .poll_egress(0)
            .expect("the re-flood returns out the ingress interface too");
        assert!(
            driver.poll_egress(0).is_none(),
            "exactly one re-flood out the ingress interface, not a double send"
        );
        let echoed = LinkFrame::ref_from_bytes(&echoed).unwrap();
        assert_eq!(echoed.dst, Mac::BROADCAST);
        assert_eq!(echoed.src, mac(1), "src is stamped with this driver's mac");

        let refloaded = driver
            .poll_egress(1)
            .expect("re-flooded out the other interface");
        assert!(
            driver.poll_egress(1).is_none(),
            "no periodic OGM yet at now=ZERO to also land in this queue"
        );
        let parsed = LinkFrame::ref_from_bytes(&refloaded).unwrap();
        assert_eq!(parsed.dst, Mac::BROADCAST);
        assert_eq!(parsed.src, mac(1));
    }

    /// A locally-queued unicast send resolves through `get_egress_interface`
    /// and lands in the egress queue that resolution names.
    #[test]
    fn queue_local_send_stages_a_unicast_on_its_resolved_egress_interface() {
        let trickle = [TrickleConfig::default()];
        let mut driver = Driver::new(mac(1), &trickle, &[], &[]);

        // Teach the router about a neighbor on interface 0 by feeding it a
        // real OGM, so `get_egress_interface` has a route to resolve.
        let ogm = bare_ogm_bytes(mac(2), 1, 50);
        let wire = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        driver
            .push_rx(0, LinkMetrics::default(), &wire)
            .expect("well-formed frame");
        driver.tick(Duration::ZERO);
        driver.poll_egress(0); // drain the re-flood, irrelevant to this test

        driver.queue_local_send(mac(2), b"hello mesh");
        driver.tick(Duration::from_millis(1));

        let sent = driver
            .poll_egress(0)
            .expect("unicast to a known neighbor is staged on its egress interface");
        let parsed = LinkFrame::ref_from_bytes(&sent).unwrap();
        assert_eq!(parsed.dst, mac(2));
        assert_eq!(parsed.src, mac(1));
    }

    /// An interface configured with a keep-alive schedule (via
    /// `LinkFeatures::tx_keepalive`) stages a heartbeat into its egress queue
    /// once `tick` reaches its due instant — the tick-driven counterpart to
    /// `poll_due_keepalives`, proving the schedule is actually wired into
    /// `Driver::new`/`tick`, not just accepted and ignored.
    #[test]
    fn tick_emits_due_keepalive_into_its_interface_egress_queue() {
        let trickle = [TrickleConfig::default()];
        let features = [LinkFeatures {
            tx_keepalive: Some(wayfinder::features::KeepAliveConfig { interval_ms: 1000 }),
            ..Default::default()
        }];
        let mut driver = Driver::new(mac(1), &trickle, &features, &[]);

        let mut now = Duration::ZERO;
        while driver.router().due_keepalive_interface(now).is_none()
            && now < Duration::from_secs(60)
        {
            now += Duration::from_millis(50);
        }
        assert!(
            driver.router().due_keepalive_interface(now).is_some(),
            "interface never came due"
        );

        driver.tick(now);

        let frame = driver
            .poll_egress(0)
            .expect("one due interface stages one heartbeat");
        let parsed = LinkFrame::ref_from_bytes(&frame).expect("valid on-wire link frame");
        assert_eq!(parsed.dst, Mac::BROADCAST);
        assert_eq!(parsed.protocol.get(), DEFAULT_BATMAN_ETHER_TYPE);
        assert_eq!(
            parsed.payload.first(),
            Some(&BatmanPacketType::Keepalive.as_u8())
        );
    }

    /// An interface with no `tx_keepalive` configured never emits a
    /// heartbeat, no matter how far `tick` advances — opt-in, matching the
    /// `LinkFeatures` default.
    #[test]
    fn tick_never_emits_keepalive_when_unconfigured() {
        let trickle = [TrickleConfig::default()];
        let mut driver = Driver::new(mac(1), &trickle, &[], &[]);

        driver.tick(Duration::from_secs(1_000));
        // Drain whatever OGM(s) landed; only a keep-alive would be a bug here.
        while let Some(frame) = driver.poll_egress(0) {
            let parsed = LinkFrame::ref_from_bytes(&frame).unwrap();
            assert_ne!(
                parsed.payload.first(),
                Some(&BatmanPacketType::Keepalive.as_u8()),
                "no interface has tx_keepalive configured"
            );
        }
    }

    /// Two `Driver`s hand-copying `poll_egress` output into `push_rx` across
    /// repeated ticks converge on a route to each other — the same
    /// end-to-end shape a Python simulation loop will drive this crate with.
    #[test]
    fn two_drivers_converge_when_egress_is_hand_copied_between_them() {
        let trickle = [TrickleConfig {
            i_min_ms: 50,
            i_max_ms: 500,
        }];
        let mut a = Driver::new(mac(1), &trickle, &[], &[]);
        let mut b = Driver::new(mac(2), &trickle, &[], &[]);

        let mut now = Duration::ZERO;
        for _ in 0..200 {
            now += Duration::from_millis(10);
            a.tick(now);
            b.tick(now);
            while let Some(frame) = a.poll_egress(0) {
                let _ = b.push_rx(0, LinkMetrics::default(), &frame);
            }
            while let Some(frame) = b.poll_egress(0) {
                let _ = a.push_rx(0, LinkMetrics::default(), &frame);
            }
        }

        assert!(
            a.router_mut().get_egress_interface(now, mac(2)).is_some(),
            "a resolves a route to b"
        );
        assert!(
            b.router_mut().get_egress_interface(now, mac(1)).is_some(),
            "b resolves a route to a"
        );
    }

    /// The two periodic schedules must be drivable independently, the same way
    /// the async driver exposes `poll_due` and `poll_due_keepalive` separately.
    ///
    /// That split is how a caller injects "this node stopped sending
    /// keep-alives while its OGMs keep flowing" — a node whose liveness
    /// signal has died but whose routing chatter has not. Collapsing them into
    /// one `tick` makes that fault unrepresentable.
    #[test]
    fn schedules_can_be_driven_independently() {
        let trickle = TrickleConfig::default();
        let mut driver = Driver::new(mac(1), &[trickle], &[], &[]);
        driver.router_mut().configure_interface_keepalive(
            0,
            Some(Duration::from_millis(150)),
            Duration::ZERO,
        );

        // Far enough ahead that both schedules are due.
        let now = Duration::from_secs(5);

        driver.tick_schedules(now, true, false);
        let types = drain_packet_types(&mut driver);
        assert!(
            types.contains(&BatmanPacketType::Ogm.as_u8()),
            "the OGM schedule ran: {types:?}"
        );
        assert!(
            !types.contains(&BatmanPacketType::Keepalive.as_u8()),
            "the keep-alive schedule was suppressed: {types:?}"
        );

        driver.tick_schedules(now, false, true);
        let types = drain_packet_types(&mut driver);
        assert!(
            types.contains(&BatmanPacketType::Keepalive.as_u8()),
            "the keep-alive schedule ran on its own: {types:?}"
        );
        assert!(
            !types.contains(&BatmanPacketType::Ogm.as_u8()),
            "and did not re-run the OGM schedule: {types:?}"
        );
    }

    /// Drain interface 0's egress queue, returning each frame's BATMAN
    /// sub-type (the first payload byte after the 14-byte link header).
    fn drain_packet_types(driver: &mut Driver) -> Vec<u8> {
        let mut types = Vec::new();
        while let Some(frame) = driver.poll_egress(0) {
            if let Some(t) = frame.get(14) {
                types.push(*t);
            }
        }
        types
    }

    /// Certificate validity is judged against wall-clock unix time, but a
    /// tick-driven caller supplies a monotonic `now` starting at zero. The
    /// driver bridges the two: `set_epoch_unix` pins what unix time
    /// `now == 0` means, and each `tick` advances the auth clock to
    /// `epoch + now`.
    ///
    /// Without this a tick-driven node's auth clock sits at 0 forever, which
    /// `OgmAuth` reads as "clock never set" — so every cert-validity check is
    /// judged against the wrong time.
    #[test]
    fn tick_advances_the_auth_clock_from_the_configured_epoch() {
        let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
        let kp = wayfinder_auth::Keypair::from_seed(&[2; 32]);
        let cert = authority.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);

        let mut driver = Driver::new(mac(1), &[TrickleConfig::default()], &[], &[]);
        driver.router_mut().set_auth(wayfinder::auth::OgmAuth::new(
            kp,
            cert,
            authority.trust_anchor(),
        ));
        driver.set_epoch_unix(1_000);

        driver.tick(Duration::from_secs(5));

        let auth_now = driver
            .router()
            .auth()
            .expect("auth was installed")
            .now_unix();
        assert_eq!(
            auth_now, 1_005,
            "the auth clock is the configured epoch plus the tick's monotonic `now`"
        );
    }
}
