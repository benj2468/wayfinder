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
//! queued, runs the same egress-resolution/split-horizon/auth-tagging logic
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

use interfaces::link::LinkMetrics;
use wayfinder::CentralRouter;
use wayfinder::MAX_INTERFACES;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::config::TrickleConfig;
use wayfinder::features::LinkFeatures;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN;
use wayfinder::interfaces::frame::Mac;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::MeshSink;
use wayfinder_driver_core::OutgoingFrame;
use wayfinder_driver_core::handle_mesh_frame;
use wayfinder_driver_core::plan_dispatch;
use wayfinder_driver_core::poll_due_keepalives;
use wayfinder_driver_core::poll_due_ogms;
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

impl MeshSink for StageSink {
    fn emit(&mut self, frame: OutgoingFrame<'_>) {
        self.frames.push(StagedFrame {
            dst: frame.dst,
            protocol: frame.protocol,
            payload: frame.payload.to_vec(),
            egress: frame.egress,
        });
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
/// length of the `trickle` slice passed to [`Driver::new`]).
pub struct Driver {
    router: CentralRouter,
    mac: Mac,
    tx_buffer: [u8; MAX_LINK_FRAME_LEN],
    rx_queue: VecDeque<QueuedRx>,
    local_tx_queue: VecDeque<(Mac, Vec<u8>)>,
    /// One outgoing queue per interface index.
    egress: Vec<VecDeque<Vec<u8>>>,
    local_rx: VecDeque<Vec<u8>>,
}

impl Driver {
    /// Build a driver for node `mac` with `trickle.len()` interfaces.
    /// `trickle[idx]` supplies that interface's adaptive OGM schedule;
    /// `features[idx]` its participation gates, defaulting to full
    /// participation ([`LinkFeatures::default`]) for any interface `features`
    /// doesn't cover. `features[idx].tx_keepalive` additionally arms that
    /// interface's fixed-cadence keep-alive schedule, left unarmed (`None`)
    /// by default.
    pub fn new(mac: Mac, trickle: &[TrickleConfig], features: &[LinkFeatures]) -> Self {
        let n = trickle.len();
        debug_assert!(
            n <= MAX_INTERFACES,
            "Driver supports at most MAX_INTERFACES mesh interfaces"
        );
        let mut router = CentralRouter::new(mac);
        for (idx, cfg) in trickle.iter().enumerate() {
            router.configure_interface_ogm(idx, cfg.i_min(), cfg.i_max(), Duration::ZERO);
            let link_features = features.get(idx).copied().unwrap_or_default();
            router.set_link_features(idx, link_features);
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
                    &mut stage,
                );
            }
        }

        while let Some((dest, payload)) = self.local_tx_queue.pop_front() {
            if let Ok(f) = self
                .router
                .handle_local(now, dest, &payload, &mut self.tx_buffer)
            {
                stage.emit(OutgoingFrame {
                    dst: f.dst,
                    protocol: f.protocol,
                    payload: f.payload,
                    // Locally originated: no ingress interface to exclude.
                    egress: Egress::Auto { exclude: None },
                });
            }
        }

        poll_due_ogms(&mut self.router, now, &mut self.tx_buffer, &mut stage);
        poll_due_keepalives(&mut self.router, now, &mut self.tx_buffer, &mut stage);

        for staged in stage.frames.drain(..) {
            self.dispatch_one(now, staged);
        }
        self.local_rx.extend(stage.local.drain(..));
    }

    /// Resolve one staged frame's egress (tagging it for pairwise auth first,
    /// when enabled) and push its wire bytes onto each selected interface's
    /// egress queue — the synchronous counterpart of the embedded/tokio
    /// drivers' `dispatch`, minus the actual link I/O.
    fn dispatch_one(&mut self, now: Duration, mut staged: StagedFrame) {
        let body_len = staged.payload.len();
        staged.payload.resize(body_len + DIRECTED_TRAILER_LEN, 0);
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
    use wayfinder::batman::wire::BATADV_IV_OGM;
    use wayfinder::batman::wire::BatmanOgmPacket;

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
            packet_type: BATADV_IV_OGM,
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

    /// One due interface's `tick` stages exactly one OGM broadcast into that
    /// interface's egress queue.
    #[test]
    fn tick_emits_due_ogm_into_its_interface_egress_queue() {
        let trickle = [TrickleConfig::default()];
        let mut driver = Driver::new(mac(1), &trickle, &[]);

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

    /// A received OGM pushed on interface 0 is re-flooded into interface 1's
    /// egress queue only — split-horizon keeps it off the interface it
    /// arrived on. Ticks at `now = ZERO`, before either interface's own
    /// Trickle timer can be due (armed within `[i_min/2, i_min)` after
    /// construction), so the only thing in interface 1's queue is the
    /// re-flood.
    #[test]
    fn tick_reforwards_received_ogm_with_split_horizon() {
        let trickle = [TrickleConfig::default(), TrickleConfig::default()];
        let mut driver = Driver::new(mac(1), &trickle, &[]);

        let ogm = bare_ogm_bytes(mac(2), 1, 50);
        let wire = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        driver
            .push_rx(0, LinkMetrics::default(), &wire)
            .expect("well-formed frame");

        driver.tick(Duration::ZERO);

        assert!(
            driver.poll_egress(0).is_none(),
            "split-horizon: no re-flood back out the ingress interface"
        );
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
        let mut driver = Driver::new(mac(1), &trickle, &[]);

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
        let mut driver = Driver::new(mac(1), &trickle, &features);

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
            Some(&wayfinder::batman::wire::BATADV_KEEPALIVE)
        );
    }

    /// An interface with no `tx_keepalive` configured never emits a
    /// heartbeat, no matter how far `tick` advances — opt-in, matching the
    /// `LinkFeatures` default.
    #[test]
    fn tick_never_emits_keepalive_when_unconfigured() {
        let trickle = [TrickleConfig::default()];
        let mut driver = Driver::new(mac(1), &trickle, &[]);

        driver.tick(Duration::from_secs(1_000));
        // Drain whatever OGM(s) landed; only a keep-alive would be a bug here.
        while let Some(frame) = driver.poll_egress(0) {
            let parsed = LinkFrame::ref_from_bytes(&frame).unwrap();
            assert_ne!(
                parsed.payload.first(),
                Some(&wayfinder::batman::wire::BATADV_KEEPALIVE),
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
        let mut a = Driver::new(mac(1), &trickle, &[]);
        let mut b = Driver::new(mac(2), &trickle, &[]);

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
}
