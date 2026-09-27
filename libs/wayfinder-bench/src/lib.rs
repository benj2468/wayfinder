//! Fixtures for the packet-path benchmarks in `benches/`.
//!
//! The benchmarks measure how fast a node moves packets: through the shared
//! planning core ([`wayfinder_driver_core`]) frame by frame, and through a
//! whole synchronous shell ([`wayfinder_tick_driver`]) in bulk.
//!
//! # Why the fixtures matter more than the benchmarks
//!
//! Nearly every interesting path through the router is reached *only* from a
//! warm routing state. A `handle_mesh_frame` on a freshly constructed
//! [`CentralRouter`] does not measure forwarding — there is no route, so it
//! measures the no-route drop, which is both much cheaper and not the thing
//! anyone wants a number for. Every fixture here therefore converges the
//! router into the state whose cost is being claimed, and the benches assert
//! that state before entering their measurement loop (see
//! [`WarmRouter::assert_route_to`]).
//!
//! The axes the fixtures are parameterised on are the ones that actually move
//! the number:
//!
//! - **payload size** — how much of the cost is per-frame versus per-byte;
//! - **originator count** — whether route lookup and OGM ingest stay flat as
//!   the table fills, which is where an accidental `O(n)` would show;
//! - **interface count** — the cost of flood fan-out;
//! - **auth on/off** — the Ed25519 tax, which is large enough to hide
//!   everything else and so is always a separate axis, never folded in.

use core::num::NonZeroU8;
use core::time::Duration;

use batman::wire::BATMAN_VERSION;
use batman::wire::BatmanOgmPacket;
use batman::wire::BatmanPacketType;
use batman::wire::BatmanUnicastPacket;
use interfaces::link::LinkMetrics;
use wayfinder::CentralRouter;
use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
use wayfinder::config::Config;
use wayfinder::config::LinkConfig;
use wayfinder::config::TrickleConfig;
use wayfinder::interfaces::frame::Mac;
use wayfinder::router_ops::RouterOps;
use wayfinder_driver_core::MeshSink;
use wayfinder_driver_core::OutgoingFrame;
use wayfinder_test::driver::TestConfig;
use wayfinder_test::driver::TestHarness;
use wayfinder_test::driver::TestMachineConfig;
use wayfinder_test::driver::TestSwitchConfig;
use wayfinder_test::driver::mac;
use zerocopy::IntoBytes;

/// The per-interface multicast fan-out declarations handed to every benchmarked
/// receive: none, on any interface.
///
/// Empty rather than a filled-in threshold because these benchmarks measure the
/// unicast, broadcast and OGM paths, where the declaration is never consulted —
/// a collapse only happens for a multicast with several next hops behind one
/// medium. An empty slice reads identically to an all-`None` one at every index
/// (`fan_out.get(idx)` yields `None` either way), and it is what a link that has
/// not opted in actually declares, so it keeps these benchmarks on the same path
/// a real node takes for them.
///
/// Timing the collapse itself needs a fixture that converges several multicast
/// destinations behind one fan-out interface; there is no such benchmark yet.
pub const NO_FAN_OUT: &[Option<NonZeroU8>] = &[];

/// Physical-layer metrics attached to every benchmarked receive: a strong,
/// noiseless link.
///
/// Fixed rather than varied because link quality changes *which* route the
/// engine picks, not how much work it does picking one — varying it would add
/// run-to-run variance to the timing without measuring anything new.
pub const GOOD_METRICS: LinkMetrics = LinkMetrics {
    rssi_dbm: Some(-40),
    snr_db: Some(10),
    quality: Some(255),
};

/// The node under measurement. Benchmarks always drive this MAC's router.
pub const SELF_MAC: u8 = 1;

/// The neighbour every benchmarked frame arrives from, and the next hop every
/// route resolves through.
pub const PEER_MAC: u8 = 2;

/// A far-side originator reachable only via [`PEER_MAC`] — the destination for
/// the forwarding benchmarks, chosen so the frame is genuinely *forwarded*
/// rather than delivered locally.
pub const REMOTE_MAC: u8 = 3;

/// Payload sizes the per-frame benchmarks sweep, in bytes.
///
/// 64 is a small control/ack-shaped frame where per-frame overhead dominates;
/// 1400 sits just under a standard Ethernet MTU, where per-byte copying does.
/// 512 is between them, and is roughly the largest payload the small-MTU radio
/// links carry without fragmentation.
pub const PAYLOAD_SIZES: [usize; 3] = [64, 512, 1400];

/// Originator-table occupancies the scaling benchmarks sweep.
///
/// The point of the sweep is the *shape*, not any one number: cost should be
/// close to flat across it. A 127-originator ingest costing ~127x a
/// 1-originator ingest is a linear scan that should not be there.
///
/// The top of the sweep is 127, not a round number, because these count the
/// *far-side* originators and the neighbour relaying them occupies a slot too —
/// so 127 fills the table to exactly [`wayfinder::ORIGINATOR_CAPACITY`]. That
/// is the interesting end deliberately: a table at capacity is where eviction
/// and probing behaviour start to matter, and it is the occupancy a saturated
/// mesh actually runs at.
pub const ORIGINATOR_COUNTS: [usize; 3] = [1, 32, 127];

/// A [`MeshSink`] that accounts for what was planned without allocating.
///
/// The sinks in the driver shells copy each frame into their staging (`Vec` on
/// host, `heapless::Vec` on embedded); this one deliberately does not, because
/// the benchmarks measure the *planning*, and a copy in the sink would show up
/// in the timing as if it were the router's cost.
///
/// It is not a no-op either: it sums the payload lengths, so the optimiser
/// cannot conclude the planned frame is unused and delete the work that
/// produced it. The counters are read back through
/// [`black_box_counts`](Self::black_box_counts) after each measured batch.
#[derive(Debug, Default, Clone, Copy)]
pub struct CountingSink {
    /// Number of frames planned for the mesh.
    pub emitted: u64,
    /// Number of payloads planned for local delivery.
    pub delivered: u64,
    /// Sum of all planned payload lengths, in bytes. Summed rather than
    /// discarded so the payload is genuinely read.
    pub bytes: u64,
}

impl CountingSink {
    /// Hand the accumulated counters to [`core::hint::black_box`], so nothing
    /// this sink recorded can be optimised away as unobserved.
    pub fn black_box_counts(&self) {
        core::hint::black_box((self.emitted, self.delivered, self.bytes));
    }
}

impl MeshSink for CountingSink {
    fn emit(&mut self, frame: OutgoingFrame<'_>) -> bool {
        self.emitted += 1;
        self.bytes += frame.payload.len() as u64;
        true
    }

    fn deliver_local(&mut self, inner: &[u8]) {
        self.delivered += 1;
        self.bytes += inner.len() as u64;
    }
}

// ── frame builders ───────────────────────────────────────────────────────────

/// Wrap `payload` in a link frame: `[dst][src][protocol be][payload]`.
///
/// The same layout as `wayfinder_test::build_frame`, restated here so the
/// benchmark fixtures do not depend on a test helper's signature staying put.
pub fn link_frame(dst: Mac, src: Mac, protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(14 + payload.len());
    raw.extend_from_slice(dst.as_bytes());
    raw.extend_from_slice(src.as_bytes());
    raw.extend_from_slice(&protocol.to_be_bytes());
    raw.extend_from_slice(payload);
    raw
}

/// The bytes of a bare one-hop OGM from `orig`: BATMAN header only, no TVLVs.
///
/// `tq` is the path quality the receiver folds into its metric; 255 is a
/// perfect path, which keeps the benchmarked route stable across iterations.
pub fn ogm_payload(orig: Mac, seqno: u32, ttl: u8, tq: u8) -> Vec<u8> {
    let ogm = BatmanOgmPacket {
        packet_type: BatmanPacketType::Ogm.as_u8(),
        version: BATMAN_VERSION,
        ttl,
        flags: 0,
        seqno: seqno.to_be(),
        orig,
        reserved: 0,
        tq,
        tvlv_len: 0,
    };
    ogm.as_bytes().to_vec()
}

/// A complete on-wire OGM frame: `orig`'s OGM, relayed by neighbour `src`,
/// broadcast on the segment.
pub fn ogm_frame(orig: Mac, src: Mac, seqno: u32, ttl: u8, tq: u8) -> Vec<u8> {
    link_frame(
        Mac::BROADCAST,
        src,
        DEFAULT_BATMAN_ETHER_TYPE,
        &ogm_payload(orig, seqno, ttl, tq),
    )
}

/// A complete on-wire BATMAN unicast frame of `payload_len` payload bytes,
/// sent by `src` toward final destination `dest`.
///
/// The link-layer destination is this node ([`SELF_MAC`]) — that is what makes
/// the frame *ours to route*: the router then consults `dest` to decide whether
/// to forward it onward or hand it up locally.
pub fn unicast_frame(src: Mac, link_dst: Mac, dest: Mac, payload_len: usize) -> Vec<u8> {
    let hdr = BatmanUnicastPacket {
        packet_type: BatmanPacketType::Unicast.as_u8(),
        version: BATMAN_VERSION,
        ttl: 50,
        dest,
    };
    let mut payload = hdr.as_bytes().to_vec();
    // A repeating byte pattern rather than zeros: a page of zeros can be
    // handled differently by memcpy and by the allocator, and the point is to
    // measure a realistic copy.
    payload.extend((0..payload_len).map(|i| (i % 251) as u8));
    link_frame(link_dst, src, DEFAULT_BATMAN_ETHER_TYPE, &payload)
}

// ── warm routers ─────────────────────────────────────────────────────────────

/// A router converged into a known routing state, plus the scratch buffer the
/// planning functions stage into.
///
/// Held together in one struct because a benchmark needs both on every
/// iteration and neither is meaningful without the other.
pub struct WarmRouter {
    /// The router under measurement.
    pub router: CentralRouter,
    /// The transmit scratchpad `handle_mesh_frame`/`plan_dispatch` plan into.
    pub tx: Vec<u8>,
    /// How many mesh interfaces the router was configured with.
    pub num_interfaces: usize,
    /// The virtual instant every measured call is made at.
    ///
    /// **Fixed, and every iteration reuses it.** Two reasons, both of which
    /// would otherwise corrupt the measurement:
    ///
    /// - Routing state is perishable. An originator not refreshed within
    ///   `MAX_MISSED_OGMS` of its learned interval is purged, so a benchmark
    ///   that advanced its clock would converge, measure forwarding for a
    ///   while, and then silently switch to measuring the no-route drop path
    ///   part-way through the run — averaging two different code paths into
    ///   one number.
    /// - A frozen clock makes every iteration identical, which is what a
    ///   timing benchmark needs in order for its variance to mean anything.
    ///
    /// It sits just past the last OGM the fixture fed in, well inside the
    /// freshness window.
    pub now: Duration,
}

impl WarmRouter {
    /// Panic unless the router resolves a route to `dst` at [`now`](Self::now).
    ///
    /// Called by every forwarding benchmark before it starts measuring. A
    /// fixture that silently stopped converging would otherwise turn the
    /// benchmark into a measurement of the no-route drop path — still a
    /// plausible-looking number, roughly an order of magnitude too fast, and
    /// attributed to the wrong code. Failing loudly here is the difference
    /// between a benchmark and a fiction.
    pub fn assert_route_to(&mut self, dst: Mac) {
        let now = self.now;
        assert!(
            self.router.get_egress_interface(now, dst).is_some(),
            "benchmark fixture is not converged: no route to {dst:?} at {now:?}"
        );
    }

    /// Panic unless the originator table holds exactly `n` entries.
    pub fn assert_originators(&self, n: usize) {
        let got = self.router.originator_table().count();
        assert_eq!(
            got, n,
            "benchmark fixture has {got} originators, wanted {n}"
        );
    }
}

/// A router with `num_interfaces` links, converged so that `n_originators`
/// remote nodes are reachable — all of them via neighbour [`PEER_MAC`] on
/// interface 0.
///
/// Built by feeding real OGMs through the real receive path rather than by
/// injecting table entries directly: an injected entry can be shaped in ways
/// the protocol never produces, and the benchmark would then measure lookups
/// against a table that cannot occur in practice.
///
/// `n_originators` counts the far-side originators; [`PEER_MAC`] itself is
/// learned in addition to them, so the table ends up with `n_originators + 1`
/// entries — which is why the ceiling is `ORIGINATOR_CAPACITY - 1` rather than
/// the capacity itself. Asking for more would not fail, it would silently
/// produce a table one entry short of what the benchmark's label claims.
pub fn warm_router(num_interfaces: usize, n_originators: usize) -> WarmRouter {
    assert!(
        n_originators < wayfinder::ORIGINATOR_CAPACITY,
        "n_originators must leave a table slot for the relaying neighbour"
    );
    assert!(num_interfaces >= 1, "a router needs at least one interface");

    let mut router = CentralRouter::new(mac(SELF_MAC));
    for idx in 0..num_interfaces {
        router.configure_interface_ogm(
            idx,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
    }

    let mut tx = vec![0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
    let mut sink = CountingSink::default();
    let mut now = Duration::ZERO;

    // One OGM round per second, and **time advances per round, never per
    // originator**. This is load-bearing, not cosmetic.
    //
    // BATMAN learns each path's expected OGM interval from the gaps between
    // sightings, and ages the path out after `MAX_MISSED_OGMS` of it. Feeding a
    // round's originators 10ms apart therefore teaches the engine that these
    // nodes announce every 10ms, which retires every path ~60ms later — the
    // fixture converges and then immediately un-converges, leaving a stale
    // `best_next_hop` cached on a record whose paths have all expired. The
    // benchmark still runs; it just silently measures the no-route drop.
    //
    // A one-second round matches the Trickle floor a real node uses, so the
    // learned interval is realistic and the measurement instant sits well
    // inside the freshness budget.
    const ROUND: Duration = Duration::from_secs(1);

    // The neighbour's own OGMs first: direct one-hop announcements, which give
    // interface 0 a link-quality sample and make PEER a usable next hop for
    // everything that follows.
    for seqno in 1..=3u32 {
        now += ROUND;
        let raw = ogm_frame(mac(PEER_MAC), mac(PEER_MAC), seqno, 50, 255);
        feed(&mut router, &raw, now, &mut tx, &mut sink);
    }

    // Then each far-side originator, relayed by PEER. Two rounds: BATMAN needs
    // more than a single sighting before it will commit to a route.
    for seqno in 1..=2u32 {
        now += ROUND;
        for i in 0..n_originators {
            let orig = mac(REMOTE_MAC.saturating_add(u8::try_from(i).unwrap_or(u8::MAX)));
            let raw = ogm_frame(orig, mac(PEER_MAC), seqno, 49, 250);
            feed(&mut router, &raw, now, &mut tx, &mut sink);
        }
    }

    sink.black_box_counts();
    WarmRouter {
        router,
        tx,
        num_interfaces,
        // A short step past the last OGM: far enough that nothing is mid-update,
        // near enough that no originator has aged out. See `WarmRouter::now`.
        now: now + Duration::from_millis(100),
    }
}

/// Push one raw frame through the real receive path, on interface 0.
fn feed<R: RouterOps>(
    router: &mut R,
    raw: &[u8],
    now: Duration,
    tx: &mut [u8],
    sink: &mut CountingSink,
) {
    feed_at(router, raw, now, 0, tx, sink);
}

/// Push one raw frame through the real receive path, on interface `idx`.
fn feed_at<R: RouterOps>(
    router: &mut R,
    raw: &[u8],
    now: Duration,
    idx: usize,
    tx: &mut [u8],
    sink: &mut CountingSink,
) {
    use zerocopy::FromBytes;
    let Ok(frame) = wayfinder::interfaces::frame::LinkFrame::ref_from_bytes(raw) else {
        panic!("bench fixture built a malformed link frame");
    };
    wayfinder_driver_core::handle_mesh_frame(
        now,
        router,
        idx,
        frame,
        GOOD_METRICS,
        tx,
        NO_FAN_OUT,
        sink,
    );
}

// ── the cloud-profile fixtures (design 26) ──────────────────────────────────

/// The router at the `cloud` capacity profile, which `wayfinder-tap` runs.
pub type CloudRouter = wayfinder::router_for!(wayfinder::cloud);

/// Originator-table occupancies the cloud sweep covers: one, a quarter of the
/// table, and full (4095 far-side originators plus the relaying neighbour).
///
/// The same question as [`ORIGINATOR_COUNTS`], asked where it matters: at 4096
/// entries a per-frame linear scan is 32x the work it is at `host`'s 128, so
/// a cost that was noise there is the whole number here.
pub const CLOUD_ORIGINATOR_COUNTS: [usize; 3] = [1, 1024, 4095];

/// The address of far-side node `i`, for sweeps wider than a `u8` can name.
///
/// Locally administered (`0x02` first octet) and prefixed so it can never
/// collide with [`SELF_MAC`], [`PEER_MAC`] or any `mac(n)` address.
pub fn wide_mac(i: usize) -> Mac {
    let Ok(i) = u16::try_from(i) else {
        panic!("wide_mac covers 65536 nodes; {i} is past that")
    };
    let [hi, lo] = i.to_be_bytes();
    Mac([0x02, 0, 0, 0x10, hi, lo])
}

/// A converged router at the `cloud` profile: the [`WarmRouter`] counterpart,
/// boxed because the router is ~1.8 MB.
///
/// Built with `Box::new(CloudRouter::with_capacities(..))`, which is fine in a
/// benchmark: `cargo bench` builds with optimisations, where construction
/// needs a fraction of the stack an unoptimised build does. Do not build one of
/// these from a debug-profile unit test — see `wayfinder-driver`'s
/// `build_off_stack` for why.
pub struct WarmCloudRouter {
    /// The router under measurement.
    pub router: Box<CloudRouter>,
    /// The transmit scratchpad.
    pub tx: Vec<u8>,
    /// The virtual instant every measured call is made at, fixed for the
    /// reasons in [`WarmRouter::now`].
    pub now: Duration,
}

impl WarmCloudRouter {
    /// Panic unless the router resolves a route to `dst` at [`now`](Self::now).
    /// See [`WarmRouter::assert_route_to`] for why every forwarding benchmark
    /// calls this first.
    pub fn assert_route_to(&mut self, dst: Mac) {
        let now = self.now;
        assert!(
            self.router.get_egress_interface(now, dst).is_some(),
            "cloud fixture is not converged: no route to {dst:?} at {now:?}"
        );
    }

    /// Panic unless the originator table holds exactly `n` entries.
    pub fn assert_originators(&self, n: usize) {
        let got = self.router.originator_table().count();
        assert_eq!(got, n, "cloud fixture has {got} originators, wanted {n}");
    }
}

/// A `cloud` router converged so that `n_originators` far-side nodes
/// ([`wide_mac`]`(0..n)`) are reachable via neighbour [`PEER_MAC`] — the
/// [`warm_router`] topology, at cloud scale. Fed through the real receive path
/// on the same one-second round, for the reasons given there.
pub fn warm_cloud_router(n_originators: usize) -> WarmCloudRouter {
    assert!(
        n_originators < wayfinder::cloud::ORIGINATORS,
        "n_originators must leave a table slot for the relaying neighbour"
    );
    const ROUND: Duration = Duration::from_secs(1);
    let mut router = Box::new(CloudRouter::with_capacities(mac(SELF_MAC)));
    router.configure_interface_ogm(
        0,
        Duration::from_secs(1),
        Duration::from_secs(8),
        Duration::ZERO,
    );
    let mut tx = vec![0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
    let mut sink = CountingSink::default();
    let mut now = Duration::ZERO;

    for seqno in 1..=3u32 {
        now += ROUND;
        let raw = ogm_frame(mac(PEER_MAC), mac(PEER_MAC), seqno, 50, 255);
        feed(&mut *router, &raw, now, &mut tx, &mut sink);
    }
    for seqno in 1..=2u32 {
        now += ROUND;
        for i in 0..n_originators {
            let raw = ogm_frame(wide_mac(i), mac(PEER_MAC), seqno, 49, 250);
            feed(&mut *router, &raw, now, &mut tx, &mut sink);
        }
    }

    sink.black_box_counts();
    WarmCloudRouter {
        router,
        tx,
        now: now + Duration::from_millis(100),
    }
}

/// A `cloud` router at the centre of a hub: `n_neighbours` nodes
/// ([`wide_mac`]`(0..n)`), every one a *direct* neighbour announcing itself.
///
/// The VPN hub's shape, and the one that fills the per-neighbour tables rather
/// than only the originator table: [`warm_cloud_router`] has one neighbour
/// relaying everything, which a scan over neighbours would never notice.
pub fn warm_cloud_hub(n_neighbours: usize) -> WarmCloudRouter {
    assert!(
        n_neighbours <= wayfinder::cloud::ORIGINATORS,
        "a hub cannot have more neighbours than originator slots"
    );
    const ROUND: Duration = Duration::from_secs(1);
    let mut router = Box::new(CloudRouter::with_capacities(mac(SELF_MAC)));
    router.configure_interface_ogm(
        0,
        Duration::from_secs(1),
        Duration::from_secs(8),
        Duration::ZERO,
    );
    let mut tx = vec![0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
    let mut sink = CountingSink::default();
    let mut now = Duration::ZERO;

    for seqno in 1..=3u32 {
        now += ROUND;
        for i in 0..n_neighbours {
            let raw = ogm_frame(wide_mac(i), wide_mac(i), seqno, 50, 255);
            feed(&mut *router, &raw, now, &mut tx, &mut sink);
        }
    }

    sink.black_box_counts();
    WarmCloudRouter {
        router,
        tx,
        now: now + Duration::from_millis(100),
    }
}

// ── the authenticated fixture ────────────────────────────────────────────────

/// A converged three-node authenticated line, `A — B — C`, with **B** the node
/// under measurement.
///
/// Three nodes rather than two because the question is what an authenticated
/// node costs to *forward*, and a node with one neighbour has nowhere to
/// forward to — it can only deliver locally, which skips the routing decision
/// and the outbound re-tag that are most of the answer.
///
/// Auth is not something a fixture can switch on after the fact: enabling it
/// resets all learned routing state *and* turns on the next-hop proof gate, so
/// a route is unusable until its next hop has answered a pairwise challenge.
/// Reproducing that by hand would mean reimplementing convergence; instead this
/// leans on [`TestHarness::converge`], which already drives signed-OGM exchange
/// and the challenge/response round trip to completion.
pub struct AuthedLine {
    /// The running three-node harness.
    pub harness: TestHarness,
    /// `machine1` — the upstream neighbour, which tags the frames B verifies.
    pub a: Mac,
    /// `machine2` — the node under measurement: it verifies A's tag, routes,
    /// and re-tags toward C.
    pub b: Mac,
    /// `machine3` — the far side, and the inner destination of every
    /// benchmarked frame, so B genuinely forwards rather than delivers.
    pub c: Mac,
    /// B's transmit scratchpad.
    pub tx: Vec<u8>,
    /// The virtual instant every measured call is made at, held fixed for the
    /// reasons in [`WarmRouter::now`].
    pub now: Duration,
}

impl AuthedLine {
    /// Tag a fresh unicast from A toward B, carrying `payload_len` bytes bound
    /// for C, and return the complete on-wire frame.
    ///
    /// **Every call consumes a new replay counter, and that is the point.**
    /// `verify_directed` rejects a counter it has already accepted, so feeding
    /// B the *same* bytes twice measures the replay-drop path on the second and
    /// every subsequent iteration — the tag is still verified (the expensive
    /// part runs before the counter check) but the frame is never forwarded, so
    /// the routing and re-tagging half of the measurement silently disappears.
    /// Benchmarks therefore call this in criterion's `iter_batched` *setup*,
    /// which is excluded from the timing.
    pub fn tag_from_a(&mut self, payload_len: usize) -> Vec<u8> {
        let (b, c) = (self.b, self.c);
        let hdr = BatmanUnicastPacket {
            packet_type: BatmanPacketType::Unicast.as_u8(),
            version: BATMAN_VERSION,
            ttl: 50,
            dest: c,
        };
        let mut body = hdr.as_bytes().to_vec();
        body.extend((0..payload_len).map(|i| (i % 251) as u8));

        let mut trailer = [0u8; wayfinder::auth::DIRECTED_TRAILER_LEN];
        let node = self.harness.get_machine_mut("machine1");
        let Some(auth) = node.router_mut().auth_mut() else {
            panic!("bench fixture: A has no auth state")
        };
        let Some(n) = auth.tag_directed(b, &body, &mut trailer) else {
            panic!("bench fixture: A cannot tag toward B — pairwise key missing")
        };
        body.extend_from_slice(&trailer[..n]);

        link_frame(b, self.a, DEFAULT_BATMAN_ETHER_TYPE, &body)
    }

    /// B's router, mutably — the node under measurement.
    pub fn router_mut(&mut self) -> &mut CentralRouter {
        self.harness.get_machine_mut("machine2").router_mut()
    }

    /// Panic unless B currently forwards a tagged frame from A onward to C.
    ///
    /// The authenticated counterpart of [`WarmRouter::assert_route_to`], and
    /// needed for more reasons: besides having a route, B must hold A's
    /// pairwise key (or the frame is dropped unverified) and must consider C a
    /// proven next hop (or the route is refused). Any one of those missing
    /// turns this benchmark into a measurement of a drop.
    pub fn assert_forwards(&mut self) {
        let raw = self.tag_from_a(64);
        let mut sink = CountingSink::default();
        let now = self.now;
        let mut tx = core::mem::take(&mut self.tx);
        feed_at(self.router_mut(), &raw, now, 0, &mut tx, &mut sink);
        self.tx = tx;
        assert_eq!(
            sink.emitted, 1,
            "bench fixture: B verified but did not forward — it needs A's pairwise \
             key, a route to C, and C proven as a next hop"
        );
    }
}

/// Build a three-node authenticated line `A — B — C`, converged far enough that
/// B verifies A's directed frames and forwards them to C.
///
/// All three nodes are members of the same mesh, minted by one [`Authority`].
/// The certs are given a wide validity window and the auth clock is pinned
/// inside it, so nothing expires part-way through a benchmark run.
///
/// [`Authority`]: wayfinder_auth::Authority
pub fn authed_line() -> AuthedLine {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig::shared("switch1"));
    config.switches.push(TestSwitchConfig::shared("switch2"));
    // A on switch1, B bridging both, C on switch2 — so B is the only path
    // between them and every A→C frame is genuinely forwarded.
    for (name, links) in [
        ("machine1", vec!["switch1"]),
        ("machine2", vec!["switch1", "switch2"]),
        ("machine3", vec!["switch2"]),
    ] {
        config.machines.push(TestMachineConfig {
            name: name.into(),
            wayfinder: Config {
                links: links.into_iter().map(LinkConfig::test).collect(),
                ..Default::default()
            },
        });
    }
    let Ok(mut harness) = config.validate() else {
        panic!("bench fixture: three-node authed line failed to validate")
    };

    let a = harness.get_machine("machine1").ident;
    let b = harness.get_machine("machine2").ident;
    let c = harness.get_machine("machine3").ident;

    let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
    for (i, name) in ["machine1", "machine2", "machine3"].iter().enumerate() {
        enable_auth(&mut harness, name, &authority, i);
    }

    // Signed OGMs exchange (each node learns its neighbours' pairwise keys,
    // without which a directed frame cannot be tagged at all), and the
    // next-hop proof challenge/response completes.
    harness.converge(Duration::from_secs(1));

    for name in ["machine1", "machine2", "machine3"] {
        assert_eq!(
            harness
                .get_machine(name)
                .router()
                .originator_table()
                .count(),
            2,
            "bench fixture: {name} did not converge under auth"
        );
    }

    let now = harness.clock + Duration::from_millis(100);
    let mut line = AuthedLine {
        harness,
        a,
        b,
        c,
        tx: vec![0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN],
        now,
    };
    line.assert_forwards();
    line
}

/// Enable mesh authentication on harness machine `index` (zero-based, in config
/// order), with a cert minted by `authority` and the auth clock pinned inside
/// the cert's validity window.
///
/// The identity comes from `wayfinder_test::machine_keypair`, the same key the
/// harness took the machine's address from: a certificate's subject is the
/// address its key derives (design 09 §5), so a fixture that minted a fresh key
/// here would produce a credential for an address this node does not answer to
/// — and the benchmark would silently measure the drop path, which is the
/// hazard the root `CLAUDE.md` records for exactly these fixtures.
fn enable_auth(
    harness: &mut TestHarness,
    name: &str,
    authority: &wayfinder_auth::Authority,
    index: usize,
) {
    let kp = wayfinder_test::driver::machine_keypair(index);
    let ident = kp.derived_mac();
    let cert = authority.issue_cert(ident, kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);
    let node = harness.get_machine_mut(name);
    node.router_mut().set_auth(wayfinder::auth::OgmAuth::new(
        kp,
        cert,
        authority.trust_anchor(),
    ));
    node.set_epoch_unix(1_000);
}

// ── tick-driver fixture ──────────────────────────────────────────────────────

/// A converged tick driver plus a batch of frames to push through it, for the
/// end-to-end throughput benchmark.
pub struct WarmTickDriver {
    /// The driver under measurement.
    pub driver: wayfinder_tick_driver::Driver,
    /// Pre-built on-wire frames, ready to `push_rx`. Built once, outside the
    /// measurement, so frame construction is not counted as routing cost.
    pub batch: Vec<Vec<u8>>,
    /// The virtual instant the benchmark's first tick runs at.
    pub start: Duration,
}

/// Build a tick driver converged on a route to [`REMOTE_MAC`] via
/// [`PEER_MAC`], together with `batch_size` unicast frames of `payload_len`
/// bytes addressed there.
///
/// This is the whole-shell counterpart to [`warm_router`]: where that measures
/// one planning call, this measures the full `push_rx` → `tick` → `poll_egress`
/// cycle a real synchronous shell runs, including the wire framing and egress
/// queueing the planning core does not do.
pub fn warm_tick_driver(batch_size: usize, payload_len: usize) -> WarmTickDriver {
    let trickle = vec![TrickleConfig::default()];
    let mut driver = wayfinder_tick_driver::Driver::new(mac(SELF_MAC), &trickle, &[], &[]);

    let mut now = Duration::ZERO;
    // One second per OGM, for the reason spelled out in `warm_router`: a
    // tighter cadence teaches the engine an unrealistically short expected
    // interval and the learned route ages out before the benchmark runs.
    let push = |driver: &mut wayfinder_tick_driver::Driver, now: &mut Duration, raw: &[u8]| {
        *now += Duration::from_secs(1);
        let Ok(()) = driver.push_rx(0, GOOD_METRICS, raw) else {
            panic!("bench fixture built a malformed link frame")
        };
        driver.tick(*now);
        // Drop whatever the driver planned in response (OGM re-floods and the
        // like); the fixture only cares about the routing state it left behind.
        while driver.poll_egress(0).is_some() {}
        while driver.poll_local().is_some() {}
    };

    for seqno in 1..=3u32 {
        push(
            &mut driver,
            &mut now,
            &ogm_frame(mac(PEER_MAC), mac(PEER_MAC), seqno, 50, 255),
        );
    }
    for seqno in 1..=2u32 {
        push(
            &mut driver,
            &mut now,
            &ogm_frame(mac(REMOTE_MAC), mac(PEER_MAC), seqno, 49, 250),
        );
    }

    assert!(
        driver
            .router_mut()
            .get_egress_interface(now, mac(REMOTE_MAC))
            .is_some(),
        "bench fixture: tick driver has no route to the remote originator"
    );

    let batch = (0..batch_size)
        .map(|_| unicast_frame(mac(PEER_MAC), mac(SELF_MAC), mac(REMOTE_MAC), payload_len))
        .collect();

    WarmTickDriver {
        driver,
        batch,
        start: now + Duration::from_secs(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixtures are the only load-bearing logic in this crate, and a
    /// silently unconverged one turns every benchmark into a measurement of
    /// the drop path. These tests are what make `assert_route_to` a check
    /// rather than a hope.

    #[test]
    fn warm_router_converges_a_route_to_the_remote_originator() {
        let mut warm = warm_router(1, 1);
        warm.assert_route_to(mac(REMOTE_MAC));
        // The far-side originator plus the neighbour itself.
        warm.assert_originators(2);
    }

    #[test]
    fn warm_router_fills_the_originator_table_to_the_requested_occupancy() {
        for n in ORIGINATOR_COUNTS {
            let warm = warm_router(1, n);
            warm.assert_originators(n + 1);
        }
    }

    /// The authenticated fixture has three ways to be silently wrong — no
    /// pairwise key, no route, an unproven next hop — and all three produce a
    /// drop rather than an error. `authed_line` asserts a real forward at
    /// construction; this pins that the assertion itself works.
    #[test]
    fn authed_line_verifies_and_forwards() {
        let mut line = authed_line();
        line.assert_forwards();
    }

    /// Each tagged frame must carry a fresh replay counter. Two frames built
    /// back to back therefore differ in their trailer, and both are accepted —
    /// if `tag_from_a` ever returned identical bytes, the benchmark would
    /// measure the replay-drop path from its second iteration on.
    #[test]
    fn authed_line_tags_each_frame_with_a_fresh_counter() {
        let mut line = authed_line();
        let first = line.tag_from_a(64);
        let second = line.tag_from_a(64);
        assert_ne!(first, second, "each tagged frame needs a fresh counter");

        let now = line.now;
        let mut tx = core::mem::take(&mut line.tx);
        let mut sink = CountingSink::default();
        feed_at(line.router_mut(), &first, now, 0, &mut tx, &mut sink);
        feed_at(line.router_mut(), &second, now, 0, &mut tx, &mut sink);
        line.tx = tx;
        assert_eq!(sink.emitted, 2, "both fresh-counter frames must forward");
    }

    #[test]
    fn warm_tick_driver_converges_and_builds_its_batch() {
        let fixture = warm_tick_driver(8, 64);
        assert_eq!(fixture.batch.len(), 8);
    }

    #[test]
    fn counting_sink_records_what_was_planned() {
        let mut warm = warm_router(1, 1);
        warm.assert_route_to(mac(REMOTE_MAC));
        let raw = unicast_frame(mac(PEER_MAC), mac(SELF_MAC), mac(REMOTE_MAC), 64);
        let mut sink = CountingSink::default();
        let now = warm.now;
        feed(&mut warm.router, &raw, now, &mut warm.tx, &mut sink);
        assert_eq!(sink.emitted, 1, "a routed unicast is forwarded once");
    }

    /// The fixed measurement instant must stay inside the routing state's
    /// freshness window for the *whole* run, not just at the first iteration —
    /// otherwise a long benchmark quietly stops measuring forwarding. Since
    /// the clock never advances, re-checking after many lookups is what proves
    /// the state is genuinely stationary.
    #[test]
    fn warm_router_route_is_stationary_across_repeated_lookups() {
        let mut warm = warm_router(1, 1);
        for _ in 0..10_000 {
            warm.assert_route_to(mac(REMOTE_MAC));
        }
    }
}
