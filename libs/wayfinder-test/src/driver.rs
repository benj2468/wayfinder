use std::collections::HashMap;
use std::time::Duration;

use interfaces::frame::Mac;
use serde::Deserialize;
use serde::Serialize;
use wayfinder::config::LinkFeatures;
use wayfinder::config::TrickleConfig;

use crate::switch::PortComms;
use crate::switch::PortConfig;
use crate::switch::PortId;
use crate::switch::Switch;
use crate::test_router::TestRouter;

/// Declarative description of a whole test topology: the switches to create and
/// the machines to attach to them.
#[derive(Serialize, Deserialize, Default)]
pub struct TestConfig {
    /// The switches (shared media) to instantiate.
    pub switches: Vec<TestSwitchConfig>,
    /// The mesh nodes to instantiate and wire onto the switches.
    pub machines: Vec<TestMachineConfig>,
}

/// Config for one switch in a [`TestConfig`].
#[derive(Serialize, Deserialize)]
pub struct TestSwitchConfig {
    /// The switch's name, referenced by machines' link transports.
    pub name: String,
}

/// Config for one mesh node in a [`TestConfig`].
#[derive(Serialize, Deserialize)]
pub struct TestMachineConfig {
    /// The machine's name, used as its handle in the [`TestHarness`].
    pub name: String,
    /// The node's wayfinder configuration (identity, links, auth).
    pub wayfinder: wayfinder::config::Config,
}

/// Everything needed to rebuild a machine after it has been taken offline: its
/// stable mesh identity and the switches it attaches to.  Captured at build
/// time so [`disconnect_machine`](TestHarness::disconnect_machine) /
/// [`reconnect_machine`](TestHarness::reconnect_machine) can churn a node
/// without the test having to remember its wiring.
#[derive(Clone)]
struct MachineSpec {
    /// The node's mesh identity, preserved across reconnects so neighbors see
    /// the *same* originator come and go (as with a rebooting device).
    mac: Mac,
    /// Names of the switches this node is wired to, one mesh interface each, in
    /// the original interface order.
    switches: Vec<String>,
    /// Per-interface OGM backoff bounds, in the same interface order, so a
    /// reconnected node comes back with its original per-link pacing.
    trickle: Vec<TrickleConfig>,
    /// Per-interface participation features, in the same interface order, so a
    /// reconnected node comes back with its original per-link gating.
    features: Vec<LinkFeatures>,
}

impl MachineSpec {
    /// Apply this spec's per-link participation features onto a freshly built
    /// [`TestRouter`] (post-construction, since the router defaults its links to
    /// full participation).  Shared by initial build and reconnect so both
    /// honor the config's `features:` blocks.
    fn apply_features(&self, router: &mut TestRouter) {
        for (idx, f) in self.features.iter().enumerate() {
            router.router_mut().set_link_features(idx, *f);
        }
    }
}

/// A running multi-node mesh built from a [`TestConfig`]: the switches, the
/// nodes wired onto them, and a virtual clock the test advances by hand. The
/// entry point for integration tests that need more than one router.
#[derive(Default)]
pub struct TestHarness {
    /// The switches (shared media) in the topology, keyed by name.
    pub switches: HashMap<String, Switch<Mac>>,
    /// The mesh nodes in the topology, keyed by machine name.
    pub machines: HashMap<String, TestRouter>,
    /// Virtual clock driving the mesh.  [`poll`](Self::poll) sets it to the
    /// instant it is given, and [`tick`](Self::tick) stamps that same instant on
    /// every frame it processes, so received originator records age against the
    /// time the test controls rather than wall-clock.
    pub clock: Duration,
    /// Per-machine wiring, keyed by machine name, retained so a node taken
    /// offline can be brought back with its original identity and links.
    specs: HashMap<String, MachineSpec>,
    /// Per-machine switch-port handles, keyed by machine name and in interface
    /// order, so a single link's loss can be tuned (up/down) without disturbing
    /// the node.  Refreshed whenever a node is (re)wired.
    links: HashMap<String, Vec<(String, PortId)>>,
}

impl TestHarness {
    /// Create an empty harness with no switches, machines, or elapsed clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit one periodic OGM round at virtual instant `now`: set the clock and
    /// have every node emit on each interface whose Trickle timer is due
    /// ([`TestRouter::poll_due`] — the production per-interface path).  Most tests
    /// call this once with `now` past the first Trickle fire (≥ `i_min`), so every
    /// interface emits its first OGM and the mesh converges; the explicit clock
    /// also drives time-based route ageing.  For multi-round backoff dynamics
    /// (settling to `i_max`) use [`run_trickle`](Self::run_trickle).
    pub async fn poll_due(&mut self, now: Duration) {
        self.clock = now;
        for router in self.machines.values_mut() {
            router.poll_due(now).await;
        }
    }

    /// Advance the simulation by one step: let every node transmit then receive
    /// at the current virtual clock, then let every switch forward what is on
    /// the wire.  Returns the number of frames the switches pulled off the wire
    /// this step; `0` means no node transmitted, i.e. the fabric is quiescent.
    pub async fn tick(&mut self) -> usize {
        let now = self.clock;
        // The periodic (OGM) arm is disabled here (`check_periodic = false`):
        // OGM rounds are driven explicitly by `poll_due`, so a tick only moves the
        // frames already on the wire — first every node transmits, then every
        // node receives.
        for router in self.machines.values_mut() {
            let _ = tokio::time::timeout(
                tokio::time::Duration::from_nanos(1),
                router.driver().run_once(now, false, true, false, false),
            )
            .await;
        }

        for router in self.machines.values_mut() {
            let _ = tokio::time::timeout(
                tokio::time::Duration::from_nanos(1),
                router.driver().run_once(now, true, false, false, false),
            )
            .await;
        }
        let mut frames = 0;
        for switch in self.switches.values_mut() {
            #[expect(
                clippy::expect_used,
                reason = "the simulated Switch::tick has no failure mode reachable from this harness"
            )]
            let tick_frames = switch.tick().await.expect("switch tick should not fail");
            frames += tick_frames;
        }
        frames
    }

    /// Emit one OGM round at virtual instant `at`, then tick until the mesh
    /// fully converges — that is, until a tick moves **zero** frames, meaning no
    /// node has anything left to flood or forward.  During a convergence phase
    /// OGMs are the only traffic, so silence means every node's routing tables
    /// have settled.
    ///
    /// This loops with **no internal bound**: a mesh that never settles (for
    /// example because of an OGM forwarding loop) makes this run forever.
    /// Callers must wrap the call in [`tokio::time::timeout`] so non-convergence
    /// surfaces as a test failure instead of a hang — the timeout doubles as the
    /// "the mesh converged" assertion, and keeps large meshes (hundreds of
    /// nodes) honest about how long settling is allowed to take.
    pub async fn converge(&mut self, at: Duration) {
        self.poll_due(at).await;
        self.settle().await;
    }

    /// Drive the fabric to quiescence **without** emitting any new OGMs: keep
    /// ticking until a sweep moves no frames, then confirm it stays quiet.
    ///
    /// A single zero-frame tick can be a lull while a node still holds an
    /// unprocessed duplicate OGM (the same seqno arriving via a second path) in
    /// its ingress, so this requires the fabric to be silent for several
    /// *consecutive* sweeps before declaring convergence.  Use after injecting
    /// traffic (e.g. `send_local`) to let it reach its destination.
    ///
    /// A mesh that never quiets — e.g. an OGM forwarding loop circulating until
    /// TTL drains — would loop here forever, so the sweep count is hard-bounded:
    /// far more than any loop-free mesh needs (diameter × duplicate drainage),
    /// but finite, so a forwarding loop fails the test deterministically instead
    /// of hanging, on the paused clock as well as the real one.
    pub async fn settle(&mut self) {
        // Enough consecutive silent sweeps to outlast any in-flight duplicate
        // draining hop by hop across the mesh diameter.
        const QUIET_SWEEPS: usize = 8;
        // A loop-free mesh settles in O(diameter) active sweeps; anything beyond
        // this many total sweeps without quiescing is a forwarding loop.
        const MAX_SWEEPS: usize = 100_000;
        let mut quiet = 0;
        let mut total = 0;
        while quiet < QUIET_SWEEPS {
            total += 1;
            assert!(
                total < MAX_SWEEPS,
                "settle did not quiesce in {MAX_SWEEPS} sweeps — likely an OGM forwarding loop"
            );
            if self.tick().await > 0 {
                quiet = 0;
            } else {
                quiet += 1;
            }
        }
    }

    /// One event step of the production per-interface Trickle drive: advance the
    /// virtual clock to the soonest interface fire across the whole mesh, have
    /// every node emit whatever interface(s) are now due (one distinct seqno
    /// each, via [`poll_due`](Self::poll_due) / `poll_due_ogms`), then flood the
    /// result to quiescence through the real [`Switch`].  The building block of
    /// [`advance_trickle`](Self::advance_trickle) and
    /// [`run_trickle`](Self::run_trickle).
    async fn trickle_step(&mut self) {
        let now = self.clock;
        let dt = self
            .machines
            .values()
            .map(|m| m.next_broadcast_after(now))
            .min()
            .unwrap_or(Duration::from_secs(1))
            .max(Duration::from_nanos(1));
        self.clock = now + dt;
        for m in self.machines.values_mut() {
            m.poll_due(self.clock).await;
        }
        self.settle().await;
    }

    /// Advance the virtual clock to at least `to` using the production
    /// per-interface Trickle drive ([`trickle_step`](Self::trickle_step)): nodes
    /// emit on their own backoff schedules, so live nodes keep refreshing each
    /// other while a node that has gone silent ages out once `to` passes its
    /// purge budget.  The deterministic image of the real driver's periodic loop.
    pub async fn advance_trickle(&mut self, to: Duration) {
        let mut guard = 0u64;
        while self.clock < to {
            guard += 1;
            assert!(guard < 2_000_000, "trickle advance failed to terminate");
            self.trickle_step().await;
        }
    }

    /// Run the Trickle drive from the current instant to `end`, returning the
    /// **minimum originator count observed at any node after `warmup`** —
    /// `num_machines - 1` means every node continuously knew every other (no
    /// spurious purge/flap); anything less means routes flapped.  Used by the
    /// whole-mesh settling test; unlike [`converge`](Self::converge) it exercises
    /// the multi-round backoff dynamics (settling to `i_max`).
    pub async fn run_trickle(&mut self, warmup: Duration, end: Duration) -> usize {
        let n = self.machines.len();
        let mut min_full = n.saturating_sub(1);
        let mut guard = 0u64;

        while self.clock < end {
            guard += 1;
            assert!(guard < 2_000_000, "trickle drive failed to terminate");
            self.trickle_step().await;
            if self.clock >= warmup {
                for m in self.machines.values() {
                    min_full = min_full.min(m.router().originator_count());
                }
            }
        }
        min_full
    }

    /// Borrow the router for machine `name`, panicking if no such machine is
    /// currently connected.
    pub fn get_machine(&self, name: &str) -> &TestRouter {
        self.machines
            .get(name)
            .unwrap_or_else(|| panic!("unknown machine '{name}' (never built or disconnected)"))
    }

    /// Mutably borrow the router for machine `name`, panicking if no such
    /// machine is currently connected.
    pub fn get_machine_mut(&mut self, name: &str) -> &mut TestRouter {
        self.machines
            .get_mut(name)
            .unwrap_or_else(|| panic!("unknown machine '{name}' (never built or disconnected)"))
    }

    /// Take a machine offline: drop its router so it stops originating and
    /// forwarding OGMs and no longer accepts frames — the simulation equivalent
    /// of a node losing power or its radio.  Its former switch ports go dead
    /// (their receiver is dropped); the fabric tolerates that and simply fails
    /// to deliver to them.
    ///
    /// The node's identity and wiring are retained, so
    /// [`reconnect_machine`](Self::reconnect_machine) can bring the *same* node
    /// back later.  Panics if the machine is unknown or already disconnected.
    pub fn disconnect_machine(&mut self, name: &str) {
        assert!(
            self.specs.contains_key(name),
            "unknown machine '{name}' (never built)"
        );
        assert!(
            self.machines.remove(name).is_some(),
            "machine '{name}' is already disconnected"
        );
    }

    /// Bring a previously [`disconnected`](Self::disconnect_machine) machine
    /// back online with its original identity, freshly attached to the same
    /// switches.  The reborn node starts with **empty** routing tables — exactly
    /// like a rebooted device — so it must re-converge from OGMs before it can
    /// route again.  Panics if the machine is unknown or currently connected.
    pub fn reconnect_machine(&mut self, name: &str) {
        assert!(
            !self.machines.contains_key(name),
            "machine '{name}' is already connected"
        );
        let spec = self
            .specs
            .get(name)
            .unwrap_or_else(|| panic!("unknown machine '{name}' (never built)"))
            .clone();
        // Fresh ports (the old ones went dead when the node was removed); record
        // the new handles so link tuning targets the live wiring.
        let (interfaces, handles) = self.wire_links(&spec.switches);
        self.links.insert(name.to_string(), handles);
        let mut router = TestRouter::new(spec.mac, interfaces, spec.trickle.clone());
        spec.apply_features(&mut router);
        self.machines.insert(name.to_string(), router);
    }

    /// Attach a fresh port to `switch_name`, returning the node's end of the
    /// duplex and the [`PortId`] the switch assigned it (so the link can later
    /// have its loss tuned to model the wire going up or down).
    pub fn add_switch_port(&mut self, switch_name: &str) -> (PortComms, PortId) {
        #[expect(
            clippy::expect_used,
            reason = "callers only ever pass a switch_name this harness itself created"
        )]
        let switch = self
            .switches
            .get_mut(switch_name)
            .expect("switch not found");

        let (router_comms, switch_comms) = PortComms::pair(10);

        #[expect(
            clippy::expect_used,
            reason = "the simulated Switch has no port-capacity limit reachable from this harness"
        )]
        let port = switch
            .add_port(switch_comms, PortConfig::no_loss())
            .expect("switch has room for another port");

        (router_comms, port)
    }

    /// Allocate one switch port per named switch (in interface order), returning
    /// the node-side duplexes to build a [`TestRouter`] from and the
    /// `(switch, port)` handles to record for link tuning.
    fn wire_links(&mut self, switches: &[String]) -> (Vec<PortComms>, Vec<(String, PortId)>) {
        let mut comms = Vec::with_capacity(switches.len());
        let mut handles = Vec::with_capacity(switches.len());
        for switch in switches {
            let (pc, port) = self.add_switch_port(switch);
            comms.push(pc);
            handles.push((switch.clone(), port));
        }
        (comms, handles)
    }

    /// Model node `name`'s interface `iface` losing its link: the switch drops
    /// **all** traffic in both directions on that port.  Unlike
    /// [`disconnect_machine`](Self::disconnect_machine), the node keeps running
    /// and **retains its routing tables** — only the wire is dead — so this is a
    /// link/radio outage, not a reboot.  Its neighbors stop hearing it and age
    /// it out; the node itself ages out anything it could only reach through the
    /// downed link.  Panics if the machine or interface is unknown.
    pub fn fail_link(&mut self, name: &str, iface: usize) {
        self.set_link_loss(name, iface, 1.0, 1.0);
    }

    /// Restore a link previously downed with [`fail_link`](Self::fail_link):
    /// traffic flows loss-free again.  Because the node never lost state, the
    /// mesh re-converges simply by the two ends hearing each other once more.
    /// Panics if the machine or interface is unknown.
    pub fn restore_link(&mut self, name: &str, iface: usize) {
        self.set_link_loss(name, iface, 0.0, 0.0);
    }

    /// Set the per-direction loss probabilities on node `name`'s interface
    /// `iface` (its port on the corresponding switch).  `outgoing` is the
    /// switch→node direction and `incoming` the node→switch direction, each in
    /// `[0.0, 1.0]`, so tests can model fully or partially degraded links.
    /// Panics if the machine or interface is unknown.
    pub fn set_link_loss(&mut self, name: &str, iface: usize, outgoing: f64, incoming: f64) {
        let (switch_name, port) = self
            .links
            .get(name)
            .unwrap_or_else(|| panic!("unknown machine '{name}' (never built)"))
            .get(iface)
            .unwrap_or_else(|| panic!("machine '{name}' has no interface {iface}"))
            .clone();
        #[expect(
            clippy::expect_used,
            reason = "switch_name/port came from self.links, which this harness keeps in sync with the switches it created"
        )]
        {
            self.switches
                .get_mut(&switch_name)
                .expect("switch backing the link is missing")
                .update_port(port, PortConfig::new(outgoing, incoming))
                .expect("link port is missing from its switch");
        }
    }
}

/// Build a [`Mac`] from a single compact byte, `00:00:00:00:00:n` — the address
/// helper used throughout the mesh integration tests.
pub fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n])
}

impl TestConfig {
    /// Validate this config and assemble it into a [`TestHarness`], erroring on
    /// duplicate switch names or machines referencing an unknown switch.
    pub fn validate(&self) -> Result<TestHarness, String> {
        let mut h = TestHarness::default();
        for switch in &self.switches {
            if h.switches
                .insert(
                    switch.name.clone(),
                    Switch::new_with_name(switch.name.clone()),
                )
                .is_some()
            {
                return Err(format!(
                    "Switch '{}' is defined multiple times",
                    switch.name
                ));
            }
        }
        for (i, machine) in self.machines.iter().enumerate() {
            let ident = mac(i as u8);
            // Capture the wiring so the node can be churned offline/online or
            // have individual links failed later.
            let switches: Vec<String> = machine
                .wayfinder
                .links
                .iter()
                .map(|link| match &link.transport {
                    wayfinder::config::LinkTransport::Test { switch_name } => switch_name.clone(),
                    _ => panic!("test harness supports only Test links"),
                })
                .collect();
            // Per-interface OGM backoff bounds, in interface order.
            let trickle: Vec<TrickleConfig> = machine
                .wayfinder
                .links
                .iter()
                .map(|link| link.ogm)
                .collect();
            let features: Vec<LinkFeatures> = machine
                .wayfinder
                .links
                .iter()
                .map(|link| link.features)
                .collect();
            let (interfaces, handles) = h.wire_links(&switches);
            let mut router = TestRouter::new(ident, interfaces, trickle.clone());
            let spec = MachineSpec {
                mac: ident,
                switches,
                trickle,
                features,
            };
            spec.apply_features(&mut router);
            h.specs.insert(machine.name.clone(), spec);
            h.links.insert(machine.name.clone(), handles);
            if h.machines.insert(machine.name.clone(), router).is_some() {
                return Err(format!(
                    "Machine '{}' is defined multiple times",
                    machine.name
                ));
            }
        }

        Ok(h)
    }
}
