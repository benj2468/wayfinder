use std::{collections::HashMap, time::Duration};

use interfaces::frame::Mac;
use serde::{Deserialize, Serialize};
use wayfinder::config::TrickleConfig;

use crate::{
    switch::{PortComms, PortConfig, PortId, Switch},
    test_router::TestRouter,
};

#[derive(Serialize, Deserialize, Default)]
pub struct TestConfig {
    pub switches: Vec<TestSwitchConfig>,
    pub machines: Vec<TestMachineConfig>,
}

#[derive(Serialize, Deserialize)]
pub struct TestSwitchConfig {
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct TestMachineConfig {
    pub name: String,
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
}

#[derive(Default)]
pub struct TestHarness {
    pub switches: HashMap<String, Switch<Mac>>,
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
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn poll(&mut self, now: Duration) {
        self.clock = now;
        for router in self.machines.values_mut() {
            router.poll(now).await;
        }
    }

    /// Advance the simulation by one step: let every node transmit then receive
    /// at the current virtual clock, then let every switch forward what is on
    /// the wire.  Returns the number of frames the switches pulled off the wire
    /// this step; `0` means no node transmitted, i.e. the fabric is quiescent.
    pub async fn tick(&mut self) -> usize {
        let now = self.clock;
        // The periodic (OGM) arm is disabled here (`check_periodic = false`):
        // OGM rounds are driven explicitly by `poll`, so a tick only moves the
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
            frames += switch.tick().await.unwrap();
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
        self.poll(at).await;
        self.settle().await;
    }

    /// Drive the fabric to quiescence **without** emitting any new OGMs: keep
    /// ticking until a sweep moves no frames, then confirm it stays quiet.
    ///
    /// A single zero-frame tick can be a lull while a node still holds an
    /// unprocessed duplicate OGM (the same seqno arriving via a second path) in
    /// its ingress, so this requires the fabric to be silent for several
    /// *consecutive* sweeps before declaring convergence.  Use after injecting
    /// traffic (e.g. `send_local`) to let it reach its destination.  Bounded by
    /// the caller's `tokio::time::timeout` for the convergence case.
    pub async fn settle(&mut self) {
        // Enough consecutive silent sweeps to outlast any in-flight duplicate
        // draining hop by hop across the mesh diameter.
        const QUIET_SWEEPS: usize = 8;
        let mut quiet = 0;
        while quiet < QUIET_SWEEPS {
            if self.tick().await > 0 {
                quiet = 0;
            } else {
                quiet += 1;
            }
        }
    }

    pub fn get_machine(&self, name: &str) -> &TestRouter {
        self.machines.get(name).unwrap()
    }

    pub fn get_machine_mut(&mut self, name: &str) -> &mut TestRouter {
        self.machines.get_mut(name).unwrap()
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
        self.machines.insert(
            name.to_string(),
            TestRouter::new(spec.mac, interfaces, spec.trickle.clone()),
        );
    }

    /// Attach a fresh port to `switch_name`, returning the node's end of the
    /// duplex and the [`PortId`] the switch assigned it (so the link can later
    /// have its loss tuned to model the wire going up or down).
    pub fn add_switch_port(&mut self, switch_name: &str) -> (PortComms, PortId) {
        let switch = self
            .switches
            .get_mut(switch_name)
            .expect("switch not found");

        let (router_comms, switch_comms) = PortComms::pair(10);

        let port = switch
            .add_port(switch_comms, PortConfig::no_loss())
            .unwrap();

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
        self.switches
            .get_mut(&switch_name)
            .expect("switch backing the link is missing")
            .update_port(port, PortConfig::new(outgoing, incoming))
            .expect("link port is missing from its switch");
    }
}

pub fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n])
}

impl TestConfig {
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
            let (interfaces, handles) = h.wire_links(&switches);
            let router = TestRouter::new(ident, interfaces, trickle.clone());
            h.specs.insert(
                machine.name.clone(),
                MachineSpec {
                    mac: ident,
                    switches,
                    trickle,
                },
            );
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
