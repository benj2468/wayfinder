use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use interfaces::frame::Mac;
use interfaces::link::LinkMetrics;
use tracing_subscriber::EnvFilter;
use wayfinder::config::{Config, LinkConfig};
use wayfinder::{
    DEFAULT_BATMAN_ETHER_TYPE, EgressInterface,
    batman::wire::{BATADV_IV_OGM, BatmanOgmPacket},
};
use zerocopy::IntoBytes;

use crate::Direction;
use crate::prelude::*;
use crate::switch::TapConfig;

/// True if `frame` is an on-the-wire BATMAN OGM: a `LinkFrame` whose protocol
/// is the BATMAN EtherType and whose first payload byte is the OGM packet type.
///
/// Wire layout: `[dst:6][src:6][proto:2 BE][payload...]`, so the protocol is at
/// offset 12 and the BATMAN sub-type tag is the first payload byte at offset 14.
fn is_ogm_frame(frame: &[u8]) -> bool {
    frame.len() > 14
        && frame[12..14] == DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes()
        && frame[14] == BATADV_IV_OGM
}

/// Install a tap on every port of every switch in `harness` that counts each
/// OGM frame entering the fabric (one count per transmission), returning the
/// shared counter.  Counts only [`Direction::ToSwitch`] so each frame a node
/// puts on the wire is tallied exactly once, regardless of fan-out.
fn count_ogms(harness: &mut TestHarness) -> Arc<AtomicUsize> {
    let counter = Arc::new(AtomicUsize::new(0));
    for (_, switch) in harness.switches.iter_mut() {
        for port in switch.port_ids() {
            let counter = counter.clone();
            switch
                .add_tap(
                    port,
                    TapConfig::new(move |meta| {
                        if meta.direction == Direction::ToSwitch && is_ogm_frame(meta.data) {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        true
                    }),
                )
                .unwrap();
        }
    }
    counter
}

/// Build a raw OGM broadcast frame as it would appear on the wire after
/// being transmitted by `src` with the given TQ and sequence number.
///
/// Wire layout: `[src:6][BROADCAST:6][proto:2 NE][BatmanOgmPacket]`.
fn build_ogm_wire_frame(src: u8, tq: u8, seqno: u32) -> Vec<u8> {
    let ogm = BatmanOgmPacket {
        packet_type: BATADV_IV_OGM,
        version: 5,
        ttl: 50,
        flags: 0,
        seqno: seqno.to_be(),
        orig: mac(src),
        prev_sender: mac(src),
        reserved: 0,
        tq,
        tvlv_len: 0,
    };
    build_frame(
        mac(src),
        Mac::BROADCAST,
        wayfinder::DEFAULT_BATMAN_ETHER_TYPE,
        ogm.as_bytes(),
    )
}

/// A single machine wired to `n` independent switches, so the machine has
/// `n` interfaces (interface `i` is its link to `switch{i}`).  Used by the
/// metric/route-inspection tests, which inject crafted OGMs onto specific
/// interfaces via [`TestRouter::receive_with_metrics`].
fn single_machine_with_links(n: usize) -> TestHarness {
    let mut config = TestConfig::default();
    let mut links = Vec::new();
    for i in 0..n {
        let switch_name = format!("switch{i}");
        config.switches.push(TestSwitchConfig {
            name: switch_name.clone(),
        });
        links.push(LinkConfig::Test { switch_name });
    }
    config.machines.push(TestMachineConfig {
        name: "a".into(),
        wayfinder: Config {
            links,
            ..Default::default()
        },
    });
    config.validate().unwrap()
}

/// Three machines all sharing a single switch, so every node is a direct
/// neighbor of the other two.
fn one_switch_with_machines(n: usize) -> TestHarness {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig {
        name: "switch1".into(),
    });

    for i in 0..n {
        let name = format!("machine{i}");
        config.machines.push(TestMachineConfig {
            name: name.into(),
            wayfinder: Config {
                links: vec![LinkConfig::Test {
                    switch_name: "switch1".into(),
                }],
                ..Default::default()
            },
        });
    }
    config.validate().unwrap()
}

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_test_writer() // Captures logs correctly within the test runner
            .init();
    });
}

/// Converge the mesh at virtual instant `at`, failing the test if it does not
/// settle in time.
///
/// Delegates to [`TestHarness::converge`], which polls one OGM round and then
/// ticks until the fabric is completely silent (no node has another frame to
/// flood or forward).  That loop is unbounded, so this wraps it in a real-time
/// `tokio` timeout: a mesh that never settles — e.g. an OGM forwarding loop —
/// fails fast here instead of hanging, and the timeout serves as the
/// "converged" assertion.
async fn converge_at(h: &mut TestHarness, at: Duration) {
    tokio::time::timeout(Duration::from_secs(10), h.converge(at))
        .await
        .expect("mesh did not converge within the timeout");
}

fn simple_pair() -> TestHarness {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig {
        name: "switch1".into(),
    });
    config.machines.push(TestMachineConfig {
        name: "machine1".into(),
        wayfinder: Config {
            links: vec![LinkConfig::Test {
                switch_name: "switch1".into(),
            }],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "machine2".into(),
        wayfinder: Config {
            links: vec![LinkConfig::Test {
                switch_name: "switch1".into(),
            }],
            ..Default::default()
        },
    });
    config.validate().unwrap()
}

fn line_of_three() -> TestHarness {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig {
        name: "switch1".into(),
    });
    config.switches.push(TestSwitchConfig {
        name: "switch2".into(),
    });
    config.machines.push(TestMachineConfig {
        name: "machine1".into(),
        wayfinder: Config {
            links: vec![LinkConfig::Test {
                switch_name: "switch1".into(),
            }],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "machine2".into(),
        wayfinder: Config {
            links: vec![
                LinkConfig::Test {
                    switch_name: "switch1".into(),
                },
                LinkConfig::Test {
                    switch_name: "switch2".into(),
                },
            ],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "machine3".into(),
        wayfinder: Config {
            links: vec![LinkConfig::Test {
                switch_name: "switch2".into(),
            }],
            ..Default::default()
        },
    });
    config.validate().unwrap()
}

/// Five nodes with two routes from `a` to `d` of unequal length:
///
/// ```text
///        b              (a–b–d : 2 hops, preferred)
///      /   \
///    a       d
///      \   /
///        c — e          (a–c–e–d : 3 hops, alternate)
/// ```
///
/// `a` neighbours `b` and `c`; `b` neighbours `d`; `c` neighbours `e`;
/// `e` neighbours `d`.  Because the `b` route is strictly shorter it carries a
/// higher TQ, so `a` records `b` as its best next hop to `d` and the longer
/// `c→e` route's lower-TQ OGMs never displace it.  Killing `b` therefore
/// requires the engine to *age out* the stale high-TQ path before traffic can
/// fall back to the surviving `c→e` route.  Machine indices: a=0, b=1, c=2,
/// d=3, e=4.
fn two_paths_unequal_length() -> TestHarness {
    let mut config = TestConfig::default();
    for sw in ["ab", "ac", "bd", "ce", "ed"] {
        config.switches.push(TestSwitchConfig { name: sw.into() });
    }
    let machine = |name: &str, links: &[&str]| TestMachineConfig {
        name: name.into(),
        wayfinder: Config {
            links: links
                .iter()
                .map(|s| LinkConfig::Test {
                    switch_name: (*s).into(),
                })
                .collect(),
            ..Default::default()
        },
    };
    config.machines.push(machine("a", &["ab", "ac"]));
    config.machines.push(machine("b", &["ab", "bd"]));
    config.machines.push(machine("c", &["ac", "ce"]));
    config.machines.push(machine("d", &["bd", "ed"]));
    config.machines.push(machine("e", &["ce", "ed"]));
    config.validate().unwrap()
}

#[tokio::test]
async fn test_validate() {
    let config = TestConfig::default();
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn test_multi_same_switch() {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig {
        name: "test1".into(),
    });
    config.switches.push(TestSwitchConfig {
        name: "test1".into(),
    });
    assert!(config.validate().is_err());
}

#[tokio::test]
#[should_panic]
async fn test_invalid_switch() {
    let mut config = TestConfig::default();
    config.machines.push(TestMachineConfig {
        name: "foo".into(),
        wayfinder: Config {
            links: vec![LinkConfig::Test {
                switch_name: "invalid".into(),
            }],
            ..Default::default()
        },
    });
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn test_simple_pair() {
    simple_pair();
}

#[tokio::test]
async fn test_simple_pair_send_data() {
    setup();
    let mut harness = simple_pair();

    harness.poll(Duration::from_secs(1)).await;
    harness.tick().await;
    harness.tick().await;

    for (_, router) in harness.machines.iter() {
        assert_eq!(router.router().originator_table().count(), 1);
    }

    tracing::info!("OGM PHASE COMPLETE");

    let m1 = harness.get_machine("machine1").ident;
    let m2 = harness.get_machine("machine2").ident;

    harness
        .get_machine_mut("machine1")
        .send_local(m2, b"Hello World")
        .await
        .unwrap();

    harness.tick().await;
    harness.tick().await;

    assert_eq!(
        harness.get_machine("machine2").local_deliveries(),
        vec![host_frame(m2, m1, b"Hello World")]
    );
}

#[tokio::test]
async fn test_line_of_three() {
    line_of_three();
}

#[tokio::test]
async fn test_line_of_three_send_data() {
    setup();
    let mut harness = line_of_three();

    harness.poll(Duration::from_secs(1)).await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;

    for (_, router) in harness.machines.iter() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    let m1 = harness.get_machine("machine1").ident;
    let m3 = harness.get_machine("machine3").ident;
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"Hello World")
        .await
        .unwrap();

    harness.tick().await;
    harness.tick().await;
    harness.tick().await;

    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"Hello World")]
    );
}

/// A broadcast (e.g. an ARP) needs no route: machine1 floods it and
/// machine2 must deliver the inner frame to its local host.  No OGM
/// convergence is required because broadcasts reach every interface.
#[tokio::test]
async fn broadcast_is_delivered_locally_at_neighbor() {
    setup();
    let mut harness = simple_pair();

    let arp = b"i am a broadcast frame";
    let m1 = harness.get_machine("machine1").ident;
    harness
        .get_machine_mut("machine1")
        .send_local(Mac::BROADCAST, arp)
        .await
        .expect("broadcast packet should build");

    harness.tick().await;
    harness.tick().await;

    assert_eq!(
        harness.get_machine("machine2").local_deliveries(),
        vec![host_frame(Mac::BROADCAST, m1, arp)]
    );
}

/// Three nodes share one switch, so each is a direct neighbor of the other
/// two.  After OGM convergence a unicast is routed only to its addressee:
/// machine0 → machine2 is delivered at machine2 and never seen by machine1,
/// and likewise machine0 → machine1 lands only at machine1.  The negative
/// deliveries stand in for the per-port tap assertions of the old test —
/// the switch's learned forwarding is what keeps the wrong node silent.
#[tokio::test]
async fn three_routers_all_connected_discover_and_exchange() {
    setup();
    let mut harness = one_switch_with_machines(3);

    // Two rounds of OGMs so every node learns direct routes to the others.
    harness.poll(Duration::from_secs(1)).await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;

    for (_, router) in harness.machines.iter() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    let m0 = harness.get_machine("machine0").ident;

    // ── unicast machine0 → machine2 ──────────────────────────────────────
    let m2 = harness.get_machine("machine2").ident;
    harness
        .get_machine_mut("machine0")
        .send_local(m2, b"hello from 0 to 2")
        .await
        .expect("machine0 must have a direct route to machine2");

    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;

    assert_eq!(
        harness.get_machine("machine2").local_deliveries(),
        vec![host_frame(m2, m0, b"hello from 0 to 2")],
        "machine2 should receive the exact payload"
    );
    assert!(
        harness
            .get_machine("machine1")
            .local_deliveries()
            .is_empty(),
        "the unicast for machine2 must not be delivered at machine1"
    );

    // ── unicast machine0 → machine1 ──────────────────────────────────────
    let m1 = harness.get_machine("machine1").ident;
    harness
        .get_machine_mut("machine0")
        .send_local(m1, b"hello from 0 to 1")
        .await
        .expect("machine0 must have a direct route to machine1");

    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;
    harness.tick().await;

    assert_eq!(
        harness.get_machine("machine1").local_deliveries(),
        vec![host_frame(m1, m0, b"hello from 0 to 1")],
        "machine1 should receive the exact payload"
    );
    assert_eq!(
        harness.get_machine("machine2").local_deliveries().len(),
        1,
        "machine2 must not receive the unicast addressed to machine1"
    );
}

/// After the mesh has converged, a single round of OGMs must propagate and
/// then *stop*: each node forwards each `(originator, seqno)` at most once, so
/// the fabric falls silent within a few ticks.  A forwarding loop — e.g.
/// re-flooding an OGM back out the interface it arrived on, or re-forwarding a
/// sequence number already seen — instead keeps OGMs circulating until their
/// TTL drains (~50 hops), which this test catches as OGM traffic that never
/// ceases.
#[tokio::test]
async fn ogms_stop_after_convergence() {
    setup();
    let mut harness = line_of_three();

    // Converge, then drain every in-flight OGM from the initial poll so the
    // fabric is quiet before we begin measuring.
    harness.poll(Duration::from_secs(1)).await;
    for _ in 0..80 {
        harness.tick().await;
    }
    for (_, router) in harness.machines.iter() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    // Watch every OGM that crosses the fabric from here on.
    let counter = count_ogms(&mut harness);

    // Emit one fresh OGM from every node.  In a loop-free mesh this single
    // round reaches every node and then dies within the network diameter.
    harness.poll(Duration::from_secs(2)).await;

    // 4 ticks are the required number for the network to settle here
    const SETTLE_TICKS: usize = 4;
    for _ in 0..SETTLE_TICKS {
        harness.tick().await;
    }
    let after_settle = counter.load(Ordering::Relaxed);

    // ...after which the fabric must stay silent: with no new poll, a converged
    // mesh has nothing left to forward.
    const QUIET_TICKS: usize = 20;
    for _ in 0..QUIET_TICKS {
        harness.tick().await;
    }
    assert_eq!(
        counter.load(Ordering::Relaxed),
        after_settle,
        "OGMs must stop after a converged mesh floods one round; continued \
         OGM traffic indicates a forwarding loop",
    );
}

/// When the node that is a destination's *best* next hop goes offline, traffic
/// must fail over to the next-best path instead of black-holing.
///
/// In [`two_paths_unequal_length`], `a` reaches `d` via `b` (2 hops, higher TQ)
/// or via `c→e` (3 hops, lower TQ).  `a` picks `b`.  Because the `c→e` route's
/// OGMs carry a strictly lower TQ, they never overwrite `a`'s recorded best hop
/// on their own — so once `b` is gone, `a` keeps forwarding into a black hole
/// until the stale path is aged out and the best hop recomputed from what
/// remains.  Time is driven by the harness's virtual clock so the staleness is
/// deterministic, not wall-clock dependent.
#[tokio::test]
async fn traffic_fails_over_when_best_next_hop_disconnects() {
    setup();
    let mut harness = two_paths_unequal_length();

    let a = harness.get_machine("a").ident;
    let b = harness.get_machine("b").ident;
    let c = harness.get_machine("c").ident;
    let d = harness.get_machine("d").ident;

    // Converge: a few poll rounds, each fully drained.
    for round in 1..=3 {
        harness.poll(Duration::from_secs(round)).await;
        for _ in 0..10 {
            harness.tick().await;
        }
    }

    let record = |h: &TestHarness| {
        h.get_machine("a")
            .router()
            .originator_table()
            .find(|r| r.neighbor_ident == d)
            .cloned()
            .expect("a must have learned a route to d")
    };

    // Precondition: `a` reaches `d` via `b` (the shorter, higher-TQ path).  The
    // longer `c→e` route carries a strictly lower TQ, so even once `a` learns it
    // the metric alone never promotes it over the recorded `b` path.
    assert_eq!(
        record(&harness).best_next_hop,
        b,
        "a's best next hop to d should be b (the 2-hop path)"
    );

    // `b` goes offline: drop it from the simulation so it stops originating and
    // forwarding.  Its switch ports go dead but the fabric tolerates that.
    harness.machines.remove("b");

    // Let plenty of virtual time pass while the surviving `c→e` route keeps
    // refreshing, far beyond any reasonable neighbor timeout, so the stale `b`
    // path ages out and `a` recomputes its best hop.
    for secs in (100..=1000).step_by(100) {
        harness.poll(Duration::from_secs(secs)).await;
        for _ in 0..10 {
            harness.tick().await;
        }
    }

    let after = record(&harness);
    assert_eq!(
        after.best_next_hop, c,
        "after b is lost, a must fail over to the c→e path"
    );

    // End-to-end: a unicast from `a` to `d` must still arrive, now routed the
    // long way round via c→e.
    harness
        .get_machine_mut("a")
        .send_local(d, b"hello via failover")
        .await
        .expect("a must have a route to d after failover");
    for _ in 0..10 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("d").local_deliveries(),
        vec![host_frame(d, a, b"hello via failover")],
        "d must receive the unicast over the surviving c→e path"
    );
}

/// A direct neighbor that goes offline and later returns must be re-learned,
/// restoring end-to-end traffic.  Two nodes share a switch; once converged each
/// knows the other directly.  When machine2 powers off, its route ages out of
/// machine1's table (no refresh for longer than `ORIGINATOR_TIMEOUT`).  When the
/// *same* node (same identity, empty tables) comes back, both must rediscover
/// each other and a unicast must flow again.
#[tokio::test]
async fn route_restored_after_neighbor_reconnects() {
    setup();
    let mut harness = simple_pair();
    let m1 = harness.get_machine("machine1").ident;
    let m2 = harness.get_machine("machine2").ident;

    // Converge: each node learns the other as a direct neighbor.
    converge_at(&mut harness, Duration::from_secs(1)).await;
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        1
    );
    assert_eq!(
        harness.get_machine("machine2").router().originator_count(),
        1
    );

    // machine2 powers off.  Advance well past ORIGINATOR_TIMEOUT (60s) with only
    // machine1 polling, so machine1's now-unrefreshed route to machine2 ages out.
    harness.disconnect_machine("machine2");
    converge_at(&mut harness, Duration::from_secs(80)).await;
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        0,
        "machine1 must drop the stale route once machine2 stops refreshing it"
    );

    // machine2 returns with its original identity but empty tables.
    harness.reconnect_machine("machine2");
    converge_at(&mut harness, Duration::from_secs(160)).await;
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        1,
        "machine1 must relearn machine2 after it returns"
    );
    assert_eq!(
        harness.get_machine("machine2").router().originator_count(),
        1,
        "the reborn machine2 must relearn machine1"
    );

    // End-to-end: a unicast flows again over the restored direct link.
    harness
        .get_machine_mut("machine1")
        .send_local(m2, b"welcome back")
        .await
        .unwrap();
    for _ in 0..6 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("machine2").local_deliveries(),
        vec![host_frame(m2, m1, b"welcome back")],
        "machine2 must receive traffic again after reconnecting"
    );
}

/// When the *only* relay on a line goes offline there is no alternate path, so
/// traffic must black-hole rather than be misdelivered; when the relay returns
/// the path heals.  In [`line_of_three`] machine1 reaches machine3 solely
/// through machine2.  Dropping machine2 leaves machine1 with no route once the
/// stale entry ages out — machine3 hears nothing more — and reconnecting it
/// restores delivery.
#[tokio::test]
async fn sole_relay_disconnect_blackholes_then_recovers() {
    setup();
    let mut harness = line_of_three();
    let m1 = harness.get_machine("machine1").ident;
    let m3 = harness.get_machine("machine3").ident;

    // Converge the line, then confirm the baseline machine1 → machine3 delivery
    // over the relay.
    converge_at(&mut harness, Duration::from_secs(1)).await;
    for (_, r) in harness.machines.iter() {
        assert_eq!(r.router().originator_count(), 2);
    }
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"before")
        .await
        .unwrap();
    for _ in 0..8 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"before")],
        "baseline: machine3 receives over the relay"
    );

    // The sole relay drops.  After the stale route ages out machine1 has nowhere
    // to forward, so a send must not reach machine3.
    harness.disconnect_machine("machine2");
    converge_at(&mut harness, Duration::from_secs(80)).await;
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        0,
        "with the relay gone, machine1's routes to both 2 and 3 age out"
    );
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"lost")
        .await
        .ok();
    for _ in 0..8 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"before")],
        "no new delivery while the only relay is offline"
    );

    // The relay returns; after re-convergence the path heals end-to-end.
    harness.reconnect_machine("machine2");
    converge_at(&mut harness, Duration::from_secs(160)).await;
    for name in ["machine1", "machine2", "machine3"] {
        assert_eq!(
            harness.get_machine(name).router().originator_count(),
            2,
            "{name} must re-converge after the relay returns"
        );
    }
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"after")
        .await
        .unwrap();
    for _ in 0..8 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"before"), host_frame(m3, m1, b"after"),],
        "delivery resumes once the relay is back"
    );
}

/// After failing over to a longer path, a node must *reclaim* the preferred
/// shorter path when its best next hop comes back.  In
/// [`two_paths_unequal_length`] `a` prefers `b` (2 hops, higher TQ).  Losing `b`
/// forces failover to the lower-TQ `c→e` path; when `b` returns its higher-TQ
/// OGMs must promote it back to best next hop (the engine lowers `max_tq` to the
/// surviving path on purge, so the returning higher-TQ path wins again).
#[tokio::test]
async fn best_hop_reclaims_preferred_path_after_reconnect() {
    setup();
    let mut harness = two_paths_unequal_length();
    let a = harness.get_machine("a").ident;
    let b = harness.get_machine("b").ident;
    let c = harness.get_machine("c").ident;
    let d = harness.get_machine("d").ident;

    let best_hop_to_d = |h: &TestHarness| {
        h.get_machine("a")
            .router()
            .originator_table()
            .find(|r| r.neighbor_ident == d)
            .map(|r| r.best_next_hop)
    };

    // Converge: `a` prefers the 2-hop path via `b`.
    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round)).await;
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(b),
        "a should prefer the shorter path via b"
    );

    // `b` drops; after the stale high-TQ path ages out, `a` fails over to c→e.
    harness.disconnect_machine("b");
    for secs in (100..=600).step_by(100) {
        converge_at(&mut harness, Duration::from_secs(secs)).await;
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(c),
        "with b gone, a must fall back to the c→e path"
    );

    // `b` returns; its shorter, higher-TQ path must be reclaimed as preferred.
    harness.reconnect_machine("b");
    for secs in (700..=1200).step_by(100) {
        converge_at(&mut harness, Duration::from_secs(secs)).await;
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(b),
        "once b is back its higher-TQ path must win again"
    );

    // And traffic flows over the restored preferred path.
    harness
        .get_machine_mut("a")
        .send_local(d, b"preferred again")
        .await
        .unwrap();
    for _ in 0..10 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("d").local_deliveries(),
        vec![host_frame(d, a, b"preferred again")],
        "d must receive over the reclaimed b path"
    );
}

/// Repeated churn on the relay must not corrupt routing: after a node flaps
/// offline/online several times, the mesh must still converge and carry traffic.
/// Each cycle keeps machine2 down long enough for its routes to age out, then
/// brings it back, stressing the relearning path under repeated disruption.
#[tokio::test]
async fn flapping_relay_reconverges() {
    setup();
    let mut harness = line_of_three();
    let m1 = harness.get_machine("machine1").ident;
    let m3 = harness.get_machine("machine3").ident;

    converge_at(&mut harness, Duration::from_secs(1)).await;

    // Flap the relay three times.  Each down/up leg advances the clock by more
    // than ORIGINATOR_TIMEOUT so routes fully age out between transitions.
    let mut clock = 60u64;
    for _ in 0..3 {
        harness.disconnect_machine("machine2");
        clock += 80;
        converge_at(&mut harness, Duration::from_secs(clock)).await;

        harness.reconnect_machine("machine2");
        clock += 80;
        converge_at(&mut harness, Duration::from_secs(clock)).await;
    }

    // After the churn settles the line must be fully converged again...
    clock += 80;
    converge_at(&mut harness, Duration::from_secs(clock)).await;
    for name in ["machine1", "machine2", "machine3"] {
        assert_eq!(
            harness.get_machine(name).router().originator_count(),
            2,
            "{name} must re-converge after repeated relay flaps"
        );
    }

    // ...and end-to-end traffic flows.
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"still here")
        .await
        .unwrap();
    for _ in 0..8 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"still here")],
        "the line must carry traffic after the relay's churn settles"
    );
}

/// Two nodes on disjoint paths can drop simultaneously and the mesh must both
/// black-hole correctly and recover.  In [`two_paths_unequal_length`] `a`
/// reaches `d` via `b` (2 hops) or via `c→e` (3 hops).  Dropping both `b` and
/// `e` at once severs *every* path to `d`; once it ages out `a` has no route and
/// traffic is dropped.  Bringing both back restores the mesh, and `a` settles on
/// the preferred path via `b`.
#[tokio::test]
async fn simultaneous_disconnects_blackhole_then_recover() {
    setup();
    let mut harness = two_paths_unequal_length();
    let a = harness.get_machine("a").ident;
    let b = harness.get_machine("b").ident;
    let d = harness.get_machine("d").ident;

    let route_to_d = |h: &TestHarness| {
        h.get_machine("a")
            .router()
            .originator_table()
            .find(|r| r.neighbor_ident == d)
            .map(|r| r.best_next_hop)
    };

    // Converge both a→d paths.
    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round)).await;
    }
    assert!(
        route_to_d(&harness).is_some(),
        "a should know a route to d after convergence"
    );

    // Both relays — b (the 2-hop path) and e (the tail of the c→e path) — drop at
    // once.  a→d now has no surviving path.
    harness.disconnect_machine("b");
    harness.disconnect_machine("e");
    for secs in (100..=600).step_by(100) {
        converge_at(&mut harness, Duration::from_secs(secs)).await;
    }
    assert_eq!(
        route_to_d(&harness),
        None,
        "with both b and e gone, a must have no route to d"
    );

    let before = harness.get_machine("d").local_deliveries().len();
    harness
        .get_machine_mut("a")
        .send_local(d, b"into the void")
        .await
        .ok();
    for _ in 0..10 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("d").local_deliveries().len(),
        before,
        "no delivery while both paths are down"
    );

    // Both return; `a` re-converges and prefers the restored 2-hop path via `b`.
    harness.reconnect_machine("b");
    harness.reconnect_machine("e");
    for secs in (700..=1300).step_by(100) {
        converge_at(&mut harness, Duration::from_secs(secs)).await;
    }
    assert_eq!(
        route_to_d(&harness),
        Some(b),
        "a should reconverge onto the preferred path via b"
    );
    harness
        .get_machine_mut("a")
        .send_local(d, b"back online")
        .await
        .unwrap();
    for _ in 0..10 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("d").local_deliveries(),
        vec![host_frame(d, a, b"back online")],
        "delivery resumes once both paths are restored"
    );
}

// ── link-down scenarios (the wire dies, the node lives) ───────────────────
//
// Distinct from the reboot tests above: `disconnect_machine` removes a node and
// it returns with empty tables, whereas `fail_link` drives a single switch port
// to 100% loss so the node keeps running and *retains its routing state* — only
// that link is dead.  These exercise that second failure mode.

/// A link going *down* (rather than a node rebooting) must also trigger
/// failover, and restoring the link must reclaim the preferred path.  Here the
/// wire between `a` and `b` is cut — `b` keeps running and serving the rest of
/// the mesh — so `a` loses its 2-hop path and falls back to c→e; once the link
/// is restored `a` re-hears `b` and promotes the shorter path again.
#[tokio::test]
async fn link_down_triggers_failover_then_restore_reclaims() {
    setup();
    let mut harness = two_paths_unequal_length();
    let a = harness.get_machine("a").ident;
    let b = harness.get_machine("b").ident;
    let c = harness.get_machine("c").ident;
    let d = harness.get_machine("d").ident;

    let best_hop_to_d = |h: &TestHarness| {
        h.get_machine("a")
            .router()
            .originator_table()
            .find(|r| r.neighbor_ident == d)
            .map(|r| r.best_next_hop)
    };

    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round)).await;
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(b),
        "a should prefer the 2-hop path via b"
    );

    // Cut a's link to b (interface 0 = switch "ab").  b stays alive — only the
    // a–b wire is dead — so the path to d via b ages out at a while b itself
    // never reboots.
    harness.fail_link("a", 0);
    for secs in (100..=600).step_by(100) {
        converge_at(&mut harness, Duration::from_secs(secs)).await;
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(c),
        "with the a–b link down, a must fail over to c→e"
    );
    // The contrast with a reboot: b kept running throughout, so it still holds
    // its own (unaffected) route to d.
    assert!(
        harness
            .get_machine("b")
            .router()
            .originator_table()
            .any(|r| r.neighbor_ident == d),
        "b stayed up and must retain its route to d over the healthy b–d link"
    );

    // Restore the wire; a re-hears b's higher-TQ OGMs and reclaims the short path.
    harness.restore_link("a", 0);
    for secs in (700..=1200).step_by(100) {
        converge_at(&mut harness, Duration::from_secs(secs)).await;
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(b),
        "restoring the a–b link must reclaim the preferred path via b"
    );

    harness
        .get_machine_mut("a")
        .send_local(d, b"link back up")
        .await
        .unwrap();
    for _ in 0..10 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("d").local_deliveries(),
        vec![host_frame(d, a, b"link back up")],
        "d must receive over the reclaimed b path"
    );
}

/// A brief link outage must not cost a node its routing state.  Because a
/// link-down (unlike a reboot) leaves the node's tables intact, a blip shorter
/// than `ORIGINATOR_TIMEOUT` loses no routes: machine1's only link drops and is
/// restored well within the 60s timeout, so its routes to both machine2 and
/// machine3 survive and traffic resumes with no re-convergence.
#[tokio::test]
async fn brief_link_blip_preserves_routes() {
    setup();
    let mut harness = line_of_three();
    let m1 = harness.get_machine("machine1").ident;
    let m3 = harness.get_machine("machine3").ident;

    converge_at(&mut harness, Duration::from_secs(1)).await;
    // converge_at(&mut harness, Duration::from_secs(2)).await;
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        2
    );

    // machine1's only link (interface 0) drops, then returns well inside
    // ORIGINATOR_TIMEOUT.  No poll crosses the timeout, so nothing ages out.
    harness.fail_link("machine1", 0);
    converge_at(&mut harness, Duration::from_secs(30)).await;
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        2,
        "a sub-timeout blip must not age out machine1's routes — state survives, unlike a reboot"
    );
    harness.restore_link("machine1", 0);
    converge_at(&mut harness, Duration::from_secs(35)).await;

    // Traffic resumes immediately over the still-known route.
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"blip survived")
        .await
        .unwrap();
    for _ in 0..8 {
        harness.tick().await;
    }
    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"blip survived")],
        "delivery resumes over routes that were never lost"
    );
}

// ── metric-based egress selection ────────────────────────────────────────
//
// These tests need the *same* OGM observed on two interfaces with
// different per-frame RSSI/SNR, which the switch fabric cannot carry (it
// forwards opaque bytes, not link metrics).  So they fetch the machine via
// `get_machine_mut` and inject the crafted OGM directly with
// `receive_with_metrics`, exercising the metric-driven egress decision
// without real hardware.

/// Machine `a` hears node B's OGM weakly on interface 0 and strongly on
/// interface 1.  The egress for node B must follow the stronger link.
#[tokio::test]
async fn egress_picks_iface_with_better_metrics_for_shared_neighbor() {
    let mut harness = single_machine_with_links(2);
    let ogm_from_b = build_ogm_wire_frame(100, 255, 1);

    let weak = LinkMetrics {
        rssi_dbm: Some(-115),
        snr_db: Some(-5),
        quality: None,
    };
    let strong = LinkMetrics {
        rssi_dbm: Some(-60),
        snr_db: Some(10),
        quality: None,
    };

    let a = harness.get_machine_mut("a");
    a.receive_with_metrics(Duration::from_secs(0), 0, &ogm_from_b, weak)
        .await;
    a.receive_with_metrics(Duration::from_secs(1), 1, &ogm_from_b, strong)
        .await;

    match a.router_mut().get_egress_interface(mac(100)) {
        Some(EgressInterface::Interface(1)) => {}
        other => {
            panic!("expected egress for node B to be Interface(1) (strong RSSI/SNR), got {other:?}")
        }
    }
}

/// Mirror of the previous test with the metrics swapped across the two
/// interfaces — confirms the choice is driven by the metrics, not by iface
/// index or arrival order.
#[tokio::test]
async fn egress_swaps_iface_when_metrics_swap() {
    let mut harness = single_machine_with_links(2);
    let ogm_from_b = build_ogm_wire_frame(100, 255, 1);

    let strong = LinkMetrics {
        rssi_dbm: Some(-60),
        snr_db: Some(10),
        quality: None,
    };
    let weak = LinkMetrics {
        rssi_dbm: Some(-115),
        snr_db: Some(-5),
        quality: None,
    };

    let a = harness.get_machine_mut("a");
    a.receive_with_metrics(Duration::from_secs(0), 0, &ogm_from_b, strong)
        .await;
    a.receive_with_metrics(Duration::from_secs(1), 1, &ogm_from_b, weak)
        .await;

    match a.router_mut().get_egress_interface(mac(100)) {
        Some(EgressInterface::Interface(0)) => {}
        other => {
            panic!("expected egress for node B to be Interface(0) (strong RSSI/SNR), got {other:?}")
        }
    }
}

// ── route-inspection API ──────────────────────────────────────────────────
//
// `CentralRouter::resolve_route` is the read-only mirror of the path the
// router would take on send; it backs the management-API ResolveRoute RPC.

/// With node B observed on a single interface, `resolve_route` reports B as
/// both the next hop and the egress (following the interface it arrived on).
#[tokio::test]
async fn resolve_route_returns_neighbor_and_observed_interface() {
    let mut harness = single_machine_with_links(2);
    let ogm_from_b = build_ogm_wire_frame(100, 255, 1);
    let strong = LinkMetrics {
        rssi_dbm: Some(-50),
        snr_db: Some(12),
        quality: None,
    };

    harness
        .get_machine_mut("a")
        .receive_with_metrics(Duration::from_secs(1), 1, &ogm_from_b, strong)
        .await;

    let (next_hop, egress) = harness.get_machine("a").router().resolve_route(mac(100));
    assert_eq!(next_hop, mac(100), "direct neighbor is its own next hop");
    assert_eq!(
        egress,
        Some(EgressInterface::Interface(1)),
        "egress must follow the interface the OGM arrived on"
    );
}

/// `resolve_route` returns [`EgressInterface::All`] for BROADCAST regardless
/// of any other table state.
#[tokio::test]
async fn resolve_route_for_broadcast_returns_all_interfaces() {
    let harness = single_machine_with_links(1);

    let (next_hop, egress) = harness
        .get_machine("a")
        .router()
        .resolve_route(Mac::BROADCAST);
    assert_eq!(next_hop, Mac::BROADCAST);
    assert_eq!(egress, Some(EgressInterface::All));
}

/// `resolve_route` must not perturb the router's state — repeated calls
/// return identical answers so management-API callers cannot disturb the
/// data plane's routing decisions.
#[tokio::test]
async fn resolve_route_is_read_only() {
    let mut harness = single_machine_with_links(1);
    let ogm_from_b = build_ogm_wire_frame(100, 255, 1);
    let metrics = LinkMetrics {
        rssi_dbm: Some(-50),
        snr_db: Some(12),
        quality: None,
    };

    harness
        .get_machine_mut("a")
        .receive_with_metrics(Duration::from_secs(0), 0, &ogm_from_b, metrics)
        .await;

    let a = harness.get_machine("a");
    let first = a.router().resolve_route(mac(100));
    let _ = a.router().resolve_route(mac(100));
    let third = a.router().resolve_route(mac(100));
    assert_eq!(first, third);
}
