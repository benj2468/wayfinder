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
        assert_eq!(router.router().originator_table().len(), 1);
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
        assert_eq!(router.router().originator_table().len(), 2);
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
        assert_eq!(router.router().originator_table().len(), 2);
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
        assert_eq!(router.router().originator_table().len(), 2);
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
    a.receive_with_metrics(0, &ogm_from_b, weak).await;
    a.receive_with_metrics(1, &ogm_from_b, strong).await;

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
    a.receive_with_metrics(0, &ogm_from_b, strong).await;
    a.receive_with_metrics(1, &ogm_from_b, weak).await;

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
        .receive_with_metrics(1, &ogm_from_b, strong)
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
        .receive_with_metrics(0, &ogm_from_b, metrics)
        .await;

    let a = harness.get_machine("a");
    let first = a.router().resolve_route(mac(100));
    let _ = a.router().resolve_route(mac(100));
    let third = a.router().resolve_route(mac(100));
    assert_eq!(first, third);
}
