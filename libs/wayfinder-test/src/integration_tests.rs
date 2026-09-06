use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use interfaces::frame::Mac;
use interfaces::link::LinkMetrics;
use tracing_subscriber::EnvFilter;
use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
use wayfinder::EgressInterface;
use wayfinder::batman::MAX_MISSED_OGMS;
use wayfinder::batman::wire::BatmanCertReplyPacket;
use wayfinder::batman::wire::BatmanCertReqPacket;
use wayfinder::batman::wire::BatmanKeepAlivePacket;
use wayfinder::batman::wire::BatmanOgmPacket;
use wayfinder::batman::wire::BatmanPacketType;
use wayfinder::batman::wire::BatmanTvlvHdr;
use wayfinder::batman::wire::TvlvType;
use wayfinder::batman::wire::find_tvlv;
use wayfinder::config::Config;
use wayfinder::config::LinkConfig;
use wayfinder::config::LinkFeatures;
use wayfinder::config::LinkTransport;
use wayfinder::config::TrickleConfig;
use wayfinder::ping::ProbeState;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::Direction;
use crate::prelude::*;
use crate::switch::TapConfig;
use wayfinder::batman::wire::BATMAN_VERSION;

/// True if `frame` is an on-the-wire BATMAN OGM: a `LinkFrame` whose protocol
/// is the BATMAN EtherType and whose first payload byte is the OGM packet type.
///
/// Wire layout: `[dst:6][src:6][proto:2 BE][payload...]`, so the protocol is at
/// offset 12 and the BATMAN sub-type tag is the first payload byte at offset 14.
fn is_ogm_frame(frame: &[u8]) -> bool {
    frame.len() > 14
        && frame[12..14] == DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes()
        && frame[14] == BatmanPacketType::Ogm.as_u8()
}

/// Install a tap on every port of every switch in `harness` that counts each
/// OGM frame entering the fabric (one count per transmission), returning the
/// shared counter.  Counts only [`Direction::ToSwitch`] so each frame a node
/// puts on the wire is tallied exactly once, regardless of fan-out.
fn count_ogms(harness: &mut TestHarness) -> Arc<AtomicUsize> {
    let counter = Arc::new(AtomicUsize::new(0));
    for switch in harness.switches.values_mut() {
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
/// being transmitted by `src` with the given TQ and sequence number — a
/// direct (self-originated) OGM, i.e. `src` is both the immediate sender and
/// the advertised originator. A thin wrapper over
/// [`build_relayed_ogm_wire_frame`] for the common single-hop case.
///
/// Wire layout: `[src:6][BROADCAST:6][proto:2 NE][BatmanOgmPacket]`.
fn build_ogm_wire_frame(src: u8, tq: u8, seqno: u32) -> Vec<u8> {
    build_relayed_ogm_wire_frame(src, src, tq, seqno)
}

/// Build a raw OGM broadcast frame as it would appear on the wire after being
/// **relayed** by `relay` on behalf of a different originator `orig` — unlike
/// [`build_ogm_wire_frame`], this decouples the immediate sender from the
/// advertised destination, letting a test simulate a multi-hop route where
/// `relay` is forwarding someone else's OGM (`tq` already reflects whatever
/// hop decrements happened before it reached `relay`).
///
/// Wire layout: `[relay:6][BROADCAST:6][proto:2 NE][BatmanOgmPacket { orig, tq, .. }]`.
fn build_relayed_ogm_wire_frame(relay: u8, orig: u8, tq: u8, seqno: u32) -> Vec<u8> {
    let ogm = BatmanOgmPacket {
        packet_type: BatmanPacketType::Ogm.as_u8(),
        version: BATMAN_VERSION,
        ttl: 50,
        flags: 0,
        seqno: seqno.to_be(),
        orig: mac(orig),
        reserved: 0,
        tq,
        tvlv_len: 0,
    };
    build_frame(
        mac(relay),
        Mac::BROADCAST,
        wayfinder::DEFAULT_BATMAN_ETHER_TYPE,
        ogm.as_bytes(),
    )
}

/// Build a raw keep-alive heartbeat frame as it would appear on the wire,
/// sent by immediate neighbor `src` — link-local, never relayed, so unlike an
/// OGM there is no separate `orig`/relay distinction.
///
/// Wire layout: `[src:6][BROADCAST:6][proto:2 NE][BatmanKeepAlivePacket]`.
fn build_keepalive_wire_frame(src: u8) -> Vec<u8> {
    let pkt = BatmanKeepAlivePacket {
        packet_type: BatmanPacketType::Keepalive.as_u8(),
        version: BATMAN_VERSION,
    };
    build_frame(
        mac(src),
        Mac::BROADCAST,
        wayfinder::DEFAULT_BATMAN_ETHER_TYPE,
        pkt.as_bytes(),
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
        config.switches.push(TestSwitchConfig::shared(&switch_name));
        links.push(LinkConfig::test(switch_name));
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
    config.switches.push(TestSwitchConfig::shared("switch1"));

    for i in 0..n {
        let name = format!("machine{i}");
        config.machines.push(TestMachineConfig {
            name,
            wayfinder: Config {
                links: vec![LinkConfig::test("switch1")],
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
/// flood or forward).  That loop is bounded by `settle`'s own sweep cap, so a
/// mesh that never settles — e.g. an OGM forwarding loop — fails there with a
/// diagnostic rather than hanging.  No wall-clock timeout is involved: the
/// whole harness is synchronous, so "did it converge" is a property of the
/// simulation, not of how fast the machine ran it.
fn converge_at(h: &mut TestHarness, at: Duration) {
    h.converge(at);
}

/// Age out routes that have stopped being refreshed by advancing the virtual
/// clock past the purge budget on the production Trickle drive
/// ([`TestHarness::advance_trickle`]).  A path ages out once `MAX_MISSED_OGMS` of
/// its learned emission interval elapse without a refresh, and the longest a
/// live path's budget can be is `MAX_MISSED_OGMS ×` the slowest OGM interval the
/// mesh has currently backed off to.  Advancing just past that (with margin)
/// ages out a node that has gone silent while the survivors keep emitting and
/// stay live — and, by keying off the *current* backoff rather than `i_max`,
/// keeps the clock jump small after a brief convergence (so later absolute-time
/// reconnect convergences still move forward).
fn age_out(h: &mut TestHarness) {
    h.advance_trickle(h.clock + slowest_ogm_interval(h) * (MAX_MISSED_OGMS + 2));
}

/// The slowest OGM interval any interface in the mesh has currently backed off
/// to — the unit both [`age_out`] and [`reconverge`] measure their clock jumps
/// in, so neither depends on what `i_max` happens to default to.
fn slowest_ogm_interval(h: &TestHarness) -> Duration {
    h.machines
        .values()
        .flat_map(|m| m.router().ogm_schedule())
        .map(|e| e.current_interval)
        .max()
        .unwrap_or(Duration::from_secs(1))
}

/// Let a mesh that has just changed shape — typically a node brought back by
/// [`TestHarness::reconnect_machine`] — re-converge on the production Trickle
/// drive, by advancing far enough for every interface to emit at least once
/// even if it had backed off all the way to `i_max`.
///
/// A single [`converge_at`] round is not enough after a reconnect: `poll_due`
/// only fires the interfaces that are *due* at the instant it is given, and the
/// survivors of a long silence are mid-way through an `i_max`-long interval, so
/// a poll one second later fires nobody.  The returning node is then heard (it
/// starts at `i_min`) while its neighbours' own OGMs — the ones carrying the
/// routes *through* it — are still minutes away.  Keying off the current
/// backoff rather than a fixed number of seconds keeps this correct whatever
/// `TrickleConfig`'s defaults are.
fn reconverge(h: &mut TestHarness) {
    h.advance_trickle(h.clock + slowest_ogm_interval(h) * 2);
}

fn simple_pair() -> TestHarness {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig::shared("switch1"));
    config.machines.push(TestMachineConfig {
        name: "machine1".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("switch1")],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "machine2".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("switch1")],
            ..Default::default()
        },
    });
    config.validate().unwrap()
}

fn line_of_three() -> TestHarness {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig::shared("switch1"));
    config.switches.push(TestSwitchConfig::shared("switch2"));
    config.machines.push(TestMachineConfig {
        name: "machine1".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("switch1")],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "machine2".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("switch1"), LinkConfig::test("switch2")],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "machine3".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("switch2")],
            ..Default::default()
        },
    });
    config.validate().unwrap()
}

/// A `machine1 — machine2 — machine3` line (as [`line_of_three`]) but with
/// `machine2`'s link toward `machine3` (its interface 1, on `switch2`) carrying
/// the given participation `features` instead of full participation.  Lets a
/// test gate exactly the middle node's egress toward the far end and observe the
/// effect through the real driver dispatch path.
fn line_of_three_mid_gated(mid_far_link: LinkFeatures) -> TestHarness {
    let mut config = TestConfig::default();
    for sw in ["switch1", "switch2"] {
        config.switches.push(TestSwitchConfig::shared(sw));
    }
    config.machines.push(TestMachineConfig {
        name: "machine1".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("switch1")],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "machine2".into(),
        wayfinder: Config {
            links: vec![
                LinkConfig::test("switch1"),
                LinkConfig {
                    name: None,
                    transport: LinkTransport::Test {
                        switch_name: "switch2".into(),
                    },
                    ogm: TrickleConfig::default(),
                    features: mid_far_link,
                },
            ],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "machine3".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("switch2")],
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
        config.switches.push(TestSwitchConfig::shared(sw));
    }
    let machine = |name: &str, links: &[&str]| TestMachineConfig {
        name: name.into(),
        wayfinder: Config {
            links: links.iter().map(|s| LinkConfig::test(*s)).collect(),
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

/// Four nodes wired as a diamond: `a` fans out to `b` and `c`, which both
/// rejoin at `d` — two *equal*-length (2-hop) paths from `a` to `d`, unlike
/// [`two_paths_unequal_length`]'s deliberately asymmetric pair. Machine
/// indices: a=0, b=1, c=2, d=3. Every link's OGM backoff uses a 1s floor and
/// the given `i_max_ms` ceiling (see [`diamond_plus_k5`] for why a small
/// ceiling keeps a settling test fast while preserving the per-interface
/// Trickle dynamics).
fn diamond(i_max_ms: u64) -> TestHarness {
    let mut config = TestConfig::default();
    for sw in ["ab", "ac", "bd", "cd"] {
        config.switches.push(TestSwitchConfig::shared(sw));
    }
    let machine = |name: &str, links: &[&str]| TestMachineConfig {
        name: name.into(),
        wayfinder: Config {
            links: links
                .iter()
                .map(|s| LinkConfig {
                    name: None,
                    transport: LinkTransport::Test {
                        switch_name: (*s).into(),
                    },
                    ogm: TrickleConfig {
                        i_min_ms: 1000,
                        i_max_ms,
                    },
                    features: LinkFeatures::default(),
                })
                .collect(),
            ..Default::default()
        },
    };
    config.machines.push(machine("a", &["ab", "ac"]));
    config.machines.push(machine("b", &["ab", "bd"]));
    config.machines.push(machine("c", &["ac", "cd"]));
    config.machines.push(machine("d", &["bd", "cd"]));
    config.validate().unwrap()
}

#[test]
fn test_validate() {
    let config = TestConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_multi_same_switch() {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig::shared("test1"));
    config.switches.push(TestSwitchConfig::shared("test1"));
    assert!(config.validate().is_err());
}

#[test]
#[should_panic]
fn test_invalid_switch() {
    let mut config = TestConfig::default();
    config.machines.push(TestMachineConfig {
        name: "foo".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("invalid")],
            ..Default::default()
        },
    });
    assert!(config.validate().is_err());
}

#[test]
fn test_simple_pair() {
    simple_pair();
}

#[test]
fn test_simple_pair_send_data() {
    setup();
    let mut harness = simple_pair();

    harness.poll_due(Duration::from_secs(1));
    harness.tick();
    harness.tick();

    for router in harness.machines.values() {
        assert_eq!(router.router().originator_table().count(), 1);
    }

    tracing::info!("OGM PHASE COMPLETE");

    let m1 = harness.get_machine("machine1").ident;
    let m2 = harness.get_machine("machine2").ident;

    harness
        .get_machine_mut("machine1")
        .send_local(m2, b"Hello World");

    harness.tick();
    harness.tick();

    assert_eq!(
        harness.get_machine("machine2").local_deliveries(),
        vec![host_frame(m2, m1, b"Hello World")]
    );
}

/// Enable opt-in mesh authentication on machine `index` (zero-based, in config
/// order), with a cert minted by `authority`, and pin the auth clock so certs
/// are within their window.
///
/// Takes the machine's index rather than an address and a seed: the two are one
/// thing now (design 09 §5 — a certificate's subject is the address its key
/// derives), so `machine_keypair` is the single place both come from and a
/// fixture cannot pair the wrong ones.
fn enable_auth(node: &mut TestRouter, authority: &wayfinder_auth::Authority, index: usize) {
    let kp = crate::driver::machine_keypair(index);
    let cert = authority.issue_cert(
        kp.derived_mac(),
        kp.ed_pubkey(),
        kp.x_pubkey(),
        0,
        1_000_000,
    );
    node.router_mut().set_auth(wayfinder::auth::OgmAuth::new(
        kp,
        cert,
        authority.trust_anchor(),
    ));
    node.set_epoch_unix(1_000);
}

/// With auth enabled on both nodes, OGMs converge (signed) and a unicast is
/// delivered with its pairwise tag verified and stripped — the host gets the
/// clean payload, proving the directed data-plane tag wiring end to end.
#[test]
fn test_authenticated_unicast_delivers_and_strips_tag() {
    setup();
    let mut harness = simple_pair();

    let m1 = harness.get_machine("machine1").ident;
    let m2 = harness.get_machine("machine2").ident;

    let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
    enable_auth(harness.get_machine_mut("machine1"), &authority, 0);
    enable_auth(harness.get_machine_mut("machine2"), &authority, 1);

    // Converge: signed OGMs exchange, so each node learns the other's pairwise
    // key (required to tag/verify directed frames), and settle so the
    // next-hop proof challenge/response round trip completes too — a route
    // whose next hop has not yet proven itself is refused by `send_local`.
    harness.converge(Duration::from_secs(1));
    for router in harness.machines.values() {
        assert_eq!(router.router().originator_table().count(), 1);
    }

    harness
        .get_machine_mut("machine1")
        .send_local(m2, b"secret payload");

    harness.tick();
    harness.tick();

    // Delivered payload is the original — the 24-byte tag trailer was verified
    // and stripped, not handed to the host.
    assert_eq!(
        harness.get_machine("machine2").local_deliveries(),
        vec![host_frame(m2, m1, b"secret payload")]
    );
}

/// An emergency revocation injected at one node floods across the mesh on
/// normal OGM traffic and shuns the revoked node: in [`line_of_three`]
/// (machine1–machine2–machine3) an operator revokes machine3 at machine1, and
/// after the purge propagates machine2 learns it *purely from machine1's OGM*
/// (no direct API call) and machine3 ages out of both survivors' routing
/// tables, because its own OGMs are now dropped.
#[test]
fn test_revocation_floods_and_shuns_node() {
    setup();
    let mut harness = line_of_three();
    let m2 = harness.get_machine("machine2").ident;
    let m3 = harness.get_machine("machine3").ident;

    let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
    enable_auth(harness.get_machine_mut("machine1"), &authority, 0);
    enable_auth(harness.get_machine_mut("machine2"), &authority, 1);
    enable_auth(harness.get_machine_mut("machine3"), &authority, 2);

    // Converge: every node learns the other two over signed OGMs.
    converge_at(&mut harness, Duration::from_secs(1));
    for r in harness.machines.values() {
        assert_eq!(r.router().originator_count(), 2);
    }

    // Operator revokes machine3 at machine1 — the injection point a provider's
    // RevokeNode RPC will drive in the portal phase.
    let record = authority.revoke(m3, 50, 1_000_000);
    assert!(
        harness
            .get_machine_mut("machine1")
            .router_mut()
            .ingest_revocation(&record, Duration::from_secs(1)),
        "machine1 must accept the authority-signed revocation"
    );

    // Drive an OGM round so the purge floods, then age out the shunned node.
    converge_at(&mut harness, Duration::from_secs(2));
    age_out(&mut harness);

    // machine2 learned the revocation purely by verifying machine1's OGM.
    assert!(
        harness
            .get_machine("machine2")
            .router()
            .auth()
            .expect("auth enabled")
            .revoked_macs()
            .any(|m| m == m3),
        "machine2 must learn the revocation flooded in machine1's OGM tail"
    );

    // machine3 is shunned: its OGMs are dropped, so it ages out of both
    // survivors' originator tables.
    assert!(
        !harness
            .get_machine("machine2")
            .router()
            .originator_table()
            .any(|r| r.neighbor_ident == m3),
        "the relay must drop the revoked node"
    );
    assert!(
        !harness
            .get_machine("machine1")
            .router()
            .originator_table()
            .any(|r| r.neighbor_ident == m3),
        "machine1 must lose its route to the revoked node once it is no longer relayed"
    );
    // The honest survivors still see each other.
    assert!(
        harness
            .get_machine("machine1")
            .router()
            .originator_table()
            .any(|r| r.neighbor_ident == m2),
        "the honest survivors must remain reachable"
    );
}

#[test]
fn test_line_of_three() {
    line_of_three();
}

#[test]
fn test_line_of_three_send_data() {
    setup();
    let mut harness = line_of_three();

    harness.poll_due(Duration::from_secs(1));
    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();

    for router in harness.machines.values() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    let m1 = harness.get_machine("machine1").ident;
    let m3 = harness.get_machine("machine3").ident;
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"Hello World");

    harness.tick();
    harness.tick();
    harness.tick();

    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"Hello World")]
    );
}

/// A lazy-cert-distribution `CertReq` relays across a real multi-hop mesh
/// (machine1 -> machine2 -> machine3) through each node's genuine driver/
/// router receive path, and terminates at its destination without ever
/// leaking to that node's host TAP.
///
/// Origination is hand-crafted directly onto the switch (via
/// `add_switch_port`, standing in for the requester logic a later phase
/// adds) rather than through any `CentralRouter` API, since this phase only
/// implements wire types + engine/router forwarding — not origination.
#[test]
fn cert_req_relays_across_the_mesh_and_does_not_reach_the_host() {
    setup();
    let mut harness = line_of_three();

    // Bootstrap routing so machine2 has a live route to machine3.
    harness.poll_due(Duration::from_secs(1));
    for _ in 0..5 {
        harness.tick();
    }
    for router in harness.machines.values() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    let m1 = harness.get_machine("machine1").ident;
    let m2 = harness.get_machine("machine2").ident;
    let m3 = harness.get_machine("machine3").ident;

    // Tap switch2 (the machine2<->machine3 segment) to observe the relayed
    // CertReq crossing the second hop with its TTL decremented.
    let relayed = Arc::new(AtomicUsize::new(0));
    {
        let switch2 = harness.switches.get_mut("switch2").unwrap();
        for port in switch2.port_ids() {
            let relayed = relayed.clone();
            switch2
                .add_tap(
                    port,
                    TapConfig::new(move |meta| {
                        if meta.direction == Direction::ToSwitch
                            && meta.data.len() > 14
                            && meta.data[12..14] == DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes()
                            && meta.data[14] == BatmanPacketType::CertReq.as_u8()
                        {
                            let (hdr, _) =
                                BatmanCertReqPacket::ref_from_prefix(&meta.data[14..]).unwrap();
                            assert_eq!(hdr.ttl, 9, "TTL must be decremented across the first hop");
                            relayed.fetch_add(1, Ordering::Relaxed);
                        }
                        true
                    }),
                )
                .unwrap();
        }
    }

    // Inject a hand-crafted CertReq directly onto switch1, link-addressed to
    // machine2 (the next hop toward machine3) — the byte-level shape a real
    // requester would produce.
    let (raw_port, _port_id) = harness.add_switch_port("switch1");
    let cert_req_hdr = BatmanCertReqPacket {
        packet_type: BatmanPacketType::CertReq.as_u8(),
        version: BATMAN_VERSION,
        ttl: 10,
        dest: m3,
    };
    let mut inner = cert_req_hdr.as_bytes().to_vec();
    inner.extend_from_slice(b"requester cert + sig");
    let wire = build_frame(m1, m2, DEFAULT_BATMAN_ETHER_TYPE, &inner);
    raw_port.egress.try_send(wire).unwrap();

    for _ in 0..3 {
        harness.tick();
    }

    assert_eq!(
        relayed.load(Ordering::Relaxed),
        1,
        "the CertReq must cross the second hop toward machine3"
    );
    assert!(
        harness
            .get_machine("machine3")
            .local_deliveries()
            .is_empty(),
        "a CertReq terminating at its destination must not reach the host TAP"
    );
}

/// A broadcast (e.g. an ARP) needs no route: machine1 floods it and
/// machine2 must deliver the inner frame to its local host.  No OGM
/// convergence is required because broadcasts reach every interface.
#[test]
fn broadcast_is_delivered_locally_at_neighbor() {
    setup();
    let mut harness = simple_pair();

    let arp = b"i am a broadcast frame";
    let m1 = harness.get_machine("machine1").ident;
    harness
        .get_machine_mut("machine1")
        .send_local(Mac::BROADCAST, arp);

    harness.tick();
    harness.tick();

    assert_eq!(
        harness.get_machine("machine2").local_deliveries(),
        vec![host_frame(Mac::BROADCAST, m1, arp)]
    );
}

/// The negative mirror of the previous test: with `tx_data` disabled on
/// machine1's only link, its locally originated broadcast is suppressed at the
/// driver's egress fan-out and never reaches machine2 — proving the per-link
/// transmit gate (`link_may_tx`) actually keeps the flood off the wire.
#[test]
fn broadcast_suppressed_on_tx_data_disabled_link() {
    setup();
    let mut harness = simple_pair();

    // Turn data-plane tx off on machine1's link to the switch (iface 0); every
    // other capability stays on.
    let f = LinkFeatures {
        tx_data: false,
        ..Default::default()
    };
    harness
        .get_machine_mut("machine1")
        .router_mut()
        .set_link_features(0, f);

    let arp = b"i am a broadcast frame";
    harness
        .get_machine_mut("machine1")
        .send_local(Mac::BROADCAST, arp);

    harness.tick();
    harness.tick();

    assert!(
        harness
            .get_machine("machine2")
            .local_deliveries()
            .is_empty(),
        "a broadcast must not egress a tx_data-disabled link"
    );
}

/// A star switch naming a machine that is not wired to it must fail to build.
/// Falling back to a shared segment would make every star test pass for the
/// wrong reason: that is the one topology which cannot detect this bug class.
#[test]
fn a_star_switch_naming_an_unwired_hub_is_rejected() {
    setup();
    let mut config = TestConfig::default();
    config
        .switches
        .push(TestSwitchConfig::star("vpn", "absent"));
    config.machines.push(TestMachineConfig {
        name: "present".into(),
        wayfinder: Config {
            links: vec![LinkConfig::test("vpn")],
            ..Default::default()
        },
    });

    let Err(err) = config.validate() else {
        panic!("an unwired hub must be rejected");
    };
    assert!(
        err.contains("absent"),
        "the error must name the machine that could not be found: {err}"
    );
}

/// A hub-and-spoke fabric: one switch in star mode, so a spoke's transmission
/// reaches only the hub (see [`Switch::set_hub_port`]). Every node has exactly
/// one interface, which is the point: the hub's only path to `spokeB` is the
/// same interface `spokeA` was heard on.
fn hub_and_two_spokes() -> TestHarness {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig::star("vpn", "hub"));
    for name in ["hub", "spokeA", "spokeB"] {
        config.machines.push(TestMachineConfig {
            name: name.into(),
            wayfinder: Config {
                links: vec![LinkConfig::test("vpn")],
                ..Default::default()
            },
        });
    }
    config.validate().unwrap()
}

/// **A node relays between neighbors on one interface that cannot hear each
/// other.** Each spoke learns the other *via the hub*, and data then reaches
/// the far spoke. Excluding the ingress interface left the relay set empty on a
/// one-interface hub, so the spokes never converged — the failure
/// `nix/tests/vpn-data-plane.nix` hit against a real Tailscale tunnel.
#[test]
fn node_relays_between_neighbors_that_cannot_hear_each_other() {
    setup();
    let mut harness = hub_and_two_spokes();

    let a = harness.get_machine("spokeA").ident;
    let b = harness.get_machine("spokeB").ident;

    // Two rounds, not one: a spoke's first OGM reaches the hub before the hub
    // has anything of its own to say about the *other* spoke, so the mesh
    // needs a second Trickle round to carry each spoke's identity all the way
    // across. Inherent to a two-hop path, not to the flooding rule.
    converge_at(&mut harness, Duration::from_secs(1));
    converge_at(&mut harness, Duration::from_secs(2));

    // `neighbor_ident` is the originator's own address, not the next hop, so
    // checking only that a record exists would pass on any path. The next hop
    // is what makes "through the hub's relay" true, and what would catch a
    // regression to direct spoke-to-spoke learning.
    let hub = harness.get_machine("hub").ident;
    assert!(
        harness
            .get_machine("spokeA")
            .router()
            .originator_table()
            .any(|r| r.neighbor_ident == b && r.best_next_hop == Some(hub)),
        "spokeA must learn spokeB with the hub as next hop"
    );
    assert!(
        harness
            .get_machine("spokeB")
            .router()
            .originator_table()
            .any(|r| r.neighbor_ident == a && r.best_next_hop == Some(hub)),
        "spokeB must learn spokeA with the hub as next hop"
    );

    harness
        .get_machine_mut("spokeA")
        .send_local(b, b"over the tunnel");
    harness.settle();

    assert_eq!(
        harness.get_machine("spokeB").local_deliveries(),
        vec![host_frame(b, a, b"over the tunnel")],
        "the learned route must actually carry data, forwarded by the hub"
    );
}

/// Churning the hub off and back on must not silently break the star. A
/// reconnected machine gets a **fresh** port, so a designation captured at
/// build time would go on naming the dead one — every spoke frame forwarded
/// into a receiver that no longer exists, and no panic and no log to say so.
#[test]
fn a_reconnected_hub_still_relays_between_the_spokes() {
    setup();
    let mut harness = hub_and_two_spokes();

    let a = harness.get_machine("spokeA").ident;
    let b = harness.get_machine("spokeB").ident;
    converge_at(&mut harness, Duration::from_secs(1));
    converge_at(&mut harness, Duration::from_secs(2));

    harness.disconnect_machine("hub");
    harness.reconnect_machine("hub");

    // The reborn hub starts with empty tables, so it has to re-learn both
    // spokes before it can relay between them again. Assert on the *hub*, not
    // the spokes: a spoke keeps its stale record of the other for a while, so
    // it would report success against a completely dead fabric.
    converge_at(&mut harness, Duration::from_secs(3));
    converge_at(&mut harness, Duration::from_secs(4));

    let hub_originators: Vec<Mac> = harness
        .get_machine("hub")
        .router()
        .originator_table()
        .map(|r| r.neighbor_ident)
        .collect();
    assert!(
        hub_originators.contains(&a) && hub_originators.contains(&b),
        "the reconnected hub must hear both spokes again on its fresh port, got {hub_originators:?}"
    );

    // And the relay must still carry data end to end.
    harness
        .get_machine_mut("spokeA")
        .send_local(b, b"after the reboot");
    harness.settle();
    assert_eq!(
        harness.get_machine("spokeB").local_deliveries(),
        vec![host_frame(b, a, b"after the reboot")],
        "spokeA must still reach spokeB through the reconnected hub"
    );
}

/// **What flooding every interface costs.** A shared segment of N nodes carries
/// **N² OGM frames** per Trickle round — N own emissions plus each node
/// re-flooding the other N-1 — where it carried N. Pinned so any future change
/// to the flooding rule has to move these numbers on purpose.
///
/// Every re-flood here is waste, since each peer heard the original directly;
/// a node just cannot tell this segment from a radio with hidden peers (see
/// `driver_core::Egress::Auto`), and BATMAN-IV floods the same way.
///
/// If a duty-cycle-limited radio segment ever gets crowded: suppressing the
/// re-flood when the sender is the only neighbour heard on that interface
/// recovers N=2, and hearing-based suppression the rest. Both want a
/// measurement behind them, and both would move these numbers deliberately.
#[test]
fn flooding_every_interface_costs_a_quadratic_number_of_ogms() {
    setup();
    for (nodes, expected) in [(2usize, 4usize), (3, 9), (4, 16)] {
        let mut harness = one_switch_with_machines(nodes);

        // Converge first, then count, so this covers steady state only.
        converge_at(&mut harness, Duration::from_secs(1));
        let counter = count_ogms(&mut harness);

        harness.poll_due(Duration::from_secs(30));
        harness.settle();

        assert_eq!(
            counter.load(Ordering::Relaxed),
            expected,
            "{nodes} nodes on one segment: expected {expected} OGM frames per round (n²)"
        );
    }
}

/// **A broadcast still reaches each node exactly once on a multi-access
/// segment.** Newly worth pinning: every node now re-floods every broadcast it
/// hears, so only the engine's de-duplication stops a three-node segment
/// turning one broadcast into a storm of duplicate local deliveries. That path
/// never executed here before — the re-flood set was always empty.
#[test]
fn a_broadcast_is_delivered_exactly_once_despite_mutual_reflooding() {
    setup();
    let mut harness = one_switch_with_machines(3);
    converge_at(&mut harness, Duration::from_secs(1));

    harness
        .get_machine_mut("machine0")
        .send_local(Mac::BROADCAST, b"one copy each");
    harness.settle();

    assert_eq!(
        harness.get_machine("machine0").local_deliveries().len(),
        0,
        "the originator must not deliver its own broadcast back to itself"
    );
    for name in ["machine1", "machine2"] {
        assert_eq!(
            harness.get_machine(name).local_deliveries().len(),
            1,
            "{name} must deliver the broadcast exactly once, not once per re-flood heard"
        );
    }
}

/// A transit OGM is not re-flooded out a `tx_ogm`-disabled link. On a
/// `machine1 — machine2 — machine3` line where machine2's link toward machine3
/// has `tx_ogm: false`, machine2 still *hears* machine1 (rx_ogm on) but never
/// announces onto the far link, so machine3 never learns machine1 — the
/// re-flood (transit) path, exercised through the real driver dispatch, is
/// suppressed distinctly from own-OGM emission.
#[test]
fn ogm_reflood_suppressed_on_tx_ogm_disabled_link() {
    setup();
    let f = LinkFeatures {
        tx_ogm: false, // machine2 stays OGM-silent toward machine3
        ..Default::default()
    };
    let mut harness = line_of_three_mid_gated(f);

    let m1 = harness.get_machine("machine1").ident;
    converge_at(&mut harness, Duration::from_secs(1));

    // The OGM path up to the middle node works: machine2 learned machine1.
    assert!(
        harness
            .get_machine("machine2")
            .router()
            .originator_table()
            .any(|r| r.neighbor_ident == m1),
        "machine2 must hear machine1 (rx_ogm is on)"
    );
    // But the re-flood onto the tx_ogm-disabled far link is suppressed, so the
    // far node never learns the origin behind the middle node.
    assert!(
        harness
            .get_machine("machine3")
            .router()
            .originator_table()
            .all(|r| r.neighbor_ident != m1),
        "machine3 must not learn machine1: the transit OGM re-flood is gated"
    );
}

/// A `tx_data`-off link is not re-advertised: the fronting node learns the
/// nodes behind it (local visibility) but never announces a route to them, so no
/// peer can black-hole traffic toward nodes it can't deliver to. On the
/// `machine1 — machine2 — machine3` line, machine2's link toward machine3 is
/// `tx_data: false`; machine2 still learns machine3 (rx_ogm on), but machine1 —
/// the "control station" one hop further out — never learns machine3, because
/// machine2 doesn't re-flood a route it couldn't honor. This is the anti-black-
/// hole rule that closes the "advertise but can't deliver" gap.
#[test]
fn tx_data_off_link_is_not_readvertised_to_peers() {
    setup();
    let f = LinkFeatures {
        tx_data: false, // machine2 can't deliver onto the far link ⇒ won't advertise it
        ..Default::default()
    };
    let mut harness = line_of_three_mid_gated(f);

    let m3 = harness.get_machine("machine3").ident;
    converge_at(&mut harness, Duration::from_secs(1));

    // The fronting node itself sees machine3 (learned locally for visibility).
    assert!(
        harness
            .get_machine("machine2")
            .router()
            .originator_table()
            .any(|r| r.neighbor_ident == m3),
        "machine2 must learn machine3 locally (rx_ogm is on)"
    );
    // But it advertises no route to machine3, so the node one hop further out
    // never learns it and thus never tries to route to it and black-hole.
    assert!(
        harness
            .get_machine("machine1")
            .router()
            .originator_table()
            .all(|r| r.neighbor_ident != m3),
        "machine1 must not learn machine3: a tx_data-off link is not re-advertised"
    );
}

/// Three nodes share one switch, so each is a direct neighbor of the other
/// two.  After OGM convergence a unicast is routed only to its addressee:
/// machine0 → machine2 is delivered at machine2 and never seen by machine1,
/// and likewise machine0 → machine1 lands only at machine1.  The negative
/// deliveries stand in for the per-port tap assertions of the old test —
/// the switch's learned forwarding is what keeps the wrong node silent.
#[test]
fn three_routers_all_connected_discover_and_exchange() {
    setup();
    let mut harness = one_switch_with_machines(3);

    // Two rounds of OGMs so every node learns direct routes to the others.
    harness.poll_due(Duration::from_secs(1));
    harness.tick();
    harness.tick();
    harness.tick();

    for router in harness.machines.values() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    let m0 = harness.get_machine("machine0").ident;

    // ── unicast machine0 → machine2 ──────────────────────────────────────
    let m2 = harness.get_machine("machine2").ident;
    harness
        .get_machine_mut("machine0")
        .send_local(m2, b"hello from 0 to 2");

    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();

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
        .send_local(m1, b"hello from 0 to 1");

    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();
    harness.tick();

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
#[test]
fn ogms_stop_after_convergence() {
    setup();
    let mut harness = line_of_three();

    // Converge, then drain every in-flight OGM from the initial poll so the
    // fabric is quiet before we begin measuring.
    harness.poll_due(Duration::from_secs(1));
    for _ in 0..80 {
        harness.tick();
    }
    for router in harness.machines.values() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    // Watch every OGM that crosses the fabric from here on.
    let counter = count_ogms(&mut harness);

    // Emit one fresh OGM from every node.  In a loop-free mesh this single
    // round reaches every node and then dies within the network diameter.
    harness.poll_due(Duration::from_secs(2));

    // 4 ticks are the required number for the network to settle here
    const SETTLE_TICKS: usize = 4;
    for _ in 0..SETTLE_TICKS {
        harness.tick();
    }
    let after_settle = counter.load(Ordering::Relaxed);

    // ...after which the fabric must stay silent: with no new poll, a converged
    // mesh has nothing left to forward.
    const QUIET_TICKS: usize = 20;
    for _ in 0..QUIET_TICKS {
        harness.tick();
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
#[test]
fn traffic_fails_over_when_best_next_hop_disconnects() {
    setup();
    let mut harness = two_paths_unequal_length();

    let a = harness.get_machine("a").ident;
    let b = harness.get_machine("b").ident;
    let c = harness.get_machine("c").ident;
    let d = harness.get_machine("d").ident;

    // Converge: a few poll rounds, each fully drained.
    for round in 1..=3 {
        harness.poll_due(Duration::from_secs(round));
        for _ in 0..10 {
            harness.tick();
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
        Some(b),
        "a's best next hop to d should be b (the 2-hop path)"
    );

    // `b` goes offline: drop it from the simulation so it stops originating and
    // forwarding.  Its switch ports go dead but the fabric tolerates that.
    harness.machines.remove("b");

    // Let plenty of virtual time pass while the surviving `c→e` route keeps
    // refreshing, far beyond any reasonable neighbor timeout, so the stale `b`
    // path ages out and `a` recomputes its best hop.
    for secs in (100..=1000).step_by(100) {
        harness.poll_due(Duration::from_secs(secs));
        for _ in 0..10 {
            harness.tick();
        }
    }

    let after = record(&harness);
    assert_eq!(
        after.best_next_hop,
        Some(c),
        "after b is lost, a must fail over to the c→e path"
    );

    // End-to-end: a unicast from `a` to `d` must still arrive, now routed the
    // long way round via c→e.
    harness
        .get_machine_mut("a")
        .send_local(d, b"hello via failover");
    harness.settle();
    assert_eq!(
        harness.get_machine("d").local_deliveries(),
        vec![host_frame(d, a, b"hello via failover")],
        "d must receive the unicast over the surviving c→e path"
    );
}

/// A direct neighbor that goes offline and later returns must be re-learned,
/// restoring end-to-end traffic.  Two nodes share a switch; once converged each
/// knows the other directly.  When machine2 powers off, its route ages out of
/// machine1's table (no refresh for `MAX_MISSED_OGMS` of machine1's OGM rounds).
/// When the *same* node (same identity, empty tables) comes back, both must
/// rediscover each other and a unicast must flow again.
#[test]
fn route_restored_after_neighbor_reconnects() {
    setup();
    let mut harness = simple_pair();
    let m1 = harness.get_machine("machine1").ident;
    let m2 = harness.get_machine("machine2").ident;

    // Converge over a few rounds: each node learns the other as a direct
    // neighbor *and* its steady OGM cadence (~1 s/round), which sets the
    // observed-rate purge budget the age-out below relies on.
    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round));
    }
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        1
    );
    assert_eq!(
        harness.get_machine("machine2").router().originator_count(),
        1
    );

    // machine2 powers off.  Drive enough OGM rounds with only machine1 polling
    // that its now-unrefreshed route to machine2 ages out by round gap.
    harness.disconnect_machine("machine2");
    age_out(&mut harness);
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        0,
        "machine1 must drop the stale route once machine2 stops refreshing it"
    );

    // machine2 returns with its original identity but empty tables.
    harness.reconnect_machine("machine2");
    converge_at(&mut harness, Duration::from_secs(160));
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
        .send_local(m2, b"welcome back");
    harness.settle();
    assert_eq!(
        harness.get_machine("machine2").local_deliveries(),
        vec![host_frame(m2, m1, b"welcome back")],
        "machine2 must receive traffic again after reconnecting"
    );
}

/// A direct neighbor's link-quality entry must not outlive the neighbor in the
/// routing table: once machine2 goes silent and its route ages out of
/// machine1's originator table, machine1's link-quality table must drop
/// machine2's row too. Otherwise the management API's Link Quality view keeps
/// showing a neighbor the Routing Table view has already forgotten.
#[test]
fn link_quality_entry_pruned_when_neighbor_ages_out() {
    setup();
    let mut harness = simple_pair();
    let m2 = harness.get_machine("machine2").ident;

    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round));
    }
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        1
    );
    assert!(
        harness
            .get_machine("machine1")
            .router()
            .link_quality_records()
            .iter()
            .any(|r| r.neighbor == m2),
        "machine1 must have a link-quality entry for machine2 once converged"
    );

    harness.disconnect_machine("machine2");
    age_out(&mut harness);
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        0,
        "machine1 must drop the stale route once machine2 stops refreshing it"
    );
    assert!(
        !harness
            .get_machine("machine1")
            .router()
            .link_quality_records()
            .iter()
            .any(|r| r.neighbor == m2),
        "machine1's link-quality entry for machine2 must be pruned once machine2 ages out of the originator table"
    );
}

/// When the *only* relay on a line goes offline there is no alternate path, so
/// traffic must black-hole rather than be misdelivered; when the relay returns
/// the path heals.  In [`line_of_three`] machine1 reaches machine3 solely
/// through machine2.  Dropping machine2 leaves machine1 with no route once the
/// stale entry ages out — machine3 hears nothing more — and reconnecting it
/// restores delivery.
#[test]
fn sole_relay_disconnect_blackholes_then_recovers() {
    setup();
    let mut harness = line_of_three();
    let m1 = harness.get_machine("machine1").ident;
    let m3 = harness.get_machine("machine3").ident;

    // Converge the line over a few rounds — learning each route's steady OGM
    // cadence (~1 s/round) so the age-out below has an observed-rate budget —
    // then confirm the baseline machine1 → machine3 delivery over the relay.
    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round));
    }
    for r in harness.machines.values() {
        assert_eq!(r.router().originator_count(), 2);
    }
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"before");
    harness.settle();
    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"before")],
        "baseline: machine3 receives over the relay"
    );

    // The sole relay drops.  After the stale routes age out machine1 has nowhere
    // to forward, so a send must not reach machine3.
    harness.disconnect_machine("machine2");
    age_out(&mut harness);
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        0,
        "with the relay gone, machine1's routes to both 2 and 3 age out"
    );
    harness.get_machine_mut("machine1").send_local(m3, b"lost");
    harness.settle();
    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"before")],
        "no new delivery while the only relay is offline"
    );

    // The relay returns; after re-convergence the path heals end-to-end.
    harness.reconnect_machine("machine2");
    converge_at(&mut harness, Duration::from_secs(160));
    for name in ["machine1", "machine2", "machine3"] {
        assert_eq!(
            harness.get_machine(name).router().originator_count(),
            2,
            "{name} must re-converge after the relay returns"
        );
    }
    harness.get_machine_mut("machine1").send_local(m3, b"after");
    harness.settle();
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
#[test]
fn best_hop_reclaims_preferred_path_after_reconnect() {
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
            .and_then(|r| r.best_next_hop)
    };

    // Converge: `a` prefers the 2-hop path via `b`.
    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round));
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(b),
        "a should prefer the shorter path via b"
    );

    // `b` drops; after the stale high-TQ path ages out, `a` fails over to c→e.
    harness.disconnect_machine("b");
    age_out(&mut harness);
    assert_eq!(
        best_hop_to_d(&harness),
        Some(c),
        "with b gone, a must fall back to the c→e path"
    );

    // `b` returns; its shorter, higher-TQ path must be reclaimed as preferred.
    harness.reconnect_machine("b");
    for secs in (700..=1200).step_by(100) {
        converge_at(&mut harness, Duration::from_secs(secs));
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(b),
        "once b is back its higher-TQ path must win again"
    );

    // And traffic flows over the restored preferred path.
    harness
        .get_machine_mut("a")
        .send_local(d, b"preferred again");
    harness.settle();
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
#[test]
fn flapping_relay_reconverges() {
    setup();
    let mut harness = line_of_three();
    let m1 = harness.get_machine("machine1").ident;
    let m3 = harness.get_machine("machine3").ident;

    converge_at(&mut harness, Duration::from_secs(1));

    // Flap the relay three times.  Each down leg drives enough OGM rounds for the
    // relay's routes to fully age out before it returns on the up leg, and each
    // up leg gives the survivors a full backed-off interval to emit again, so
    // the relearning is driven by the mesh's own schedule rather than by a poll
    // that happens to land on a due instant.
    for _ in 0..3 {
        harness.disconnect_machine("machine2");
        age_out(&mut harness);

        harness.reconnect_machine("machine2");
        reconverge(&mut harness);
    }

    // After the churn settles the line must be fully converged again...
    reconverge(&mut harness);
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
        .send_local(m3, b"still here");
    harness.settle();
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
#[test]
fn simultaneous_disconnects_blackhole_then_recover() {
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
            .and_then(|r| r.best_next_hop)
    };

    // Converge both a→d paths.
    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round));
    }
    assert!(
        route_to_d(&harness).is_some(),
        "a should know a route to d after convergence"
    );

    // Both relays — b (the 2-hop path) and e (the tail of the c→e path) — drop at
    // once.  a→d now has no surviving path.
    harness.disconnect_machine("b");
    harness.disconnect_machine("e");
    age_out(&mut harness);
    assert_eq!(
        route_to_d(&harness),
        None,
        "with both b and e gone, a must have no route to d"
    );

    let before = harness.get_machine("d").local_deliveries().len();
    harness.get_machine_mut("a").send_local(d, b"into the void");
    harness.settle();
    assert_eq!(
        harness.get_machine("d").local_deliveries().len(),
        before,
        "no delivery while both paths are down"
    );

    // Both return; `a` re-converges and prefers the restored 2-hop path via `b`.
    harness.reconnect_machine("b");
    harness.reconnect_machine("e");
    for secs in (700..=1300).step_by(100) {
        converge_at(&mut harness, Duration::from_secs(secs));
    }
    assert_eq!(
        route_to_d(&harness),
        Some(b),
        "a should reconverge onto the preferred path via b"
    );
    harness.get_machine_mut("a").send_local(d, b"back online");
    harness.settle();
    assert_eq!(
        harness.get_machine("d").local_deliveries(),
        vec![host_frame(d, a, b"back online")],
        "delivery resumes once both paths are restored"
    );
}

// ── equal-cost tie-break stability ─────────────────────────────────────────
//
// Every failover test above uses a path pair with a *strictly* unequal TQ (a
// shorter, higher-quality path and a longer, lower-quality one), so the
// engine's metric alone decides the winner. This exercises the other case: two
// paths that are exactly tied. `handle_ogm` (`libs/batman/src/engine.rs`) keeps
// the incumbent on a tie (only a *strictly* better path displaces it), but the
// periodic purge sweep's `recompute_best` deliberately recomputes from scratch
// and prefers the most-recently-refreshed path on a tie instead — favoring
// freshness against the risk that the older tied path is about to be evicted
// by loss. So `a`'s pick between `b`/`c` may legitimately swap from round to
// round; what must never happen is that swap being mistaken for a topology
// change, which would reset Trickle and re-flood the mesh. Neither
// `handle_ogm` nor `purge_stale` flips `topology_changed` for a pure
// best-hop swap (only a genuinely new/lost originator or path does), so this
// is a regression test for that invariant, not for a fixed pick.

/// With two equal-length paths (`a–b–d` and `a–c–d` in [`diamond`]), both carry
/// the same TQ, so `a`'s best-next-hop pick between `b` and `c` may swap from
/// round to round (the periodic purge sweep prefers the freshest tied path).
/// That swap must not be treated as a topology change: every interface must
/// still back all the way off to `i_max` and stay there — exactly like the
/// loop-free settling test — and delivery must keep working over whichever
/// tied path is currently selected.
#[test]
fn equal_cost_path_swaps_do_not_trigger_reflood() {
    setup();
    let i_max = Duration::from_secs(8);
    let mut harness = diamond(8_000);
    let a = harness.get_machine("a").ident;
    let b = harness.get_machine("b").ident;
    let c = harness.get_machine("c").ident;
    let d = harness.get_machine("d").ident;

    // Warm up well past the time the backoff needs to climb 1→2→4→8s, and past
    // several periodic purge sweeps that could churn the tied best-hop pick,
    // then run a further window over which the mesh must stay both complete
    // and calm — mirroring `diamond_plus_k5_settles_to_i_max`'s proven timing.
    let min_full = harness.run_trickle(Duration::from_secs(40), Duration::from_secs(80));
    assert_eq!(
        min_full, 3,
        "a, b, c, and d must continuously know their other 3 peers despite any tied-path churn"
    );

    let hop = harness
        .get_machine("a")
        .router()
        .originator_table()
        .find(|r| r.neighbor_ident == d)
        .and_then(|r| r.best_next_hop);
    assert!(
        hop == Some(b) || hop == Some(c),
        "a's best next hop to d must be one of the two equal-cost neighbors, got {hop:?}"
    );

    // The tied pick swapping (if it did) must not have been treated as a
    // topology change: every interface must have backed off to i_max and
    // stayed there, not been pinned near i_min by spurious Trickle resets.
    for (name, machine) in harness.machines.iter() {
        for e in machine.router().ogm_schedule() {
            assert_eq!(
                e.current_interval, i_max,
                "node {name} iface {} never backed off to i_max (stuck at {:?}) — a tied \
                 best-hop swap incorrectly reset the Trickle timer",
                e.iface_idx, e.current_interval
            );
        }
    }

    // End-to-end: delivery works over whichever tied path is currently in use.
    harness
        .get_machine_mut("a")
        .send_local(d, b"steady over equal-cost path");
    harness.settle();
    assert_eq!(
        harness.get_machine("d").local_deliveries(),
        vec![host_frame(d, a, b"steady over equal-cost path")],
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
#[test]
fn link_down_triggers_failover_then_restore_reclaims() {
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
            .and_then(|r| r.best_next_hop)
    };

    for round in 1..=3 {
        converge_at(&mut harness, Duration::from_secs(round));
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
    age_out(&mut harness);
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
        converge_at(&mut harness, Duration::from_secs(secs));
    }
    assert_eq!(
        best_hop_to_d(&harness),
        Some(b),
        "restoring the a–b link must reclaim the preferred path via b"
    );

    harness.get_machine_mut("a").send_local(d, b"link back up");
    harness.settle();
    assert_eq!(
        harness.get_machine("d").local_deliveries(),
        vec![host_frame(d, a, b"link back up")],
        "d must receive over the reclaimed b path"
    );
}

/// A brief link outage must not cost a node its routing state.  Because a
/// link-down (unlike a reboot) leaves the node's tables intact, a blip spanning
/// fewer than `MAX_MISSED_OGMS` OGM rounds loses no routes: machine1's only link
/// drops and is restored within the gap budget, so its routes to both machine2
/// and machine3 survive and traffic resumes with no re-convergence.
#[test]
fn brief_link_blip_preserves_routes() {
    setup();
    let mut harness = line_of_three();
    let m1 = harness.get_machine("machine1").ident;
    let m3 = harness.get_machine("machine3").ident;

    converge_at(&mut harness, Duration::from_secs(1));
    // converge_at(&mut harness, Duration::from_secs(2));
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        2
    );

    // machine1's only link (interface 0) drops, then returns within a single
    // OGM round — far inside the MAX_MISSED_OGMS gap budget — so nothing ages out.
    harness.fail_link("machine1", 0);
    converge_at(&mut harness, Duration::from_secs(30));
    assert_eq!(
        harness.get_machine("machine1").router().originator_count(),
        2,
        "a sub-timeout blip must not age out machine1's routes — state survives, unlike a reboot"
    );
    harness.restore_link("machine1", 0);
    converge_at(&mut harness, Duration::from_secs(35));

    // Traffic resumes immediately over the still-known route.
    harness
        .get_machine_mut("machine1")
        .send_local(m3, b"blip survived");
    harness.settle();
    assert_eq!(
        harness.get_machine("machine3").local_deliveries(),
        vec![host_frame(m3, m1, b"blip survived")],
        "delivery resumes over routes that were never lost"
    );
}

/// Severing the single bridge link between the diamond (`d1..d4`) and the K5
/// mesh (`m1..m5`) in [`diamond_plus_k5`] must **partition** the network into
/// two independently-converged islands — each side keeps knowing every other
/// node *within* its own island but loses every route across the former
/// bridge — rather than either side black-holing internally or a stale
/// cross-partition route lingering.  Restoring the bridge must reunite the
/// whole mesh.  This is the same `fail_link`/`restore_link` mechanism as
/// [`link_down_triggers_failover_then_restore_reclaims`], but severing the one
/// link that joins two otherwise-independent sub-meshes rather than a single
/// neighbor's link.
#[test]
fn bridge_failure_partitions_mesh_then_restore_reunites() {
    setup();
    let mut harness = diamond_plus_k5(8_000);

    // Converge the whole mesh first (same warmup/window the settling test
    // uses for this topology and i_max).
    let min_full = harness.run_trickle(Duration::from_secs(40), Duration::from_secs(80));
    assert_eq!(
        min_full, 8,
        "whole mesh must fully converge before the bridge is severed"
    );

    // Sever the single bridge link: d4's interface 2 is its "d4_m1" link (its
    // link order, filtered from EDGES, is [d2_d4, d3_d4, d4_m1]).
    harness.fail_link("d4", 2);
    age_out(&mut harness);

    const DIAMOND: [&str; 4] = ["d1", "d2", "d3", "d4"];
    const MESH: [&str; 5] = ["m1", "m2", "m3", "m4", "m5"];

    for name in DIAMOND {
        assert_eq!(
            harness.get_machine(name).router().originator_count(),
            3,
            "{name} must still know its 3 diamond-side peers after the partition"
        );
    }
    for name in MESH {
        assert_eq!(
            harness.get_machine(name).router().originator_count(),
            4,
            "{name} must still know its 4 mesh-side peers after the partition"
        );
    }

    // No cross-partition route survives on either side.
    let m5 = harness.get_machine("m5").ident;
    let d1 = harness.get_machine("d1").ident;
    assert!(
        harness
            .get_machine("d1")
            .router()
            .originator_table()
            .all(|r| r.neighbor_ident != m5),
        "d1 must have no route across the severed bridge"
    );
    assert!(
        harness
            .get_machine("m5")
            .router()
            .originator_table()
            .all(|r| r.neighbor_ident != d1),
        "m5 must have no route across the severed bridge"
    );

    // Restore the bridge; the two islands must reunite.
    harness.restore_link("d4", 2);
    harness.advance_trickle(harness.clock + Duration::from_secs(200));
    for name in DIAMOND.iter().chain(MESH.iter()) {
        assert_eq!(
            harness.get_machine(name).router().originator_count(),
            8,
            "{name} must reconverge onto the whole mesh once the bridge is restored"
        );
    }
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
#[test]
fn egress_picks_iface_with_better_metrics_for_shared_neighbor() {
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
    a.receive_with_metrics(Duration::from_secs(0), 0, &ogm_from_b, weak);
    a.receive_with_metrics(Duration::from_secs(1), 1, &ogm_from_b, strong);

    match a
        .router_mut()
        .get_egress_interface(Duration::from_secs(1), mac(100))
    {
        Some(EgressInterface::Interface(1)) => {}
        other => {
            panic!("expected egress for node B to be Interface(1) (strong RSSI/SNR), got {other:?}")
        }
    }
}

/// Mirror of the previous test with the metrics swapped across the two
/// interfaces — confirms the choice is driven by the metrics, not by iface
/// index or arrival order.
#[test]
fn egress_swaps_iface_when_metrics_swap() {
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
    a.receive_with_metrics(Duration::from_secs(0), 0, &ogm_from_b, strong);
    a.receive_with_metrics(Duration::from_secs(1), 1, &ogm_from_b, weak);

    match a
        .router_mut()
        .get_egress_interface(Duration::from_secs(1), mac(100))
    {
        Some(EgressInterface::Interface(0)) => {}
        other => {
            panic!("expected egress for node B to be Interface(0) (strong RSSI/SNR), got {other:?}")
        }
    }
}

/// A neighbor first heard strongly on interface 0 and weakly on interface 1
/// must have its egress *switch* to interface 1 once interface 0's measured
/// quality fades and interface 1's improves — the metrics equivalent of a link
/// going down, but a continuous fade rather than a binary wire failure.
/// [`egress_picks_iface_with_better_metrics_for_shared_neighbor`] only proves
/// the *initial* pick follows the metric; this proves the choice actually
/// changes when conditions change, not just once at first contact.
#[test]
fn egress_switches_interface_as_metrics_degrade() {
    let mut harness = single_machine_with_links(2);
    let ogm_from_b = build_ogm_wire_frame(100, 255, 1);

    let strong = LinkMetrics {
        rssi_dbm: None,
        snr_db: None,
        quality: Some(250),
    };
    let weak = LinkMetrics {
        rssi_dbm: None,
        snr_db: None,
        quality: Some(5),
    };

    let a = harness.get_machine_mut("a");

    // Initial contact: interface 0 strong, interface 1 weak.
    a.receive_with_metrics(Duration::from_secs(0), 0, &ogm_from_b, strong);
    a.receive_with_metrics(Duration::from_secs(1), 1, &ogm_from_b, weak);
    match a
        .router_mut()
        .get_egress_interface(Duration::from_secs(1), mac(100))
    {
        Some(EgressInterface::Interface(0)) => {}
        other => panic!("expected initial egress to be Interface(0) (strong), got {other:?}"),
    }

    // Interface 0 fades and interface 1 improves over many further OGMs — the
    // EWMA (alpha = 1/4) takes several samples to cross over, unlike the
    // single-shot injection above.
    let mut now = Duration::ZERO;
    for i in 0..10 {
        now = Duration::from_secs(2 + i);
        a.receive_with_metrics(now, 0, &ogm_from_b, weak);
        a.receive_with_metrics(now, 1, &ogm_from_b, strong);
    }

    match a.router_mut().get_egress_interface(now, mac(100)) {
        Some(EgressInterface::Interface(1)) => {}
        other => panic!(
            "expected egress to switch to Interface(1) once its measured quality overtook \
             the now-degraded interface 0, got {other:?}"
        ),
    }
}

// ── metrics-driven relay selection (BATMAN engine level) ───────────────────
//
// The egress tests above are about *interface* choice for a single direct
// neighbor reached over two radios — `CentralRouter`'s own link-quality table,
// entirely separate from the BATMAN engine (which doesn't know about
// interfaces at all). This is the other metrics-driven path: `local_quality`
// (looked up per (neighbor, iface) and passed into `BatmanEngine::handle_rx`)
// clamps a relayed OGM's advertised TQ (`libs/batman/src/engine.rs`,
// `handle_ogm`: `computed_tq.min(local)`), so two *different* relay neighbors
// advertising an identical, tied, hop-count-based TQ for some distant
// destination can still end up with different effective TQs — and therefore a
// different chosen next hop — purely from the measured physical link to each
// relay.

/// Two different neighbors, `b` and `c`, both relay an identical OGM (same
/// encoded TQ, same hop count) from a common distant originator `d`. `c`'s
/// copy arrives first and is heard weakly; `b`'s arrives second but is heard
/// strongly. The strictly higher *measured* quality to `b` must win —
/// overriding both the tied encoded TQ and `c`'s first-mover incumbency —
/// proving the next-hop choice follows the physical link, not just the OGM's
/// advertised (hop-count) metric.
#[test]
fn relay_choice_follows_measured_link_quality_on_tied_hop_count() {
    let mut harness = single_machine_with_links(2);
    let b = mac(10);
    let d = mac(20);

    // Both relays advertise the same tq for d — a genuine tie at the
    // OGM/hop-count level.
    let via_c = build_relayed_ogm_wire_frame(11, 20, 245, 1);
    let via_b = build_relayed_ogm_wire_frame(10, 20, 245, 1);

    let weak = LinkMetrics {
        rssi_dbm: None,
        snr_db: None,
        quality: Some(50),
    };
    let strong = LinkMetrics {
        rssi_dbm: None,
        snr_db: None,
        quality: Some(250),
    };

    let a = harness.get_machine_mut("a");
    // c's weak copy arrives first and becomes the incumbent.
    a.receive_with_metrics(Duration::from_secs(0), 1, &via_c, weak);
    // b's strong copy arrives second, tied on encoded TQ, but its measured
    // link quality is strictly better — it must still take over.
    a.receive_with_metrics(Duration::from_secs(1), 0, &via_b, strong);

    let record = a
        .router()
        .originator_table()
        .find(|r| r.neighbor_ident == d)
        .expect("a must have learned a route to d");
    assert_eq!(
        record.best_next_hop,
        Some(b),
        "the relay with strictly better measured link quality must win, even though c \
         arrived first and both advertised the same encoded TQ"
    );
}

// ── route-inspection API ──────────────────────────────────────────────────
//
// `CentralRouter::resolve_route` is the read-only mirror of the path the
// router would take on send; it backs the management-API ResolveRoute RPC.

/// With node B observed on a single interface, `resolve_route` reports B as
/// both the next hop and the egress (following the interface it arrived on).
#[test]
fn resolve_route_returns_neighbor_and_observed_interface() {
    let mut harness = single_machine_with_links(2);
    let ogm_from_b = build_ogm_wire_frame(100, 255, 1);
    let strong = LinkMetrics {
        rssi_dbm: Some(-50),
        snr_db: Some(12),
        quality: None,
    };

    harness.get_machine_mut("a").receive_with_metrics(
        Duration::from_secs(1),
        1,
        &ogm_from_b,
        strong,
    );

    let (next_hop, egress) = harness
        .get_machine("a")
        .router()
        .resolve_route(Duration::from_secs(1), mac(100));
    assert_eq!(next_hop, mac(100), "direct neighbor is its own next hop");
    assert_eq!(
        egress,
        Some(EgressInterface::Interface(1)),
        "egress must follow the interface the OGM arrived on"
    );
}

/// `resolve_route` returns [`EgressInterface::All`] for BROADCAST regardless
/// of any other table state.
#[test]
fn resolve_route_for_broadcast_returns_all_interfaces() {
    let harness = single_machine_with_links(1);

    let (next_hop, egress) = harness
        .get_machine("a")
        .router()
        .resolve_route(Duration::from_secs(1), Mac::BROADCAST);
    assert_eq!(next_hop, Mac::BROADCAST);
    assert_eq!(egress, Some(EgressInterface::All));
}

/// `resolve_route` must not perturb the router's state — repeated calls
/// return identical answers so management-API callers cannot disturb the
/// data plane's routing decisions.
#[test]
fn resolve_route_is_read_only() {
    let mut harness = single_machine_with_links(1);
    let ogm_from_b = build_ogm_wire_frame(100, 255, 1);
    let metrics = LinkMetrics {
        rssi_dbm: Some(-50),
        snr_db: Some(12),
        quality: None,
    };

    harness.get_machine_mut("a").receive_with_metrics(
        Duration::from_secs(0),
        0,
        &ogm_from_b,
        metrics,
    );

    let a = harness.get_machine("a");
    let first = a.router().resolve_route(Duration::from_secs(1), mac(100));
    let _ = a.router().resolve_route(Duration::from_secs(1), mac(100));
    let third = a.router().resolve_route(Duration::from_secs(1), mac(100));
    assert_eq!(first, third);
}

// ── keep-alive link liveness ────────────────────────────────────────────────
//
// These exercise the full production `Driver`/`TestRouter` stack (unlike the
// engine- and router-level unit tests, which call `BatmanEngine`/
// `CentralRouter` methods directly) to prove the keep-alive wiring — startup
// configuration, wire dispatch, and the widened `next_hop`-based route
// selection — actually works end to end, on the keep-alive timescale rather
// than the (far slower) OGM-staleness timescale.

/// Node `a` has two alternate paths to destination `mac(100)`: a high-TQ path
/// relayed by neighbor 2 (interface 0), which sends keep-alives, and a
/// lower-TQ path relayed by neighbor 3 (interface 1), which never does. Once
/// neighbor 2's keep-alive budget is missed — well before its OGM path would
/// have gone OGM-stale — resolving a route to `mac(100)` must switch to the
/// live neighbor 3, exactly as the feature promises.
#[test]
fn keepalive_miss_switches_route_before_ogm_staleness_would() {
    let mut harness = single_machine_with_links(2);
    let ogm_via_2 = build_relayed_ogm_wire_frame(2, 100, 255, 1);
    let ogm_via_3 = build_relayed_ogm_wire_frame(3, 100, 100, 1);
    // Neighbor 2's own OGM, so it's a known originator in its own right — a
    // keep-alive is only accepted from a neighbor we've actually heard an
    // OGM from.
    let ogm_from_2 = build_relayed_ogm_wire_frame(2, 2, 255, 1);
    let keepalive_via_2 = build_keepalive_wire_frame(2);

    let a = harness.get_machine_mut("a");
    // Two alternate OGM paths to the same destination, via different
    // neighbors on different interfaces.
    a.receive_with_metrics(Duration::ZERO, 0, &ogm_via_2, LinkMetrics::default());
    a.receive_with_metrics(Duration::ZERO, 1, &ogm_via_3, LinkMetrics::default());
    a.receive_with_metrics(Duration::ZERO, 0, &ogm_from_2, LinkMetrics::default());
    // Neighbor 2 sends two keep-alives a second apart, teaching a 1s cadence.
    a.receive_with_metrics(Duration::ZERO, 0, &keepalive_via_2, LinkMetrics::default());
    a.receive_with_metrics(
        Duration::from_secs(1),
        0,
        &keepalive_via_2,
        LinkMetrics::default(),
    );

    // Before any miss, the higher-TQ path via neighbor 2 wins.
    let (next_hop, _) = a.router().resolve_route(Duration::from_secs(1), mac(100));
    assert_eq!(
        next_hop,
        mac(2),
        "higher-TQ path should win before any miss"
    );

    // Advance past neighbor 2's keep-alive budget (3 * 1s = 3s since t=1) but
    // nowhere near OGM staleness (6 * ~1s seed = ~6s since t=0 for a fresh
    // path, and this OGM path was never refreshed again either way — the
    // point is the keep-alive-driven switch happens first).
    let t = Duration::from_secs(5);
    let (next_hop, _) = a.router().resolve_route(t, mac(100));
    assert_eq!(
        next_hop,
        mac(3),
        "a missed keep-alive must switch the route to the live alternate"
    );

    // The switch is driven by the keep-alive overlay, not eviction: node 2's
    // path is still present in the table (deprioritized, not gone).
    assert!(
        a.router()
            .originator_table()
            .find(|r| r.neighbor_ident == mac(100))
            .is_some_and(|r| r.paths.iter().any(|p| p.neighbor_ident == mac(2))),
        "the missed-keepalive path must still exist, just deprioritized"
    );
}

/// A triangle topology (a-b, b-c, a-c): `a` learns `c` two ways — directly
/// (higher TQ, one hop) and relayed through `b` (lower TQ, two hops). `c`'s
/// direct link to `a` has a real, config-armed keep-alive schedule; `b`'s
/// does not. Unlike [`keepalive_miss_switches_route_before_ogm_staleness_would`]
/// (which hand-crafts wire frames and calls `resolve_route` directly), this
/// drives `c`'s *actual* `TestRouter::poll_due_keepalive` — the production
/// per-interface keep-alive tick — so the heartbeat is a genuine
/// `Driver`-produced, `Switch`-delivered frame, not a fixture. Once `c`
/// stops ticking its keep-alive (while its OGM Trickle schedule, and thus
/// the direct path's OGM freshness, keeps running normally), `a`'s route to
/// `c` must switch to the relayed path through `b`.
#[test]
fn real_keepalive_tick_switches_route_when_it_stops() {
    setup();
    let i_min = Duration::from_millis(100);
    let i_max = Duration::from_millis(200);

    let mut config = TestConfig::default();
    for name in ["ab", "bc", "ac"] {
        config.switches.push(TestSwitchConfig::shared(name));
    }
    let link = |switch_name: &str| LinkConfig {
        name: None,
        transport: LinkTransport::Test {
            switch_name: switch_name.into(),
        },
        ogm: TrickleConfig {
            i_min_ms: i_min.as_millis() as u64,
            i_max_ms: i_max.as_millis() as u64,
        },
        features: LinkFeatures::default(),
    };
    config.machines.push(TestMachineConfig {
        name: "a".into(),
        wayfinder: Config {
            links: vec![link("ab"), link("ac")],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "b".into(),
        wayfinder: Config {
            links: vec![link("ab"), link("bc")],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "c".into(),
        wayfinder: Config {
            links: vec![link("ac"), link("bc")],
            ..Default::default()
        },
    });
    let mut harness = config.validate().unwrap();

    // Arm a real keep-alive schedule on `c`'s interface 0 (the `ac` link).
    // The declarative `TestConfig`/`MachineSpec` wiring doesn't thread
    // `tx_keepalive` through yet (a harness gap, not a production one — the
    // real drivers arm it at construction, see `Driver::new`), so wire it
    // directly onto the already-built router.
    let keepalive_interval = Duration::from_millis(150);
    harness
        .get_machine_mut("c")
        .router_mut()
        .configure_interface_keepalive(0, Some(keepalive_interval), Duration::ZERO);

    // Converge the mesh over the real Trickle schedule so `a` learns both
    // the direct path to `c` and the relayed one through `b`.
    harness.advance_trickle(Duration::from_secs(2));

    let dest = harness.get_machine("c").ident;
    let b_ident = harness.get_machine("b").ident;

    // Count genuine keep-alive frames hitting the wire, so the test proves
    // real transmissions occurred rather than only checking the eventual
    // routing effect.
    let ka_counter = Arc::new(AtomicUsize::new(0));
    for switch in harness.switches.values_mut() {
        for port in switch.port_ids() {
            let ka_counter = ka_counter.clone();
            switch
                .add_tap(
                    port,
                    TapConfig::new(move |meta| {
                        if meta.direction == Direction::ToSwitch
                            && meta.data.len() > 14
                            && meta.data[12..14] == DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes()
                            && meta.data[14] == BatmanPacketType::Keepalive.as_u8()
                        {
                            ka_counter.fetch_add(1, Ordering::Relaxed);
                        }
                        true
                    }),
                )
                .unwrap();
        }
    }

    // Two real keep-alive ticks from `c`, `keepalive_interval` apart, teach
    // `a` the learned cadence — delivered through the actual `ac` switch.
    for _ in 0..2u32 {
        harness.clock += keepalive_interval;
        let t = harness.clock;
        harness.get_machine_mut("c").poll_due_keepalive(t);
        harness.tick();
    }
    assert_eq!(
        ka_counter.load(Ordering::Relaxed),
        2,
        "both keep-alive ticks must have produced a real, wire-delivered frame"
    );

    let (next_hop, _) = harness
        .get_machine("a")
        .router()
        .resolve_route(harness.clock, dest);
    assert_eq!(next_hop, dest, "before any miss, the direct path wins");

    // `c` stops ticking its keep-alive, but keeps converging normally over
    // Trickle — the direct path's OGM freshness alone must not save it.
    harness.advance_trickle(harness.clock + keepalive_interval * 5);

    let (next_hop, _) = harness
        .get_machine("a")
        .router()
        .resolve_route(harness.clock, dest);
    assert_eq!(
        next_hop, b_ident,
        "a missed keep-alive must switch the route to the relayed path, \
         even though the direct link's OGM path is still fresh"
    );
}

/// The default `sim/topology.py` wiring as a test harness: a 4-node diamond
/// (d1..d4) bridged at d4–m1 to a 5-node complete graph (m1..m5), every edge its
/// own point-to-point link.  Each link's OGM backoff uses a 1 s floor and the
/// given `i_max_ms` ceiling (a small ceiling keeps the settling test fast while
/// preserving the per-interface Trickle dynamics).
fn diamond_plus_k5(i_max_ms: u64) -> TestHarness {
    const EDGES: &[(&str, &str)] = &[
        // diamond
        ("d1", "d2"),
        ("d1", "d3"),
        ("d2", "d4"),
        ("d3", "d4"),
        // bridge
        ("d4", "m1"),
        // K5 on m1..m5
        ("m1", "m2"),
        ("m1", "m3"),
        ("m1", "m4"),
        ("m1", "m5"),
        ("m2", "m3"),
        ("m2", "m4"),
        ("m2", "m5"),
        ("m3", "m4"),
        ("m3", "m5"),
        ("m4", "m5"),
    ];
    const NODES: &[&str] = &["d1", "d2", "d3", "d4", "m1", "m2", "m3", "m4", "m5"];

    let mut config = TestConfig::default();
    for (a, b) in EDGES {
        config
            .switches
            .push(TestSwitchConfig::shared(format!("{a}_{b}")));
    }
    for node in NODES {
        let links: Vec<LinkConfig> = EDGES
            .iter()
            .filter(|(a, b)| a == node || b == node)
            .map(|(a, b)| LinkConfig {
                name: None,
                transport: LinkTransport::Test {
                    switch_name: format!("{a}_{b}"),
                },
                ogm: TrickleConfig {
                    i_min_ms: 1000,
                    i_max_ms,
                },
                features: LinkFeatures::default(),
            })
            .collect();
        config.machines.push(TestMachineConfig {
            name: (*node).into(),
            wayfinder: Config {
                links,
                ..Default::default()
            },
        });
    }
    config.validate().unwrap()
}

/// **Whole-mesh convergence over the production per-interface Trickle path.**
/// With a fixed topology and no loss, the `sim/topology.py` mesh must quieten:
/// after a warmup every node continuously knows every other (no spurious
/// purge/flap), and every interface's Trickle backoff climbs to and stays at
/// `i_max` (steady-state calm).  Driven by [`TestHarness::run_trickle`], so it
/// exercises the real `poll_due_ogms` emission and flooding — the dynamics the
/// lockstep `converge` path cannot reach.  Regression for the mesh that never
/// settled (OGMs pinned near `i_min`, routes flapping forever).
///
/// Runs on tokio's **paused** clock (`start_paused`): the harness advances its
/// own virtual `clock` event-to-event, and the only real timers are the `1 ns`
/// non-blocking poll timeouts inside `settle`/`tick`, which a paused runtime
/// auto-advances instantly instead of waiting out tokio's ~1 ms timer
/// granularity — so the run is bounded by work done, not by simulated seconds.
#[test]
fn diamond_plus_k5_settles_to_i_max() {
    setup();
    let i_max = Duration::from_secs(8);
    let mut harness = diamond_plus_k5(8_000);

    // Warm up well past the time the backoff needs to climb 1→2→4→8 s, then run
    // a further window over which the mesh must stay both complete and calm.
    let min_full = harness.run_trickle(Duration::from_secs(40), Duration::from_secs(80));

    assert_eq!(
        min_full, 8,
        "a node lost originators after warmup — routes flapping, mesh never converged"
    );

    for (name, machine) in harness.machines.iter() {
        for e in machine.router().ogm_schedule() {
            assert_eq!(
                e.current_interval, i_max,
                "node {name} iface {} never backed off to i_max (stuck at {:?}) — mesh not calm",
                e.iface_idx, e.current_interval
            );
        }
    }
}

/// Re-encode a genuinely `OgmAuth::augment_ogm`-produced (legacy `Cert`
/// -bearing) OGM into its lazy-cert-distribution wire form: the same
/// `OgmSig` bytes (the signature covers the full cert regardless of which
/// TVLV shape carries it — see `auth.rs::signed_message`) but with the
/// `Cert` record replaced by an 8-byte `CertFp` — matching what
/// `OgmAuth::augment_ogm_lazy` emits directly; built by post-processing
/// genuine `augment_ogm` output (via the real `MembershipCert::fingerprint()`)
/// so none of the actual signing logic is duplicated in this test helper.
fn to_lazy_ogm(buf: &[u8], hdr_len: usize) -> Vec<u8> {
    let tail = &buf[hdr_len..];
    let cert_bytes = find_tvlv(tail, TvlvType::Cert).expect("augmented OGM carries a cert");
    let sig_bytes = find_tvlv(tail, TvlvType::OgmSig).expect("augmented OGM carries a signature");
    let cert = wayfinder_auth::MembershipCert::from_bytes(cert_bytes).expect("valid cert bytes");
    let fp = cert.fingerprint();

    let mut out = buf[..hdr_len].to_vec();
    let tvlv_hdr_size = core::mem::size_of::<BatmanTvlvHdr>();
    let mut tvlv_len = 0u16;

    let fp_hdr = BatmanTvlvHdr {
        tvlv_type: TvlvType::CertFp.as_u8(),
        version: 1,
        len: (fp.len() as u16).to_be(),
    };
    out.extend_from_slice(fp_hdr.as_bytes());
    out.extend_from_slice(&fp);
    tvlv_len += (tvlv_hdr_size + fp.len()) as u16;

    let sig_hdr = BatmanTvlvHdr {
        tvlv_type: TvlvType::OgmSig.as_u8(),
        version: 1,
        len: (sig_bytes.len() as u16).to_be(),
    };
    out.extend_from_slice(sig_hdr.as_bytes());
    out.extend_from_slice(sig_bytes);
    tvlv_len += (tvlv_hdr_size + sig_bytes.len()) as u16;

    let tvlv_len_off = hdr_len - 2;
    out[tvlv_len_off..tvlv_len_off + 2].copy_from_slice(&tvlv_len.to_be_bytes());
    out
}

/// A sequence number the relay X will read as genuinely A's next one: just past
/// the high-water X already holds for A.
///
/// A far-ahead literal would land outside [`batman::OGM_SEQNO_WINDOW`] and be
/// treated as evidence against the *high-water* rather than as a fresh OGM, so
/// X would not re-flood it — see `docs/design/implemented/09-mesh-auth-gaps.md`
/// §8.11 for why a leap a live originator could not have made is refused.
fn next_seqno_after_relay(harness: &TestHarness, relay: &str, orig: Mac) -> u32 {
    harness
        .get_machine(relay)
        .router()
        .originator_table()
        .find(|r| r.neighbor_ident == orig)
        .map_or(0, |r| r.last_seqno)
        + 1
}

/// The requester-side round trip end to end, over a real multi-hop mesh
/// (machine1 = A, machine2 = X the relay, machine3 = B the requester): B has
/// no route to A (per design doc §3.2), hears a fingerprint-only OGM
/// relayed via X, and must fetch A's cert before it can verify — seeding the
/// `CertReq`'s first hop with X, exactly as `verify_ogm`'s `NeedCert`
/// requires. Genuine router/engine code drives the `NeedCert` detection,
/// `CertReq` origination + multi-hop relay through X, and `CertReply`
/// ingestion + caching (all real requester-side logic); only *A's answer* is
/// hand-injected here, isolating requester-side correctness from responder-
/// side correctness — the latter is exercised for real (a genuine responder,
/// no stand-in) by `cert_fetch_round_trip_with_real_responder` below.
#[test]
fn cert_fetch_round_trip_resolves_via_seeded_first_hop() {
    setup();
    let mut harness = line_of_three();

    // Bootstrap routing with everybody open (no auth), so machine2 has real
    // routes to both machine1 and machine3 before any auth state exists —
    // otherwise the CertReq/CertReply relay below would have nothing to
    // route on.
    harness.poll_due(Duration::from_secs(1));
    for _ in 0..5 {
        harness.tick();
    }
    for router in harness.machines.values() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    let m1 = harness.get_machine("machine1").ident; // A
    let m2 = harness.get_machine("machine2").ident; // X, the relay
    let m3 = harness.get_machine("machine3").ident; // B, the requester

    let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);

    // A's identity: a real cert, but deliberately never installed on
    // machine1's router — machine1 stays open the whole test, isolating
    // requester-side (B's) correctness from responder-side correctness.
    // Only A's identity/signature is needed to build the frames a real
    // lazy-cert-distribution-enabled node would send/receive.
    // The machine's own key, not a fresh one: a certificate names the address
    // its key derives, so a cert that is to bind `m1` can only be minted under
    // machine1's identity.
    let a_kp = crate::driver::machine_keypair(0);
    debug_assert_eq!(a_kp.derived_mac(), m1);
    let a_cert = authority.issue_cert(m1, a_kp.ed_pubkey(), a_kp.x_pubkey(), 0, 1_000_000);
    let mut a_auth = wayfinder::auth::OgmAuth::new(a_kp, a_cert, authority.trust_anchor());
    a_auth.set_time(1_000);

    // B is a real authenticated node: this is what actually runs the
    // requester logic under test. `set_auth` resets machine3's own learned
    // routing state, so it genuinely has no route to A afterward.
    enable_auth(harness.get_machine_mut("machine3"), &authority, 2);

    // Tap switch1 (A<->X) to observe the real CertReq X relays onward.
    let cert_req_seen = Arc::new(AtomicUsize::new(0));
    {
        let switch1 = harness.switches.get_mut("switch1").unwrap();
        for port in switch1.port_ids() {
            let cert_req_seen = cert_req_seen.clone();
            switch1
                .add_tap(
                    port,
                    TapConfig::new(move |meta| {
                        if meta.direction == Direction::ToSwitch
                            && meta.data.len() > 14
                            && meta.data[12..14] == DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes()
                            && meta.data[14] == BatmanPacketType::CertReq.as_u8()
                        {
                            cert_req_seen.fetch_add(1, Ordering::Relaxed);
                        }
                        true
                    }),
                )
                .unwrap();
        }
    }

    // Build a real signed OGM from A via `augment_ogm`, then re-encode it as
    // a fingerprint-only (lazy) OGM, matching what `augment_ogm_lazy` emits.
    let ogm_hdr_len = core::mem::size_of::<BatmanOgmPacket>();
    let mut ogm_buf = vec![0u8; 512];
    let ogm = BatmanOgmPacket {
        packet_type: BatmanPacketType::Ogm.as_u8(),
        version: BATMAN_VERSION,
        ttl: 50,
        flags: 0,
        seqno: next_seqno_after_relay(&harness, "machine2", m1).to_be(),
        orig: m1,
        reserved: 0,
        tq: 255,
        tvlv_len: 0,
    };
    ogm_buf[..ogm_hdr_len].copy_from_slice(ogm.as_bytes());
    let ogm_len = a_auth.augment_ogm(&mut ogm_buf, ogm_hdr_len).unwrap();
    let lazy_ogm = to_lazy_ogm(&ogm_buf[..ogm_len], ogm_hdr_len);

    // Inject it as A's own transmission on switch1, spoofing A's identity —
    // safe *only* because nothing else in this test needs the switch to
    // route traffic to a live A afterward (A never responds for real; see
    // below). X's genuine engine then re-floods it onward to switch2 under
    // X's own real port, so B hears it exactly as if relayed by X, with no
    // corruption of switch2's learned mapping for X. (A raw port spoofing an
    // in-mesh node's identity on its *own* switch corrupts that switch's
    // learned Ident->Port entry for the real node — discovered by an earlier
    // version of this test that spoofed X's identity directly on switch2 and
    // silently broke B's subsequent CertReq delivery to X.)
    let (raw_port, _port_id) = harness.add_switch_port("switch1");
    let wire = build_frame(m1, Mac::BROADCAST, DEFAULT_BATMAN_ETHER_TYPE, &lazy_ogm);
    raw_port.egress.try_send(wire).unwrap();

    for _ in 0..8 {
        harness.tick();
    }

    assert_eq!(
        cert_req_seen.load(Ordering::Relaxed),
        1,
        "B's CertReq, seeded via X as its first hop, must reach and cross switch1 toward A"
    );
    assert!(
        harness
            .get_machine("machine3")
            .router()
            .auth()
            .unwrap()
            .neighbor_cert(m1)
            .is_none(),
        "no reply yet: A is open in this test (no set_auth), so nothing has answered it"
    );

    // Stand in for A's real responder (deliberately not installed on A in
    // this test, to isolate B's requester-side logic — see
    // `cert_fetch_round_trip_with_real_responder` for the real responder
    // exercised end to end): reply with A's cert, injected at switch1 and
    // relayed for real through X to B.
    let reply_hdr = BatmanCertReplyPacket {
        packet_type: BatmanPacketType::CertReply.as_u8(),
        version: BATMAN_VERSION,
        ttl: 50,
        dest: m3,
    };
    let mut reply_payload = reply_hdr.as_bytes().to_vec();
    reply_payload.extend_from_slice(a_auth.own_cert().as_bytes());
    let reply_wire = build_frame(m1, m2, DEFAULT_BATMAN_ETHER_TYPE, &reply_payload);
    raw_port.egress.try_send(reply_wire).unwrap();

    for _ in 0..8 {
        harness.tick();
    }

    let (cached_cert, cached_fp) = harness
        .get_machine("machine3")
        .router()
        .auth()
        .unwrap()
        .neighbor_cert(m1)
        .expect("A's cert must be cached once the reply arrives");
    assert_eq!(cached_cert.as_bytes(), a_auth.own_cert().as_bytes());
    assert_eq!(cached_fp, a_auth.own_cert().fingerprint());

    // A later fingerprint-only OGM from A now verifies from the cache: no
    // second CertReq is sent.
    let mut ogm_buf2 = vec![0u8; 512];
    let ogm2 = BatmanOgmPacket {
        seqno: next_seqno_after_relay(&harness, "machine2", m1).to_be(),
        ..ogm
    };
    ogm_buf2[..ogm_hdr_len].copy_from_slice(ogm2.as_bytes());
    let ogm2_len = a_auth.augment_ogm(&mut ogm_buf2, ogm_hdr_len).unwrap();
    let lazy_ogm2 = to_lazy_ogm(&ogm_buf2[..ogm2_len], ogm_hdr_len);
    let wire2 = build_frame(m1, Mac::BROADCAST, DEFAULT_BATMAN_ETHER_TYPE, &lazy_ogm2);
    raw_port.egress.try_send(wire2).unwrap();

    for _ in 0..8 {
        harness.tick();
    }

    assert_eq!(
        cert_req_seen.load(Ordering::Relaxed),
        1,
        "a subsequent OGM with the same fingerprint must verify from cache, not re-fetch"
    );
}

/// The full round trip with a *real* responder (Phase 4) on A: B's `NeedCert`
/// detection, `CertReq` origination, and multi-hop relay through X are
/// genuine (as in the requester-only test above), and this time so is A's
/// answer — no hand-injected `CertReply` standing in for it. A's route to B
/// is primed directly (bypassing Trickle timing, which is orthogonal to what
/// this test checks) so the reply path is exercised over the real wire
/// without fighting two independent adaptive OGM schedules.
#[test]
fn cert_fetch_round_trip_with_real_responder() {
    setup();
    let mut harness = line_of_three();

    harness.poll_due(Duration::from_secs(1));
    for _ in 0..5 {
        harness.tick();
    }
    for router in harness.machines.values() {
        assert_eq!(router.router().originator_table().count(), 2);
    }

    let m1 = harness.get_machine("machine1").ident; // A, the real responder
    let m3 = harness.get_machine("machine3").ident; // B, the requester

    let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
    enable_auth(harness.get_machine_mut("machine1"), &authority, 0);
    enable_auth(harness.get_machine_mut("machine3"), &authority, 2);

    // Prime A's route + cert cache for B directly (bypassing Trickle
    // timing): a signed OGM from B, fed straight to A's router. This node
    // never leaves this process, so nothing about the fetch mechanism under
    // test is bypassed — only the unrelated question of when Trickle would
    // have delivered this on its own.
    let b_ogm_hdr_len = core::mem::size_of::<BatmanOgmPacket>();
    let mut b_ogm_buf = vec![0u8; 512];
    let b_ogm = BatmanOgmPacket {
        packet_type: BatmanPacketType::Ogm.as_u8(),
        version: BATMAN_VERSION,
        ttl: 50,
        flags: 0,
        seqno: 1u32.to_be(),
        orig: m3,
        reserved: 0,
        tq: 255,
        tvlv_len: 0,
    };
    b_ogm_buf[..b_ogm_hdr_len].copy_from_slice(b_ogm.as_bytes());
    let b_ogm_len = {
        let b_auth = harness
            .get_machine_mut("machine3")
            .router_mut()
            .auth_mut()
            .unwrap();
        b_auth.augment_ogm(&mut b_ogm_buf, b_ogm_hdr_len).unwrap()
    };
    harness.get_machine_mut("machine1").receive_with_metrics(
        Duration::from_secs(1),
        0,
        &build_frame(
            m3,
            Mac::BROADCAST,
            DEFAULT_BATMAN_ETHER_TYPE,
            &b_ogm_buf[..b_ogm_len],
        ),
        LinkMetrics::default(),
    );
    assert!(
        harness
            .get_machine("machine1")
            .router()
            .auth()
            .unwrap()
            .neighbor_cert(m3)
            .is_some(),
        "A must have B's cert + a route to B primed"
    );

    // Build A's lazy (CertFp) OGM from its real installed auth state, and
    // inject it via switch1 as if A had sent it — B has never heard A
    // before, so this is a cold miss.
    let ogm_hdr_len = core::mem::size_of::<BatmanOgmPacket>();
    let mut ogm_buf = vec![0u8; 512];
    let ogm = BatmanOgmPacket {
        packet_type: BatmanPacketType::Ogm.as_u8(),
        version: BATMAN_VERSION,
        ttl: 50,
        flags: 0,
        seqno: next_seqno_after_relay(&harness, "machine2", m1).to_be(),
        orig: m1,
        reserved: 0,
        tq: 255,
        tvlv_len: 0,
    };
    ogm_buf[..ogm_hdr_len].copy_from_slice(ogm.as_bytes());
    let ogm_len = {
        let a_auth = harness
            .get_machine_mut("machine1")
            .router_mut()
            .auth_mut()
            .unwrap();
        a_auth.augment_ogm(&mut ogm_buf, ogm_hdr_len).unwrap()
    };
    let lazy_ogm = to_lazy_ogm(&ogm_buf[..ogm_len], ogm_hdr_len);

    let (raw_port, _port_id) = harness.add_switch_port("switch1");
    let wire = build_frame(m1, Mac::BROADCAST, DEFAULT_BATMAN_ETHER_TYPE, &lazy_ogm);
    raw_port.egress.try_send(wire).unwrap();

    for _ in 0..8 {
        harness.tick();
    }

    let (cached_cert, cached_fp) = harness
        .get_machine("machine3")
        .router()
        .auth()
        .unwrap()
        .neighbor_cert(m1)
        .expect("A's cert must be cached: A answered its own CertReq for real");
    let a_own_cert = *harness
        .get_machine("machine1")
        .router()
        .auth()
        .unwrap()
        .own_cert();
    assert_eq!(cached_cert.as_bytes(), a_own_cert.as_bytes());
    assert_eq!(cached_fp, a_own_cert.fingerprint());
}

/// Phase 5 acceptance criterion: two *fresh* auth nodes, both with
/// `lazy_cert_distribution` on from their very first OGM, reach mutual
/// verified routing with zero full certs ever appearing on the wire — only
/// fingerprints. Both sides start simultaneously cold (neither has the
/// other's cert, mirroring a freshly-deployed mesh), so this also exercises
/// the doc's cold-start argument for a direct-neighbor pair: A's reply to
/// B's `CertReq` parks (A has no route to B yet) until A verifies B's own
/// next OGM — resolvable specifically because verifying a `CertReq`
/// caches the requester's cert too (§5.4), so that OGM can be checked as
/// soon as it arrives — which requires more than one Trickle round, hence
/// driving several here.
#[test]
fn two_fresh_lazy_nodes_converge_with_zero_certs_on_the_wire() {
    setup();
    let mut harness = simple_pair();

    let m1 = harness.get_machine("machine1").ident;
    let m2 = harness.get_machine("machine2").ident;
    let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
    enable_auth(harness.get_machine_mut("machine1"), &authority, 0);
    enable_auth(harness.get_machine_mut("machine2"), &authority, 1);
    harness
        .get_machine_mut("machine1")
        .router_mut()
        .set_lazy_cert_distribution(true);
    harness
        .get_machine_mut("machine2")
        .router_mut()
        .set_lazy_cert_distribution(true);

    // Tap switch1 for every OGM crossing it, checking its TVLV tail never
    // carries a full `Cert` record, only `CertFp`.
    let cert_seen = Arc::new(AtomicUsize::new(0));
    let certfp_seen = Arc::new(AtomicUsize::new(0));
    {
        let ogm_hdr_len = core::mem::size_of::<BatmanOgmPacket>();
        let switch1 = harness.switches.get_mut("switch1").unwrap();
        for port in switch1.port_ids() {
            let cert_seen = cert_seen.clone();
            let certfp_seen = certfp_seen.clone();
            switch1
                .add_tap(
                    port,
                    TapConfig::new(move |meta| {
                        if meta.direction == Direction::ToSwitch && is_ogm_frame(meta.data) {
                            let tail = &meta.data[14 + ogm_hdr_len..];
                            if find_tvlv(tail, TvlvType::Cert).is_some() {
                                cert_seen.fetch_add(1, Ordering::Relaxed);
                            }
                            if find_tvlv(tail, TvlvType::CertFp).is_some() {
                                certfp_seen.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        true
                    }),
                )
                .unwrap();
        }
    }

    // Drive several Trickle rounds: round 1 triggers the mutual NeedCert +
    // CertReq exchange (each side's reply parks, no route yet); a later
    // round's OGM — now verifiable from the cert cached off the CertReq
    // itself — installs the route and flushes the parked reply.
    for round in 1..=6u64 {
        converge_at(&mut harness, Duration::from_secs(round));
    }

    for router in harness.machines.values() {
        assert_eq!(
            router.router().originator_table().count(),
            1,
            "both nodes must reach mutual verified routing"
        );
    }
    assert_eq!(
        cert_seen.load(Ordering::Relaxed),
        0,
        "zero full certs must ever appear on the wire"
    );
    assert!(
        certfp_seen.load(Ordering::Relaxed) > 0,
        "OGMs must carry fingerprints instead"
    );
    assert!(
        harness
            .get_machine("machine1")
            .router()
            .auth()
            .unwrap()
            .neighbor_cert(m2)
            .is_some(),
        "machine1 must have fetched machine2's cert"
    );
    assert!(
        harness
            .get_machine("machine2")
            .router()
            .auth()
            .unwrap()
            .neighbor_cert(m1)
            .is_some(),
        "machine2 must have fetched machine1's cert"
    );
}

// ---------------------------------------------------------------------------
// Reachability probing (`ping`) across a real multi-node fabric.
//
// The unit tests in `libs/wayfinder` prove a probe is built, answered and
// credited correctly against hand-crafted frames. What only a fabric can prove
// is the part that matters to an operator: that a probe survives being *routed*
// — relayed by an intermediate node, answered by a target that had to find its
// own way back, and credited with hop counts that describe the path it actually
// took.
// ---------------------------------------------------------------------------

/// A chain `a — b — c`: `a` and `c` share no link, so anything between them is
/// relayed by `b`.
fn ping_chain() -> TestHarness {
    let mut config = TestConfig::default();
    for name in ["ab", "bc"] {
        config.switches.push(TestSwitchConfig::shared(name));
    }
    let link = |switch_name: &str| LinkConfig {
        name: None,
        transport: LinkTransport::Test {
            switch_name: switch_name.into(),
        },
        ogm: TrickleConfig {
            i_min_ms: 100,
            i_max_ms: 200,
        },
        features: LinkFeatures::default(),
    };
    config.machines.push(TestMachineConfig {
        name: "a".into(),
        wayfinder: Config {
            links: vec![link("ab")],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "b".into(),
        wayfinder: Config {
            links: vec![link("ab"), link("bc")],
            ..Default::default()
        },
    });
    config.machines.push(TestMachineConfig {
        name: "c".into(),
        wayfinder: Config {
            links: vec![link("bc")],
            ..Default::default()
        },
    });
    config.validate().unwrap()
}

/// The whole feature, end to end over a real fabric: `a` pings `c` two hops
/// away, every probe comes back, and the hop counts describe the path it took.
///
/// The hop assertion is the load-bearing one. A probe that reported `0/0` would
/// still "work" — the round trip happened — while telling an operator that a
/// relayed path is direct, which is precisely the thing they would be running
/// this to find out.
#[test]
fn a_probe_reaches_a_node_two_hops_away_and_reports_the_path_it_took() {
    setup();
    let mut harness = ping_chain();
    harness.advance_trickle(Duration::from_secs(2));

    let target = harness.get_machine("c").ident;
    let now = harness.clock;
    let (session_seq, _) = harness.get_machine_mut("a").router_mut().start_ping(
        now,
        target,
        3,
        Duration::from_millis(100),
        Duration::from_secs(5),
        8,
    );

    harness.advance_trickle(now + Duration::from_secs(2));

    let session = harness
        .get_machine("a")
        .router()
        .ping_session(session_seq)
        .expect("the session answers the handle that started it");

    assert_eq!(session.sent(), 3, "every probe asked for went out");
    assert_eq!(session.received(), 3, "and every one came back");
    assert_eq!(session.lost(), 0);
    assert!(!session.active(), "the session finished");

    for probe in session.probes() {
        assert_eq!(probe.state, ProbeState::Replied);
        assert_eq!(probe.fwd_hops, 1, "one relay (b) on the way out");
        assert_eq!(probe.rev_hops, 1, "and one on the way back");
    }
}

/// A neighbour one hop away reports zero relays — the number that makes the
/// count above mean something rather than being an off-by-one nobody could see.
#[test]
fn a_probe_to_a_direct_neighbour_reports_no_relays() {
    setup();
    let mut harness = ping_chain();
    harness.advance_trickle(Duration::from_secs(2));

    let target = harness.get_machine("b").ident;
    let now = harness.clock;
    let (session_seq, _) = harness.get_machine_mut("a").router_mut().start_ping(
        now,
        target,
        1,
        Duration::from_millis(100),
        Duration::from_secs(5),
        0,
    );
    harness.advance_trickle(now + Duration::from_secs(1));

    let session = harness
        .get_machine("a")
        .router()
        .ping_session(session_seq)
        .expect("session");
    assert_eq!(session.received(), 1);
    let probe = session.probes().next().expect("one row");
    assert_eq!((probe.fwd_hops, probe.rev_hops), (0, 0));
}

/// A destination nothing has ever announced is *tried*, addressed directly,
/// and times out — it is not refused up front.
///
/// That is `resolve_next_hop`'s deliberate fallback rather than an oversight,
/// and worth pinning: a MAC absent from the originator table may be a neighbour
/// whose first OGM has not arrived yet, and refusing to probe it would make
/// `ping` unable to answer the question it is best at — "is that thing on the
/// wire?". `ProbeState::NoRoute` is the *narrower* case, a destination the
/// table knows about and has no live path to.
#[test]
fn a_probe_to_a_never_announced_destination_is_tried_and_times_out() {
    setup();
    let mut harness = ping_chain();
    harness.advance_trickle(Duration::from_secs(2));

    let now = harness.clock;
    let (session_seq, _) = harness.get_machine_mut("a").router_mut().start_ping(
        now,
        mac(200),
        2,
        Duration::from_millis(100),
        Duration::from_millis(400),
        0,
    );
    harness.advance_trickle(now + Duration::from_secs(2));

    let session = harness
        .get_machine("a")
        .router()
        .ping_session(session_seq)
        .expect("session");
    assert_eq!(session.sent(), 2, "both probes were attempted");
    assert_eq!(session.received(), 0);
    assert_eq!(session.lost(), 2);
    assert!(
        session.probes().all(|p| p.state == ProbeState::TimedOut),
        "attempted-and-unanswered, not refused"
    );
    assert!(!session.active());
}

/// A target that goes away mid-session reads as loss rather than as a stall:
/// the probes go out, nothing answers, and the session finishes.
#[test]
fn probes_to_a_departed_node_time_out() {
    setup();
    let mut harness = ping_chain();
    harness.advance_trickle(Duration::from_secs(2));

    let target = harness.get_machine("c").ident;
    // `c` stops taking part entirely — the frames still reach its port, and it
    // simply never answers.
    harness.get_machine_mut("c").router_mut().set_link_features(
        0,
        LinkFeatures {
            rx_data: false,
            ..Default::default()
        },
    );

    let now = harness.clock;
    let (session_seq, _) = harness.get_machine_mut("a").router_mut().start_ping(
        now,
        target,
        2,
        Duration::from_millis(100),
        Duration::from_millis(500),
        0,
    );
    harness.advance_trickle(now + Duration::from_secs(2));

    let session = harness
        .get_machine("a")
        .router()
        .ping_session(session_seq)
        .expect("session");
    assert_eq!(session.received(), 0);
    assert_eq!(session.lost(), 2, "both probes counted as lost");
    assert!(!session.active(), "and the session stopped waiting");
}

/// Starting a second session displaces the first, and the first's handle stops
/// resolving — the property the whole handle mechanism exists for. Without it a
/// client polling a displaced session would silently report another target's
/// round trips as its own.
#[test]
fn a_second_session_displaces_the_first_and_its_handle_stops_resolving() {
    setup();
    let mut harness = ping_chain();
    harness.advance_trickle(Duration::from_secs(2));

    let b = harness.get_machine("b").ident;
    let c = harness.get_machine("c").ident;
    let now = harness.clock;

    let (first, _) = harness.get_machine_mut("a").router_mut().start_ping(
        now,
        c,
        5,
        Duration::from_millis(100),
        Duration::from_secs(5),
        0,
    );
    harness.advance_trickle(now + Duration::from_millis(300));

    let now = harness.clock;
    let (second, _) = harness.get_machine_mut("a").router_mut().start_ping(
        now,
        b,
        1,
        Duration::from_millis(100),
        Duration::from_secs(5),
        0,
    );

    let router = harness.get_machine("a").router();
    assert!(router.ping_session(first).is_none(), "the first is gone");
    assert_eq!(
        router.ping_session(second).map(|s| s.target()),
        Some(b),
        "and the handle that answers is the new one's"
    );
}

// ── design 17: multicast across a wired/radio boundary ──────────────────────

/// A multicast group MAC (`01:00:5e:00:00:NN`).
fn mcast_group(n: u8) -> Mac {
    Mac([0x01, 0x00, 0x5e, 0x00, 0x00, n])
}

/// True if `frame` is an on-the-wire BATMAN data-plane multicast frame.
///
/// One tag covers both shapes: design 17 changes `Mcast`'s *layout* rather than
/// adding a sub-type, so this counts transmissions carrying the group's traffic
/// before and after without caring which layout is on the wire — which is what
/// makes the before/after comparison below meaningful.
fn is_mcast_frame(frame: &[u8]) -> bool {
    frame.len() > 14
        && frame[12..14] == DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes()
        && frame[14] == BatmanPacketType::Mcast.as_u8()
}

/// Count multicast data frames entering one named switch's fabric, one count
/// per transmission (`Direction::ToSwitch`), so a frame that fans out to four
/// listeners on a shared medium still counts once — which is the entire
/// quantity design 17 is about.
fn count_mcast_on(harness: &mut TestHarness, switch: &str) -> Arc<AtomicUsize> {
    let counter = Arc::new(AtomicUsize::new(0));
    let sw = harness
        .switches
        .get_mut(switch)
        .expect("switch exists in this topology");
    for port in sw.port_ids() {
        let counter = counter.clone();
        sw.add_tap(
            port,
            TapConfig::new(move |meta| {
                if meta.direction == Direction::ToSwitch && is_mcast_frame(meta.data) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                // Keep the tap installed for the life of the test.
                true
            }),
        )
        .expect("port accepts a tap");
    }
    counter
}

/// `a —eth— b —radio— {c, d, e, f}`: one wired peer bridging onto a shared
/// radio segment. `a`, `d`, `e` and `f` are in the group; `b` and `c` are not.
fn wired_peer_onto_radio_segment() -> TestHarness {
    let mut config = TestConfig::default();
    config.switches.push(TestSwitchConfig::shared("eth"));
    config.switches.push(TestSwitchConfig::shared("radio"));
    let machine = |name: &str, links: &[&str]| TestMachineConfig {
        name: name.into(),
        wayfinder: Config {
            links: links.iter().map(|s| LinkConfig::test(*s)).collect(),
            ..Default::default()
        },
    };
    config.machines.push(machine("a", &["eth"]));
    config.machines.push(machine("b", &["eth", "radio"]));
    for spoke in ["c", "d", "e", "f"] {
        config.machines.push(machine(spoke, &["radio"]));
    }
    config.validate().unwrap()
}

/// **The topology design 17 exists for.** Three listeners sit behind one relay
/// on a shared radio segment; the sender is on the far side of a wired link.
///
/// ```text
///   a ──eth── b ──radio──┬── c        group: a, d, e, f
///                        ├── d        (b and c are not members)
///                        ├── e
///                        └── f
/// ```
///
/// One multicast frame from `a`'s host must cost **one** transmission on the
/// radio: `b` transmits once and all three listeners hear it. The radio count
/// is the one that matters, because that is the duty-cycle-limited medium.
///
/// `a` sends one frame to `b` listing `[d, e, f]`; `b` finds all three behind
/// one radio interface and transmits once. `c` hears it, is in neither the
/// destination list nor any route it serves, and ignores it — it does not
/// forward, because nothing was routed through it.
///
/// The total is asserted as well as the per-medium counts, because a design can
/// deliver correctly and still cost more than what it replaces: an earlier
/// flood-based revision spent seven transmissions against today's six, and
/// delivery assertions alone sailed straight through it.
///
/// Two different numbers are wrong today, depending on which driver shell runs:
///
/// * Through the **tokio** driver, three on each — `McastPlan::Unicast` builds
///   one `Mcast` per listener and the relay forwards each individually.
/// * Through the **tick** driver this harness uses, *zero*: it measures 0
///   rather than 3 because `queue_local_send` goes straight to `handle_local`,
///   which sends a group MAC down the unicast path, finds no route, and drops
///   it. Multicast planning is reachable only from `plan_host_frame`.
///
/// That second number is why this test is worth having even before the packet
/// exists: it pins a gap in the tick driver that no other test covers.
///
/// The radio assertion is the load-bearing one. The Ethernet count could be
/// argued down to a nicety; three transmissions on a LoRa segment where one
/// would do is the cost this design was written to remove.
///
/// Ignored until design 17 lands, since none of its prerequisites exists yet:
/// the multi-destination `Mcast` layout, multi-frame emission from the engine,
/// and a multicast plan in the tick driver at all.
#[test]
fn one_multicast_frame_crosses_the_wire_and_the_radio_once_each() {
    let group = mcast_group(9);
    let mut h = wired_peer_onto_radio_segment();

    // Everyone but the relay and `c` joins the group, so membership propagates
    // in OGMs and every node's `mcast_members` learns who is interested.
    for member in ["a", "d", "e", "f"] {
        h.machines
            .get_mut(member)
            .expect("machine exists")
            .router_mut()
            .set_local_mcast_groups(Duration::ZERO, &[group]);
    }
    // Converge until the *precondition* holds rather than until a fixed
    // instant. `TestHarness::machines` is a `HashMap`, so `values_mut()` polls
    // the nodes in a per-process order — which changes how many rounds
    // membership takes to propagate, and left this test failing about one run
    // in six on a fixed 30-second budget. Waiting on the state the test
    // actually needs makes it deterministic, and names the missing
    // precondition when it genuinely cannot be reached.
    let mut at = Duration::from_secs(30);
    for _ in 0..10 {
        converge_at(&mut h, at);
        let known = h.machines["a"].router().mcast_targets(group).count();
        let relayed = ["d", "e", "f"].iter().all(|m| {
            let ident = h.machines[*m].ident;
            h.machines["b"]
                .router()
                .resolve_route(at, ident)
                .1
                .is_some()
        });
        if known == 3 && relayed {
            break;
        }
        at += Duration::from_secs(30);
    }
    assert_eq!(
        h.machines["a"].router().mcast_targets(group).count(),
        3,
        "the sender must have learned d, e and f as listeners before it sends"
    );

    let eth = count_mcast_on(&mut h, "eth");
    let radio = count_mcast_on(&mut h, "radio");
    let payload = host_frame(group, Mac([0, 0, 0, 0, 0, 0xaa]), b"multicast payload");
    h.machines
        .get_mut("a")
        .expect("machine a exists")
        .send_local(group, &payload);
    // Converge *forward* of whatever instant the precondition loop reached: a
    // fixed instant would run the virtual clock backwards once that loop
    // needed more than one round.
    h.converge(at + Duration::from_secs(5));

    assert_eq!(
        radio.load(Ordering::Relaxed),
        1,
        "one transmission must serve every listener on the shared radio segment; \
         three means the relay sent one copy per listener"
    );
    // One, not two. `a` is itself a member, but the sender excludes itself from
    // the destination list — its host already has the frame — so nothing is
    // ever addressed back toward the originator. The "relay echoes at its
    // sender" problem belonged to the flood design and does not exist here.
    assert_eq!(
        eth.load(Ordering::Relaxed),
        1,
        "the sender puts one frame on the wire listing all three destinations"
    );

    // The invariant an earlier revision violated: never more transmissions than
    // the per-listener plan this replaces, which costs three on each medium
    // here. Batching only ever merges frames, so this holds by construction —
    // and the flood design held by construction too, right up until its
    // re-broadcasts were counted.
    assert!(
        eth.load(Ordering::Relaxed) + radio.load(Ordering::Relaxed) < 6,
        "this must not cost more transmissions than McastPlan::Unicast does today"
    );

    for member in ["d", "e", "f"] {
        assert!(
            !h.machines[member].local_deliveries().is_empty(),
            "{member} joined the group and must receive the frame"
        );
    }
    assert!(
        h.machines["c"].local_deliveries().is_empty(),
        "c is not in the group and must not be delivered to, even though it \
         hears every frame on the shared radio segment"
    );
    // **The delivered bytes are the frame, not the routing envelope.** The
    // destination list sits between the header and the encapsulated frame, so
    // an `inner_offset` that skips only the fixed header hands the host the
    // listeners' MAC addresses prepended to its payload. Asserting merely that
    // *something* was delivered sails straight past that.
    // `send_local` wraps the caller's bytes in `a`'s own host frame, so that
    // is what every listener must receive — nothing more.
    let sent = host_frame(group, h.machines["a"].ident, &payload);
    for member in ["d", "e", "f"] {
        let delivered = &h.machines[member].local_deliveries()[0];
        assert_eq!(
            delivered.as_slice(),
            sent.as_slice(),
            "{member} must receive the host frame verbatim, with no destination list attached"
        );
    }
}
