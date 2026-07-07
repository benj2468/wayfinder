//! End-to-end tests that drive the real `rylr998::RylrClient` `LinkT`
//! implementation through the real `Driver`/`CentralRouter` stack, instead of
//! the channel-based `Switch` fabric the rest of this crate's tests use.
//!
//! These deliberately bypass [`TestHarness`](crate::driver::TestHarness) and
//! its deterministic virtual-clock tick model: `TestHarness::tick` and
//! `TestRouter::drain_all` both drive interfaces with a single non-blocking
//! poll (a 1ns timeout, or `now_or_never` inside `Driver::process_pending`),
//! which works for immediately-ready-or-empty in-process channels but would
//! almost never observe traffic on a `RylrClient` link, whose bytes move
//! asynchronously through a separately-scheduled background `LoraSwitch` task
//! over a real `tokio::io::duplex`. (`TestRouter::poll_due` isn't
//! non-blocking-poll-based at all — it only emits already-due OGMs via a
//! plain `.await`, it never reads inbound traffic — but it's still the wrong
//! primitive here since it never drives `recv`.) Instead this drives
//! `Driver::run_once` directly — the real event loop, which genuinely
//! `.await`s and reads inbound traffic as one of its select arms.
//!
//! Both nodes' `run_once` are driven concurrently via `tokio::join!`, never
//! `tokio::select!` between the two: `RylrClient::recv` accumulates a line
//! byte-by-byte into a stack-local buffer across several `.await` points, so
//! a `select!` that cancels the loser would silently drop a partial line —
//! rare enough to merely cost a wasted OGM round, but fatal for a
//! multi-fragment payload on this fire-and-forget medium, since a lost
//! fragment is never retransmitted. `join!` polls both concurrently and
//! drops neither; each `run_once` still returns every round regardless of
//! traffic because its periodic Trickle-timer arm always eventually fires.

use std::time::{Duration, Instant};

use interfaces::frame::Mac;
use rylr998_sim::{LoraSwitch, make_node};
use wayfinder::config::TrickleConfig;
use wayfinder_driver::DynLinkT;

use crate::test_router::{TestRouter, host_frame};

fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n])
}

/// Aggressive Trickle bounds so convergence doesn't need to wait out a
/// production-scale backoff ceiling.
fn fast_trickle() -> Vec<TrickleConfig> {
    vec![TrickleConfig {
        i_min_ms: 20,
        i_max_ms: 100,
    }]
}

/// Drive both routers' real event loops concurrently (never racing one
/// against the other — see the module doc) until `done` reports true, or
/// fail the test after a generous fail-fast bound.
async fn drive_until(
    a: &mut TestRouter,
    b: &mut TestRouter,
    mut done: impl FnMut(&TestRouter, &TestRouter) -> bool,
) {
    let t0 = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let now = t0.elapsed();
            let (ra, rb) = tokio::join!(
                a.driver().run_once(now, true, true, true, true),
                b.driver().run_once(now, true, true, true, true),
            );
            ra.unwrap();
            rb.unwrap();
            if done(a, b) {
                break;
            }
        }
    })
    .await
    .expect("did not reach expected state over the RYLR link");
}

/// Two nodes wired onto one simulated LoRa air medium converge to knowing
/// about each other, driven entirely through the real RYLR998 `LinkT`
/// implementation.
#[tokio::test]
async fn rylr_two_node_convergence() {
    let mut switch = LoraSwitch::new();
    // Distinct AT+ADDRESS per node: the fragment reassembler keys on it (see
    // rylr998/CLAUDE.md's fragmentation deployment note).
    let (ca, _sim_a) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (cb, _sim_b) = make_node(&mut switch, 2, 18, 915_000_000).await;
    let _switch_task = tokio::spawn(switch.run());

    let mut a = TestRouter::from_links(mac(1), vec![DynLinkT::new_box(ca)], fast_trickle());
    let mut b = TestRouter::from_links(mac(2), vec![DynLinkT::new_box(cb)], fast_trickle());

    drive_until(&mut a, &mut b, |a, b| {
        a.router().originator_count() == 1 && b.router().originator_count() == 1
    })
    .await;

    assert_eq!(a.router().originator_count(), 1);
    assert_eq!(b.router().originator_count(), 1);
}

/// A payload well past the RYLR998 link's single-fragment payload budget
/// (104 bytes: 120-byte on-air frame minus the 2-byte frag header minus the
/// 14-byte link header) survives fragmentation on send and reassembly on
/// receive, carried end-to-end through the real router/driver stack.
#[tokio::test]
async fn rylr_fragmented_payload_end_to_end() {
    let mut switch = LoraSwitch::new();
    let (ca, _sim_a) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (cb, _sim_b) = make_node(&mut switch, 2, 18, 915_000_000).await;
    let _switch_task = tokio::spawn(switch.run());

    let mut a = TestRouter::from_links(mac(1), vec![DynLinkT::new_box(ca)], fast_trickle());
    let mut b = TestRouter::from_links(mac(2), vec![DynLinkT::new_box(cb)], fast_trickle());

    // A unicast needs a route first.
    drive_until(&mut a, &mut b, |a, b| {
        a.router().originator_count() == 1 && b.router().originator_count() == 1
    })
    .await;

    // 300 bytes + 14-byte link header = 314 bytes -> ceil(314/118) = 3 on-air
    // fragments (FRAG_PAYLOAD = 118 in rylr998::frag).
    let payload: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
    a.send_local(mac(2), &payload).await.unwrap();

    let expected = host_frame(mac(2), mac(1), &payload);
    drive_until(&mut a, &mut b, |_, b| {
        b.local_deliveries().contains(&expected)
    })
    .await;

    assert!(
        b.local_deliveries().contains(&expected),
        "node B must receive the exact 300-byte payload reassembled from 3 fragments"
    );
}
