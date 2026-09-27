//! The per-frame paths at the `cloud` capacity profile (design 26 phase 1).
//!
//! `wayfinder-tap` runs a router whose tables are up to 32x the `host`
//! profile's. Most of them are hashed maps, which should not notice; several
//! are `heapless::Vec`s searched linearly, which would. This suite exists to
//! say which, with numbers, before any table is converted: every group sweeps
//! occupancy, and a curve that tracks it is the scan.
//!
//! - `cloud/ogm_ingest`, `cloud/unicast_forward` — the routing core against an
//!   originator table from one entry to full.
//! - `cloud/hub_poll` — the periodic tick on a hub whose every peer is a direct
//!   neighbour: the work a node does between frames, which scales with the
//!   neighbourhood rather than the traffic.
//! - `cloud/directed_verify` — verifying a directed frame against a neighbour
//!   key table from one entry to full, from the neighbour stored *last*, since
//!   that is the worst case a linear search can have.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "benchmark code: a fixture that cannot be built is a bug in the benchmark, and panicking is the correct, loudest response — there is no caller to return an error to"
)]

use core::cell::RefCell;
use core::time::Duration;
use criterion::BatchSize;
use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use std::hint::black_box;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::auth::OgmAuth;
use wayfinder::auth::OgmVerdict;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::Mac;
use wayfinder_auth::Authority;
use wayfinder_auth::Clocked;
use wayfinder_auth::Keypair;
use wayfinder_bench::CLOUD_ORIGINATOR_COUNTS;
use wayfinder_bench::CountingSink;
use wayfinder_bench::NO_FAN_OUT;
use wayfinder_bench::PEER_MAC;
use wayfinder_bench::WarmCloudRouter;
use wayfinder_bench::ogm_frame;
use wayfinder_bench::ogm_payload;
use wayfinder_bench::unicast_frame;
use wayfinder_bench::warm_cloud_hub;
use wayfinder_bench::warm_cloud_router;
use wayfinder_bench::wide_mac;
use wayfinder_driver_core::handle_mesh_frame;
use wayfinder_driver_core::poll_due_all;
use wayfinder_test::driver::mac;
use zerocopy::FromBytes;

/// Neighbour-key occupancies the directed-verify sweep covers: one, the `host`
/// profile's whole table, and the `cloud` profile's.
const NEIGHBOR_COUNTS: [usize; 3] = [1, 64, 1024];

/// Hub sizes: `host`'s neighbour-key capacity, the `cloud` one, and a full
/// originator table of direct neighbours.
const HUB_SIZES: [usize; 3] = [64, 1024, 4096];

/// Run one measured receive of `raw` against `warm`, parse included, exactly
/// as `packet_path`'s `recv` does.
fn recv(warm: &mut WarmCloudRouter, raw: &[u8], sink: &mut CountingSink) {
    let frame = LinkFrame::ref_from_bytes(black_box(raw)).unwrap();
    handle_mesh_frame(
        warm.now,
        &mut *warm.router,
        0,
        frame,
        wayfinder_bench::GOOD_METRICS,
        &mut warm.tx,
        NO_FAN_OUT,
        sink,
    );
}

/// OGM ingest against a cloud-sized originator table, one entry to full.
fn ogm_ingest(c: &mut Criterion) {
    let mut group = c.benchmark_group("cloud/ogm_ingest");
    group.throughput(Throughput::Elements(1));
    for n in CLOUD_ORIGINATOR_COUNTS {
        let mut warm = warm_cloud_router(n);
        warm.assert_originators(n + 1);
        let raw = ogm_frame(mac(PEER_MAC), mac(PEER_MAC), 5_000, 50, 255);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            let mut sink = CountingSink::default();
            b.iter(|| recv(&mut warm, &raw, &mut sink));
            sink.black_box_counts();
        });
    }
    group.finish();
}

/// Forwarding a unicast to the far-side originator learned last, against a
/// table one entry to full.
fn unicast_forward(c: &mut Criterion) {
    let mut group = c.benchmark_group("cloud/unicast_forward");
    group.throughput(Throughput::Elements(1));
    for n in CLOUD_ORIGINATOR_COUNTS {
        let mut warm = warm_cloud_router(n);
        let dest = wide_mac(n - 1);
        warm.assert_route_to(dest);
        let raw = unicast_frame(mac(PEER_MAC), mac(wayfinder_bench::SELF_MAC), dest, 512);
        // Prove the frame is forwarded, not dropped, before timing it.
        let mut probe = CountingSink::default();
        recv(&mut warm, &raw, &mut probe);
        assert_eq!(
            probe.emitted, 1,
            "cloud fixture must forward toward {dest:?}"
        );
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            let mut sink = CountingSink::default();
            b.iter(|| recv(&mut warm, &raw, &mut sink));
            sink.black_box_counts();
        });
    }
    group.finish();
}

/// The periodic tick on a hub of `n` direct neighbours, at an instant with
/// nothing due: what the node pays on every timer wake-up just to find that
/// out. The first call (outside the timing) emits the OGM that *was* due.
fn hub_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("cloud/hub_poll");
    group.throughput(Throughput::Elements(1));
    for n in HUB_SIZES {
        let mut warm = warm_cloud_hub(n);
        assert_eq!(
            warm.router.originator_table().count(),
            n,
            "hub fixture must hold every neighbour as an originator"
        );
        let now = warm.now;
        let mut sink = CountingSink::default();
        poll_due_all(&mut *warm.router, now, &mut warm.tx, &mut sink);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            let mut sink = CountingSink::default();
            b.iter(|| poll_due_all(&mut *warm.router, now, &mut warm.tx, &mut sink));
            sink.black_box_counts();
        });
    }
    group.finish();
}

/// The `cloud` profile's auth state: 1024 neighbour keys, 1024 revocations.
type CloudAuth = OgmAuth<
    { wayfinder::cloud::NEIGHBOR_KEYS },
    { wayfinder::cloud::REVOKED },
    { wayfinder::cloud::IN_FLIGHT_CERT_REQUESTS },
    { wayfinder::cloud::PENDING_REPLIES },
>;

/// A cloud-profile node holding `n` neighbours' keys, and the neighbour it
/// learned last, holding the node's keys in turn — so the last neighbour can
/// tag frames the node verifies.
struct Neighbourhood {
    node: Box<CloudAuth>,
    node_mac: Mac,
    last: OgmAuth,
    last_mac: Mac,
}

/// A fully signed OGM payload from `auth`, originated as `orig`.
fn signed_ogm<const K: usize, const R: usize, const F: usize, const P: usize>(
    auth: &mut OgmAuth<K, R, F, P>,
    orig: Mac,
    seqno: u32,
) -> Vec<u8> {
    let mut buf = ogm_payload(orig, seqno, 50, 255);
    let hdr = buf.len();
    buf.resize(1024, 0);
    let len = auth.augment_ogm(&mut buf, hdr).expect("sign OGM");
    buf.truncate(len);
    buf
}

/// Build a [`Neighbourhood`] of `n` members of one mesh, each learned by the
/// node from a signed OGM, as on the air.
fn neighbourhood(n: usize) -> Neighbourhood {
    let authority = Authority::from_seed(&[1; 32], 0xABCD);
    let now = Duration::from_secs(1_000);
    let member = |i: usize| {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        seed[31] = 0x5a;
        let kp = Keypair::from_seed(&seed);
        // The key-derived address, the only one `verify_cert` accepts a
        // certificate for (design 09 §5).
        let id = kp.derived_mac();
        let cert = authority.issue_cert(id, kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);
        (kp, cert, id)
    };

    let node_kp = Keypair::from_seed(&[0xee; 32]);
    let node_mac = node_kp.derived_mac();
    let node_cert = authority.issue_cert(
        node_mac,
        node_kp.ed_pubkey(),
        node_kp.x_pubkey(),
        0,
        1_000_000,
    );
    let mut node = Box::new(CloudAuth::with_capacities(
        node_kp,
        node_cert,
        authority.trust_anchor(),
    ));
    node.set_time(now, Clocked::At(1_000));

    let mut last = None;
    for i in 0..n {
        let (kp, cert, id) = member(i);
        let mut peer = OgmAuth::new(kp, cert, authority.trust_anchor());
        peer.set_time(now, Clocked::At(1_000));
        let ogm = signed_ogm(&mut peer, id, 1);
        assert!(
            matches!(node.verify_ogm(&ogm), OgmVerdict::Verified),
            "the node must accept neighbour {i}'s signed OGM: {:?}",
            node.verify_ogm(&ogm)
        );
        last = Some((peer, id));
    }
    let (mut last, last_mac) = last.expect("at least one neighbour");
    let node_ogm = signed_ogm(&mut *node, node_mac, 1);
    assert!(
        matches!(last.verify_ogm(&node_ogm), OgmVerdict::Verified),
        "the last neighbour must accept the node's signed OGM"
    );
    Neighbourhood {
        node,
        node_mac,
        last,
        last_mac,
    }
}

/// Verifying a directed frame from the neighbour stored last, against a key
/// table one entry to full. Fresh replay counter per iteration, tagged in the
/// untimed setup, for the reason `auth.rs`'s `directed_verify` spells out.
fn directed_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("cloud/directed_verify");
    group.throughput(Throughput::Elements(1));
    let frame = vec![0xa5u8; 512];
    for n in NEIGHBOR_COUNTS {
        let hood = RefCell::new(neighbourhood(n));
        let tag = |hood: &mut Neighbourhood| {
            let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
            let len = hood
                .last
                .tag_directed(hood.node_mac, &frame, &mut trailer)
                .expect("pairwise key is known");
            trailer[..len].to_vec()
        };
        {
            let mut h = hood.borrow_mut();
            let trailer = tag(&mut h);
            let src = h.last_mac;
            assert!(
                h.node.verify_directed(src, &frame, &trailer),
                "the fixture must tag a frame the node accepts"
            );
        }
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || tag(&mut hood.borrow_mut()),
                |trailer| {
                    let mut h = hood.borrow_mut();
                    let src = h.last_mac;
                    black_box(h.node.verify_directed(src, black_box(&frame), &trailer))
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    ogm_ingest,
    unicast_forward,
    hub_poll,
    directed_verify
);
criterion_main!(benches);
