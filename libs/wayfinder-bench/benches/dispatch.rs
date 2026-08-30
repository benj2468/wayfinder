//! The transmit side: what it costs to decide where a frame goes.
//!
//! [`plan_dispatch`] makes the whole outgoing decision — authenticate the
//! frame, resolve its egress, apply each candidate link's transmit gate — and
//! returns how much to send and which interfaces to send it on. Every driver
//! shell calls it for every outgoing frame, so it is on the hot path exactly
//! as much as the receive side is.
//!
//! The interesting comparison is `resolved` against `no_route`. A destination
//! with no route still costs a full lookup before it can be dropped, and on a
//! node being probed by traffic for unknown destinations that cost is paid
//! per frame with nothing to show for it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "benchmark code: a fixture that cannot be built is a bug in the benchmark, and panicking is the correct, loudest response — there is no caller to return an error to"
)]

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use std::hint::black_box;
use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::interfaces::frame::Mac;
use wayfinder_bench::PAYLOAD_SIZES;
use wayfinder_bench::REMOTE_MAC;
use wayfinder_bench::WarmRouter;
use wayfinder_bench::warm_router;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::plan_dispatch;
use wayfinder_test::driver::mac;

/// Plan one outgoing frame of `body_len` bytes toward `dst`.
///
/// `buf` is sized `body_len + DIRECTED_TRAILER_LEN` exactly as a shell sizes
/// it: the trailer room must be there whether or not auth is on, because
/// `plan_dispatch` writes the pairwise tag past the body.
fn plan(warm: &mut WarmRouter, dst: Mac, buf: &mut [u8], body_len: usize) {
    let n = warm.num_interfaces;
    let plan = plan_dispatch(
        &mut warm.router,
        warm.now,
        black_box(dst),
        DEFAULT_BATMAN_ETHER_TYPE,
        Egress::Auto,
        body_len,
        buf,
        n,
    );
    // Read both halves of the answer, so neither the egress resolution nor the
    // length computation can be optimised out.
    black_box(plan.map(|p| (p.payload().len(), p.targets())));
}

/// A unicast toward a destination with a resolved route: one interface chosen
/// by metric, gate consulted, frame tagged.
fn unicast_resolved(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx/unicast_resolved");
    group.throughput(Throughput::Elements(1));
    for len in PAYLOAD_SIZES {
        let mut warm = warm_router(1, 1);
        warm.assert_route_to(mac(REMOTE_MAC));
        let mut buf = vec![0u8; len + DIRECTED_TRAILER_LEN];
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| plan(&mut warm, mac(REMOTE_MAC), &mut buf, len));
        });
    }
    group.finish();
}

/// A broadcast: every interface in the set, each one's transmit gate consulted.
/// Swept over interface count, which is the fan-out this path pays for.
fn broadcast(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx/broadcast");
    group.throughput(Throughput::Elements(1));
    for ifaces in [1usize, 4, 8] {
        let mut warm = warm_router(ifaces, 1);
        let len = 128usize;
        let mut buf = vec![0u8; len + DIRECTED_TRAILER_LEN];
        group.bench_with_input(BenchmarkId::from_parameter(ifaces), &ifaces, |b, _| {
            b.iter(|| plan(&mut warm, Mac::BROADCAST, &mut buf, len));
        });
    }
    group.finish();
}

/// A unicast toward a destination the router has never heard of: a full lookup
/// that ends in a drop. The cost of traffic for unknown destinations.
fn unicast_no_route(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx/unicast_no_route");
    group.throughput(Throughput::Elements(1));

    let mut warm = warm_router(1, 1);
    let unknown = mac(240);
    assert!(
        warm.router
            .get_egress_interface(warm.now, unknown)
            .is_none(),
        "the no-route benchmark needs a destination that genuinely has no route"
    );
    let len = 128usize;
    let mut buf = vec![0u8; len + DIRECTED_TRAILER_LEN];
    group.bench_function("unknown_dst", |b| {
        b.iter(|| plan(&mut warm, unknown, &mut buf, len));
    });
    group.finish();
}

criterion_group!(benches, unicast_resolved, broadcast, unicast_no_route);
criterion_main!(benches);
