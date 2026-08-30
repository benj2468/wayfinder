//! The receive hot path: what one frame costs a node, frame by frame.
//!
//! Every group here measures a single [`handle_mesh_frame`] call — the receive
//! arm of every driver shell's event loop — against a converged router. The
//! groups differ only in *which* path through the router the frame takes, which
//! is what makes them comparable: forwarding versus local delivery versus a
//! duplicate-OGM drop are the same call with different work behind it.
//!
//! Each group declares `Throughput::Elements(1)`, so criterion reports these
//! directly in packets/sec alongside the per-call time. The payload-size sweep
//! additionally reports bytes/sec.
//!
//! Read the numbers as a ladder. `ogm_duplicate` is the floor (parse, recognise,
//! drop); `local_deliver` adds delivery; `unicast_forward` adds route lookup and
//! staging; `broadcast_flood` adds fan-out. If a change moves the floor, it
//! moved parsing; if it moves only the top of the ladder, it moved routing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "benchmark code: a fixture that cannot be built is a bug in the benchmark, and panicking is the correct, loudest response — there is no caller to return an error to"
)]

use core::cell::RefCell;
use criterion::BatchSize;
use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use std::hint::black_box;
use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::Mac;
use wayfinder_bench::CountingSink;
use wayfinder_bench::NO_FAN_OUT;
use wayfinder_bench::ORIGINATOR_COUNTS;
use wayfinder_bench::PAYLOAD_SIZES;
use wayfinder_bench::PEER_MAC;
use wayfinder_bench::REMOTE_MAC;
use wayfinder_bench::SELF_MAC;
use wayfinder_bench::WarmRouter;
use wayfinder_bench::authed_line;
use wayfinder_bench::ogm_frame;
use wayfinder_bench::unicast_frame;
use wayfinder_bench::warm_router;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::MeshSink;
use wayfinder_driver_core::OutgoingFrame;
use wayfinder_driver_core::handle_mesh_frame;
use wayfinder_driver_core::plan_dispatch;
use wayfinder_test::driver::mac;
use zerocopy::FromBytes;

/// Run one measured receive of `raw` against `warm`.
///
/// Factored out so every group measures byte-for-byte the same thing: parse the
/// frame (as a real driver does, from bytes off the wire), plan it, and observe
/// the result. The parse is deliberately *inside* the measurement — a shell
/// pays it on every frame, so excluding it would flatter the number.
fn recv(warm: &mut WarmRouter, raw: &[u8], sink: &mut CountingSink) {
    let frame = LinkFrame::ref_from_bytes(black_box(raw)).unwrap();
    handle_mesh_frame(
        warm.now,
        &mut warm.router,
        0,
        frame,
        wayfinder_bench::GOOD_METRICS,
        &mut warm.tx,
        NO_FAN_OUT,
        sink,
    );
}

/// Forwarding a unicast that is routed onward — the number most people mean by
/// "how fast can it move packets".
fn unicast_forward(c: &mut Criterion) {
    let mut group = c.benchmark_group("rx/unicast_forward");
    for len in PAYLOAD_SIZES {
        let mut warm = warm_router(1, 1);
        warm.assert_route_to(mac(REMOTE_MAC));
        let raw = unicast_frame(mac(PEER_MAC), mac(SELF_MAC), mac(REMOTE_MAC), len);

        // Both, deliberately: Elements gives packets/sec (the per-frame cost
        // that dominates small frames), Bytes gives B/s (the per-byte cost that
        // dominates large ones). Which of the two is flat across the sweep is
        // the whole question.
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("pps", len), &len, |b, _| {
            let mut sink = CountingSink::default();
            b.iter(|| recv(&mut warm, &raw, &mut sink));
            sink.black_box_counts();
        });

        group.throughput(Throughput::Bytes(raw.len() as u64));
        group.bench_with_input(BenchmarkId::new("bps", len), &len, |b, _| {
            let mut sink = CountingSink::default();
            b.iter(|| recv(&mut warm, &raw, &mut sink));
            sink.black_box_counts();
        });
    }
    group.finish();
}

/// A broadcast re-flood, swept over interface count.
///
/// A flood goes out *every* interface, including the one it arrived on (there
/// is deliberately no split-horizon — see `Egress::Auto` in
/// `wayfinder-driver-core`). So this sweep is the direct cost of that decision,
/// and the slope across it is what an operator adding a fourth radio pays.
fn broadcast_flood(c: &mut Criterion) {
    let mut group = c.benchmark_group("rx/broadcast_flood");
    group.throughput(Throughput::Elements(1));
    for ifaces in [1usize, 4, 8] {
        let mut warm = warm_router(ifaces, 1);
        // A fresh originator each iteration would be ideal but is not
        // reachable from a fixed clock; instead this measures the re-flood of a
        // *new-seqno* OGM, which is the flooding path proper.
        let raw = ogm_frame(mac(REMOTE_MAC), mac(PEER_MAC), 9_000, 40, 200);
        group.bench_with_input(BenchmarkId::from_parameter(ifaces), &ifaces, |b, _| {
            let mut sink = CountingSink::default();
            b.iter(|| recv(&mut warm, &raw, &mut sink));
            sink.black_box_counts();
        });
    }
    group.finish();
}

/// A unicast addressed to this node: parsed, unwrapped, handed up to the host.
/// The terminal-node cost, with no forwarding decision in it.
fn local_deliver(c: &mut Criterion) {
    let mut group = c.benchmark_group("rx/local_deliver");
    group.throughput(Throughput::Elements(1));
    for len in PAYLOAD_SIZES {
        let mut warm = warm_router(1, 1);
        // `dest` is this node, so the router delivers rather than forwards.
        let raw = unicast_frame(mac(PEER_MAC), mac(SELF_MAC), mac(SELF_MAC), len);
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            let mut sink = CountingSink::default();
            b.iter(|| recv(&mut warm, &raw, &mut sink));
            sink.black_box_counts();
        });
    }
    group.finish();
}

/// OGM ingest against a table of increasing occupancy.
///
/// **The scaling canary.** Route selection walks an originator's paths and the
/// table is a `heapless` map, so this should be close to flat from 1 originator
/// to a full table of 127. A curve that tracks the occupancy is a linear scan
/// on the control plane, and on a large mesh that is the cost that bites first.
fn ogm_ingest(c: &mut Criterion) {
    let mut group = c.benchmark_group("rx/ogm_ingest");
    group.throughput(Throughput::Elements(1));
    for n in ORIGINATOR_COUNTS {
        let mut warm = warm_router(1, n);
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

/// An OGM whose sequence number has already been seen: recognised and dropped.
///
/// The floor of the ladder — the cheapest thing a node can do with a frame that
/// is genuinely addressed to the mesh. On a settled multi-node segment this is
/// also the *most common* outcome, since every node re-floods every OGM and
/// each neighbour therefore sees most of them more than once. Worth having a
/// number for on its own.
fn ogm_duplicate(c: &mut Criterion) {
    let mut group = c.benchmark_group("rx/ogm_duplicate");
    group.throughput(Throughput::Elements(1));

    let mut warm = warm_router(1, 1);
    let raw = ogm_frame(mac(PEER_MAC), mac(PEER_MAC), 1, 50, 255);
    // Prime it: after this the seqno is behind the high-water mark, so every
    // measured iteration takes the duplicate-drop path.
    let mut sink = CountingSink::default();
    recv(&mut warm, &raw, &mut sink);

    group.bench_function("seen_seqno", |b| {
        let mut sink = CountingSink::default();
        b.iter(|| recv(&mut warm, &raw, &mut sink));
        sink.black_box_counts();
    });
    group.finish();
}

/// A [`MeshSink`] that keeps the frame it was handed, so the transmit half can
/// be planned from it — what a real shell's staging does.
#[derive(Default)]
struct StagingSink {
    /// The most recent planned frame's payload.
    payload: Vec<u8>,
    /// Its final destination.
    dst: Mac,
    /// How many frames have been staged.
    emitted: u64,
}

impl MeshSink for StagingSink {
    fn emit(&mut self, frame: OutgoingFrame<'_>) -> bool {
        self.payload.clear();
        self.payload.extend_from_slice(frame.payload);
        self.dst = frame.dst;
        self.emitted += 1;
        true
    }
}

/// **An authenticated node verifying an inbound frame and forwarding it on.**
///
/// The number for "how fast can an authenticated node move a packet", and the
/// one to compare against `rx/unicast_forward` — the same work with the mesh
/// open. The difference between them is the whole cost of authentication on the
/// data plane.
///
/// The measured region is both halves of a forward, which is what a driver
/// shell does per frame: `handle_mesh_frame` verifies the inbound pairwise tag
/// (rejecting the frame outright if it fails), strips the trailer and resolves
/// the route; then `plan_dispatch` re-tags the frame for the *next* hop and
/// picks its egress. A directed frame is authenticated hop by hop, so a relay
/// pays a verify and a tag, not one or the other.
///
/// Two things make this fixture fragile in ways that would not announce
/// themselves, both handled in `AuthedLine`:
///
/// - Frames are tagged in `iter_batched`'s **setup**, excluded from the timing,
///   because every tag burns a replay counter. Reusing one frame would measure
///   the replay-drop path from the second iteration onward — with the
///   expensive signature check still running, so the number would look
///   plausible while the forward it claims to measure never happened.
/// - B must hold A's pairwise key, have a route to C, *and* consider C proven.
///   `AuthedLine::assert_forwards` checks all three before any measurement.
fn unicast_forward_authed(c: &mut Criterion) {
    let mut group = c.benchmark_group("rx/unicast_forward_authed");
    group.throughput(Throughput::Elements(1));

    for len in PAYLOAD_SIZES {
        let line = RefCell::new(authed_line());
        line.borrow_mut().assert_forwards();

        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter_batched(
                // Setup: a freshly tagged frame with an unused replay counter.
                // Not measured.
                || line.borrow_mut().tag_from_a(len),
                // Measured: verify the inbound tag, route, re-tag for the next
                // hop, resolve egress.
                |raw| {
                    let mut l = line.borrow_mut();
                    let now = l.now;
                    let mut tx = core::mem::take(&mut l.tx);
                    let mut sink = StagingSink::default();

                    let frame = LinkFrame::ref_from_bytes(black_box(&raw)).unwrap();
                    handle_mesh_frame(
                        now,
                        l.router_mut(),
                        0,
                        frame,
                        wayfinder_bench::GOOD_METRICS,
                        &mut tx,
                        NO_FAN_OUT,
                        &mut sink,
                    );

                    // The outbound half: re-tag toward C and choose the egress.
                    // Skipped only if the verify rejected the frame, which the
                    // fixture's assertions exist to prevent.
                    let mut out = 0usize;
                    if sink.emitted > 0 {
                        let body_len = sink.payload.len();
                        sink.payload.resize(body_len + DIRECTED_TRAILER_LEN, 0);
                        let dst = sink.dst;
                        let plan = plan_dispatch(
                            l.router_mut(),
                            now,
                            dst,
                            DEFAULT_BATMAN_ETHER_TYPE,
                            Egress::Auto,
                            body_len,
                            &mut sink.payload,
                            2,
                        );
                        out = plan.map_or(0, |p| p.payload().len());
                    }

                    l.tx = tx;
                    black_box((sink.emitted, out))
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    unicast_forward,
    unicast_forward_authed,
    broadcast_flood,
    local_deliver,
    ogm_ingest,
    ogm_duplicate
);
criterion_main!(benches);
