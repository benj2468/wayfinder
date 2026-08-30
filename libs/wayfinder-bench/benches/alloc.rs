//! The allocation gate: proof that the planning core allocates nothing.
//!
//! `wayfinder-driver-core` is documented as "deliberately synchronous and
//! allocation-free", and that is not a stylistic preference — it is what lets
//! the same routing code run on an nRF52840 with no allocator at all. Nothing
//! in the test suite enforces it. A `Vec` introduced on the receive path would
//! pass every test in the workspace and fail only when someone next built the
//! firmware, or worse, only under memory pressure on a device in the field.
//!
//! This is the one benchmark CI actually fails on, and it is here rather than
//! in the criterion suite because of what it measures. An allocation count is
//! **deterministic**: it is the same number on a loaded shared CI runner as on
//! a quiet laptop, so it can be asserted rather than eyeballed. Wall-clock
//! timings cannot be — which is why the criterion benchmarks are reported and
//! compared, never gated.
//!
//! Run it with `just bench-alloc`. Divan prints per-call allocation counts; the
//! assertions below are what make a regression a failure rather than a number
//! someone has to notice.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "benchmark code: a fixture that cannot be built is a bug in the benchmark, and panicking is the correct, loudest response — there is no caller to return an error to"
)]

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::cell::Cell;
use divan::AllocProfiler;
use divan::Bencher;
use divan::counter::ItemsCount;
use std::hint::black_box;
use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder_bench::CountingSink;
use wayfinder_bench::GOOD_METRICS;
use wayfinder_bench::NO_FAN_OUT;
use wayfinder_bench::PEER_MAC;
use wayfinder_bench::REMOTE_MAC;
use wayfinder_bench::SELF_MAC;
use wayfinder_bench::unicast_frame;
use wayfinder_bench::warm_router;
use wayfinder_driver_core::Egress;
use wayfinder_driver_core::handle_mesh_frame;
use wayfinder_driver_core::plan_dispatch;
use wayfinder_test::driver::mac;
use zerocopy::FromBytes;

thread_local! {
    /// Allocations made on this thread since the last [`reset_allocs`].
    ///
    /// Thread-local rather than a global `AtomicUsize` on purpose: divan runs
    /// benchmarks on their own threads, and a process-wide counter would fold
    /// in every allocation made by the harness itself — reporting a
    /// regression that is really just criterion-style bookkeeping.
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

/// A `GlobalAlloc` that counts allocations into [`ALLOCS`] and forwards
/// everything to the system allocator.
///
/// This exists because divan's own allocation tallies, while displayed in its
/// output, are `pub(crate)` — there is no public API to read them back, so they
/// can report a regression but cannot fail on one. Counting separately is what
/// turns this suite from a report into a gate.
struct CountingAlloc;

// SAFETY: every method forwards directly to the system allocator with the
// caller's own pointer and layout, adding only a thread-local counter bump.
// The counter never touches the allocation itself, so all of `System`'s
// guarantees carry through unchanged.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        // SAFETY: `layout` is the caller's, forwarded unmodified.
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` are the caller's, forwarded unmodified.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        // SAFETY: arguments are the caller's, forwarded unmodified.
        unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        // SAFETY: `layout` is the caller's, forwarded unmodified.
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }
}

/// Divan's profiler layered over the counting allocator: divan gets its
/// per-benchmark allocation table for a human reading the output, and
/// [`assert_no_alloc`] gets a number it can actually fail on.
///
/// A `#[global_allocator]` can only be installed once per binary, which is why
/// this suite is its own bench target rather than a group inside the criterion
/// benches.
#[global_allocator]
static ALLOC: AllocProfiler<CountingAlloc> = AllocProfiler::new(CountingAlloc);

/// Zero the calling thread's allocation counter.
fn reset_allocs() {
    ALLOCS.with(|c| c.set(0));
}

/// The calling thread's allocation count since [`reset_allocs`].
fn allocs() -> usize {
    ALLOCS.with(Cell::get)
}

fn main() {
    divan::main();
}

/// Receiving and forwarding a routed unicast must not allocate.
#[divan::bench]
fn rx_unicast_forward(bencher: Bencher) {
    let mut warm = warm_router(1, 1);
    warm.assert_route_to(mac(REMOTE_MAC));
    let raw = unicast_frame(mac(PEER_MAC), mac(SELF_MAC), mac(REMOTE_MAC), 512);
    let mut sink = CountingSink::default();

    let mut recv = || {
        let frame = LinkFrame::ref_from_bytes(black_box(&raw[..])).unwrap();
        handle_mesh_frame(
            warm.now,
            &mut warm.router,
            0,
            frame,
            GOOD_METRICS,
            &mut warm.tx,
            NO_FAN_OUT,
            &mut sink,
        );
    };

    assert_no_alloc("handle_mesh_frame (unicast forward)", &mut recv);
    bencher.counter(ItemsCount::new(1usize)).bench_local(recv);
}

/// Receiving a locally-delivered unicast must not allocate.
#[divan::bench]
fn rx_local_deliver(bencher: Bencher) {
    let mut warm = warm_router(1, 1);
    let raw = unicast_frame(mac(PEER_MAC), mac(SELF_MAC), mac(SELF_MAC), 512);
    let mut sink = CountingSink::default();

    let mut recv = || {
        let frame = LinkFrame::ref_from_bytes(black_box(&raw[..])).unwrap();
        handle_mesh_frame(
            warm.now,
            &mut warm.router,
            0,
            frame,
            GOOD_METRICS,
            &mut warm.tx,
            NO_FAN_OUT,
            &mut sink,
        );
    };

    assert_no_alloc("handle_mesh_frame (local deliver)", &mut recv);
    bencher.counter(ItemsCount::new(1usize)).bench_local(recv);
}

/// Planning an outgoing frame must not allocate.
#[divan::bench]
fn tx_plan_dispatch(bencher: Bencher) {
    let mut warm = warm_router(1, 1);
    warm.assert_route_to(mac(REMOTE_MAC));
    let len = 512usize;
    let mut buf = vec![0u8; len + DIRECTED_TRAILER_LEN];
    let n = warm.num_interfaces;

    let mut dispatch = || {
        let plan = plan_dispatch(
            &mut warm.router,
            warm.now,
            black_box(mac(REMOTE_MAC)),
            DEFAULT_BATMAN_ETHER_TYPE,
            Egress::Auto,
            len,
            &mut buf,
            n,
        );
        black_box(plan.map(|p| (p.payload().len(), p.targets())));
    };

    assert_no_alloc("plan_dispatch", &mut dispatch);
    bencher
        .counter(ItemsCount::new(1usize))
        .bench_local(dispatch);
}

/// How many times [`assert_no_alloc`] exercises an operation while counting.
///
/// More than one so a regression that allocates only on some iterations (a
/// `Vec` that grows on a capacity boundary, say) still trips the gate.
const GATE_ITERATIONS: usize = 1_000;

/// Run `op` repeatedly with allocation counting on, and fail if it allocated.
///
/// Runs **outside** divan's measurement loop rather than inside `bench_local`.
/// Divan's harness does its own per-iteration bookkeeping, and folding that
/// into the count would make the gate depend on harness internals — a number
/// that could change on a divan upgrade and be indistinguishable from a real
/// regression in the router.
///
/// `op` is called twice before counting starts, and that warm-up is doing real
/// work, not papering over anything: `tracing` registers each callsite the
/// first time it is hit, which allocates once per `trace!` site, permanently.
/// The planning core is full of them. The property worth defending is that
/// *steady-state* packet processing allocates nothing — one-time callsite
/// registration at startup is not what would break a board.
fn assert_no_alloc(what: &str, mut op: impl FnMut()) {
    op();
    op();

    reset_allocs();
    for _ in 0..GATE_ITERATIONS {
        op();
    }
    let n = allocs();

    assert_eq!(
        n, 0,
        "{what} allocated {n} time(s) over {GATE_ITERATIONS} iterations; the planning \
         core is required to be allocation-free so the same routing code can run on a \
         board with no allocator at all"
    );
}
