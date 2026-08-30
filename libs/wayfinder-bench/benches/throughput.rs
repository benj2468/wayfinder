//! End-to-end throughput through a whole driver shell — the headline number.
//!
//! Where [`packet_path`] measures one planning call in isolation, this measures
//! the full cycle a synchronous shell actually runs: `push_rx` a batch of
//! frames, one `tick` to drain and plan them, then `poll_egress` to collect
//! what came out. That adds the wire framing, the egress queueing and the
//! transmit accounting the planning core does not do — everything between "a
//! frame arrived" and "a frame is ready to go out".
//!
//! This is the number to quote for "how fast can we process packets", and it is
//! the pessimistic end of the honest range: [`wayfinder_tick_driver`] owns
//! `Vec`-backed queues and copies each frame into and out of them, which a
//! `heapless` embedded shell does differently and a tokio shell overlaps with
//! I/O. Read it as the routing-and-staging cost of a packet on one core, not as
//! a line-rate figure for any particular deployment.
//!
//! Reported with `Throughput::Elements(batch)`, so criterion prints it directly
//! in packets/sec.
//!
//! [`packet_path`]: ../packet_path/index.html
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "benchmark code: a fixture that cannot be built is a bug in the benchmark, and panicking is the correct, loudest response — there is no caller to return an error to"
)]

use core::time::Duration;
use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use std::hint::black_box;
use wayfinder_bench::GOOD_METRICS;
use wayfinder_bench::PAYLOAD_SIZES;
use wayfinder_bench::warm_tick_driver;

/// How many frames are pushed through per measured iteration.
///
/// Batching amortises criterion's per-iteration overhead across many frames,
/// which matters when a single frame costs a few hundred nanoseconds. It also
/// matches how a real shell wakes: a driver drains everything its links have
/// queued in one pass, it does not tick once per frame.
const BATCH: usize = 64;

/// Push a batch of routed unicasts through `push_rx` → `tick` → `poll_egress`.
///
/// The clock advances by a millisecond per iteration. That is deliberately
/// small: it keeps the periodic schedules (OGM emission, keep-alives) from
/// firing inside the measurement and polluting it with control-plane work,
/// while still being monotonic, which the driver requires.
fn forward_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("tick_driver/forward_batch");
    for len in PAYLOAD_SIZES {
        let mut fixture = warm_tick_driver(BATCH, len);
        let mut now = fixture.start;

        group.throughput(Throughput::Elements(BATCH as u64));
        group.bench_with_input(BenchmarkId::new("pps", len), &len, |b, _| {
            b.iter(|| {
                for raw in &fixture.batch {
                    let Ok(()) = fixture.driver.push_rx(0, GOOD_METRICS, black_box(raw)) else {
                        panic!("benchmark pushed a malformed frame")
                    };
                }
                now += Duration::from_millis(1);
                fixture.driver.tick(now);

                // Drain, and observe what came out: an undrained queue would
                // grow without bound across iterations, turning a throughput
                // benchmark into a memory-growth benchmark.
                let mut out = 0u64;
                while let Some(frame) = fixture.driver.poll_egress(0) {
                    out += frame.len() as u64;
                }
                while fixture.driver.poll_local().is_some() {
                    out += 1;
                }
                black_box(out)
            });
        });

        // The same loop reported per byte, for the payload-size sweep.
        let frame_bytes = fixture.batch.first().map_or(0, Vec::len) as u64;
        group.throughput(Throughput::Bytes(frame_bytes * BATCH as u64));
        group.bench_with_input(BenchmarkId::new("bps", len), &len, |b, _| {
            b.iter(|| {
                for raw in &fixture.batch {
                    let Ok(()) = fixture.driver.push_rx(0, GOOD_METRICS, black_box(raw)) else {
                        panic!("benchmark pushed a malformed frame")
                    };
                }
                now += Duration::from_millis(1);
                fixture.driver.tick(now);
                let mut out = 0u64;
                while let Some(frame) = fixture.driver.poll_egress(0) {
                    out += frame.len() as u64;
                }
                while fixture.driver.poll_local().is_some() {
                    out += 1;
                }
                black_box(out)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, forward_batch);
criterion_main!(benches);
