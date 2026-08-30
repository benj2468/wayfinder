//! Wire-format encode/decode: the floor every other number sits on.
//!
//! Parsing here is `zerocopy`, so a `LinkFrame` decode should be a bounds check
//! and a pointer cast — nanoseconds, and flat in payload size. That property is
//! the reason the routing core can be allocation-free at all, and it is exactly
//! the kind of thing that regresses silently: add one owned field to a wire
//! struct, or lose `Immutable`/`KnownLayout` on a derive, and the "zero-copy"
//! parse quietly becomes a copy.
//!
//! A parse whose cost tracks payload size is that regression. That is what this
//! benchmark is for; nobody needs a headline number for a pointer cast.
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
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder_bench::PAYLOAD_SIZES;
use wayfinder_bench::PEER_MAC;
use wayfinder_bench::REMOTE_MAC;
use wayfinder_bench::SELF_MAC;
use wayfinder_bench::ogm_payload;
use wayfinder_bench::unicast_frame;
use wayfinder_test::driver::mac;
use zerocopy::FromBytes;

/// Zero-copy parse of raw bytes into a `&LinkFrame`, swept over payload size.
///
/// **This should be flat.** A rising curve means the parse is copying.
fn link_frame_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire/link_frame_parse");
    group.throughput(Throughput::Elements(1));
    for len in PAYLOAD_SIZES {
        let raw = unicast_frame(mac(PEER_MAC), mac(SELF_MAC), mac(REMOTE_MAC), len);
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| {
                let frame = LinkFrame::ref_from_bytes(black_box(&raw[..])).unwrap();
                // Touch the header so the parse cannot be elided as unused.
                black_box((frame.dst, frame.src))
            });
        });
    }
    group.finish();
}

/// Building an OGM header's bytes — the encode side of the same floor, paid
/// once per OGM emission per interface.
fn ogm_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire/ogm_encode");
    group.throughput(Throughput::Elements(1));
    group.bench_function("header", |b| {
        let mut seqno = 0u32;
        b.iter(|| {
            seqno = seqno.wrapping_add(1);
            black_box(ogm_payload(mac(REMOTE_MAC), black_box(seqno), 50, 255))
        });
    });
    group.finish();
}

criterion_group!(benches, link_frame_parse, ogm_encode);
criterion_main!(benches);
