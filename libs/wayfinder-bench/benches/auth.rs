//! The cost of mesh authentication, isolated from routing.
//!
//! These primitives are separated out for one reason: they are large enough to
//! hide everything else. An Ed25519 verification costs on the order of tens of
//! microseconds, while a whole unauthenticated forward costs hundreds of
//! nanoseconds — so an auth-on end-to-end number is, to two significant
//! figures, a measurement of the signature library, and any routing regression
//! underneath it is invisible.
//!
//! Measuring them here instead answers the question directly ("what does auth
//! cost per frame, and on which frames?") and keeps [`packet_path`]'s ladder
//! interpretable as routing cost.
//!
//! The asymmetry is the thing to read. **OGM signing and verification are
//! public-key operations, paid per OGM** — a control-plane rate, once per
//! Trickle interval per originator. **Directed tagging and verification are
//! symmetric-key operations over a pairwise secret, paid per data frame.** If
//! the second pair were as expensive as the first, an authenticated mesh could
//! not carry data at all; confirming they are orders apart is what these
//! benchmarks are for.
//!
//! [`packet_path`]: ../packet_path/index.html
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
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::auth::OgmAuth;
use wayfinder::auth::OgmVerdict;
use wayfinder::interfaces::frame::Mac;
use wayfinder_auth::Authority;
use wayfinder_auth::Clocked;
use wayfinder_auth::Keypair;
use wayfinder_bench::PAYLOAD_SIZES;
use wayfinder_bench::ogm_payload;

/// Two members of one mesh, each holding the other's keys — the state in which
/// directed traffic between them can actually be tagged.
struct Pair {
    a: OgmAuth,
    b: OgmAuth,
    /// A's address: the one its key derives, as its certificate must name.
    a_mac: Mac,
    /// B's address, likewise.
    b_mac: Mac,
}

/// Build two mutually-known members of the same mesh.
///
/// The mutual-knowledge step is not optional: `tag_directed` derives a pairwise
/// key by X25519 agreement with the peer's public key, and returns `None` until
/// that peer's certificate has been ingested. Exchanging one signed OGM each
/// way is the cheapest way to reach that state through the real code path.
fn pair() -> Pair {
    let authority = Authority::from_seed(&[1; 32], 0xABCD);

    // Each member's address is the one its key derives: a certificate naming
    // any other is refused by `verify_cert` (design 09 §5), and a fixture that
    // minted one would measure the rejection instead of the verification.
    let member = |seed: u8| {
        let kp = Keypair::from_seed(&[seed; 32]);
        let id = kp.derived_mac();
        let cert = authority.issue_cert(id, kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);
        let mut auth = OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(core::time::Duration::from_secs(1_000), Clocked::At(1_000));
        (auth, id)
    };
    let (mut a, a_mac) = member(2);
    let (mut b, b_mac) = member(3);

    // Each learns the other's keys from a signed OGM, exactly as it would on
    // the air.
    let a_ogm = signed_ogm(&mut a, a_mac, 1);
    assert!(
        matches!(b.verify_ogm(&a_ogm), OgmVerdict::Verified),
        "peer B must accept A's signed OGM"
    );
    let b_ogm = signed_ogm(&mut b, b_mac, 1);
    assert!(
        matches!(a.verify_ogm(&b_ogm), OgmVerdict::Verified),
        "peer A must accept B's signed OGM"
    );

    Pair { a, b, a_mac, b_mac }
}

/// A fully signed OGM payload from `auth` for originator `id`.
fn signed_ogm(auth: &mut OgmAuth, id: Mac, seqno: u32) -> Vec<u8> {
    let mut buf = ogm_payload(id, seqno, 50, 255);
    let hdr = buf.len();
    buf.resize(1024, 0);
    let len = auth.augment_ogm(&mut buf, hdr).expect("sign OGM");
    buf.truncate(len);
    buf
}

/// Signing an outgoing OGM: the per-emission control-plane cost.
fn ogm_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth/ogm_sign");
    group.throughput(Throughput::Elements(1));
    let mut p = pair();
    let mut seqno = 100u32;
    group.bench_function("augment_ogm", |b| {
        let a_mac = p.a_mac;
        b.iter(|| {
            let mut buf = ogm_payload(a_mac, seqno, 50, 255);
            let hdr = buf.len();
            buf.resize(1024, 0);
            seqno = seqno.wrapping_add(1);
            black_box(p.a.augment_ogm(&mut buf, hdr))
        });
    });
    group.finish();
}

/// Verifying an incoming OGM: paid once per received OGM, by every node that
/// hears it.
fn ogm_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth/ogm_verify");
    group.throughput(Throughput::Elements(1));
    let mut p = pair();
    // Pre-sign a batch so the measurement is verification only, not signing.
    let b_mac = p.b_mac;
    let signed: Vec<Vec<u8>> = (200..232).map(|s| signed_ogm(&mut p.b, b_mac, s)).collect();
    let mut i = 0usize;
    group.bench_function("verify_ogm", |b| {
        b.iter(|| {
            let payload = &signed[i % signed.len()];
            i += 1;
            black_box(p.a.verify_ogm(black_box(payload)))
        });
    });
    group.finish();
}

/// Tagging an outgoing directed frame — the per-data-frame transmit cost, over
/// a symmetric pairwise key rather than a signature.
fn directed_tag(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth/directed_tag");
    group.throughput(Throughput::Elements(1));
    let mut p = pair();
    for len in PAYLOAD_SIZES {
        let frame = vec![0xa5u8; len];
        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| black_box(p.a.tag_directed(p.b_mac, black_box(&frame), &mut trailer)));
        });
    }
    group.finish();
}

/// Verifying an incoming directed frame — the per-data-frame receive cost, and
/// the one every forwarded packet on an authenticated mesh pays.
///
/// Each iteration verifies a frame carrying a **fresh replay counter**, tagged
/// in `iter_batched`'s setup and so excluded from the timing.
///
/// Re-verifying one frame instead would not fail loudly, which is what makes
/// this worth spelling out: `verify_directed` checks the tag *before* the
/// counter, so a replay still pays the full MAC and still reports a plausible
/// number — it simply never reaches `accept_recv_counter`, measuring the reject
/// path rather than the accept path. Doing exactly that here understated the
/// cost enough that these primitives stopped summing to the end-to-end
/// authenticated forward in `packet_path`, which is how it was caught. Treat a
/// primitive that no longer bounds the composite as a bug in the primitive's
/// benchmark until proven otherwise.
fn directed_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth/directed_verify");
    group.throughput(Throughput::Elements(1));
    let p = RefCell::new(pair());
    for len in PAYLOAD_SIZES {
        let frame = vec![0xa5u8; len];

        // Prove the fixture produces frames B genuinely accepts before
        // measuring anything: a tag B rejects would measure the wrong path.
        {
            let mut guard = p.borrow_mut();
            let p = &mut *guard;
            let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
            let n =
                p.a.tag_directed(p.b_mac, &frame, &mut trailer)
                    .expect("pairwise key is known");
            let trailer = trailer[..n].to_vec();
            assert!(
                p.b.verify_directed(p.a_mac, &frame, &trailer),
                "the fixture must tag a frame B actually accepts"
            );
        }

        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter_batched(
                || {
                    let mut guard = p.borrow_mut();
                    let p = &mut *guard;
                    let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
                    let n =
                        p.a.tag_directed(p.b_mac, &frame, &mut trailer)
                            .expect("pairwise key is known");
                    trailer[..n].to_vec()
                },
                |trailer| {
                    let mut guard = p.borrow_mut();
                    let p = &mut *guard;
                    black_box(p.b.verify_directed(p.a_mac, black_box(&frame), &trailer))
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, ogm_sign, ogm_verify, directed_tag, directed_verify);
criterion_main!(benches);
