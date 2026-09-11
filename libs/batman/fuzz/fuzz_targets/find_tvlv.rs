//! Fuzz [`find_tvlv`]/[`iter_tvlv`], the TVLV-tail scanner every OGM's
//! variable-length trailer is parsed through (multicast membership, cert,
//! signature, fingerprint, revocation and previous-sender records), plus
//! [`stamp_prev_sender`]/[`stamped_len`], the rewrite a relay applies to that
//! same attacker-controlled tail on the forwarding path. Zero setup: pure
//! functions over an attacker-controlled OGM tail.
#![no_main]

use batman::wire::TvlvType;
use batman::wire::find_tvlv;
use batman::wire::iter_tvlv;
use batman::wire::prev_sender;
use batman::wire::stamp_prev_sender;
use batman::wire::stamped_len;
use interfaces::frame::Mac;
use libfuzzer_sys::fuzz_target;

const TYPES: [TvlvType; 6] = [
    TvlvType::Mcast,
    TvlvType::Cert,
    TvlvType::OgmSig,
    TvlvType::Revoke,
    TvlvType::CertFp,
    TvlvType::PrevSender,
];

fuzz_target!(|data: &[u8]| {
    for ty in TYPES {
        let _ = find_tvlv(data, ty);
        // `iter_tvlv` is lazy — drain it so the scanning logic actually runs.
        for _ in iter_tvlv(data, ty) {}
    }
    let _ = prev_sender(data);

    // The relay rewrite: a second attacker-reachable parse loop, and unlike
    // the scanners above it also *writes*. Two output buffers, one comfortably
    // larger than any tail a frame can carry and one deliberately tight, so
    // both the success path and the refusal path are exercised.
    let stamp = Mac([1, 2, 3, 4, 5, 6]);
    for cap in [4usize, 2048] {
        let mut out = vec![0u8; cap];
        let written = stamp_prev_sender(data, &mut out, stamp);

        // `stamped_len` is what the engine asks *before* stamping to tell a
        // malformed tail from a short buffer, so the two must agree about
        // which tails are parseable, and about how many bytes a stamp needs.
        match (stamped_len(data), written) {
            (Some(need), Some(n)) => {
                assert_eq!(need, n, "stamped_len must predict the write exactly");
                assert!(n <= cap);
                assert_eq!(
                    prev_sender(&out[..n]),
                    Some(stamp),
                    "a stamped tail must read back the stamp"
                );
            }
            // A tail `stamped_len` accepts may still not fit a tight buffer.
            (Some(need), None) => assert!(need > cap),
            // But one it rejects must never be written.
            (None, w) => assert!(w.is_none(), "a malformed tail must not be stamped"),
        }
    }
});
