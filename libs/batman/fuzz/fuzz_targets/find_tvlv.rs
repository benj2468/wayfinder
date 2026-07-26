//! Fuzz [`find_tvlv`]/[`iter_tvlv`], the TVLV-tail scanner every OGM's
//! variable-length trailer is parsed through (multicast membership, cert,
//! signature, and revocation records). Zero setup: pure `fn(&[u8]) -> ...`
//! over an attacker-controlled OGM tail.
#![no_main]

use batman::wire::TvlvType;
use batman::wire::find_tvlv;
use batman::wire::iter_tvlv;
use libfuzzer_sys::fuzz_target;

const TYPES: [TvlvType; 4] = [
    TvlvType::Mcast,
    TvlvType::Cert,
    TvlvType::OgmSig,
    TvlvType::Revoke,
];

fuzz_target!(|data: &[u8]| {
    for ty in TYPES {
        let _ = find_tvlv(data, ty);
        // `iter_tvlv` is lazy — drain it so the scanning logic actually runs.
        for _ in iter_tvlv(data, ty) {}
    }
});
