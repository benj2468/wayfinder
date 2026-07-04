//! Fuzz [`TrustAnchor::verify_cert`], the crypto-verification core that
//! `OgmAuth::verify_ogm` (in the `wayfinder` crate) depends on: a zero-copy
//! parse of an attacker-controlled `MembershipCert` followed by an Ed25519
//! signature check and version/mesh/expiry validation.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wayfinder_auth::{Keypair, MembershipCert, TrustAnchor};
use zerocopy::FromBytes;

fuzz_target!(|data: &[u8]| {
    // A fixed anchor for a fixed mesh — deterministic per input, no crypto
    // recomputation needed since the root pubkey never changes.
    let anchor = TrustAnchor {
        mesh_id: 0xABCD,
        root_pubkey: Keypair::from_seed(&[1; 32]).ed_pubkey(),
    };
    if let Ok((cert, _)) = MembershipCert::ref_from_prefix(data) {
        let _ = anchor.verify_cert(cert, 1_000_000_000);
    }
});
