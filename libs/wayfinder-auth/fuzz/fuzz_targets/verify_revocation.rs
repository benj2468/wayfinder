//! Fuzz [`TrustAnchor::verify_revocation`]: the same crypto/packed-struct
//! shape as `verify_cert.rs` but the distinct revocation code path — a
//! zero-copy `RevocationRecord` parse followed by Ed25519 verification.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wayfinder_auth::{Keypair, RevocationRecord, TrustAnchor};
use zerocopy::FromBytes;

fuzz_target!(|data: &[u8]| {
    let anchor = TrustAnchor {
        mesh_id: 0xABCD,
        root_pubkey: Keypair::from_seed(&[1; 32]).ed_pubkey(),
    };
    if let Ok((record, _)) = RevocationRecord::ref_from_prefix(data) {
        let _ = anchor.verify_revocation(record);
    }
});
