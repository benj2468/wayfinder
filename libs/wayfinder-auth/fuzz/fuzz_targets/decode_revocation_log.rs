//! Fuzz [`decode_revocation_log`]: the stored revocation list, read back from
//! a file or from flash that may be damaged or edited.
//!
//! Beyond not panicking, two properties: whatever decodes re-encodes to the
//! very same bytes (so nothing was skipped or invented), and every decoded
//! record can go to verification, as loading does.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wayfinder_auth::Keypair;
use wayfinder_auth::TrustAnchor;
use wayfinder_auth::decode_revocation_log;
use wayfinder_auth::encode_revocation_log;

fuzz_target!(|data: &[u8]| {
    let Ok(records) = decode_revocation_log(data) else {
        return;
    };
    let mut out = vec![0u8; data.len()];
    assert_eq!(encode_revocation_log(records, &mut out), Some(data.len()));
    assert_eq!(out, data);

    let anchor = TrustAnchor {
        mesh_id: 0xABCD,
        root_pubkey: Keypair::from_seed(&[1; 32]).ed_pubkey(),
    };
    for record in records {
        let _ = anchor.verify_revocation(record, 0);
    }
});
