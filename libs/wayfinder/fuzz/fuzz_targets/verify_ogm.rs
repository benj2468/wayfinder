//! Fuzz [`OgmAuth::verify_ogm`], the gate an incoming OGM must pass before it
//! reaches the routing engine: header-length check, TVLV scan for the cert and
//! signature records, zero-copy cert parse, trust-anchor verification, and an
//! Ed25519 signature check. This is the highest-value target in the crate —
//! it's the entry point a mesh peer (or an attacker) controls directly, and it
//! composes several other fuzzable layers (TVLV scanning, cert parsing, the
//! crypto verification core) in one call.
#![no_main]

use std::sync::OnceLock;

use interfaces::frame::Mac;
use libfuzzer_sys::fuzz_target;
use wayfinder::auth::OgmAuth;
use wayfinder_auth::{Authority, Keypair, MembershipCert, TrustAnchor};

/// The mesh trust anchor plus a fixed seed for the verifying node's own
/// (unused-by-`verify_ogm`) identity, built once per fuzzer process.
/// `verify_ogm` only ever reads `self.anchor`/`self.now_unix`/
/// `self.revocations` — never the verifier's own keypair or cert — so sharing
/// this across iterations is safe even though every call gets a fresh
/// `OgmAuth` (deliberately: per-input-only state keeps a crash reproducible
/// from its input alone, not from fuzzing history).
struct Fixture {
    verifier_seed: [u8; 32],
    verifier_cert: MembershipCert,
    anchor: TrustAnchor,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let verifier_seed = [9; 32];
        let verifier_kp = Keypair::from_seed(&verifier_seed);
        let verifier_cert = authority.issue_cert(
            Mac([0, 0, 0, 0, 0, 9]),
            verifier_kp.ed_pubkey(),
            verifier_kp.x_pubkey(),
            0,
            u64::MAX,
        );
        Fixture {
            verifier_seed,
            verifier_cert,
            anchor: authority.trust_anchor(),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let kp = Keypair::from_seed(&f.verifier_seed);
    let mut auth = OgmAuth::new(kp, f.verifier_cert, f.anchor);
    // Mid-range unix time, well inside the wide-open validity windows this
    // harness's certs/revocations are issued with, so cert-expiry checks don't
    // trivially reject every input before reaching the interesting logic.
    auth.set_time(1_000_000_000);
    let _ = auth.verify_ogm(data);
});
