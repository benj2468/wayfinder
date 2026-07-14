//! The offline `cert` tooling produces the exact raw-byte files a
//! `wayfinder-tap` loads, and the issued certificate verifies against the
//! written trust anchor (using the same `wayfinder-auth` API the node uses).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use wayfinder_auth::{Keypair, MembershipCert, TrustAnchor};
use wayfinderctl::cert::{self, CertCommand};

/// Run the full init-ca → keygen → issue flow into a temp dir and return the
/// written (anchor, cert) paths' bytes plus the temp dir guard.
fn issue_into_tmp(mesh_id: u32) -> (tempfile::TempDir, Vec<u8>, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.seed");
    let anchor = dir.path().join("anchor.bin");
    let node = dir.path().join("node.seed");
    let cert = dir.path().join("node.cert");

    cert::run(CertCommand::InitCa {
        mesh_id,
        seed: None,
        generate: true,
        out_seed: Some(root.clone()),
        out_anchor: anchor.clone(),
    })
    .unwrap();
    cert::run(CertCommand::Keygen {
        out_seed: Some(node.clone()),
    })
    .unwrap();
    cert::run(CertCommand::Issue {
        ca_seed: root.clone(),
        mesh_id,
        mac: Some("02:00:00:00:00:09".into()),
        node_seed: node.clone(),
        not_before: 0,
        not_after: 1_000_000,
        out_cert: cert.clone(),
    })
    .unwrap();

    // The files are exactly the sizes the tap's loader expects.
    assert_eq!(std::fs::metadata(&root).unwrap().len(), 32);
    assert_eq!(std::fs::metadata(&node).unwrap().len(), 32);
    assert_eq!(std::fs::metadata(&cert).unwrap().len(), 156);

    let anchor_bytes = std::fs::read(&anchor).unwrap();
    let cert_bytes = std::fs::read(&cert).unwrap();
    (dir, anchor_bytes, cert_bytes)
}

#[test]
fn issued_cert_verifies_against_written_anchor() {
    let (_dir, anchor_bytes, cert_bytes) = issue_into_tmp(0xABCD);

    // Reload via the same `from_bytes` the node uses.
    let anchor = TrustAnchor::from_bytes(&anchor_bytes).expect("anchor reloads");
    let cert = MembershipCert::from_bytes(&cert_bytes).expect("cert reloads");

    let verified = anchor
        .verify_cert(&cert, 500)
        .expect("issued cert verifies within its window against its own anchor");
    assert_eq!(verified.mac.0, [0x02, 0, 0, 0, 0, 9]);
}

/// Omitting `--mac` must derive the issued cert's MAC from `--node-seed`'s
/// keypair, rather than requiring the operator to pick one — the same
/// derivation `wayfinder-tap` applies at startup, so a manually-provisioned
/// node's cert matches the MAC it will actually run under.
#[test]
fn issue_without_mac_derives_it_from_the_node_seed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.seed");
    let anchor = dir.path().join("anchor.bin");
    let node = dir.path().join("node.seed");
    let cert = dir.path().join("node.cert");

    cert::run(CertCommand::InitCa {
        mesh_id: 0xABCD,
        seed: None,
        generate: true,
        out_seed: Some(root.clone()),
        out_anchor: anchor.clone(),
    })
    .unwrap();
    cert::run(CertCommand::Keygen {
        out_seed: Some(node.clone()),
    })
    .unwrap();
    cert::run(CertCommand::Issue {
        ca_seed: root.clone(),
        mesh_id: 0xABCD,
        mac: None,
        node_seed: node.clone(),
        not_before: 0,
        not_after: 1_000_000,
        out_cert: cert.clone(),
    })
    .unwrap();

    let node_seed: [u8; 32] = std::fs::read(&node).unwrap().try_into().unwrap();
    let expected_mac = Keypair::from_seed(&node_seed).derived_mac();

    let anchor = TrustAnchor::from_bytes(&std::fs::read(&anchor).unwrap()).unwrap();
    let cert = MembershipCert::from_bytes(&std::fs::read(&cert).unwrap()).unwrap();
    let verified = anchor.verify_cert(&cert, 500).expect("cert verifies");
    assert_eq!(verified.mac, expected_mac);
}

#[test]
fn cert_is_rejected_by_a_foreign_mesh_anchor() {
    // A cert from one mesh must not verify against another mesh's anchor.
    let (_dir_a, anchor_a, _cert_a) = issue_into_tmp(0x1111);
    let (_dir_b, _anchor_b, cert_b) = issue_into_tmp(0x2222);

    let anchor_a = TrustAnchor::from_bytes(&anchor_a).unwrap();
    let cert_b = MembershipCert::from_bytes(&cert_b).unwrap();
    assert!(
        anchor_a.verify_cert(&cert_b, 500).is_err(),
        "a cert from mesh 0x2222 must not verify under mesh 0x1111's anchor"
    );
}

#[test]
fn tampered_cert_fails_verification() {
    let (_dir, anchor_bytes, mut cert_bytes) = issue_into_tmp(0xABCD);
    let anchor = TrustAnchor::from_bytes(&anchor_bytes).unwrap();
    // Flip a byte in the signed body (the node MAC).
    cert_bytes[6] ^= 0xff;
    let cert = MembershipCert::from_bytes(&cert_bytes).unwrap();
    assert!(anchor.verify_cert(&cert, 500).is_err());
}
