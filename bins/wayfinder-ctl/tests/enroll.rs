//! `enroll` / `revoke` against an in-process provider node: the provider runs a
//! real `CertAuthority`, and `run_query` drives the full client → server →
//! authority path.  Asserts the issued certificate verifies against the anchor
//! the client wrote.
//!
//! The provider itself lives in `provider/mod.rs`, shared with the account
//! tests — see that module for why the mock routes its mutations through a real
//! `AuthorityAdapter`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod provider;

use std::path::PathBuf;

use wayfinder_auth::Keypair;
use wayfinder_auth::MembershipCert;
use wayfinder_auth::TrustAnchor;
use wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest;
use wayfinderctl::Command;
use wayfinderctl::Endpoint;
use wayfinderctl::csr::CsrCommand;
use wayfinderctl::output::OutputFormat;
use wayfinderctl::run_query;

use provider::spawn_approval_gated_provider;
use provider::spawn_provider;
use provider::spawn_provider_full;

/// The case online enrollment actually has to serve: the provider is itself an
/// enrolled member of the mesh it certifies, and the node asking to join holds
/// nothing — no certificate, no relationship to the provider at all. It gets to
/// submit its CSR anyway, and comes away with a certificate that verifies.
///
/// This is what a self-service "join this mesh" is made of. Before the
/// enrollment grant it could not happen: the provider's management API admitted
/// only admins, so a node with no certificate could never open the connection
/// that would have got it one.
#[tokio::test]
async fn a_node_with_no_certificate_can_enroll_with_an_enrolled_provider() {
    let endpoint = spawn_provider_full(None, true, true).await;
    let dir = tempfile::tempdir().unwrap();
    let anchor_path = dir.path().join("anchor");
    let cert_path = dir.path().join("cert");

    run_query(
        Command::Enroll {
            mac: Some("02:00:00:00:00:09".into()),
            token: String::new(),
            out_seed: dir.path().join("seed"),
            out_cert: cert_path.clone(),
            out_anchor: anchor_path.clone(),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("a stranger may enroll");

    let anchor = TrustAnchor::from_bytes(&std::fs::read(&anchor_path).unwrap()).unwrap();
    let cert = MembershipCert::from_bytes(&std::fs::read(&cert_path).unwrap()).unwrap();
    anchor.verify_cert(&cert, 500).expect("cert verifies");
}

/// The other half of the enrollment grant: it enrolls and nothing more. The
/// same stranger that just submitted a CSR cannot read the provider's state or
/// approve its own request.
#[tokio::test]
async fn an_enrolling_node_cannot_do_anything_but_enroll() {
    let endpoint = spawn_provider_full(None, false, true).await;

    let err = run_query(Command::ListCerts, &endpoint, OutputFormat::Human)
        .await
        .unwrap_err();
    let err = format!("{err:#}");
    assert!(err.contains("limited to enrollment"), "got: {err}");

    let err = run_query(
        Command::Csr(CsrCommand::Approve {
            mac: "02:00:00:00:00:09".into(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap_err();
    let err = format!("{err:#}");
    assert!(
        err.contains("limited to enrollment"),
        "a node must not approve its own request: {err}"
    );
}

#[tokio::test]
async fn enroll_yields_a_cert_that_verifies_against_the_anchor() {
    let endpoint = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed");
    let cert = dir.path().join("cert");
    let anchor = dir.path().join("anchor");

    let out = run_query(
        Command::Enroll {
            mac: Some("02:00:00:00:00:09".into()),
            token: String::new(),
            out_seed: seed.clone(),
            out_cert: cert.clone(),
            out_anchor: anchor.clone(),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("enroll succeeds");
    assert!(out.contains("enrolled"), "got: {out}");

    // The written seed is 32 bytes; the issued cert verifies against the written
    // anchor within its validity window.
    assert_eq!(std::fs::metadata(&seed).unwrap().len(), 32);
    let anchor = TrustAnchor::from_bytes(&std::fs::read(&anchor).unwrap()).unwrap();
    let cert = MembershipCert::from_bytes(&std::fs::read(&cert).unwrap()).unwrap();
    let verified = anchor.verify_cert(&cert, 500).expect("cert verifies");
    assert_eq!(verified.mac.0, [0x02, 0, 0, 0, 0, 9]);
}

/// Omitting `--mac` must derive the enrolled MAC from the freshly-generated
/// keypair, rather than requiring the operator to pick one — the same
/// derivation `wayfinder-tap` applies at startup, so the enrolled cert matches
/// the MAC the node will actually run under.
#[tokio::test]
async fn enroll_without_mac_derives_it_from_the_keypair() {
    let endpoint = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed");
    let cert = dir.path().join("cert");
    let anchor = dir.path().join("anchor");

    run_query(
        Command::Enroll {
            mac: None,
            token: String::new(),
            out_seed: seed.clone(),
            out_cert: cert.clone(),
            out_anchor: anchor.clone(),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("enroll succeeds");

    let seed_bytes: [u8; 32] = std::fs::read(&seed).unwrap().try_into().unwrap();
    let expected_mac = Keypair::from_seed(&seed_bytes).derived_mac();

    let anchor = TrustAnchor::from_bytes(&std::fs::read(&anchor).unwrap()).unwrap();
    let cert = MembershipCert::from_bytes(&std::fs::read(&cert).unwrap()).unwrap();
    let verified = anchor.verify_cert(&cert, 500).expect("cert verifies");
    assert_eq!(verified.mac, expected_mac);
}

#[tokio::test]
async fn enroll_reuses_an_existing_seed_file_instead_of_minting_a_new_identity() {
    // The sim entrypoint retries `enroll` for the same MAC against a fixed
    // `--out-seed` path until the CSR is approved.  Each retry must reuse the
    // identity it already wrote, not mint a fresh keypair — otherwise a
    // require-approval provider sees a "different key" on every retry and the
    // enrollment can never converge.
    let endpoint = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed");
    let cert = dir.path().join("cert");
    let anchor = dir.path().join("anchor");

    let enroll_cmd = |seed: PathBuf, cert: PathBuf, anchor: PathBuf| Command::Enroll {
        mac: Some("02:00:00:00:00:09".into()),
        token: String::new(),
        out_seed: seed,
        out_cert: cert,
        out_anchor: anchor,
        no_vpn: true,
        print_vpn_command: false,
    };

    run_query(
        enroll_cmd(seed.clone(), cert.clone(), anchor.clone()),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("first enroll succeeds");
    let first_seed_bytes = std::fs::read(&seed).unwrap();

    // Retry: the seed file already exists at `out_seed`, so it must be read
    // back and reused rather than replaced with a freshly-generated one.
    run_query(
        enroll_cmd(seed.clone(), cert.clone(), anchor.clone()),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("retry enroll succeeds");
    let second_seed_bytes = std::fs::read(&seed).unwrap();

    assert_eq!(
        first_seed_bytes, second_seed_bytes,
        "seed is stable across retries"
    );

    let cert_bytes = MembershipCert::from_bytes(&std::fs::read(&cert).unwrap()).unwrap();
    let seed_array: [u8; 32] = first_seed_bytes.try_into().unwrap();
    let kp = Keypair::from_seed(&seed_array);
    assert_eq!(
        cert_bytes.ed_pubkey,
        kp.ed_pubkey(),
        "cert is bound to the reused identity, not a new one"
    );
}

#[tokio::test]
async fn enroll_rejected_without_required_token() {
    let endpoint = spawn_provider(Some("s3cret".to_string())).await;
    let dir = tempfile::tempdir().unwrap();
    let err = run_query(
        Command::Enroll {
            mac: Some("02:00:00:00:00:09".into()),
            token: String::new(), // missing
            out_seed: dir.path().join("seed"),
            out_cert: dir.path().join("cert"),
            out_anchor: dir.path().join("anchor"),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap_err();
    // Format with the full cause chain (`{:#}`) so the provider's "invalid or
    // missing enrollment token" message is visible, not just the top context.
    let err = format!("{err:#}");
    assert!(err.contains("token"), "got: {err}");
}

#[tokio::test]
async fn list_certs_shows_an_enrolled_node() {
    let endpoint = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    run_query(
        Command::Enroll {
            mac: Some("02:00:00:00:00:09".into()),
            token: String::new(),
            out_seed: dir.path().join("seed"),
            out_cert: dir.path().join("cert"),
            out_anchor: dir.path().join("anchor"),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Json,
    )
    .await
    .unwrap();

    let out = run_query(Command::ListCerts, &endpoint, OutputFormat::Json)
        .await
        .expect("list-certs succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let certs = parsed["certs"].as_array().unwrap();
    assert_eq!(certs.len(), 1, "the provider lists the enrolled node");
    // node_mac is the raw bytes of 02:00:00:00:00:09.
    assert_eq!(certs[0]["node_mac"][0], 2);
    assert_eq!(certs[0]["node_mac"][5], 9);
}

#[tokio::test]
async fn list_certs_is_empty_before_any_enrollment() {
    let endpoint = spawn_provider(None).await;
    let out = run_query(Command::ListCerts, &endpoint, OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("no certificates issued"), "got: {out}");
}

#[tokio::test]
async fn revoke_round_trips() {
    let endpoint = spawn_provider(None).await;
    let out = run_query(
        Command::Revoke {
            mac: "02:00:00:00:00:09".into(),
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("revoke succeeds");
    assert!(out.contains("revoked"), "got: {out}");
}

/// Poll `csr list` until a CSR appears pending, then return once it does — the
/// operator's cue to act.
async fn wait_for_pending(endpoint: &Endpoint) {
    for _ in 0..500 {
        let out = run_query(Command::Csr(CsrCommand::List), endpoint, OutputFormat::Json)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        if parsed["pending"].as_array().is_some_and(|p| !p.is_empty()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("CSR never appeared as pending");
}

#[tokio::test]
async fn enroll_waits_for_operator_approval_then_succeeds() {
    let endpoint = spawn_approval_gated_provider().await;
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert");
    let anchor_path = dir.path().join("anchor");

    // Operator: wait for the CSR to be parked as pending, then approve it.
    let approver_endpoint = endpoint.clone();
    let _approver = tokio::spawn(async move {
        wait_for_pending(&approver_endpoint).await;
    });

    // Enrolling node: fails at first, responds with pending
    let err = run_query(
        Command::Enroll {
            mac: Some("02:00:00:00:00:09".into()),
            token: String::new(),
            out_seed: dir.path().join("seed"),
            out_cert: cert_path.clone(),
            out_anchor: anchor_path.clone(),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("CSR still awaiting operator approval"),
        "got: {err}"
    );

    run_query(
        Command::Csr(CsrCommand::Approve {
            mac: "02:00:00:00:00:09".into(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("approve succeeds");

    // Enrolling node: once approved, collects the cert
    let out = run_query(
        Command::Enroll {
            mac: Some("02:00:00:00:00:09".into()),
            token: String::new(),
            out_seed: dir.path().join("seed"),
            out_cert: cert_path.clone(),
            out_anchor: anchor_path.clone(),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("enroll eventually succeeds after approval");
    assert!(out.contains("enrolled"), "got: {out}");

    // The collected cert verifies against the written anchor.
    let anchor = TrustAnchor::from_bytes(&std::fs::read(&anchor_path).unwrap()).unwrap();
    let cert = MembershipCert::from_bytes(&std::fs::read(&cert_path).unwrap()).unwrap();
    assert_eq!(
        anchor.verify_cert(&cert, 500).unwrap().mac.0,
        [0x02, 0, 0, 0, 0, 9]
    );
}

#[tokio::test]
async fn enroll_fails_when_operator_denies() {
    let endpoint = spawn_approval_gated_provider().await;
    let dir = tempfile::tempdir().unwrap();

    let err = run_query(
        Command::Enroll {
            mac: Some("02:00:00:00:00:09".into()),
            token: String::new(),
            out_seed: dir.path().join("seed"),
            out_cert: dir.path().join("cert"),
            out_anchor: dir.path().join("anchor"),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect_err("a denied CSR fails enrollment");
    assert!(
        format!("{err:#}").contains("CSR still awaiting operator approval"),
        "got: {err}"
    );

    run_query(
        Command::Csr(CsrCommand::Deny {
            mac: "02:00:00:00:00:09".into(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();

    let err = run_query(
        Command::Enroll {
            mac: Some("02:00:00:00:00:09".into()),
            token: String::new(),
            out_seed: dir.path().join("seed"),
            out_cert: dir.path().join("cert"),
            out_anchor: dir.path().join("anchor"),
            no_vpn: true,
            print_vpn_command: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect_err("a denied CSR fails enrollment");
    assert!(format!("{err:#}").contains("rejected"), "got: {err}");
}

/// Write a CSR file in the shape `csr request` produces at the node, so these
/// tests consume exactly what an operator would carry to the provider.
fn write_csr(path: &std::path::Path, kp: &Keypair, token: &str) {
    let req = SubmitCsrRequest {
        node_mac: kp.derived_mac().0.to_vec(),
        ed_pubkey: kp.ed_pubkey().to_vec(),
        x_pubkey: kp.x_pubkey().to_vec(),
        enrollment_token: token.to_string(),
    };
    std::fs::write(path, serde_json::to_vec_pretty(&req).unwrap()).unwrap();
}

/// `csr submit` is the middle of the out-of-band chain: it uploads a CSR file
/// that arrived from an unreachable node, and writes back the certificate and
/// anchor to carry home.
///
/// Note what it does *not* need: a membership certificate of its own.
/// `SubmitCsr` sits on the enrollment tier, so an operator can hand a provider
/// a CSR without holding any credential for it — which is what makes this a
/// substitute for `cert approve` and its copy of the mesh root key.
#[tokio::test]
async fn csr_submit_writes_the_certificate_the_provider_issues() {
    let endpoint = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    let request = dir.path().join("request.json");
    let out_cert = dir.path().join("node.cert");
    let out_anchor = dir.path().join("anchor.bin");

    let node = Keypair::from_seed(&[33u8; 32]);
    write_csr(&request, &node, "");

    run_query(
        Command::Csr(CsrCommand::Submit {
            request: request.clone(),
            out_cert: out_cert.clone(),
            out_anchor: out_anchor.clone(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("an auto-approving provider issues on submission");

    let anchor = TrustAnchor::from_bytes(&std::fs::read(&out_anchor).unwrap()).unwrap();
    let cert = MembershipCert::from_bytes(&std::fs::read(&out_cert).unwrap()).unwrap();
    let verified = anchor.verify_cert(&cert, 500).expect("cert verifies");
    assert_eq!(
        verified.ed_pubkey,
        node.ed_pubkey(),
        "the certificate must be bound to the keys the CSR named, not to anything \
         about the operator who carried it"
    );
    assert_eq!(verified.mac, node.derived_mac());
}

/// The download half. A provider that parks requests for approval cannot answer
/// the first submission, so the operator approves in the UI and re-runs the
/// same command against the same file — re-submitting an identical CSR is how
/// the issued certificate is collected, since the protocol has no separate
/// "fetch my certificate" request.
#[tokio::test]
async fn csr_submit_collects_the_certificate_after_an_operator_approves() {
    let endpoint = spawn_approval_gated_provider().await;
    let dir = tempfile::tempdir().unwrap();
    let request = dir.path().join("request.json");
    let out_cert = dir.path().join("node.cert");
    let out_anchor = dir.path().join("anchor.bin");

    let node = Keypair::from_seed(&[44u8; 32]);
    write_csr(&request, &node, "");

    // First upload: parked, and nothing is written.
    let err = run_query(
        Command::Csr(CsrCommand::Submit {
            request: request.clone(),
            out_cert: out_cert.clone(),
            out_anchor: out_anchor.clone(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect_err("a gated provider cannot issue on first submission");
    assert!(
        format!("{err:#}").contains("awaiting operator approval"),
        "got: {err}"
    );
    assert!(
        !out_cert.exists() && !out_anchor.exists(),
        "a pending submission must not leave files an operator could mistake for \
         an issued certificate"
    );

    // The operator approves — here through the API the web/TUI screens call.
    run_query(
        Command::Csr(CsrCommand::Approve {
            mac: node
                .derived_mac()
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();

    // Re-running the identical submission collects the certificate.
    run_query(
        Command::Csr(CsrCommand::Submit {
            request: request.clone(),
            out_cert: out_cert.clone(),
            out_anchor: out_anchor.clone(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("re-submitting an approved CSR collects the certificate");

    let anchor = TrustAnchor::from_bytes(&std::fs::read(&out_anchor).unwrap()).unwrap();
    let cert = MembershipCert::from_bytes(&std::fs::read(&out_cert).unwrap()).unwrap();
    anchor.verify_cert(&cert, 500).expect("cert verifies");
}

/// A refusal must name why. The operator holding the file is not the person who
/// configured the provider, so "rejected" alone leaves them nothing to act on.
#[tokio::test]
async fn csr_submit_surfaces_the_providers_rejection_reason() {
    let endpoint = spawn_provider(Some("the-real-token".to_string())).await;
    let dir = tempfile::tempdir().unwrap();
    let request = dir.path().join("request.json");
    let out_cert = dir.path().join("node.cert");
    let out_anchor = dir.path().join("anchor.bin");

    write_csr(&request, &Keypair::from_seed(&[55u8; 32]), "wrong-token");

    let err = run_query(
        Command::Csr(CsrCommand::Submit {
            request,
            out_cert: out_cert.clone(),
            out_anchor: out_anchor.clone(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect_err("a bad enrollment token is refused");
    let err = format!("{err:#}");
    assert!(err.contains("token"), "got: {err}");
    assert!(!out_cert.exists() && !out_anchor.exists());
}

/// The enrollment token travels *in the CSR file*, written when the request was
/// made at the node — so an operator relaying a file need not know the secret,
/// and `csr submit` takes no token flag of its own.
#[tokio::test]
async fn csr_submit_presents_the_token_carried_in_the_request_file() {
    let endpoint = spawn_provider(Some("the-real-token".to_string())).await;
    let dir = tempfile::tempdir().unwrap();
    let request = dir.path().join("request.json");

    write_csr(&request, &Keypair::from_seed(&[66u8; 32]), "the-real-token");

    run_query(
        Command::Csr(CsrCommand::Submit {
            request,
            out_cert: dir.path().join("node.cert"),
            out_anchor: dir.path().join("anchor.bin"),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("the token in the file admits the request");
}
