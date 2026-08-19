//! Joining a mesh from the dashboard, against a real provider.
//!
//! The workflow this exists for, end to end: an open node's dashboard asks a
//! certificate authority to admit it, an operator approves the request on the
//! authority's own dashboard, and the node comes back holding a certificate —
//! without ever having changed identity.
//!
//! Both ends are the production stack. The node and the authority each run the
//! real `wayfinder-server` TLS listener, the authority runs the real
//! `CertAuthority`, and the request travels the real management protocol, so
//! what is under test is the whole path rather than a stub of it.

#![cfg(feature = "mock-node")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use wayfinder_client::Client;
use wayfinder_client::Identity;
use wayfinder_web::conn::NodeConnection;
use wayfinder_web::enroll::EnrollmentOutcome;
use wayfinder_web::enroll::ProviderTarget;
use wayfinder_web::enroll::request;
use wayfinder_web::mock::MOCK_MESH_ID;
use wayfinder_web::mock::Mock;

/// Start an auto-approving authority — one that signs on submission — and
/// describe it the way the dashboard's form does: an address, a pinned key as
/// hex, and a token.
async fn serve_authority() -> ProviderTarget {
    target(Mock::authority(true, None)).await
}

/// Start an authority in the closed posture, which holds each request until an
/// operator approves it.
///
/// A named helper rather than a bool at the call site: which of the two paths a
/// test drives is the most important thing about it, and `true`/`false` in
/// argument position does not say.
async fn serve_approval_gated_authority() -> ProviderTarget {
    target(Mock::authority(false, None)).await
}

/// Serve `mock` and describe it as a provider target the enrollment form could
/// have been filled in with.
async fn target(mock: Mock) -> ProviderTarget {
    let (addr, node_key) = wayfinder_web::mock::serve_mock_node_with(mock).await;
    ProviderTarget {
        address: addr.to_string(),
        node_key: node_key.iter().map(|b| format!("{b:02x}")).collect(),
        token: String::new(),
    }
}

/// As [`serve_authority`], but the provider requires `token` for a request to
/// be admitted at all. The returned target's own `token` field is left empty —
/// each test fills in what it wants to present, which is the point.
async fn serve_token_gated_authority(token: &str) -> ProviderTarget {
    target(Mock::authority(true, Some(token))).await
}

/// The node's security posture as it reports it right now.
async fn posture(
    conn: &NodeConnection,
) -> wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse {
    conn.run(async |client| client.security_status().await)
        .await
        .unwrap()
}

/// Approve the one request an authority is holding, the way an operator does
/// from its own dashboard.
async fn approve_the_pending_request(target: &ProviderTarget) {
    let mut admin = Client::connect_tls(
        target.address.parse().unwrap(),
        &hex(&target.node_key),
        // The authority's own key: full management access, which is what the
        // operator's dashboard has.
        &Identity {
            seed: wayfinder_web::mock::NODE_SEED,
            cert: Vec::new(),
        },
    )
    .await
    .unwrap();

    let pending = admin.list_pending_csrs().await.unwrap();
    assert_eq!(pending.pending.len(), 1, "one node is waiting to join");
    admin
        .approve_csr(&pending.pending[0].node_mac)
        .await
        .unwrap();
}

/// Decode a 64-character hex key back to bytes.
fn hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// An authority that signs on submission admits the node in one step, and the
/// node comes back a member of that mesh.
#[tokio::test]
async fn an_open_node_joins_a_mesh_and_reports_itself_a_member() {
    let node: Arc<NodeConnection> = common::serve_unauthenticated_mock_node().await;
    let provider = serve_authority().await;

    let before = posture(&node).await;
    assert!(!before.auth_enabled, "the node starts with no certificate");

    let outcome = request(&node, &provider).await.unwrap();
    assert_eq!(
        outcome,
        EnrollmentOutcome::Enrolled {
            mesh_id: MOCK_MESH_ID
        }
    );

    let after = posture(&node).await;
    assert!(after.auth_enabled, "the certificate was installed");
    assert_eq!(after.mesh_id, MOCK_MESH_ID);
}

/// The property the whole design turns on: enrolling certifies the identity the
/// node already had. Its keys are untouched, and the certificate it now holds
/// is bound to the MAC its peers already know it by — so joining a mesh does
/// not move it, and nothing has to restart for the two to agree.
#[tokio::test]
async fn joining_certifies_the_identity_the_node_already_had() {
    let node = common::serve_unauthenticated_mock_node().await;
    let provider = serve_authority().await;

    let before = posture(&node).await;
    let node_mac = node
        .run(async |client| client.node_info().await)
        .await
        .unwrap()
        .node_id;

    request(&node, &provider).await.unwrap();

    let after = posture(&node).await;
    assert_eq!(
        after.own_ed_pubkey, before.own_ed_pubkey,
        "the node kept its own identity key"
    );
    assert_eq!(after.own_x_pubkey, before.own_x_pubkey);
    assert_eq!(
        after.node_mac, node_mac,
        "the certificate is bound to the address the node was already running under"
    );
}

/// The path with a person in the middle, which is the one an authority is
/// normally configured for: the request is parked, the dashboard reports that
/// rather than a failure, and asking again after an operator approves collects
/// the certificate.
#[tokio::test]
async fn a_held_request_is_collected_once_an_operator_approves_it() {
    let node = common::serve_unauthenticated_mock_node().await;
    let provider = serve_approval_gated_authority().await;

    assert_eq!(
        request(&node, &provider).await.unwrap(),
        EnrollmentOutcome::AwaitingApproval,
        "waiting for a person is an outcome, not an error"
    );
    assert!(
        !posture(&node).await.auth_enabled,
        "nothing is installed while the request is only pending"
    );

    // Asking again before anyone approves must not queue a second request, and
    // must not start looking like progress.
    assert_eq!(
        request(&node, &provider).await.unwrap(),
        EnrollmentOutcome::AwaitingApproval
    );

    approve_the_pending_request(&provider).await;

    assert_eq!(
        request(&node, &provider).await.unwrap(),
        EnrollmentOutcome::Enrolled {
            mesh_id: MOCK_MESH_ID
        },
        "the same request, re-submitted, is how the certificate is collected"
    );
    assert!(posture(&node).await.auth_enabled);
}

/// A mistyped provider key is named as such, before anything is opened — not
/// surfaced later as a handshake failure against a provider that is fine.
#[tokio::test]
async fn a_malformed_provider_key_is_reported_as_one() {
    let node = common::serve_unauthenticated_mock_node().await;
    let mut provider = serve_authority().await;
    provider.node_key = "not-a-key".to_string();

    let err = format!("{:#}", request(&node, &provider).await.unwrap_err());
    assert!(err.contains("64 hex characters"), "got: {err}");
    assert!(!posture(&node).await.auth_enabled);
}

/// Pinning is what stops a stranger answering in the provider's place and
/// enrolling the node into a mesh of its own: a key that is well-formed but
/// wrong fails the handshake, and nothing is installed.
#[tokio::test]
async fn a_provider_that_does_not_match_its_pinned_key_is_refused() {
    let node = common::serve_unauthenticated_mock_node().await;
    let mut provider = serve_authority().await;
    provider.node_key = "aa".repeat(32);

    assert!(request(&node, &provider).await.is_err());
    assert!(
        !posture(&node).await.auth_enabled,
        "nothing is installed from a provider that could not be verified"
    );
}

/// The token is the primary admission control for the whole feature: a
/// request presenting the wrong one is refused outright, as
/// `EnrollmentOutcome::Rejected` rather than an error or a silent park, and
/// nothing is installed on the node.
#[tokio::test]
async fn a_wrong_enrollment_token_is_rejected() {
    let node = common::serve_unauthenticated_mock_node().await;
    let mut provider = serve_token_gated_authority("the-real-token").await;
    provider.token = "not-the-real-token".to_string();

    match request(&node, &provider).await.unwrap() {
        EnrollmentOutcome::Rejected { reason } => {
            assert!(!reason.is_empty(), "the provider's reason is reported")
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    assert!(
        !posture(&node).await.auth_enabled,
        "a rejected request installs nothing"
    );
}

/// The same request, with the right token, is admitted — proving the token is
/// actually carried to the provider rather than dropped on the floor. Without
/// this, a `request` that silently discarded `provider.token` would still
/// pass every other test in this file, since none of the others configure a
/// provider that checks it.
#[tokio::test]
async fn the_right_enrollment_token_is_admitted() {
    let node = common::serve_unauthenticated_mock_node().await;
    let mut provider = serve_token_gated_authority("the-real-token").await;
    provider.token = "the-real-token".to_string();

    assert_eq!(
        request(&node, &provider).await.unwrap(),
        EnrollmentOutcome::Enrolled {
            mesh_id: MOCK_MESH_ID
        }
    );
    assert!(posture(&node).await.auth_enabled);
}
