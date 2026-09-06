//! End-to-end check that a dashboard poll reads a real node correctly.
//!
//! Spins up the production `wayfinder-server` TLS listener backed by a canned
//! data provider, points a [`NodeConnection`] at it, and asserts the snapshot
//! that comes back. This is what catches an RPC wired into the wrong snapshot
//! field — a mistake that compiles, and that every tab would then render
//! confidently and wrongly.
//!
//! The harness mirrors `libs/wayfinder-client/tests/transport.rs`, whose `Mock`
//! is the reference for a provider that answers every RPC.

#![cfg(feature = "mock-node")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::serve_mock_node;
use common::serve_mock_provider_node;
use wayfinder_web::snapshot::PollScope;
use wayfinder_web::snapshot::build_snapshot;

/// Every table in one poll lands in the field the tabs read it from.
#[tokio::test]
async fn snapshot_reads_every_table_from_a_real_node() {
    let conn = serve_mock_node().await;
    let snap = build_snapshot(&conn, 0, PollScope::Administrator)
        .await
        .unwrap();

    let info = snap.node_info.expect("node info was fetched");
    // The mock answers to the address its own identity key derives, like any
    // real node — not an invented constant.
    assert_eq!(
        info.node_id,
        wayfinder_auth::derive_mac(&[0x11; 32]).0.to_vec()
    );
    assert_eq!(info.num_originators, 2);
    assert!(info.auth_locked);

    assert_eq!(snap.routing.entries.len(), 1);
    assert_eq!(snap.routing.entries[0].tq, 240);
    assert_eq!(snap.routing.entries[0].paths.len(), 1);

    assert_eq!(snap.link_quality.entries.len(), 1);
    assert_eq!(snap.link_quality.entries[0].ewma_quality, Some(200));

    // Distinct gate values, so a table transposed against `link_quality` or
    // `ogm_schedule` shows up rather than coincidentally matching.
    assert_eq!(snap.link_features.entries.len(), 1);
    assert!(snap.link_features.entries[0].tx_ogm);
    assert!(!snap.link_features.entries[0].tx_data);
    assert_eq!(
        snap.link_features.entries[0].tx_keepalive_interval_ms,
        Some(2000)
    );

    assert_eq!(snap.keepalive.entries.len(), 1);
    assert!(snap.keepalive.entries[0].missed);

    assert_eq!(snap.ogm_schedule.entries.len(), 1);
    assert_eq!(snap.ogm_schedule.entries[0].current_interval_ms, 4000);

    assert_eq!(snap.throughput.interfaces.len(), 1);
    assert_eq!(snap.throughput.interfaces[0].rx_bps, 1500.0);
    assert_eq!(snap.throughput.total_tx_fps, 6.0);

    let metrics = snap.metrics.expect("metrics were fetched");
    assert_eq!(metrics.uptime_secs, 7384);
    assert_eq!(metrics.neighbor_count, 1);

    assert!(snap.security.is_some(), "security posture was fetched");
}

/// A non-provider node errors the enrollment RPCs. That has to read as "no
/// provider data" and leave the rest of the poll intact, rather than failing
/// the whole snapshot — the Security tab is one tab, not the dashboard.
#[tokio::test]
async fn snapshot_survives_a_node_that_is_not_a_certificate_authority() {
    let conn = serve_mock_node().await;
    let snap = build_snapshot(&conn, 0, PollScope::Administrator)
        .await
        .unwrap();

    assert!(snap.pending_csrs.is_none());
    assert!(
        snap.node_info.is_some(),
        "the rest of the poll still filled"
    );
}

/// A read-only poll skips both admin-gated queries and still returns every
/// table a viewer is entitled to.
///
/// The node refuses `GetLogs` and `ListVpnPeers` to the viewer tier, and this
/// poll fails whole if any request in it fails — so asking for either would
/// cost a viewer the entire dashboard, not just the pane they cannot see. That
/// is the regression this guards: the fix for issue #32 narrowed the tier, and
/// the client half has to stop asking in the same change.
#[tokio::test]
async fn a_read_only_poll_skips_the_admin_gated_queries() {
    let conn = serve_mock_node().await;

    let snapshot = build_snapshot(&conn, 0, PollScope::ReadOnly)
        .await
        .expect("a read-only poll succeeds rather than failing on a refusal");

    assert!(
        snapshot.logs.is_none(),
        "the log ring is not asked for on a read-only connection"
    );
    assert!(
        snapshot.vpn_peers.is_none(),
        "and neither is the VPN peer table"
    );

    // The tables a viewer *is* entitled to still arrive, so the narrowing cost
    // exactly the two panes it was supposed to and not the dashboard.
    assert!(snapshot.node_info.is_some());
    assert!(snapshot.metrics.is_some());
    assert!(snapshot.security.is_some());
    assert_eq!(snapshot.routing.entries.len(), 1);
}

/// The log cursor advances across polls, so a browser that passes `next_seq`
/// back reads each record once instead of re-reading the ring every second.
#[tokio::test]
async fn snapshot_log_cursor_advances_across_polls() {
    let conn = serve_mock_node().await;

    let first = build_snapshot(&conn, 0, PollScope::Administrator)
        .await
        .unwrap();
    let cursor = first
        .logs
        .as_ref()
        .expect("an administrator's poll carries the log ring")
        .next_seq;

    wayfinder_log::record(
        wayfinder_log::Level::Warn,
        "wayfinder_web::snapshot_test",
        "drop: no route",
    );

    let second = build_snapshot(&conn, cursor, PollScope::Administrator)
        .await
        .unwrap();
    let logs = second
        .logs
        .as_ref()
        .expect("an administrator's poll carries the log ring");
    assert!(
        logs.records
            .iter()
            .any(|r| r.target == "wayfinder_web::snapshot_test"),
        "a record emitted between polls is delivered on the next one"
    );
    assert!(logs.next_seq > cursor, "the resume point moved forward");
}

/// Consecutive polls reuse one connection rather than reconnecting each time —
/// the dashboard polls about once a second, so a fresh TLS handshake per poll
/// would be a self-inflicted load on the node.
#[tokio::test]
async fn snapshot_reuses_the_connection_across_polls() {
    let conn = serve_mock_node().await;

    assert!(!conn.is_connected(), "no connection before the first poll");
    build_snapshot(&conn, 0, PollScope::Administrator)
        .await
        .unwrap();
    assert!(conn.is_connected(), "the first poll left a live connection");
    build_snapshot(&conn, 0, PollScope::Administrator)
        .await
        .unwrap();
    assert!(conn.is_connected(), "and the second reused it");
}

/// The posture and enrollment policy survive the real round trip, and an edit
/// made through the client is visible on the next poll.
///
/// The end-to-end check the render tests cannot make: they seed a snapshot
/// directly, so a field wired into the wrong place on the wire — or a
/// `SetConfig` that reports success without changing anything — passes them
/// and fails here.
#[tokio::test]
async fn a_security_setting_changed_through_the_api_shows_up_on_the_next_poll() {
    let conn = serve_mock_provider_node().await;

    let before = build_snapshot(&conn, 0, PollScope::Administrator)
        .await
        .unwrap()
        .security
        .expect("security posture was fetched");
    assert!(before.require_auth, "the mock node starts fail-closed");
    let policy = before.enrollment.expect("the mock node is a provider");
    assert!(policy.enrollment_token_set);
    assert_eq!(policy.cert_ttl_secs, 86_400);

    conn.run(async |client| client.set_require_auth(false).await)
        .await
        .expect("the node accepted the change");

    let after = build_snapshot(&conn, 0, PollScope::Administrator)
        .await
        .unwrap()
        .security
        .expect("security posture was fetched");
    assert!(
        !after.require_auth,
        "the next poll reports the node's new state, not the old one"
    );
}

/// Clearing the enrollment token opens enrollment, and the node reports that
/// rather than continuing to claim a token is required.
#[tokio::test]
async fn clearing_the_enrollment_token_is_reported_back() {
    use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicy;
    use wayfinder_protos::wayfinder::v1alpha::enrollment_policy::EnrollmentTokenUpdate;

    let conn = serve_mock_provider_node().await;

    conn.run(async |client| {
        client
            .set_enrollment_policy(EnrollmentPolicy {
                enrollment_token_update: Some(EnrollmentTokenUpdate::EnrollmentTokenCleared(true)),
                ..Default::default()
            })
            .await
    })
    .await
    .expect("the node accepted the change");

    let policy = build_snapshot(&conn, 0, PollScope::Administrator)
        .await
        .unwrap()
        .security
        .expect("security posture was fetched")
        .enrollment
        .expect("the mock node is a provider");
    assert!(!policy.enrollment_token_set);
}

/// A rejected setting is an error, not a silent no-op: a zero certificate
/// lifetime would issue certificates that have already expired.
#[tokio::test]
async fn a_rejected_enrollment_policy_surfaces_as_an_error() {
    use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicy;

    let conn = serve_mock_provider_node().await;

    let result = conn
        .run(async |client| {
            client
                .set_enrollment_policy(EnrollmentPolicy {
                    cert_ttl_secs: Some(0),
                    ..Default::default()
                })
                .await
        })
        .await;

    assert!(result.is_err(), "a zero certificate lifetime is refused");
}
