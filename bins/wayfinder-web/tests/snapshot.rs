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
use wayfinder_web::snapshot::build_snapshot;

/// Every table in one poll lands in the field the tabs read it from.
#[tokio::test]
async fn snapshot_reads_every_table_from_a_real_node() {
    let conn = serve_mock_node().await;
    let snap = build_snapshot(&conn, 0).await.unwrap();

    let info = snap.node_info.expect("node info was fetched");
    assert_eq!(info.node_id, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    assert_eq!(info.num_originators, 2);
    assert!(info.auth_locked);

    assert_eq!(snap.routing.entries.len(), 1);
    assert_eq!(snap.routing.entries[0].tq, 240);
    assert_eq!(snap.routing.entries[0].paths.len(), 1);

    assert_eq!(snap.link_quality.entries.len(), 1);
    assert_eq!(snap.link_quality.entries[0].ewma_quality, 200);

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
    let snap = build_snapshot(&conn, 0).await.unwrap();

    assert!(snap.pending_csrs.is_none());
    assert!(
        snap.node_info.is_some(),
        "the rest of the poll still filled"
    );
}

/// The log cursor advances across polls, so a browser that passes `next_seq`
/// back reads each record once instead of re-reading the ring every second.
#[tokio::test]
async fn snapshot_log_cursor_advances_across_polls() {
    let conn = serve_mock_node().await;

    let first = build_snapshot(&conn, 0).await.unwrap();
    let cursor = first.logs.next_seq;

    wayfinder_log::record(
        wayfinder_log::Level::Warn,
        "wayfinder_web::snapshot_test",
        "drop: no route",
    );

    let second = build_snapshot(&conn, cursor).await.unwrap();
    assert!(
        second
            .logs
            .records
            .iter()
            .any(|r| r.target == "wayfinder_web::snapshot_test"),
        "a record emitted between polls is delivered on the next one"
    );
    assert!(
        second.logs.next_seq > cursor,
        "the resume point moved forward"
    );
}

/// Consecutive polls reuse one connection rather than reconnecting each time —
/// the dashboard polls about once a second, so a fresh TLS handshake per poll
/// would be a self-inflicted load on the node.
#[tokio::test]
async fn snapshot_reuses_the_connection_across_polls() {
    let conn = serve_mock_node().await;

    assert!(!conn.is_connected(), "no connection before the first poll");
    build_snapshot(&conn, 0).await.unwrap();
    assert!(conn.is_connected(), "the first poll left a live connection");
    build_snapshot(&conn, 0).await.unwrap();
    assert!(conn.is_connected(), "and the second reused it");
}
