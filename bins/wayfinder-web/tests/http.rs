//! Checks the HTTP surface the browser actually talks to.
//!
//! `tests/snapshot.rs` proves the node-facing half — that a poll reads a real
//! node correctly. This proves the browser-facing half: that the server function
//! is routed, that the node connection reaches it through leptos context, and
//! that what comes back deserializes into the same [`NodeSnapshot`] the browser
//! will decode.
//!
//! Between them is the bug this file exists for: everything can be individually
//! correct while the context is provided on only one of the two router arms, so
//! the dashboard renders and every poll fails.
//!
//! The router is driven in-process with `tower`'s `oneshot` rather than over a
//! socket — same code path, no port to race on.

#![cfg(feature = "mock-node")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use tower::ServiceExt;
use wayfinder_web::snapshot::NodeSnapshot;

/// A poll issued the way the browser issues it comes back as a decodable
/// snapshot.
#[tokio::test]
async fn fetch_snapshot_server_fn_answers_over_http() {
    let conn = common::serve_mock_node().await;
    let app = wayfinder_web::server::build_router(common::test_leptos_options(), conn);

    let response = app
        .oneshot(
            Request::post("/api/snapshot")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("accept", "application/json")
                .body(Body::from("since_seq=0"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the server function is routed and the connection reached it"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let snapshot: NodeSnapshot = serde_json::from_slice(&body)
        .expect("the response is the snapshot the browser will decode");

    assert_eq!(snapshot.routing.entries.len(), 1);
    assert_eq!(
        snapshot
            .node_info
            .expect("node info present")
            .num_originators,
        2
    );
}

/// The dashboard page itself still renders — the server-function route must not
/// shadow the page routes.
#[tokio::test]
async fn dashboard_page_renders() {
    let conn = common::serve_mock_node().await;
    let app = wayfinder_web::server::build_router(common::test_leptos_options(), conn);

    let response = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("wf-tabs"),
        "the tab bar rendered: {html:.400}"
    );
}

/// Every tab route is served, rather than falling through to the 404 view.
///
/// A typo'd route path renders the fallback with a 200, so status alone would
/// not catch it — the tab bar is what proves the shell rendered around a real
/// route.
#[tokio::test]
async fn every_tab_route_is_served() {
    for path in [
        "/",
        "/routing",
        "/link-quality",
        "/links",
        "/metrics",
        "/security",
        "/logs",
    ] {
        let conn = common::serve_mock_node().await;
        let app = wayfinder_web::server::build_router(common::test_leptos_options(), conn);

        let response = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "{path} is served");

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("wf-tabs"), "{path} rendered the shell");
        assert!(!html.contains("Not found."), "{path} is a real route");
    }
}

/// A gate flip reaches the node over the same server-function path.
///
/// The read path and the write path share the connection but not the code, so
/// a snapshot that works proves nothing about a mutation that does not.
#[tokio::test]
async fn set_link_gate_server_fn_answers_over_http() {
    let conn = common::serve_mock_node().await;
    let app = wayfinder_web::server::build_router(common::test_leptos_options(), conn);

    let response = app
        .oneshot(
            Request::post("/api/set_link_gate")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("accept", "application/json")
                .body(Body::from("iface_idx=0&gate=TxOgm&value=false"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the mutation is routed and reached the node"
    );
}

/// The favicon is served from the crate's own route rather than the static-file
/// fallback, so it resolves in every deployment: a plain `cargo build` of the
/// `ssr` binary has no populated `site-root` to serve it from.
#[tokio::test]
async fn favicon_is_served() {
    let conn = common::serve_mock_node().await;
    let app = wayfinder_web::server::build_router(common::test_leptos_options(), conn);

    let response = app
        .oneshot(Request::get("/favicon.svg").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("image/svg+xml"),
        "served as an image, not as the fallback's text/html error page"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("<svg"),
        "the response body is the mark itself"
    );
}

/// The page points at that favicon. Serving it and linking it are separate
/// mistakes: either alone leaves a blank tab icon.
#[tokio::test]
async fn dashboard_page_links_the_favicon() {
    let conn = common::serve_mock_node().await;
    let app = wayfinder_web::server::build_router(common::test_leptos_options(), conn);

    let response = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let markup = String::from_utf8_lossy(&body);

    assert!(
        markup.contains(r#"rel="icon""#),
        "the document declares a favicon"
    );
    assert!(
        markup.contains("/favicon.svg"),
        "and points it at the route that serves one"
    );
}

/// The header carries the mark, not just the wordmark.
#[tokio::test]
async fn dashboard_page_renders_the_logo() {
    let conn = common::serve_mock_node().await;
    let app = wayfinder_web::server::build_router(common::test_leptos_options(), conn);

    let response = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let markup = String::from_utf8_lossy(&body);

    assert!(
        markup.contains("wf-logo"),
        "the header renders the logo component"
    );
    assert!(
        markup.contains(wayfinder_web::components::logo::MARK_PATH),
        "and it draws the real mark geometry"
    );
}
