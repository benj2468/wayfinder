//! Shared setup for the integration tests.
//!
//! The stand-in node itself lives in `src/mock.rs` behind the `mock-node`
//! feature, so the tests and the runnable `examples/mock_node.rs` drive the same
//! one — a canned value that only the tests can see is a canned value the
//! dashboard was never actually rendered against.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::sync::Arc;

use leptos::config::LeptosOptions;
use wayfinder_client::Endpoint;
use wayfinder_client::Identity;
use wayfinder_web::conn::NodeConnection;
use wayfinder_web::conn::Target;

/// Start the stand-in node and return a connection pointed at it.
pub async fn serve_mock_node() -> Arc<NodeConnection> {
    let (addr, node_key) = wayfinder_web::mock::serve_mock_node().await;

    Arc::new(NodeConnection::new(Target::Tls(Endpoint {
        addr,
        node_key,
        identity: Identity {
            // Bootstrap: an un-enrolled node is reached by proving its own key.
            seed: wayfinder_web::mock::NODE_SEED,
            cert: Vec::new(),
        },
    })))
}

/// Minimal [`LeptosOptions`] for driving the router in tests.
///
/// The asset paths never resolve here — no test requests `/pkg/*` — so only
/// `output_name` has to be right, and it only affects the URLs in the emitted
/// markup.
pub fn test_leptos_options() -> LeptosOptions {
    LeptosOptions::builder()
        .output_name("wayfinder-web")
        .build()
}
