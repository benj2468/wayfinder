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
use wayfinder_web::server::HostPolicy;

/// Start the stand-in node (a plain member) and return a connection to it.
pub async fn serve_mock_node() -> Arc<NodeConnection> {
    connect(wayfinder_web::mock::serve_mock_node().await)
}

/// Start the stand-in node as a certificate authority — with an enrollment
/// policy and a CSR queue — and return a connection to it.
pub async fn serve_mock_provider_node() -> Arc<NodeConnection> {
    connect(wayfinder_web::mock::serve_mock_provider_node().await)
}

/// Start the stand-in node with mesh authentication switched off — a node with
/// an identity but no certificate, which is what asks to join a mesh.
pub async fn serve_unauthenticated_mock_node() -> Arc<NodeConnection> {
    connect(
        wayfinder_web::mock::serve_mock_node_with(wayfinder_web::mock::Mock::unauthenticated())
            .await,
    )
}

/// Wrap a connection in the static-credential access every test that is not
/// about logging in uses — today's dashboard, with one identity for the whole
/// process.
pub fn static_access(conn: Arc<NodeConnection>) -> Arc<wayfinder_web::session::Access> {
    Arc::new(wayfinder_web::session::Access::Static(conn))
}

/// A router in **login mode** against the login-capable stand-in node, which
/// is its own certificate authority.
///
/// Node and provider are the same host here, as they are for the simulation's
/// provider node and for any single-node deployment. What that costs is the
/// ability to notice a mix-up between the two addresses; what it buys is a test
/// that needs one listener instead of two, and the mix-up is a wiring mistake in
/// `main.rs` rather than in anything this exercises.
pub async fn login_router() -> axum::Router {
    let (addr, node_key) = wayfinder_web::mock::serve_mock_login_node().await;
    let endpoint = wayfinder_web::session::PinnedNode {
        addr,
        key: node_key,
    };
    let access = Arc::new(wayfinder_web::session::Access::Login(Arc::new(
        wayfinder_web::session::SessionStore::new(endpoint, endpoint),
    )));
    wayfinder_web::server::build_router(test_leptos_options(), access, test_hosts())
}

/// A router in login mode whose **provider is not there**: the node is the real
/// mock listener, and the certificate authority is an address nothing is
/// listening on.
///
/// The shape an offline deployment actually has — the node in front of you is
/// fine, the authority behind it is not — and the only configuration in which
/// "signing in with a credential file needs no provider" can be *proved* rather
/// than assumed. A test against a live provider would pass just as happily if
/// the bundle sign-in quietly asked it anyway.
///
/// The dead address is a port bound and immediately released, so it is one
/// nothing on the machine is using rather than a number picked and hoped over.
pub async fn login_router_with_dead_provider() -> axum::Router {
    let (addr, node_key) = wayfinder_web::mock::serve_mock_login_node().await;
    let dead = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let access = Arc::new(wayfinder_web::session::Access::Login(Arc::new(
        wayfinder_web::session::SessionStore::new(
            wayfinder_web::session::PinnedNode {
                addr,
                key: node_key,
            },
            wayfinder_web::session::PinnedNode {
                addr: dead,
                key: node_key,
            },
        ),
    )));
    wayfinder_web::server::build_router(test_leptos_options(), access, test_hosts())
}

/// Wrap a bound mock node's address and pinned key in a connection.
fn connect((addr, node_key): (std::net::SocketAddr, [u8; 32])) -> Arc<NodeConnection> {
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
/// The asset paths do not resolve here — most tests never request `/pkg/*` —
/// so only `output_name` has to be right, and it only affects the URLs in the
/// emitted markup. Use [`SiteRoot`] for a test that needs a real bundle on
/// disk to fetch.
pub fn test_leptos_options() -> LeptosOptions {
    LeptosOptions::builder()
        .output_name("wayfinder-web")
        .build()
}

/// The address the test router is treated as bound to.
///
/// Doubles as the `Host` and `Origin` a same-origin request carries, so a test
/// that needs to look like the dashboard's own poll has one name to use.
pub const TEST_LISTEN: &str = "127.0.0.1:8080";

/// The host allowlist for a router bound at [`TEST_LISTEN`].
pub fn test_hosts() -> HostPolicy {
    HostPolicy::for_listen(TEST_LISTEN.parse().unwrap())
}

/// A throwaway `site-root` holding a stand-in wasm bundle, so a test can
/// request `/pkg/wayfinder-web.wasm` and get a real file back.
///
/// Removed on drop: leaving these behind would accumulate a directory per test
/// run in the system temp dir.
pub struct SiteRoot {
    /// The directory the router is pointed at.
    path: std::path::PathBuf,
}

impl SiteRoot {
    /// Create the directory and write a stand-in bundle into `pkg/`.
    pub fn new() -> Self {
        let unique = format!(
            "wayfinder-web-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(path.join("pkg")).unwrap();
        std::fs::write(path.join("pkg").join("wayfinder-web.wasm"), b"\0asm-stub").unwrap();
        Self { path }
    }

    /// [`LeptosOptions`] pointed at this directory.
    pub fn options(&self) -> LeptosOptions {
        LeptosOptions::builder()
            .output_name("wayfinder-web")
            .site_root(self.path.to_string_lossy().into_owned())
            .build()
    }
}

impl Drop for SiteRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
