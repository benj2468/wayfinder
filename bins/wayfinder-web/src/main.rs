//! The `wayfinder-web` server binary.
//!
//! Serves the dashboard over plain HTTP and is the only party that speaks the
//! management API: it holds the mesh identity and the node connection, and the
//! browser reaches the node exclusively through `#[server]` functions.
//!
//! That makes the listen address a security boundary. It defaults to loopback,
//! because there is no login here — anyone who can reach the port has whatever
//! access the configured identity has. Exposing it beyond the host is a
//! reverse-proxy's job, and binding elsewhere logs a warning to say so.
//!
//! The node-facing arguments mirror `wayfinder-tui`'s, so an operator who knows
//! how to point the TUI at a node already knows how to point this at one.

// The whole binary is server-side. Under `--features hydrate` (the wasm build)
// this file compiles to an empty `main`, which is also what keeps a plain
// `cargo build --workspace` — where neither feature is on — green.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// Run the dashboard server.
#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use clap::Parser;
    use leptos::prelude::*;
    use tracing::info;
    use tracing::warn;
    use wayfinder_client::Endpoint;
    use wayfinder_web::conn::NodeConnection;
    use wayfinder_web::conn::Target;
    use wayfinder_web::server::build_router;

    /// Command-line arguments.
    #[derive(Parser, Debug)]
    #[command(about = "Web dashboard for the Wayfinder management API")]
    struct Args {
        /// Address to serve the dashboard on.
        ///
        /// Loopback by default: the dashboard has no login of its own, so a
        /// non-loopback bind exposes the node to anyone who can reach the port.
        #[arg(long, env = "WAYFINDER_WEB_LISTEN", default_value = "127.0.0.1:8080")]
        listen: SocketAddr,

        /// TLS address of the node's management API.
        #[arg(long, default_value = "127.0.0.1:7700")]
        addr: SocketAddr,

        /// Path to this dashboard's 32-byte Ed25519 identity seed (secret),
        /// presented as an RFC 7250 raw public key in the TLS handshake. To
        /// reach an un-enrolled node, point this at the node's own identity
        /// seed and omit `--cert`. Required unless `--serial` is used.
        #[arg(
            long,
            env = "WAYFINDER_WEB_IDENTITY",
            default_value = "/var/lib/wayfinder/identity.seed"
        )]
        identity: Option<PathBuf>,

        /// Serial port of an embedded node's *unauthenticated* management API
        /// (e.g. `/dev/ttyACMX` for an nRF52840 over its USB CDC-ACM port).
        /// The connection carries no TLS and no authentication, so the TLS
        /// arguments cannot be combined with it; `--addr` is simply unused.
        #[arg(long, conflicts_with_all = ["identity", "cert", "node_key"])]
        serial: Option<String>,

        /// Baud rate for `--serial`. A formality `tokio_serial` requires to
        /// open the port rather than a rate a USB CDC-ACM device enforces.
        #[arg(long, default_value_t = 115_200)]
        baud: u32,

        /// Path to this dashboard's membership certificate. Omit to reach an
        /// un-enrolled node by proving the node's own key.
        #[arg(long, env = "WAYFINDER_WEB_CERT")]
        cert: Option<PathBuf>,

        /// The node's Ed25519 public key (64 hex chars) to pin. Defaults to the
        /// public key of `--identity`, which is correct when bootstrapping a
        /// node with its own seed; pass it to reach a *different* node.
        #[arg(long, env = "WAYFINDER_WEB_NODE_KEY")]
        node_key: Option<String>,
    }

    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let target = match &args.serial {
        Some(path) => Target::Serial {
            path: path.clone(),
            baud: args.baud,
        },
        None => {
            let identity = args.identity.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--identity is required unless --serial is given")
            })?;
            Target::Tls(Endpoint::load(
                args.addr,
                identity,
                args.cert.as_deref(),
                args.node_key.as_deref(),
            )?)
        }
    };

    // No I/O yet: the first poll establishes the connection, so the dashboard
    // starts even with the node down and recovers on its own.
    let conn = Arc::new(NodeConnection::new(target));
    info!(node = %conn.label(), "node target configured");

    // Everything but the address comes from the environment cargo-leptos sets
    // (site root, package dir, hash file), so the binary finds its own assets.
    let mut leptos_options = get_configuration(None)?.leptos_options;
    leptos_options.site_addr = args.listen;

    if !args.listen.ip().is_loopback() {
        warn!(
            listen = %args.listen,
            "dashboard bound to a non-loopback address; it has no authentication of its own, \
             so anyone who can reach this port has the access its node identity carries"
        );
    }

    let app = build_router(leptos_options, conn);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    info!(listen = %args.listen, "dashboard listening");
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

/// Stub entry point for the non-server builds.
///
/// The wasm bundle enters through `wayfinder_web::hydrate` rather than `main`,
/// and a featureless `cargo build --workspace` has no server to run — both need
/// a `main` to exist, and neither needs it to do anything.
#[cfg(not(feature = "ssr"))]
fn main() {
    panic!("Running wayfinder-web without ssr.");
}
