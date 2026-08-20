//! The `wayfinder-web` server binary.
//!
//! Serves the dashboard over plain HTTP and is the only party that speaks the
//! management API: it holds the credential and the node connection, and the
//! browser reaches the node exclusively through `#[server]` functions.
//!
//! # Which credential — the one argument that decides everything else
//!
//! `--provider` selects **login mode**: the dashboard holds no credential of
//! its own, and a person signs in to obtain a short-lived session certificate
//! from the mesh's certificate authority. Nothing is reachable without one.
//!
//! Without it the dashboard runs on a **static credential**: `--identity` and
//! `--cert`, held by the process and shared by everyone who can reach the port.
//! That mode is kept deliberately (§8.3 of
//! `docs/design/06-management-api-authentication.md`) because two deployments
//! have no login available to them and no other way in — an un-enrolled node,
//! which has no user store, and an embedded node reached over `--serial`, which
//! has no authentication at all. It is announced at startup as what it is.
//!
//! Either way the listen address is a security boundary, because this process
//! terminates no TLS of its own: it defaults to loopback, and exposing it
//! beyond the host is a reverse-proxy's job.
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
    use wayfinder_web::server::HostPolicy;
    use wayfinder_web::server::build_router;
    use wayfinder_web::session::Access;
    use wayfinder_web::session::PinnedNode;
    use wayfinder_web::session::SessionStore;

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

        /// An extra `Host` name to answer to, beyond the loopback names and
        /// `--listen`'s own address. Repeatable, or comma-separated.
        ///
        /// Needed for the reverse proxy a non-loopback deployment is supposed
        /// to sit behind, since the browser then names the proxy rather than
        /// this process. Requests naming anything else are refused: a page on
        /// any site can point a name it controls at this address, and the
        /// `Host` it sends is the only part of that it cannot choose.
        #[arg(
            long = "allowed-host",
            env = "WAYFINDER_WEB_ALLOWED_HOSTS",
            value_delimiter = ','
        )]
        allowed_host: Vec<String>,

        /// TLS address of the node's management API.
        #[arg(long, default_value = "127.0.0.1:7700")]
        addr: SocketAddr,

        /// TLS address of the certificate authority a viewer signs in to.
        ///
        /// Given, this dashboard runs in **login mode**: it holds no credential
        /// of its own, and each viewer obtains a short-lived session
        /// certificate by signing in with a user name, password and
        /// authenticator code. Nothing but the sign-in page is reachable
        /// without one, which is what makes a shared or exposed dashboard safe
        /// in a way the static credential below never is.
        ///
        /// Often, but not always, the same node as `--addr`: the accounts live
        /// wherever the mesh's certificate authority runs, and a dashboard may
        /// be pointed at any node in the mesh.
        #[arg(
            long,
            env = "WAYFINDER_WEB_PROVIDER",
            conflicts_with_all = ["identity", "cert", "serial"]
        )]
        provider: Option<SocketAddr>,

        /// The provider's Ed25519 public key (64 hex chars) to pin. Defaults to
        /// `--node-key`, which is correct when the node being viewed is itself
        /// the certificate authority.
        ///
        /// Not optional in substance: a sign-in sends a password to whatever
        /// answers at `--provider`, so something has to say which host that is
        /// allowed to be.
        #[arg(long, env = "WAYFINDER_WEB_PROVIDER_KEY", requires = "provider")]
        provider_key: Option<String>,

        /// Path to this dashboard's 32-byte Ed25519 identity seed (secret),
        /// presented as an RFC 7250 raw public key in the TLS handshake. To
        /// reach an un-enrolled node, point this at the node's own identity
        /// seed and omit `--cert`.
        ///
        /// The **static credential**: one identity, held by the process and
        /// shared by every viewer that can reach the port. Used when
        /// `--provider` is not given.
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
        ///
        /// Required in login mode: there is no identity to derive a default
        /// from, and an unpinned node is one anything on the path may answer
        /// for.
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

    // Which credential this dashboard runs on, decided once, here. Every
    // `#[server]` function then reaches the node through whichever this is,
    // rather than each rediscovering the mode for itself.
    let access = Arc::new(match (&args.serial, args.provider) {
        // Serial: no TLS, no authentication and no provider to log in to. The
        // port itself is the credential, which is why it is a debug interface.
        (Some(path), _) => {
            let conn = NodeConnection::new(Target::Serial {
                path: path.clone(),
                baud: args.baud,
            });
            info!(node = %conn.label(), "node target configured (serial, unauthenticated)");
            Access::Static(Arc::new(conn))
        }

        // Login mode: this process holds no credential at all. Both endpoints
        // are pinned by key, and neither key can be defaulted from an identity
        // — there is none.
        (None, Some(provider_addr)) => {
            let node_key = args.node_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "--node-key is required with --provider: a login holds no identity to \
                     default the node's pinned key from"
                )
            })?;
            let node_key = wayfinder_client::parse_key32(node_key)
                .map_err(|e| anyhow::anyhow!("parsing --node-key: {e}"))?;
            let provider_key = match args.provider_key.as_deref() {
                Some(hex) => wayfinder_client::parse_key32(hex)
                    .map_err(|e| anyhow::anyhow!("parsing --provider-key: {e}"))?,
                // The node being viewed is its own certificate authority, which
                // is the single-node case and the simulation's.
                None => node_key,
            };
            info!(
                node = %args.addr,
                provider = %provider_addr,
                "login mode: viewers sign in for their own short-lived session certificate"
            );
            Access::Login(Arc::new(SessionStore::new(
                PinnedNode {
                    addr: args.addr,
                    key: node_key,
                },
                PinnedNode {
                    addr: provider_addr,
                    key: provider_key,
                },
            )))
        }

        // Static credential: one identity for the whole process.
        (None, None) => {
            let identity = args.identity.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--identity is required unless --serial or --provider is given")
            })?;
            let conn = NodeConnection::new(Target::Tls(Endpoint::load(
                args.addr,
                identity,
                args.cert.as_deref(),
                args.node_key.as_deref(),
            )?));
            // Which credentials are configured, not just the address.
            //
            // A node that has been enrolled refuses any management client that
            // cannot present an *admin* membership certificate, and it
            // deliberately answers with a bare "authentication denied" — the
            // reason stays in the node's log so an unauthenticated peer cannot
            // use the response to probe. That is the right call there and it
            // leaves this side with nothing to report, so the next best thing
            // is to say up front what was presented. "cert: none" beside a
            // denial is the whole diagnosis: bootstrap credentials against a
            // node that has outgrown them.
            info!(
                node = %conn.label(),
                identity = ?args.identity,
                cert = ?args.cert,
                pinned_node_key = args.node_key.is_some(),
                "node target configured"
            );
            if args.cert.is_none() {
                info!(
                    "no --cert given: authenticating with the identity's own key, which only an \
                     un-enrolled node accepts. An enrolled node needs an admin certificate."
                );
            }
            // Said every time, not only on a non-loopback bind: this is the
            // mode where the process *is* the credential, so whoever reaches
            // the port inherits it whole — with no sign-in to pass, nothing
            // that expires, and nothing to revoke short of restarting this
            // process. Pass --provider to make each viewer bring their own.
            warn!(
                "static credential: every viewer of this dashboard shares the identity it was \
                 started with, and there is no sign-in to keep anyone out"
            );
            Access::Static(Arc::new(conn))
        }
    });

    // Everything but the address comes from the environment cargo-leptos sets
    // (site root, package dir, hash file), so the binary finds its own assets.
    let mut leptos_options = get_configuration(None)?.leptos_options;
    leptos_options.site_addr = args.listen;

    if !args.listen.ip().is_loopback() {
        // Two different warnings, because the two modes carry two different
        // risks and one wording would be wrong for both. Static: everyone who
        // can reach the port is an administrator. Login: the sign-in stands,
        // but a password crosses the network in whatever this bind is reached
        // over, and this process terminates no TLS.
        if args.provider.is_some() {
            warn!(
                listen = %args.listen,
                "dashboard bound to a non-loopback address and serves plain HTTP; put it behind \
                 a TLS-terminating reverse proxy, or passwords cross the network in the clear"
            );
        } else {
            warn!(
                listen = %args.listen,
                "dashboard bound to a non-loopback address with a static credential and no \
                 sign-in, so anyone who can reach this port has the access that identity carries"
            );
        }
    }

    info!(
        allowed_hosts = ?args.allowed_host,
        "answering to the loopback names, the listen address, and these"
    );

    let hosts = HostPolicy::for_listen(args.listen).allow(&args.allowed_host);
    let app = build_router(leptos_options, access, hosts);

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
