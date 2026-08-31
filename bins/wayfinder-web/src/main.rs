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
//! The node-facing arguments are literally `wayfinder-tui`'s and
//! `wayfinderctl`'s — one `ConnectArgs` flattened into all three — so an
//! operator who knows how to point the TUI at a node already knows how to point
//! this at one, and the three cannot drift apart.

// The whole binary is server-side. Under `--features hydrate` (the wasm build)
// this file compiles to an empty `main`, which is also what keeps a plain
// `cargo build --workspace` — where neither feature is on — green.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// Run the dashboard server.
#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use clap::Parser;
    use leptos::prelude::*;
    use tracing::info;
    use tracing::warn;
    use wayfinder_client::ConnectArgs;
    use wayfinder_client::NodeAddr;
    use wayfinder_web::conn::NodeConnection;
    use wayfinder_web::server::HostPolicy;
    use wayfinder_web::server::build_router;
    use wayfinder_web::session::Access;
    use wayfinder_web::session::PinnedNode;
    use wayfinder_web::session::SessionStore;

    /// Command-line arguments.
    #[derive(Parser, Debug)]
    #[command(about = "Web dashboard for the Wayfinder management API", long_about = None)]
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

        /// How this dashboard reaches the node it displays: `--connect` and a
        /// credential to present, or `--serial` instead of both.
        ///
        /// The same arguments `wayfinderctl` and `wayfinder-tui` take, declared
        /// once in `wayfinder-client` — a dashboard is one more management-API
        /// client, and pointing one at a node should not be a third dialect.
        #[command(flatten)]
        connection: ConnectArgs,

        /// TLS address of the certificate authority a viewer signs in to.
        ///
        /// Given, this dashboard runs in **login mode**: it holds no credential
        /// of its own, and each viewer obtains a short-lived session
        /// certificate by signing in with a user name, password and
        /// authenticator code. Nothing but the sign-in page is reachable
        /// without one, which is what makes a shared or exposed dashboard safe
        /// in a way the static credential (`--identity`/`--cert`) never is.
        ///
        /// Often, but not always, the same node as `--connect`: the accounts
        /// live wherever the mesh's certificate authority runs, and a dashboard
        /// may be pointed at any node in the mesh.
        #[arg(
            long,
            env = "WAYFINDER_WEB_PROVIDER",
            conflicts_with_all = ["identity", "cert", "serial"]
        )]
        provider: Option<NodeAddr>,

        /// The provider's Ed25519 public key (64 hex chars) to pin. Defaults to
        /// `--node-key`, which is correct when the node being viewed is itself
        /// the certificate authority.
        ///
        /// Not optional in substance: a sign-in sends a password to whatever
        /// answers at `--provider`, so something has to say which host that is
        /// allowed to be.
        #[arg(long, env = "WAYFINDER_WEB_PROVIDER_KEY", requires = "provider")]
        provider_key: Option<String>,

        /// Where a *joining node* should reach the certificate authority, when
        /// that is not the address this dashboard dials it on.
        ///
        /// Display only: it is what the dashboard shows an operator who is
        /// enrolling a new device, and nothing connects to it. Without it the
        /// dialled address is shown — right when the dashboard and the
        /// authority are not on the same host, and wrong on the deployment
        /// this exists for, where a cloud provider's dashboard reaches its
        /// node over loopback and the join details would otherwise read
        /// `127.0.0.1:7700` to somebody standing in front of a device on the
        /// other side of the internet.
        ///
        /// Not derivable, which is why it is asked for: the management
        /// endpoint's name is not `--allowed-host` (they are separate DNS
        /// records on the deployed provider — the dashboard is proxied and the
        /// management API cannot be), and the node itself does not know the
        /// address the world reaches it at.
        #[arg(
            long,
            env = "WAYFINDER_WEB_PUBLIC_PROVIDER_ADDRESS",
            requires = "provider"
        )]
        public_provider_address: Option<String>,
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
    let access = Arc::new(match (&args.connection.serial, args.provider.clone()) {
        // Serial: no TLS, no authentication and no provider to log in to. The
        // port itself is the credential, which is why it is a debug interface.
        (Some(_), _) => {
            let conn = NodeConnection::new(args.connection.target()?);
            info!(node = %conn.label(), "node target configured (serial, unauthenticated)");
            Access::Static(Arc::new(conn))
        }

        // Login mode: this process holds no credential at all. Both endpoints
        // are pinned by key, and neither key can be defaulted from an identity
        // — there is none.
        (None, Some(provider_addr)) => {
            // Refused rather than ignored. `--cert-from` fetches a node's
            // certificate over a connection proving that node's seed, and this
            // mode deliberately holds no identity at all — each viewer signs in
            // for a session certificate of their own. There is nothing for the
            // flag to act on, and silently dropping a credential argument is
            // how somebody ends up believing they configured one.
            //
            // Not expressible as a clap conflict: `--provider` is this
            // binary's own argument, while `--cert-from` lives on the shared
            // `ConnectArgs`, so nothing rejects the pair before this point.
            if args.connection.cert_from.is_some() {
                anyhow::bail!(
                    "--cert-from cannot be combined with --provider: in login mode this                      dashboard holds no identity of its own, so there is no node whose                      certificate it could present. Drop --cert-from, or run in static                      credential mode without --provider."
                );
            }
            let node_key = args.connection.node_key.as_deref().ok_or_else(|| {
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
                node = %args.connection.connect,
                provider = %provider_addr,
                "login mode: viewers sign in for their own short-lived session certificate"
            );
            Access::Login(Arc::new(
                SessionStore::new(
                    PinnedNode {
                        addr: args.connection.connect.clone(),
                        key: node_key,
                    },
                    PinnedNode {
                        addr: provider_addr,
                        key: provider_key,
                    },
                )
                .advertising_provider_at(args.public_provider_address.clone()),
            ))
        }

        // Static credential: one identity for the whole process.
        (None, None) => {
            let conn = NodeConnection::new(args.connection.resolve_target().await?);
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
                identity = ?args.connection.identity_path(),
                cert = ?args.connection.cert,
                cert_from = ?args.connection.cert_from,
                pinned_node_key = args.connection.node_key.is_some(),
                "node target configured"
            );
            // Gated on `cert_from` too, not `cert` alone. Under `--cert-from` a
            // certificate *was* fetched and will be presented, while `--cert`
            // is necessarily `None` (clap forbids both) — so keying this on
            // `--cert` alone made the one message written to explain an
            // otherwise unexplainable denial state the opposite of the truth.
            match (&args.connection.cert, &args.connection.cert_from) {
                (None, None) => info!(
                    "no certificate given: authenticating with the identity's own key, which \
                     only an un-enrolled node accepts. An enrolled node needs an admin \
                     certificate."
                ),
                // A node's own certificate carries membership, not a management
                // capability, so it is admitted at the member tier and reads
                // nothing. Said plainly here because the node's denial will not.
                (None, Some(source)) => info!(
                    %source,
                    "presenting the certificate fetched from this node. If it carries no \
                     admin capability the node will refuse every query — --cert-from is for \
                     presenting a device identity elsewhere, not for reading this node."
                ),
                (Some(_), _) => {}
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
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(wayfinder_web::shutdown::shutdown_signal())
        .await?;

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
