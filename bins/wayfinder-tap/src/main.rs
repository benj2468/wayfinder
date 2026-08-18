//! The runnable Wayfinder node: bridges a host TAP device onto the mesh,
//! carries mesh links over UDP, and exposes the management API.
//!
//! All of the routing event loop lives in `wayfinder-driver`; this binary only
//! assembles the concrete transports (a kernel TAP, UDP links) and the
//! management-API listeners from the YAML config, then hands them to a
//! [`Driver`] and runs it.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod tap;

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use clap::Parser;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tun_rs::DeviceBuilder;
use tun_rs::Layer;
use wayfinder::config::Config;
use wayfinder::config::LinkFeatures;
use wayfinder::config::LinkTransport;
use wayfinder::config::LocalDistributionMechanism;
use wayfinder::config::ServerConfig;
use wayfinder::config::TrickleConfig;
use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::Keypair;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder_driver::AuthSnapshotRx;
use wayfinder_driver::AuthSnapshotTx;
use wayfinder_driver::BleLinkParams;
use wayfinder_driver::Driver;
use wayfinder_driver::QueryRx;
use wayfinder_driver::QueryTx;
use wayfinder_driver::Rylr998LinkParams;
use wayfinder_driver::bind_tcp_server;
use wayfinder_driver::build_ble_link;
use wayfinder_driver::build_raw_ip_link;
use wayfinder_driver::build_raw_l2_link;
use wayfinder_driver::build_rylr998_link;
use wayfinder_driver::build_udp_link;
use wayfinder_driver::build_udp_multi_link;
use wayfinder_driver::serve_tls_server;
use wayfinder_server::SettingsFile;
use wayfinder_server::SettingsStore;

use crate::tap::TapDevice;

/// Command-line arguments.
#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Path to the YAML configuration file.
    #[clap(short, long, default_value = "var/conf/install.yml")]
    pub(crate) config: PathBuf,
}

/// Load this node's persisted identity keypair from a 32-byte seed file.
fn load_keypair(seed_path: &str) -> anyhow::Result<Keypair> {
    let seed: [u8; 32] = std::fs::read(seed_path)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("identity seed at {seed_path} must be 32 bytes"))?;
    Ok(Keypair::from_seed(&seed))
}

/// Narrow raw seed bytes to the fixed-size seed, for a seed that came from
/// somewhere other than a file — the runtime settings store, which holds the
/// identity a `SetAuth` installed.
fn seed_bytes(seed: &[u8]) -> anyhow::Result<[u8; 32]> {
    seed.try_into()
        .map_err(|_| anyhow!("identity seed must be 32 bytes, got {}", seed.len()))
}

/// Build a keypair from raw seed bytes; see [`seed_bytes`].
fn keypair_from_seed_bytes(seed: &[u8]) -> anyhow::Result<Keypair> {
    Ok(Keypair::from_seed(&seed_bytes(seed)?))
}

/// Read this node's persisted TAP MAC from `state_path`, or generate one and
/// persist it on first boot. Used when mesh auth is not configured, so there
/// is no identity keypair to derive a stable MAC from — without this, the
/// kernel would hand out a fresh random MAC (and mesh identity) on every
/// restart.
fn load_or_generate_mac(state_path: &str) -> anyhow::Result<[u8; 6]> {
    match std::fs::read(state_path) {
        Ok(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("MAC state file at {state_path} must be 6 bytes")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Reuse `Keypair::generate`'s OS-RNG plumbing rather than taking a
            // direct `getrandom` dependency here; the keypair itself is
            // discarded; only its derived MAC bytes are persisted.
            let mac = wayfinder::wayfinder_auth::Keypair::generate()
                .derived_mac()
                .0;
            if let Some(parent) = Path::new(state_path).parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create MAC state directory {}", parent.display())
                })?;
            }
            std::fs::write(state_path, mac)
                .with_context(|| format!("failed to persist generated MAC to {state_path}"))?;
            tracing::info!(
                state_path,
                "generated and persisted a new stable MAC address"
            );
            Ok(mac)
        }
        Err(e) => Err(e).with_context(|| format!("failed to read MAC state file at {state_path}")),
    }
}

/// Read a 32-byte identity seed from `path`.
fn read_seed(path: &str) -> anyhow::Result<[u8; 32]> {
    std::fs::read(path)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("identity seed at {path} must be 32 bytes"))
}

/// Read this node's persisted management-TLS identity seed from `path`, or
/// generate one and persist it on first boot. The TLS server identity (which
/// clients pin, and which is the bootstrap key before enrollment) must be stable
/// across restarts. Used when there is no `[auth]` seed to reuse. The seed is
/// secret, so the persisted file is created owner-read/write only.
fn load_or_generate_seed(path: &str) -> anyhow::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("identity seed at {path} must be 32 bytes")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let seed = Keypair::generate_seed();
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create identity seed directory {}",
                        parent.display()
                    )
                })?;
            }
            // Create the file already restricted to owner-only rather than
            // writing it world-readable and narrowing afterwards: the seed is
            // secret and must never be exposed, even briefly, in a window where
            // another local process could read it.
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .with_context(|| {
                        format!("failed to create identity seed file {path} (owner-only)")
                    })?;
                f.write_all(&seed).with_context(|| {
                    format!("failed to persist generated identity seed to {path}")
                })?;
            }
            #[cfg(not(unix))]
            std::fs::write(path, seed)
                .with_context(|| format!("failed to persist generated identity seed to {path}"))?;
            tracing::info!(
                path,
                "generated and persisted a new management-TLS identity seed"
            );
            Ok(seed)
        }
        Err(e) => Err(e).with_context(|| format!("failed to read identity seed at {path}")),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `wayfinder-log`'s stack rather than a bare `tracing_subscriber::fmt`, so
    // this node also fills the log ring the management API serves `GetLogs`
    // from — and so `SetLogLevel` moves the console and the ring together, the
    // same way it moves RTT and the ring on a board.
    //
    // The filter grammar is a subset of `EnvFilter`'s (no span/field
    // directives); a `RUST_LOG` it can't parse is reported and the default is
    // used, rather than refusing to start the node over an environment
    // variable.
    if let Err(e) = wayfinder_log::subscriber::init(std::env::var("RUST_LOG").ok().as_deref()) {
        tracing::warn!(%e, "ignoring unparsable RUST_LOG; using the default filter");
    }

    let args = Args::parse();

    let config: Config = serde_yaml::from_slice(std::fs::read_to_string(args.config)?.as_bytes())?;

    tracing::info!("Welcome to Wayfinder");
    // The config can carry sensitive material (enrollment tokens, seed paths),
    // so keep the full dump at DEBUG rather than INFO.
    tracing::debug!(?config, "loaded configuration");

    // Security settings an operator changed at runtime, from the previous run.
    // Loaded before anything reads the config, because these override it —
    // including the identity the node's own MAC is derived from below. A
    // corrupt or unreadable state file is fatal rather than ignored: starting
    // with an empty one would silently drop a fail-closed gate or a runtime
    // enrollment, putting a node the operator had secured back on the open
    // mesh under its old identity.
    let settings_store = SettingsFile::load(config.runtime_state_path.clone().map(PathBuf::from))
        .map_err(|e| anyhow!("failed to load runtime settings: {e}"))?;
    let settings = settings_store.settings().clone();
    if !settings_store.is_durable() {
        tracing::info!(
            "no runtime_state_path configured; security settings changed through the \
             management API will apply immediately but will not survive a restart"
        );
    } else if !settings.is_empty() {
        tracing::info!(
            require_auth = ?settings.require_auth,
            lazy_cert_distribution = ?settings.lazy_cert_distribution,
            identity_installed = settings.identity.is_some(),
            "restored runtime security settings; these take precedence over the \
             startup configuration"
        );
    }

    let mut join_set: JoinSet<anyhow::Result<()>> = JoinSet::new();

    // This binary's local egress is a kernel TAP; reject any other mechanism.
    let LocalDistributionMechanism::Tap(tap) = match config.local_egress {
        Some(mechanism) => mechanism,
        None => bail!("config.local_egress must be a TAP for the wayfinder-tap node"),
    };

    // Cap the TAP MTU so a full host frame still fits inside a mesh link's
    // carrier once wrapped in BATMAN + link + auth encapsulation; without this,
    // full-size frames would be silently truncated on read or dropped on wrap.
    let mtu = tap.mtu.unwrap_or(wayfinder::config::TapConfig::DEFAULT_MTU);

    // Decide this node's MAC *before* creating the TAP device, rather than
    // trusting whatever the kernel assigns a freshly-created device — that is
    // random on every restart and would silently change this node's mesh
    // identity (and, with auth enabled, its cert would stop matching) each
    // time it starts. When mesh auth is configured, derive the MAC from the
    // persisted identity keypair, so it is stable across restarts and
    // self-consistent with the MAC the membership cert is bound to. Otherwise
    // fall back to a MAC generated once and persisted to `tap.mac_state_path`.
    //
    // An identity installed at runtime wins over the `auth:` block, for the
    // same reason it does everywhere else: it is the operator's more recent
    // intent. It has to be consulted *here*, not only where auth is enabled
    // below — the MAC is what a certificate is bound to, so reading it later
    // would give this node an address its own certificate is not.
    //
    // For that identity the *certificate* names the MAC, rather than the seed
    // deriving it. The two agree when the identity was minted whole (offline
    // `enroll` picks the MAC its keypair derives to), and they deliberately do
    // not when a node enrolled online: there the node already had an address
    // its peers knew it by, and the certificate was issued for that address
    // precisely so joining a mesh does not move it. Deriving here instead would
    // rename the node on its first restart after enrolling and orphan the
    // certificate it just obtained.
    let mac_addr = match (&settings.identity, &config.auth) {
        (Some(identity), _) => {
            MembershipCert::from_bytes(&identity.cert)
                .ok_or_else(|| anyhow!("invalid membership cert in the runtime settings store"))?
                .node_mac
        }
        (None, Some(auth_cfg)) => load_keypair(&auth_cfg.seed_path)?.derived_mac().0,
        (None, None) => load_or_generate_mac(&tap.resolved_mac_state_path())?,
    };

    let mut builder = DeviceBuilder::new()
        .layer(Layer::L2)
        .name(&tap.device_name)
        .mtu(mtu)
        .mac_addr(mac_addr);
    // The IPv4 address/netmask are optional: when no address is configured the
    // TAP is brought up unaddressed (the mesh routes on MAC, not IP).
    if let Some(ip_address) = tap.ip_address {
        let netmask = tap
            .netmask
            .unwrap_or(wayfinder::config::TapConfig::DEFAULT_NETMASK);
        builder = builder.ipv4(ip_address, netmask, None);
    }
    let dev = builder
        .build_async()
        .context("failed to create TAP device")?;

    tracing::info!(
        "Starting wayfinder with MAC address: {:?}",
        pretty_hex::simple_hex(&mac_addr)
    );

    let mut interfaces = Vec::new();
    // Per-interface OGM backoff bounds, participation features and display
    // names, collected in interface order alongside the transports so the
    // driver can pace, gate and label each link independently.
    let mut trickle: Vec<TrickleConfig> = Vec::new();
    let mut features: Vec<LinkFeatures> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for (idx, link) in config.links.into_iter().enumerate() {
        // Resolve the label before the transport is moved out below; an unnamed
        // link falls back to its transport kind plus this index.
        names.push(link.interface_name(idx));
        match link.transport {
            LinkTransport::Udp {
                bind_addr,
                remote_addr,
            } => {
                interfaces.push(build_udp_link(bind_addr, remote_addr, &mut join_set).await?);
            }
            LinkTransport::UdpMulti {
                bind_addr,
                discovery_addr,
                multicast_interface,
            } => {
                interfaces.push(
                    build_udp_multi_link(bind_addr, discovery_addr, multicast_interface.as_deref())
                        .await?,
                );
            }
            LinkTransport::RawIp {
                bind_addr,
                remote_addr,
                protocol,
            } => {
                interfaces.push(
                    build_raw_ip_link(bind_addr, remote_addr, protocol, &mut join_set).await?,
                );
            }
            LinkTransport::RawL2 {
                interface,
                ethertype,
            } => {
                interfaces.push(build_raw_l2_link(&interface, ethertype)?);
            }
            LinkTransport::Rylr998 {
                device,
                baud_rate,
                address,
                network_id,
                spreading_factor,
                bandwidth_khz,
                coding_rate_denominator,
                preamble,
            } => {
                interfaces.push(
                    build_rylr998_link(Rylr998LinkParams {
                        device,
                        baud_rate,
                        address,
                        network_id,
                        spreading_factor,
                        bandwidth_khz,
                        coding_rate_denominator,
                        preamble,
                    })
                    .await?,
                );
            }
            LinkTransport::Ble {
                adapter,
                advertise_dwell_ms,
            } => {
                interfaces.push(
                    build_ble_link(BleLinkParams {
                        adapter,
                        advertise_dwell: std::time::Duration::from_millis(advertise_dwell_ms),
                    })
                    .await?,
                );
            }
            LinkTransport::Test { .. } => {
                bail!("test links are only valid in the test harness, not the wayfinder-tap node")
            }
        }
        trickle.push(link.ogm);
        features.push(link.features);
    }

    // Optional management API server — queries are forwarded to the driver over
    // a channel so the router is never shared across tasks.
    let (query_tx, query_rx): (QueryTx, QueryRx) = mpsc::channel(16);

    // Set when a TLS management server is configured. The `CentralRouter` (and
    // so the current trust anchor + revocation list) lives only on the driver's
    // task, but the TLS server needs that state on its own task to decide
    // whether to admit each incoming connection (`decide_access`). Rather than
    // sharing the router across tasks, the server asks for a fresh `AuthSnapshot`
    // over this channel on every new connection and the driver answers it
    // in-line with its event loop — so authorization always reflects the
    // router's current state (e.g. a revocation made moments earlier) without
    // giving the server task direct access to the router. Installed on the
    // driver below, after it's built.
    let mut auth_snapshot_rx: Option<AuthSnapshotRx> = None;
    // The identity this node runs as, once resolved below. Handed to the driver
    // so the management API can report its public half and certify it on
    // enrollment — the same key the TLS server presents, so a client that
    // enrolls this node certifies the identity it was already talking to.
    let mut node_identity_seed: Option<[u8; 32]> = None;

    if let Some(server_cfg) = config.server {
        let tx = query_tx.clone();
        match server_cfg {
            ServerConfig::Tls {
                addr,
                identity_seed_path,
            } => {
                // The TLS server identity: an identity installed at runtime
                // wins (the operator's more recent intent, and the same
                // precedence the MAC above follows), else the mesh membership
                // seed when one is configured, else a dedicated persistent
                // identity seed generated on first boot. It must exist even
                // before enrollment, since a client with no certificate yet
                // authenticates by proving this key.
                let identity_seed = match (&settings.identity, &config.auth) {
                    (Some(identity), _) => {
                        seed_bytes(&identity.seed).context("runtime-installed identity seed")?
                    }
                    (None, Some(auth_cfg)) => read_seed(&auth_cfg.seed_path)?,
                    (None, None) => {
                        let path = identity_seed_path
                            .unwrap_or_else(ServerConfig::default_identity_seed_path);
                        load_or_generate_seed(&path)?
                    }
                };
                node_identity_seed = Some(identity_seed);
                let listener = bind_tcp_server(addr).await?;
                let (snapshot_tx, snapshot_rx): (AuthSnapshotTx, AuthSnapshotRx) =
                    mpsc::channel(16);
                auth_snapshot_rx = Some(snapshot_rx);
                join_set.spawn(async move {
                    serve_tls_server(listener, identity_seed, snapshot_tx, tx).await
                });
            }
        }
    }

    let mut driver = Driver::new(
        Mac(mac_addr),
        TapDevice(dev),
        interfaces,
        trickle,
        features,
        names,
        query_rx,
    );
    // Give the driver the receiver the TLS server snapshots authorization state
    // over (no-op when no TLS server is configured).
    if let Some(rx) = auth_snapshot_rx {
        driver.set_auth_snapshot_rx(rx);
    }
    // And the identity that server presents, so the management API can report
    // its public half for enrollment and install a certificate issued for it.
    if let Some(seed) = node_identity_seed {
        driver.set_identity_seed(seed);
    }

    // The two posture flags, each taking the runtime override when the
    // operator has set one and otherwise following the config.
    let require_auth = settings.require_auth.unwrap_or(config.require_auth);
    let lazy_cert_distribution = settings
        .lazy_cert_distribution
        .unwrap_or(config.lazy_cert_distribution);

    // Fail-closed policy: when configured, the router stays inert (see
    // `CentralRouter::auth_locked`) until a membership cert is installed below
    // (from `[auth]`, from the runtime settings store) or later via a runtime
    // `set-auth`. Set unconditionally, regardless of whether `[auth]` is
    // present below: a `require_auth: true` node with no `[auth]` block
    // (relying entirely on a runtime `set-auth`) must still start out
    // correctly locked.
    driver.router_mut().set_require_auth(require_auth);
    if require_auth && config.auth.is_none() && settings.identity.is_none() {
        tracing::warn!(
            "require_auth is set but no [auth] block is configured; this node will \
             stay locked (no routing, no OGM emission) until a certificate is \
             installed via a runtime set-auth"
        );
    }

    // Lazy cert distribution: set unconditionally (like `require_auth`
    // above) so it takes effect immediately if auth is installed via a later
    // runtime `set-auth`, not just from a startup `[auth]` block. A no-op
    // until auth is enabled either way. Flag-day only — see
    // `Config::lazy_cert_distribution`.
    driver
        .router_mut()
        .set_lazy_cert_distribution(lazy_cert_distribution);
    if lazy_cert_distribution && config.auth.is_none() && settings.identity.is_none() {
        tracing::warn!(
            "lazy_cert_distribution is set but no [auth] block is configured; it has \
             no effect until authentication is enabled (config or runtime set-auth)"
        );
    }

    // Opt-in mesh authentication: load this node's identity, certificate, and
    // the mesh trust anchor, then enable OGM auth on the router.  Absent ⇒ the
    // node runs unauthenticated.
    //
    // The three blobs come either from the runtime settings store (a `SetAuth`
    // on a previous run — the operator's more recent intent, and the source
    // the MAC above was already derived from) or from the `auth:` block's
    // files. Whichever supplies them, everything below — the MAC binding
    // check, the mesh id, enabling auth — is the same, so the two sources
    // differ only in where the bytes are read from.
    let mut auth_mesh_id: Option<u32> = None;
    let identity_material = match (&settings.identity, &config.auth) {
        (Some(identity), _) => {
            if config.auth.is_some() {
                tracing::info!(
                    "using the identity installed at runtime; the [auth] block's files \
                     are ignored while it is present"
                );
            }
            Some((
                keypair_from_seed_bytes(&identity.seed)?,
                identity.cert.clone(),
                identity.trust_anchor.clone(),
                "the runtime settings store".to_string(),
            ))
        }
        (None, Some(auth_cfg)) => Some((
            load_keypair(&auth_cfg.seed_path)?,
            std::fs::read(&auth_cfg.cert_path)?,
            std::fs::read(&auth_cfg.trust_anchor_path)?,
            auth_cfg.cert_path.clone(),
        )),
        (None, None) => None,
    };

    if let Some((keypair, cert_bytes, anchor_bytes, source)) = identity_material {
        use wayfinder::auth::OgmAuth;
        use wayfinder::wayfinder_auth::TrustAnchor;

        let cert = MembershipCert::from_bytes(&cert_bytes)
            .ok_or_else(|| anyhow!("invalid membership cert from {source}"))?;

        let anchor = TrustAnchor::from_bytes(&anchor_bytes)
            .ok_or_else(|| anyhow!("invalid trust anchor from {source}"))?;

        // The cert must bind this node's MAC, or it would sign OGMs no peer
        // attributes to us.
        if cert.node_mac != mac_addr {
            bail!(
                "membership cert is bound to MAC {:?}, but this node's MAC is {:?}",
                cert.node_mac,
                mac_addr
            );
        }

        let mesh_id = anchor.mesh_id;
        auth_mesh_id = Some(mesh_id);
        driver
            .router_mut()
            .set_auth(OgmAuth::new(keypair, cert, anchor));
        tracing::info!("mesh authentication enabled (mesh_id = {:#x})", mesh_id);
    }

    // Opt-in provider (certificate-authority) mode: load the mesh root seed and
    // serve enrollment over the management API.  Only the provider holds the
    // root key.
    if let Some(provider_cfg) = config.provider {
        use wayfinder_server::CertAuthority;

        // A provider should also be an authenticated member of the *same* mesh:
        // it floods revocations over its own OGMs. Auth may be configured here
        // (`[auth]`) or pushed at runtime via SetAuth — so a missing `[auth]` is
        // only a warning (the adapter's revoke path still fails closed until auth
        // is set). When `[auth]` *is* present, its mesh must match.
        match auth_mesh_id {
            None => tracing::warn!(
                "provider mode enabled without [auth]; set authentication (config or \
                 runtime SetAuth) before revoking, or revocations cannot be flooded"
            ),
            Some(id) if id != provider_cfg.mesh_id => bail!(
                "provider mesh_id {:#x} does not match this node's auth mesh_id {:#x}",
                provider_cfg.mesh_id,
                id
            ),
            Some(_) => {}
        }

        let root_seed: [u8; 32] = std::fs::read(&provider_cfg.root_seed_path)?
            .as_slice()
            .try_into()
            .map_err(|_| {
                anyhow!(
                    "mesh root seed at {} must be 32 bytes",
                    provider_cfg.root_seed_path
                )
            })?;
        driver.set_provider(
            CertAuthority::from_config(&root_seed, &provider_cfg)
                .map_err(|e| anyhow!("failed to load certificate-authority state: {e}"))?,
        );
        tracing::info!(
            "certificate-authority (provider) mode enabled (mesh_id = {:#x})",
            provider_cfg.mesh_id
        );
    }

    // Hand the store to the driver last, so every startup-time read of the
    // settings above is done before anything can write to it.
    driver.set_settings_store(settings_store);

    if let Err(err) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
        tracing::trace!("Failed to notify systemd: {}", err);
    }

    driver.run().await
}
