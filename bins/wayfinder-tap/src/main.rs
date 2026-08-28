//! The runnable Wayfinder node: bridges its local host-facing egress (a kernel
//! TAP device, or a physical ethernet NIC — see [`LocalDistributionMechanism`])
//! onto the mesh, carries mesh links over UDP, and exposes the management API.
//!
//! Every one of those is optional. A node configured with no `local_egress`
//! and no `links` still runs the same event loop, and is exactly what a
//! certificate authority is: it holds the mesh root of trust and serves
//! enrollment over the management API, with no host traffic to bridge and no
//! radio to bridge it onto.
//!
//! All of the routing event loop lives in `wayfinder-driver`; this binary only
//! assembles the concrete transports (the local egress, UDP links) and the
//! management-API listeners from the YAML config, then hands them to a
//! [`Driver`] and runs it.
//!
//! [`LocalDistributionMechanism`]: wayfinder::config::LocalDistributionMechanism

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod shutdown;
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
use wayfinder_driver::FrameIo;
use wayfinder_driver::NullEgress;
use wayfinder_driver::QueryRx;
use wayfinder_driver::QueryTx;
use wayfinder_driver::Rylr998LinkParams;
use wayfinder_driver::bind_tcp_server;
use wayfinder_driver::build_ble_link;
use wayfinder_driver::build_raw_ip_link;
use wayfinder_driver::build_raw_l2_egress;
use wayfinder_driver::build_raw_l2_link;
use wayfinder_driver::build_rylr998_link;
use wayfinder_driver::build_udp_link;
use wayfinder_driver::build_udp_multi_link;
use wayfinder_driver::serve_tls_server_with_vpn;
use wayfinder_server::AuthorityRx;
use wayfinder_server::AuthorityTx;
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

/// How many commands may be queued for the certificate authority before new
/// ones are refused.
///
/// Bounded and shallow on purpose. The authority serves one command at a time
/// and a login costs ~100 ms, so a deep queue would not absorb a flood — it
/// would only convert it into connections waiting minutes for an answer. At
/// capacity the connection task answers "busy" immediately instead, which is
/// the failure a client can act on.
const AUTHORITY_QUEUE_DEPTH: usize = 16;

/// Say, at startup, whether this node's clock is trusted and what follows from
/// it.
///
/// Worth a dedicated line because the failure it describes is otherwise
/// invisible in the right way to be maximally confusing: routing comes up, the
/// node looks healthy, and enrollment and logins fail with what read like
/// unrelated errors. An operator should be able to find the cause in the first
/// screen of logs.
fn report_clock_posture(require_time_sync: bool, sync: wayfinder_server::ClockSync) {
    use wayfinder_server::ClockSync;
    match sync {
        ClockSync::Synchronized { max_error_us } => tracing::info!(
            max_error_us,
            "system clock is disciplined; credential operations enabled"
        ),
        // Not an `error!`: the node is working as configured and an operator
        // who turned the gate off does not need to be told again every restart.
        ClockSync::Unsupported if !require_time_sync => tracing::warn!(
            "clock-sync enforcement is disabled (require_time_sync = false); this node will \
             issue and accept credentials against an unverified clock"
        ),
        ClockSync::Unsupported => tracing::warn!(
            "this platform exposes no NTP status, so require_time_sync cannot be enforced \
             here; credentials will be issued and accepted against an unverified clock"
        ),
        // `error!` is right by CLAUDE.md's rule: a misconfiguration of *this*
        // node that an operator must act on, not reachable by remote input.
        ClockSync::Unreadable { errno } => tracing::error!(
            errno,
            "could not read the host's NTP status at all; refusing every credential \
             operation. This is not a missing time daemon -- the syscall itself failed. \
             The usual cause is a sandbox denying `adjtimex` (Docker's default seccomp \
             profile without CAP_SYS_TIME, or a systemd SystemCallFilter without @clock)"
        ),
        ClockSync::Unsynchronized => tracing::error!(
            "system clock is not disciplined (no NTP sync); refusing every credential \
             operation until it is. The node still routes. Start chronyd, or set \
             require_time_sync = false to accept an unverified clock"
        ),
        ClockSync::ErrorTooLarge {
            max_error_us,
            bound_us,
        } => tracing::error!(
            max_error_us,
            bound_us,
            "system clock's estimated error exceeds max_clock_error_us; refusing every \
             credential operation until it converges. The node still routes"
        ),
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

    // The mesh-identity MAC is persisted independently of which local egress
    // is configured — a raw-L2 egress's own NIC hardware MAC is unrelated to
    // it, just as a TAP's kernel-assigned MAC is, and a node with no egress
    // still has an identity to keep across restarts. Resolved up front so the
    // MAC derivation below (which needs it before any egress is constructed)
    // stays a single block regardless of which mechanism is chosen — and
    // before `local_egress` is moved out of the config below.
    let mac_state_path = config.resolved_mac_state_path();

    // A local egress is optional. A node with none bridges no host traffic at
    // all: the certificate-authority posture, where the node holds the mesh
    // root of trust and answers the management API but has no TAP to create
    // (and, on a cloud host, no CAP_NET_ADMIN or /dev/net/tun to create one
    // with). Everything below — the identity, the management server, provider
    // mode — is unchanged; only the local device differs.
    let local_egress = config.local_egress;

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
        (None, None) => load_or_generate_mac(&mac_state_path)?,
    };

    let local: Box<dyn FrameIo> = match local_egress {
        None => {
            tracing::info!(
                "no local_egress configured; this node bridges no host traffic and \
                 serves the management API only"
            );
            Box::new(NullEgress)
        }
        Some(LocalDistributionMechanism::Tap(tap)) => {
            // Cap the TAP MTU so a full host frame still fits inside a mesh
            // link's carrier once wrapped in BATMAN + link + auth
            // encapsulation; without this, full-size frames would be silently
            // truncated on read or dropped on wrap.
            let mtu = tap.mtu.unwrap_or(wayfinder::config::TapConfig::DEFAULT_MTU);
            let mut builder = DeviceBuilder::new()
                .layer(Layer::L2)
                .name(&tap.device_name)
                .mtu(mtu)
                .mac_addr(mac_addr);
            // The IPv4 address/netmask are optional: when no address is
            // configured the TAP is brought up unaddressed (the mesh routes
            // on MAC, not IP).
            if let Some(ip_address) = tap.ip_address {
                let netmask = tap
                    .netmask
                    .unwrap_or(wayfinder::config::TapConfig::DEFAULT_NETMASK);
                builder = builder.ipv4(ip_address, netmask, None);
            }
            let dev = builder
                .build_async()
                .context("failed to create TAP device")?;
            Box::new(TapDevice(dev))
        }
        Some(LocalDistributionMechanism::RawL2Egress(cfg)) => {
            Box::new(build_raw_l2_egress(&cfg.interface).context("failed to bind raw-L2 egress")?)
        }
    };

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
                if discovery_addr.is_none() && multicast_interface.is_some() {
                    bail!(
                        "udpmulti link {:?}: multicast_interface is meaningless without a \
                         discovery_addr to join a multicast group at",
                        names.last()
                    );
                }
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

    // The certificate authority's own channel, separate from `query_tx` so
    // authority work and router work never queue behind each other — the point
    // of design 13. Opened here because a management listener needs the sending
    // half, while the authority itself is not loaded until further down; both
    // halves are `None` on a node that runs no authority at all.
    let authority_channel: Option<(AuthorityTx, AuthorityRx)> = config
        .provider
        .as_ref()
        .map(|_| mpsc::channel(AUTHORITY_QUEUE_DEPTH));
    let authority_tx = authority_channel.as_ref().map(|(tx, _)| tx.clone());
    let mut authority_channel = authority_channel;

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

    /// A management listener that is bound but not yet served.
    ///
    /// Binding has to happen during config parsing, so a taken address fails
    /// startup rather than a minute later; serving has to happen after the
    /// driver is built, because a connection task answers reads through the
    /// driver's `RouterHandle`. This carries the arguments between the two.
    struct PendingTlsListener {
        listener: tokio::net::TcpListener,
        identity_seed: [u8; 32],
        snapshot_tx: AuthSnapshotTx,
        query_tx: QueryTx,
        vpn: Option<wayfinder_server::vpn::SharedCoordinator>,
        authority: Option<wayfinder_server::AuthorityTx>,
    }
    let mut pending_tls_listener: Option<PendingTlsListener> = None;

    // Built here, before the listener spawns, because the listener is what
    // answers the VPN requests — the router loop is never told who is calling,
    // and `GetVpnEnrollment` mints a credential for the caller's own identity.
    // Constructing it now also means a bad URL or an unreadable API key file is
    // a startup failure an operator sees immediately, rather than an enrollment
    // that fails later against a node they have walked away from.
    let vpn_coordinator: Option<wayfinder_server::vpn::SharedCoordinator> =
        match config.provider.as_ref().and_then(|p| p.headscale.as_ref()) {
            Some(headscale_cfg) => {
                let coordinator = wayfinder_server::vpn::HeadscaleCoordinator::new(headscale_cfg)
                    .map_err(|e| anyhow::anyhow!("VPN coordination: {e}"))?;
                tracing::info!(
                    api_url = %headscale_cfg.api_url,
                    "VPN coordination enabled (Headscale)"
                );
                Some(std::sync::Arc::new(coordinator) as wayfinder_server::vpn::SharedCoordinator)
            }
            None => None,
        };

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
                // Bound here, so an address already in use is a startup error
                // an operator sees immediately — but *served* below, once the
                // driver exists to hand out the read handle the connection
                // tasks answer their queries from.
                let listener = bind_tcp_server(addr).await?;
                let (snapshot_tx, snapshot_rx): (AuthSnapshotTx, AuthSnapshotRx) =
                    mpsc::channel(16);
                auth_snapshot_rx = Some(snapshot_rx);
                pending_tls_listener = Some(PendingTlsListener {
                    listener,
                    identity_seed,
                    snapshot_tx,
                    query_tx: tx,
                    vpn: vpn_coordinator.clone(),
                    authority: authority_tx.clone(),
                });
            }
        }
    }

    let mut driver = Driver::new(
        Mac(mac_addr),
        local,
        interfaces,
        trickle,
        features,
        names,
        query_rx,
    );
    // Where certificate-validity time comes from. Applied before anything can
    // make a dated decision, and reported at startup either way: an operator
    // whose node is silently refusing to issue certificates must be able to see
    // *why* in the first screen of logs rather than inferring it from the
    // refusals.
    let clock_trust = wayfinder_server::ClockTrust::from_settings(
        config.require_time_sync,
        config.max_clock_error_us,
    );
    driver.set_clock_trust(clock_trust);
    report_clock_posture(config.require_time_sync, driver.clock_sync());

    // Give the driver the receiver the TLS server snapshots authorization state
    // over (no-op when no TLS server is configured).
    if let Some(rx) = auth_snapshot_rx {
        driver.set_auth_snapshot_rx(rx);
    }
    // And the identity that server presents, so the management API can report
    // its public half for enrollment and install a certificate issued for it.
    if let Some(seed) = node_identity_seed {
        driver.set_identity_seed(seed).await;
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
    driver
        .with_router_mut(|r| r.set_require_auth(require_auth))
        .await;
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
        .with_router_mut(|r| r.set_lazy_cert_distribution(lazy_cert_distribution))
        .await;
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
        use wayfinder::wayfinder_auth::RevocationRecord;
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

        // A revocation naming this node, heard before some earlier restart and
        // written to the settings store, is re-verified here against the
        // anchor about to be installed.
        //
        // This is the half that cannot be handled by clearing the stored
        // identity: when the material comes from a config `auth:` block, those
        // files belong to the operator and the node must not rewrite them, so
        // the record is the only thing it can durably change. Re-verified
        // rather than trusted as a flag, so a hand-edited settings file cannot
        // forge one without the mesh root key — and it self-expires, since
        // past its `not_after` the anchor refuses it and this node may
        // legitimately arm again.
        // `host_unix_now` rather than a raw `SystemTime::now()`: it is this
        // repo's one definition of a *plausible* wall clock, floors an
        // undisciplined reading to zero, and is what the router's own clock
        // uses. A second host-clock read with a different floor is how the two
        // come to disagree.
        let now_unix = wayfinder_server::host_unix_now();
        let stored = settings
            .self_revocation
            .as_deref()
            .filter(|b| !b.is_empty())
            .and_then(RevocationRecord::from_bytes);
        // Judged only when this node has a clock to judge with. Without one,
        // the record is *held* rather than discarded — the opposite of the
        // wire path's caution, and deliberately so: this record was already
        // accepted by this node under a good clock and durably stored, so an
        // unreadable clock is a reason not to decide, never a reason to arm.
        // Discarding it here would let a dead RTC undo the revocation on every
        // boot, which is the most ordinary way this feature could fail.
        let self_revocation = match (stored, now_unix) {
            (Some(record), 0) => {
                tracing::error!(
                    ?record,
                    "this node holds a revocation of itself but has no usable clock to judge it; staying inert"
                );
                Some(record)
            }
            (Some(record), now) => {
                match anchor.verify_revocation(&record, now) {
                    Ok(_)
                        if record.cancels_cert_for(&cert.node_mac, cert.not_before.get(), now) =>
                    {
                        Some(record)
                    }
                    // Superseded by the certificate about to be installed: the
                    // authority re-admitted this node, which is the recovery
                    // path working.
                    Ok(_) => {
                        tracing::info!(
                            "the stored self-revocation no longer cancels this node's certificate; re-admitting"
                        );
                        None
                    }
                    // Expired is the documented self-heal. Anything else means
                    // the stored record and this anchor do not belong together
                    // — say which, rather than silently arming.
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "the stored self-revocation does not verify against this node's anchor; ignoring it"
                        );
                        None
                    }
                }
            }
            (None, _) => None,
        };

        let mesh_id = anchor.mesh_id;
        auth_mesh_id = Some(mesh_id);
        if let Some(record) = self_revocation {
            tracing::error!(
                ?record,
                "this node's mesh membership was revoked; it stays inert until an authority re-admits it with a newer certificate"
            );
            wayfinder_alarm::alarm!(
                wayfinder_alarm::Severity::Critical,
                wayfinder_alarm::AlarmKind::SelfRevoked,
                wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&record.node_mac)),
                "mesh membership revoked; re-enroll this node to bring it back"
            );
            driver
                .with_router_mut(|r| r.note_self_revoked(record))
                .await;
        } else {
            driver
                .with_router_mut(|r| r.set_auth(OgmAuth::new(keypair, cert, anchor)))
                .await;
            tracing::info!("mesh authentication enabled (mesh_id = {:#x})", mesh_id);
        }
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
        let mut ca = CertAuthority::from_config(&root_seed, &provider_cfg)
            .map_err(|e| anyhow!("failed to load certificate-authority state: {e}"))?;
        // The authority reads the same clock under the same policy as the
        // router. Two components disagreeing about whether time is trustworthy
        // is how a node signs a certificate it will then refuse to verify.
        ca.set_clock(wayfinder_server::Clock::System(clock_trust));
        // The posture is worth an operator's attention at startup, and it is
        // read back off the authority rather than off the config: a persisted
        // runtime override wins over the YAML, so the config alone can say the
        // wrong thing. `auto_approve` means this node signs a membership
        // certificate for whoever asks (subject to the token, if one is set);
        // off means requests queue for approval.
        // Read off the authority, not the driver: this is the clock the CA
        // will actually sign against, and a provider that cannot sign is worth
        // saying so beside the posture it would have signed under.
        let ca_clock = ca.clock_sync();
        if !ca_clock.is_trusted() {
            tracing::error!(
                state = ca_clock.name(),
                "certificate authority has no trusted clock; every issuing path will \
                 refuse until it does"
            );
        }
        let policy = ca.enrollment_policy();
        tracing::info!(
            auto_approve = policy.auto_approve,
            enrollment_token_set = policy.enrollment_token_set,
            "certificate-authority (provider) mode enabled (mesh_id = {:#x})",
            provider_cfg.mesh_id
        );
        // The authority runs on its own task from here: it no longer shares the
        // driver's event loop, so a login's Argon2id and its durable write
        // cannot stall a link `recv` or an OGM.
        // Opened above iff `config.provider` was set, which is the branch we are
        // in — matched rather than unwrapped so the two stay tied together by
        // the compiler instead of by a comment.
        let Some((_, authority_rx)) = authority_channel.take() else {
            bail!("internal: provider configured but its command channel was never opened");
        };
        // Every direction wired in one call, so provider mode cannot be
        // half-enabled. Without the clock the authority's `now_unix` stays 0,
        // which every issuing path treats as fail-closed — so it would refuse
        // every request, silently.
        let ports = driver.attach_authority(authority_rx);
        join_set.spawn(async move {
            wayfinder_server::serve_authority(ca, ports).await;
            Ok(())
        });
    }

    // Hand the store to the driver last, so every startup-time read of the
    // settings above is done before anything can write to it.
    driver.set_settings_store(settings_store);

    // Serve the management listener now that the driver exists to hand out a
    // read handle. Every router *read* is then answered on the connection's own
    // task under a shared borrow, instead of being forwarded to the loop that
    // forwards mesh frames; the three mutations still go down `query_tx`.
    if let Some(pending) = pending_tls_listener.take() {
        let PendingTlsListener {
            listener,
            identity_seed,
            snapshot_tx,
            query_tx,
            vpn,
            authority,
        } = pending;
        let router_handle = driver.router_handle();
        join_set.spawn(async move {
            serve_tls_server_with_vpn(
                listener,
                identity_seed,
                snapshot_tx,
                query_tx,
                wayfinder_server::ServerServices {
                    vpn,
                    authority_tx: authority,
                    router: Some(router_handle),
                },
            )
            .await
        });
    }

    if let Err(err) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
        tracing::trace!("Failed to notify systemd: {}", err);
    }

    // Not `driver.run().await`: every listener and carrier spawned above lives
    // in `join_set`, and awaiting only the driver let one of them die leaving
    // the node routing perfectly with no management API and nothing said about
    // it. See `shutdown`, which also installs the signal handling this binary
    // had none of.
    let outcome = shutdown::run_until_shutdown(driver.run(), &mut join_set).await;

    // Announced before the tasks are torn down, so `systemctl stop` sees a
    // service on its way out rather than one that stopped answering.
    if let Err(err) = sd_notify::notify(&[sd_notify::NotifyState::Stopping]) {
        tracing::trace!("Failed to notify systemd: {}", err);
    }
    join_set.shutdown().await;
    outcome
}
