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
use wayfinder_driver::BleSendMode;
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
use zerocopy::IntoBytes;

use crate::tap::TapDevice;

/// Command-line arguments.
#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Path to the YAML configuration file.
    #[clap(short, long, default_value = "var/conf/install.yml")]
    pub(crate) config: PathBuf,
}

/// Load this node's persisted identity keypair from a 32-byte seed file.
///
/// Delegates to [`read_seed`] so there is exactly one place that opens a seed
/// file and one shape of error from it: the `auth:` seed is now read twice on
/// the startup path (once to resolve the node's identity and MAC, once here to
/// build the keypair), and two reads of one secret with two error shapes is a
/// seam that drifts.
fn load_keypair(seed_path: &str) -> anyhow::Result<Keypair> {
    Ok(Keypair::from_seed(&read_seed(seed_path)?))
}

/// The lifetime a provider stamps on the membership certificate it issues to
/// *itself*: one year, deliberately far longer than the week-scale
/// `cert_ttl_secs` it hands to members.
///
/// The asymmetry predates this function — it is the window the offline runbook
/// minted by hand — and the reason is unchanged: a member certificate is short
/// *because* passive expiry is the only revocation that reaches every member,
/// while the authority's own identity is what the fleet pins and should be
/// stable. What self-issuing changes is that the window is also refreshed on
/// every start, so the failure this constant guards against — an authority that
/// outlives its own certificate and silently stops being a member of the mesh
/// it signs for — needs a year of uninterrupted uptime to reach rather than a
/// week.
const OWN_CERT_TTL_SECS: u64 = 365 * 24 * 60 * 60;

/// Derive the membership material a provider-mode node need not be handed:
/// its own administrator certificate, and the mesh trust anchor.
///
/// Both are functions of the mesh root key this node already holds, so the
/// files that used to carry them (`wayfinderctl cert init-ca --out-anchor` and
/// `cert issue --admin`) were copies of a computation rather than independent
/// inputs. Only a provider may call this: on any other node the root seed is
/// absent, which is exactly the property that makes a certificate mean
/// something.
///
/// Fails rather than signing when `now_unix` is zero. That is
/// [`wayfinder_server::host_unix_now`]'s report of a clock it will not vouch
/// for, and a certificate stamped from the epoch is not a lesser certificate —
/// it is one every peer rejects, on a node that started cleanly and says
/// nothing. The authority's issuing paths already fail closed on the same
/// reading; this is the same rule applied to the first certificate it issues.
///
/// One consequence to state plainly, because it looks alarming and is not: the
/// window opens at *this* start, so a stored self-revocation naming this node
/// no longer cancels the certificate derived here, and a restart re-admits the
/// authority to its own mesh. That is not a hole this opens. A revocation
/// cancels certificates issued at or before its instant, and the holder of the
/// mesh root key could always mint a later one — offline, in seconds. Revoking
/// a certificate authority to itself was never the mechanism that stops it;
/// taking custody of `root.seed` away is.
fn derive_own_membership(
    root_seed: &[u8; 32],
    mesh_id: u32,
    keypair: &Keypair,
    now_unix: u64,
    cert_ttl_secs: u64,
) -> anyhow::Result<(MembershipCert, wayfinder::wayfinder_auth::TrustAnchor)> {
    if now_unix == 0 {
        bail!(
            "this node has no trusted clock, so it cannot self-issue the membership \
             certificate its [auth] block leaves out; set auth.cert_path to a \
             certificate minted offline, or fix time sync before starting"
        );
    }

    let authority = wayfinder::wayfinder_auth::Authority::from_seed(root_seed, mesh_id);
    // `issue_user_cert(.., admin = true)`, matching byte for byte what
    // `wayfinderctl cert issue --admin` minted for this node before: the
    // capability an operator reaches the authority's own management API with,
    // and what `--cert-from` hands back to a client. Chosen to keep this a
    // change of *where the bytes come from* and not a change of posture —
    // adding `CERT_FLAG_MEMBER` here would look tidier and would silently
    // reclassify the authority from a session to a device in every reader that
    // distinguishes them.
    let cert = authority.issue_user_cert(
        keypair.derived_mac(),
        keypair.ed_pubkey(),
        keypair.x_pubkey(),
        now_unix,
        now_unix.saturating_add(cert_ttl_secs),
        true,
    );
    Ok((cert, authority.trust_anchor()))
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
    // Named, unlike a bare `?`: this is now the first file the node opens on
    // the startup path (the identity seed is resolved before anything else), and
    // an unwrapped `std::fs::read` here surfaces as nothing but "No such file or
    // directory (os error 2)" after the welcome banner — no path, no clue which
    // of the several configured paths was missing. `load_keypair` carried this
    // context and was the first reader until the seed resolution moved above it;
    // the context has to move too, or the diagnostic is lost.
    std::fs::read(path)
        .with_context(|| format!("failed to read the identity seed at {path}"))?
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

/// Map the config layer's [`wayfinder::config::BleSendMode`] onto `blue`'s own
/// [`BleSendMode`].
///
/// Two enums exist for two reasons, and only the first is the obvious one.
/// `blue` depends on `wayfinder`, so the config crate cannot name the link
/// crate's type — the same reason
/// `LinkTransport::default_ble_advertise_dwell_ms` restates a constant instead
/// of referencing it. But that alone would leave the reverse open, and the
/// reverse is blocked separately: `wayfinder::config` sits behind that crate's
/// `alloc` feature (`alloc = ["dep:serde"]`), and `blue` pins `wayfinder` with
/// `default-features = false` precisely to keep serde out of the SoftDevice
/// image. Since `BleSendMode` is read on the firmware side too
/// (`blue::NrfBleLink::new`), naming the config type from `blue` would drag
/// alloc+serde into a `thumbv7em` build. Worth stating, because the dependency
/// direction on its own invites a refactor that fails at link time.
fn ble_send_mode(configured: wayfinder::config::BleSendMode) -> BleSendMode {
    let mapped = match configured {
        wayfinder::config::BleSendMode::Legacy => BleSendMode::Legacy,
        wayfinder::config::BleSendMode::Extended => BleSendMode::Extended,
        wayfinder::config::BleSendMode::Both => BleSendMode::Both,
    };

    // Exhaustive in the *other* direction too. The match above only forces a
    // variant added to `wayfinder::config::BleSendMode` to be handled; one
    // added to `blue::BleSendMode` would otherwise compile fine here and be
    // silently unconfigurable from YAML — the mode would exist in the link
    // crate with no way for an operator to select it. This guard costs nothing
    // and turns that into a compile error at the one place that could fix it.
    match mapped {
        BleSendMode::Legacy | BleSendMode::Extended | BleSendMode::Both => mapped,
    }
}

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

    // Resolve this node's identity seed *once*, up front. Everything below is a
    // function of it: the MAC the router answers to, and the management-TLS
    // server identity a client pins. They used to be resolved by two separate
    // matches of the same three-way shape, which is one match too many for two
    // things that must never disagree.
    //
    // The precedence is the same one that applies everywhere else — an identity
    // installed at runtime is the operator's more recent intent, so it wins over
    // the `auth:` block, which in turn wins over a seed generated for the
    // management port on first boot.
    let mgmt_identity_seed_path = config.server.as_ref().map(|server| match server {
        ServerConfig::Tls {
            identity_seed_path, ..
        } => identity_seed_path
            .clone()
            .unwrap_or_else(ServerConfig::default_identity_seed_path),
    });
    let node_identity_seed: Option<[u8; 32]> = match (&settings.identity, &config.auth) {
        (Some(identity), _) => {
            Some(seed_bytes(&identity.seed).context("runtime-installed identity seed")?)
        }
        (None, Some(auth_cfg)) => Some(read_seed(&auth_cfg.seed_path)?),
        // No mesh identity yet. The management port still needs a stable server
        // key, and generating it here rather than inside the server block is
        // what lets the MAC below derive from it.
        (None, None) => match &mgmt_identity_seed_path {
            Some(path) => Some(load_or_generate_seed(path)?),
            None => None,
        },
    };

    // Decide this node's MAC *before* creating the TAP device, rather than
    // trusting whatever the kernel assigns a freshly-created device — that is
    // random on every restart and would silently change this node's mesh
    // identity each time it starts.
    //
    // **A node routes under the address its identity key derives**, whenever it
    // has an identity key at all. Since design 09 §5's key↔address binding a
    // certificate may name no other address, so any other choice here would give
    // this node an address it cannot be certified for — and would break
    // enrollment rather than merely look untidy.
    //
    // This is a change from the behaviour that preceded the binding, and worth
    // stating because the old comment argued the opposite: a node enrolling
    // online used to keep the address its peers already knew it by, and the
    // certificate was issued for *that* address so joining a mesh did not move
    // it. That is no longer expressible. An un-enrolled node runs under a
    // provisional address until it has an identity to derive one from, and
    // enrolling is what moves it — once, to the address it keeps. `csr request`
    // says so out loud when it builds the request.
    //
    // The fallback survives for the one node that has no identity key at all:
    // no `auth:` block, no runtime identity, and no management server to have
    // generated a seed for. Such a node cannot be enrolled over the wire
    // anyway, so a MAC generated once and persisted is exactly right for it.
    let mac_addr = match node_identity_seed {
        Some(seed) => {
            let derived = Keypair::from_seed(&seed).derived_mac().0;
            // A persisted MAC that disagrees is this node's *previous* address:
            // it ran under a randomly-generated one before the binding made the
            // address a function of the identity key. Said out loud, once,
            // because this is the only place in the flow where the renumber
            // actually happens — `csr request` and the dashboard warn about a
            // renumber they are *about* to cause, and this one has no such
            // warning attached to it at all.
            //
            // `warn!`, not `info!`: it is not reachable by remote input (it is a
            // local file read at startup), it happens at most once in a node's
            // life, and an operator who learns about it from peers going quiet
            // learns about it the worst way.
            if let Ok(previous) = std::fs::read(&mac_state_path)
                && previous.as_slice() != derived
            {
                tracing::warn!(
                    previous = %pretty_hex::simple_hex(&previous),
                    now = %pretty_hex::simple_hex(&derived),
                    state_path = %mac_state_path,
                    "this node has renumbered: its address is now the one its \
                     identity key derives. Peers will relearn it; anything pinned \
                     to the old address needs updating, and the state file is now \
                     stale and unread."
                );
            }
            derived
        }
        None => load_or_generate_mac(&mac_state_path)?,
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
                // The discovery_addr/multicast_interface combinations that
                // cannot work are rejected inside the builder (`discovery_mode`),
                // so every caller gets the check rather than only this one.
                // All this adds is which link the operator has to go fix.
                interfaces.push(
                    build_udp_multi_link(bind_addr, discovery_addr, multicast_interface.as_deref())
                        .await
                        .with_context(|| format!("udpmulti link {:?}", names.last()))?,
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
                send_mode,
            } => {
                interfaces.push(
                    build_ble_link(BleLinkParams {
                        adapter,
                        advertise_dwell: std::time::Duration::from_millis(advertise_dwell_ms),
                        send_mode: ble_send_mode(send_mode),
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
            // `identity_seed_path` is consumed at the top of startup, where the
            // node's one identity seed is resolved; only the bind address is
            // this block's business.
            ServerConfig::Tls { addr, .. } => {
                // The TLS server identity is the node's identity, resolved
                // once at the top of startup — the same key the MAC derives
                // from, so a client that enrolls this node certifies the
                // identity it was already talking to, at the address that
                // identity gives it. It must exist even before enrollment,
                // since a client with no certificate yet authenticates by
                // proving this key.
                //
                let identity_seed = node_identity_seed.ok_or_else(|| {
                    anyhow!(
                        "the management server needs an identity seed, and none was \
                         resolved at startup"
                    )
                })?;
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
    //
    // A third possibility joins those two below: a node in provider mode may
    // leave the certificate and the anchor out of its `auth:` block entirely
    // and have them *derived* from the mesh root key it holds anyway. That is a
    // third source of the same three blobs, not a third code path — it lands in
    // the same tuple and is checked by the same code.
    let mut auth_mesh_id: Option<u32> = None;

    // Read once, here, rather than where provider mode is enabled further down:
    // the `auth:` resolution below may need it to derive this node's own
    // membership, and provider startup needs the same 32 bytes. Two reads of
    // the mesh root of trust with two error shapes is the seam `read_seed`'s
    // own doc comment warns about, one file up.
    let provider_root_seed: Option<[u8; 32]> = match &config.provider {
        Some(provider_cfg) => Some(
            std::fs::read(&provider_cfg.root_seed_path)
                .with_context(|| {
                    format!(
                        "failed to read the mesh root seed at {}",
                        provider_cfg.root_seed_path
                    )
                })?
                .as_slice()
                .try_into()
                .map_err(|_| {
                    anyhow!(
                        "mesh root seed at {} must be 32 bytes",
                        provider_cfg.root_seed_path
                    )
                })?,
        ),
        None => None,
    };

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
        (None, Some(auth_cfg)) => {
            let keypair = load_keypair(&auth_cfg.seed_path)?;

            // Derived once, and only when a half is actually missing: a node
            // handed both files must not sign a certificate it throws away,
            // and the clock requirement inside must only bite the
            // configuration that depends on it.
            let derived = match (&config.provider, &provider_root_seed) {
                (Some(provider_cfg), Some(root_seed))
                    if auth_cfg.cert_path.is_none() || auth_cfg.trust_anchor_path.is_none() =>
                {
                    let material = derive_own_membership(
                        root_seed,
                        provider_cfg.mesh_id,
                        &keypair,
                        wayfinder_server::host_unix_now(),
                        OWN_CERT_TTL_SECS,
                    )?;
                    // Worth an operator's attention at `info!`: this is the
                    // node minting its own mesh membership, which on any other
                    // node would be the thing certificates exist to prevent.
                    // Saying so at startup is what keeps it a deliberate
                    // property of provider mode rather than a quiet one.
                    tracing::info!(
                        mesh_id = format!("{:#x}", provider_cfg.mesh_id),
                        cert = auth_cfg.cert_path.is_none(),
                        trust_anchor = auth_cfg.trust_anchor_path.is_none(),
                        "deriving this provider's own membership material from the mesh root seed"
                    );
                    Some(material)
                }
                _ => None,
            };

            // Each half resolves the same way: the configured file if there is
            // one, the derived value if this node could compute it, and
            // otherwise an error naming the field. A named path always wins —
            // an operator who wrote one meant that file, and quietly preferring
            // a derived copy would paper over a stale one instead of letting
            // the certificate checks below catch it.
            let cert_bytes = match (&auth_cfg.cert_path, &derived) {
                (Some(path), _) => std::fs::read(path)
                    .with_context(|| format!("failed to read the membership cert at {path}"))?,
                (None, Some((cert, _))) => cert.as_bytes().to_vec(),
                (None, None) => bail!(
                    "auth.cert_path must be set: only a node in provider mode may leave it \
                     out, because only a provider holds the mesh root key that would sign \
                     its certificate"
                ),
            };
            let anchor_bytes = match (&auth_cfg.trust_anchor_path, &derived) {
                (Some(path), _) => std::fs::read(path)
                    .with_context(|| format!("failed to read the trust anchor at {path}"))?,
                (None, Some((_, anchor))) => anchor.to_bytes().to_vec(),
                (None, None) => bail!(
                    "auth.trust_anchor_path must be set: only a node in provider mode may \
                     leave it out, because only a provider holds the mesh root key the \
                     anchor is derived from"
                ),
            };

            // Names where the bytes came from, for the errors the checks below
            // raise against them: a path when a file supplied them, and the
            // root seed when this node computed them.
            let source = auth_cfg
                .cert_path
                .clone()
                .unwrap_or_else(|| "this provider's own mesh root seed".to_string());

            Some((keypair, cert_bytes, anchor_bytes, source))
        }
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
        //
        // Load-bearing, and *more* so since the key↔address binding (design 09
        // §5) rather than less. Note what this path does **not** do: it hands
        // the certificate straight to `OgmAuth::new` without calling
        // `verify_cert` on it, so for material read from an operator's `auth:`
        // files this comparison is the only structural check standing between a
        // wrong cert and a node that boots happily while every peer drops its
        // OGMs. (It is the certificate's own subject against a MAC derived from
        // the seed beside it, so it catches a cert/seed pair copied from
        // different nodes — the likeliest way to get here.)
        //
        // The binding also made this reachable on the runtime-identity path,
        // where it previously could not fire at all: `mac_addr` used to be read
        // *out of this very certificate*, making the comparison tautological.
        // Deriving it from the seed is what gives the two sides independent
        // provenance and so something to disagree about.
        //
        // A misattributed OGM is a silent fault; refusing to start is not.
        if cert.node_mac != mac_addr {
            bail!(
                "membership cert is bound to MAC {:?}, but this node's MAC is {:?} — \
                 a certificate's MAC must be the address its identity key derives, so \
                 this certificate belongs to a different key (or predates that rule \
                 and must be re-issued)",
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
    if let Some(provider_cfg) = &config.provider {
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

        // Read at the top of auth resolution, because the `auth:` block may
        // have needed the same bytes to derive this node's own membership.
        // Matched rather than unwrapped so the compiler ties it to the branch
        // that filled it: both are conditioned on `config.provider`.
        let Some(root_seed) = provider_root_seed else {
            bail!("internal: provider configured but its root seed was never read");
        };
        let mut ca = CertAuthority::from_config(&root_seed, provider_cfg)
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

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder::wayfinder_auth::Authority;
    use wayfinder::wayfinder_auth::TrustAnchor;

    /// The mesh this node's tests sign for.
    const MESH: u32 = 0x5741_594e;

    /// A root seed, and the node identity seed beside it. Distinct constants
    /// because the whole point of the derivation is that the two are separate
    /// keys held by one process.
    const ROOT_SEED: [u8; 32] = [7u8; 32];
    const NODE_SEED: [u8; 32] = [9u8; 32];

    /// The trust anchor a provider derives is the one its root seed defines —
    /// the same 36 bytes `wayfinderctl cert init-ca --out-anchor` would have
    /// written, which is why the file is redundant on a node holding the root.
    #[test]
    fn derived_anchor_matches_the_root_seed() {
        let node = Keypair::from_seed(&NODE_SEED);
        let (_, anchor) = derive_own_membership(&ROOT_SEED, MESH, &node, 1_000, 3_600)
            .expect("a trusted clock and a valid root seed");

        let expected = Authority::from_seed(&ROOT_SEED, MESH).trust_anchor();
        assert_eq!(anchor.mesh_id, expected.mesh_id);
        assert_eq!(anchor.root_pubkey, expected.root_pubkey);
        assert_eq!(anchor.mesh_id, MESH);
    }

    /// The self-issued certificate verifies against the anchor derived beside
    /// it, and binds the address this node's identity key derives — the same
    /// two properties `main` checks on a certificate read from a file.
    #[test]
    fn self_issued_cert_verifies_and_binds_the_derived_mac() {
        let node = Keypair::from_seed(&NODE_SEED);
        let now = 1_000;
        let (cert, anchor) = derive_own_membership(&ROOT_SEED, MESH, &node, now, 3_600)
            .expect("a trusted clock and a valid root seed");

        assert_eq!(cert.node_mac, node.derived_mac().0);
        let verified = anchor
            .verify_cert(&cert, now + 1)
            .expect("a certificate signed by the anchor's own root");
        assert!(
            verified.admin,
            "a provider's own certificate carries the administration capability, or the \
             operator loses management access to the node holding the mesh root"
        );
    }

    /// The window opens at the instant of issue and runs for the requested
    /// lifetime, so a freshly self-issued certificate is valid now and expires
    /// on schedule.
    #[test]
    fn self_issued_cert_window_starts_now_and_runs_for_the_ttl() {
        let node = Keypair::from_seed(&NODE_SEED);
        let now = 2_000_000;
        let ttl = 31_536_000;
        let (cert, anchor) = derive_own_membership(&ROOT_SEED, MESH, &node, now, ttl)
            .expect("a trusted clock and a valid root seed");

        assert_eq!(cert.not_before.get(), now);
        assert_eq!(cert.not_after.get(), now + ttl);
        assert!(anchor.verify_cert(&cert, now + ttl - 1).is_ok());
        assert!(
            anchor.verify_cert(&cert, now + ttl + 1).is_err(),
            "the certificate must age out at its stated expiry"
        );
    }

    /// Without a usable wall clock there is no honest validity window to sign,
    /// so the node refuses to mint one rather than stamping a window starting
    /// at the epoch that every peer would reject.
    #[test]
    fn refuses_to_self_issue_without_a_trusted_clock() {
        let node = Keypair::from_seed(&NODE_SEED);
        let err = derive_own_membership(&ROOT_SEED, MESH, &node, 0, 3_600)
            .expect_err("an untrusted clock must not yield a certificate");
        assert!(
            err.to_string().contains("clock"),
            "the error must name the clock as the cause, got: {err}"
        );
    }

    /// A derived anchor and a derived certificate are consistent with what the
    /// *rest* of startup expects: `TrustAnchor::from_bytes` round-trips the
    /// anchor, since the same bytes reach `OgmAuth` either way.
    #[test]
    fn derived_anchor_round_trips_through_its_wire_bytes() {
        let node = Keypair::from_seed(&NODE_SEED);
        let (_, anchor) = derive_own_membership(&ROOT_SEED, MESH, &node, 1_000, 3_600)
            .expect("a trusted clock and a valid root seed");

        let reparsed =
            TrustAnchor::from_bytes(&anchor.to_bytes()).expect("a derived anchor is well-formed");
        assert_eq!(reparsed.mesh_id, MESH);
        assert_eq!(reparsed.root_pubkey, anchor.root_pubkey);
    }
}
