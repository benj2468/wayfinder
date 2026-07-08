//! The runnable Wayfinder node: bridges a host TAP device onto the mesh,
//! carries mesh links over UDP, and exposes the management API.
//!
//! All of the routing event loop lives in `wayfinder-driver`; this binary only
//! assembles the concrete transports (a kernel TAP, UDP links) and the
//! management-API listeners from the YAML config, then hands them to a
//! [`Driver`] and runs it.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod tap;

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use clap::Parser;
use tokio::{sync::mpsc, task::JoinSet};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, Layer};
use wayfinder::config::{Config, LocalDistributionMechanism, ServerConfig, TrickleConfig};
use wayfinder::interfaces::frame::Mac;
use wayfinder_driver::{
    Driver, LINK_BUILDERS, QueryRx, QueryTx, bind_tcp_server, bind_udp_server, bind_unix_server,
    serve_tcp_server, serve_udp_server, serve_unix_server,
};

use crate::tap::TapDevice;

/// Command-line arguments.
#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Path to the YAML configuration file.
    #[clap(short, long, default_value = "var/conf/install.yml")]
    pub(crate) config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let config: Config = serde_yaml::from_slice(std::fs::read_to_string(args.config)?.as_bytes())?;

    tracing::info!("Welcome to Wayfinder");
    // The config can carry sensitive material (enrollment tokens, seed paths),
    // so keep the full dump at DEBUG rather than INFO.
    tracing::debug!(?config, "loaded configuration");

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
    let mut builder = DeviceBuilder::new()
        .layer(Layer::L2)
        .name(&tap.device_name)
        .mtu(mtu);
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
        .context("failed to craete TAP device")?;

    let mac_addr = dev.mac_address().context("unable to get mac address")?;
    tracing::info!(
        "Starting wayfinder with MAC address: {:?}",
        pretty_hex::simple_hex(&mac_addr)
    );

    let mut interfaces = Vec::new();
    // Per-interface OGM backoff bounds, collected in interface order alongside
    // the transports so the driver can pace each link independently.
    let mut trickle: Vec<TrickleConfig> = Vec::new();
    for link in config.links {
        let builder = LINK_BUILDERS
            .iter()
            .find(|b| b.type_tag == link.link_type)
            .ok_or_else(|| anyhow!("unknown link type: {}", link.link_type))?;
        interfaces.push((builder.build)(&link.params, &mut join_set).await?);
        trickle.push(link.ogm);
    }

    // Optional management API server — queries are forwarded to the driver over
    // a channel so the router is never shared across tasks.
    let (query_tx, query_rx): (QueryTx, QueryRx) = mpsc::channel(16);

    if let Some(server_cfg) = config.server {
        let tx = query_tx.clone();
        match server_cfg {
            ServerConfig::Tcp { addr } => {
                let listener = bind_tcp_server(addr).await?;
                join_set.spawn(async move { serve_tcp_server(listener, tx).await });
            }
            ServerConfig::UnixSocket { path } => {
                let path = Path::new(&path).to_path_buf();
                let socket = bind_unix_server(path).await?;
                join_set.spawn(async move { serve_unix_server(socket, tx).await });
            }
            ServerConfig::Udp { addr } => {
                let socket = bind_udp_server(addr).await?;
                join_set.spawn(async move { serve_udp_server(socket, tx).await });
            }
        }
    }

    let mut driver = Driver::new(Mac(mac_addr), TapDevice(dev), interfaces, trickle, query_rx);

    // Fail-closed policy: when configured, the router stays inert (see
    // `CentralRouter::auth_locked`) until a membership cert is installed below
    // (from `[auth]`) or later via a runtime `set-auth`. Set unconditionally,
    // regardless of whether `[auth]` is present below: a `require_auth: true`
    // node with no `[auth]` block (relying entirely on a runtime `set-auth`)
    // must still start out correctly locked.
    driver.router_mut().set_require_auth(config.require_auth);
    if config.require_auth && config.auth.is_none() {
        tracing::warn!(
            "require_auth is set but no [auth] block is configured; this node will \
             stay locked (no routing, no OGM emission) until a certificate is \
             installed via a runtime set-auth"
        );
    }

    // Opt-in mesh authentication: load this node's identity, certificate, and
    // the mesh trust anchor, then enable OGM auth on the router.  Absent ⇒ the
    // node runs unauthenticated.
    let mut auth_mesh_id: Option<u32> = None;
    if let Some(auth_cfg) = config.auth {
        use wayfinder::auth::OgmAuth;
        use wayfinder::wayfinder_auth::{Keypair, MembershipCert, TrustAnchor};

        let seed: [u8; 32] = std::fs::read(&auth_cfg.seed_path)?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("identity seed at {} must be 32 bytes", auth_cfg.seed_path))?;
        let keypair = Keypair::from_seed(&seed);

        let cert_bytes = std::fs::read(&auth_cfg.cert_path)?;
        let cert = MembershipCert::from_bytes(&cert_bytes)
            .ok_or_else(|| anyhow!("invalid membership cert at {}", auth_cfg.cert_path))?;

        let anchor_bytes = std::fs::read(&auth_cfg.trust_anchor_path)?;
        let anchor = TrustAnchor::from_bytes(&anchor_bytes)
            .ok_or_else(|| anyhow!("invalid trust anchor at {}", auth_cfg.trust_anchor_path))?;

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

    if let Err(err) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
        tracing::trace!("Failed to notify systemd: {}", err);
    }

    driver.run().await
}
