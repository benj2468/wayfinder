//! The runnable Wayfinder node: bridges a host TAP device onto the mesh,
//! carries mesh links over UDP, and exposes the management API.
//!
//! All of the routing event loop lives in `wayfinder-driver`; this binary only
//! assembles the concrete transports (a kernel TAP, UDP links) and the
//! management-API listeners from the YAML config, then hands them to a
//! [`Driver`] and runs it.

mod tap;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use clap::Parser;
use tokio::{sync::mpsc, task::JoinSet};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, Layer};
use wayfinder::config::{
    Config, LinkTransport, LocalDistributionMechanism, ServerConfig, TrickleConfig,
};
use wayfinder::interfaces::frame::Mac;
use wayfinder_driver::{
    Driver, QueryRx, QueryTx, build_raw_ip_link, build_raw_l2_link, build_udp_link, run_tcp_server,
    run_udp_server, run_unix_server,
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
    tracing::debug!("{:#?}", config);

    let mut join_set: JoinSet<anyhow::Result<()>> = JoinSet::new();

    // This binary's local egress is a kernel TAP; reject any other mechanism.
    let LocalDistributionMechanism::Tap(tap) = match config.local_egress {
        Some(mechanism) => mechanism,
        None => bail!("config.local_egress must be a TAP for the wayfinder-tap node"),
    };

    let mut builder = DeviceBuilder::new().layer(Layer::L2).name(&tap.device_name);
    // The IPv4 address/netmask are optional: when no address is configured the
    // TAP is brought up unaddressed (the mesh routes on MAC, not IP).
    if let Some(ip_address) = tap.ip_address {
        let netmask = tap
            .netmask
            .unwrap_or(wayfinder::config::TapConfig::DEFAULT_NETMASK);
        builder = builder.ipv4(ip_address, netmask, None);
    }
    let dev = builder.build_async()?;

    let mac_addr = dev.mac_address()?;
    tracing::info!(
        "Starting wayfinder with MAC address: {:?}",
        pretty_hex::simple_hex(&mac_addr)
    );

    let mut interfaces = Vec::new();
    // Per-interface OGM backoff bounds, collected in interface order alongside
    // the transports so the driver can pace each link independently.
    let mut trickle: Vec<TrickleConfig> = Vec::new();
    for link in config.links {
        match link.transport {
            LinkTransport::Udp {
                bind_addr,
                remote_addr,
            } => {
                interfaces.push(build_udp_link(bind_addr, remote_addr, &mut join_set).await?);
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
            LinkTransport::Test { .. } => {
                bail!("test links are only valid in the test harness, not the wayfinder-tap node")
            }
        }
        trickle.push(link.ogm);
    }

    // Optional management API server — queries are forwarded to the driver over
    // a channel so the router is never shared across tasks.
    let (query_tx, query_rx): (QueryTx, QueryRx) = mpsc::channel(16);

    if let Some(server_cfg) = config.server {
        let tx = query_tx.clone();
        match server_cfg {
            ServerConfig::Tcp { addr } => {
                join_set.spawn(async move { run_tcp_server(addr, tx).await });
            }
            ServerConfig::UnixSocket { path } => {
                let path = Path::new(&path).to_path_buf();
                join_set.spawn(async move { run_unix_server(path, tx).await });
            }
            ServerConfig::Udp { addr } => {
                join_set.spawn(async move { run_udp_server(addr, tx).await });
            }
        }
    }

    let mut driver = Driver::new(Mac(mac_addr), TapDevice(dev), interfaces, trickle, query_rx);

    // Opt-in mesh authentication: load this node's identity, certificate, and
    // the mesh trust anchor, then enable OGM auth on the router.  Absent ⇒ the
    // node runs unauthenticated.
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
        driver
            .router_mut()
            .set_auth(OgmAuth::new(keypair, cert, anchor));
        tracing::info!("mesh authentication enabled (mesh_id = {:#x})", mesh_id);
    }

    driver.run().await
}
