//! The runnable Wayfinder node: bridges a host TAP device onto the mesh,
//! carries mesh links over UDP, and exposes the management API.
//!
//! All of the routing event loop lives in `wayfinder-driver`; this binary only
//! assembles the concrete transports (a kernel TAP, UDP links) and the
//! management-API listeners from the YAML config, then hands them to a
//! [`Driver`] and runs it.

mod tap;

use std::path::{Path, PathBuf};

use anyhow::bail;
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

    let dev = DeviceBuilder::new()
        .layer(Layer::L2)
        .name(&tap.device_name)
        .ipv4(tap.ip_address, tap.netmask, None)
        .build_async()?;

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

    driver.run().await
}

#[cfg(test)]
mod tests {
    use wayfinder::config::{Config, LinkTransport};

    /// The exact config shape the sim image's entrypoint emits must parse:
    /// RawL2 links, with an optional per-link `ogm:` block that defaults when
    /// omitted.  Locks the schema the docker simulation depends on.
    #[test]
    fn sim_generated_config_parses() {
        let yaml = r#"
local_egress:
  type: Tap
  device_name: wayfinder0
  ip_address: 10.0.0.1
  netmask: 255.255.255.0
server:
  type: Tcp
  addr: 0.0.0.0:7700
links:
  - type: RawL2
    interface: eth0
    ethertype: 0x4305
    ogm:
      i_min_ms: 2000
      i_max_ms: 120000
  - type: RawL2
    interface: eth1
    ethertype: 0x4305
"#;
        let cfg: Config = serde_yaml::from_str(yaml).expect("sim config must parse");
        assert_eq!(cfg.links.len(), 2);

        // First link carries explicit OGM bounds.
        assert!(matches!(
            cfg.links[0].transport,
            LinkTransport::RawL2 {
                ethertype: 0x4305,
                ..
            }
        ));
        assert_eq!(cfg.links[0].ogm.i_min_ms, 2000);
        assert_eq!(cfg.links[0].ogm.i_max_ms, 120_000);

        // Second link omits `ogm:` and falls back to the defaults.
        assert_eq!(cfg.links[1].ogm.i_min_ms, 1000);
        assert_eq!(cfg.links[1].ogm.i_max_ms, 64_000);
    }
}
