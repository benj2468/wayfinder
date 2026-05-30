//! The runnable Wayfinder node: bridges a host TAP device onto the mesh,
//! carries mesh links over UDP, and exposes the management API.

mod config;
mod executor;
mod links;

#[cfg(test)]
mod tests;

use clap::Parser;
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, Layer};
use wayfinder::CentralRouter;

use crate::config::{Args, Config, LinkConfig, ServerConfig};
use crate::executor::EventLoop;
use crate::links::Link;
use wayfinder_server::{QueryRx, QueryTx, run_tcp_server, run_udp_server, run_unix_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let config: Config = serde_yaml::from_slice(std::fs::read_to_string(args.config)?.as_bytes())?;

    tracing::info!("Welcome to Wayfinder");

    let mut join_set: JoinSet<anyhow::Result<()>> = JoinSet::new();

    let dev = DeviceBuilder::new()
        .layer(Layer::L2)
        .name(&config.tap.device_name)
        .ipv4(config.tap.ip_address, config.tap.netmask, None)
        .build_async()?;

    let mac_addr = dev.mac_address()?;
    tracing::info!(
        "Starting wayfinder with MAC address: {:?}",
        pretty_hex::simple_hex(&mac_addr)
    );

    tracing::debug!("{:#?}", config);

    let mut interfaces = vec![];

    for link in config.links {
        match link {
            LinkConfig::Udp {
                bind_addr,
                remote_addr,
            } => {
                let udp_socket = UdpSocket::bind(bind_addr).await?;
                udp_socket.connect(remote_addr).await?;

                let (dp1, dp2) = tokio::net::UnixDatagram::pair()?;

                join_set.spawn(async move {
                    let mut rx_buf = [0; 1500];
                    let mut tx_buf = [0; 1500];
                    loop {
                        tokio::select! {
                            Ok(bytes) = udp_socket.recv(&mut rx_buf) => {
                                if let Err(e) = dp1.send(&rx_buf[..bytes]).await {
                                    tracing::error!("Error sending to in-process socket: {:?}", e);
                                }
                            },
                            Ok(bytes) = dp1.recv(&mut tx_buf) => {
                                // TODO: The UDP socket needs to be connected to the remote address before sending
                                // Or we need to specify the remote address in the send call
                                if let Err(e) = udp_socket.send(&tx_buf[..bytes]).await {
                                    tracing::error!("Error sending to off-process socket: {:?}", e);
                                }
                            },
                        }
                    }
                });

                interfaces.push(Link::new(dp2));
            }
        }
    }

    // Optional management API server — queries are forwarded to the main loop
    // over a channel so the router is never shared across tasks.
    let (query_tx, query_rx): (QueryTx, QueryRx) = mpsc::channel(16);

    if let Some(server_cfg) = config.server {
        match server_cfg {
            ServerConfig::Tcp { addr } => {
                let tx = query_tx.clone();
                join_set.spawn(async move { run_tcp_server(addr, tx).await });
            }
            ServerConfig::UnixSocket { path } => {
                let tx = query_tx.clone();
                join_set.spawn(async move { run_unix_server(path, tx).await });
            }
            ServerConfig::Udp { addr } => {
                let tx = query_tx.clone();
                join_set.spawn(async move { run_udp_server(addr, tx).await });
            }
        }
    }

    let mut event_loop = EventLoop {
        tap: dev,
        interfaces,
        router: CentralRouter::<[u8; 6]>::new(mac_addr),
        query_rx,
        mac_addr,
        start: std::time::Instant::now(),
        rx_buffer: [0u8; 1500],
        tx_buffer: [0u8; 1500],
    };

    loop {
        event_loop.run_once().await?;
    }
}
