use std::{
    io::Read,
    net::{SocketAddr, SocketAddrV4},
    path::PathBuf,
    time::Instant,
};

use anyhow::bail;
use clap::Parser;
use core::net::Ipv4Addr;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, net::UdpSocket, task::JoinSet};
use tracing::warn;
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, Layer};
use wayfinder::{
    CentralRouter,
    interfaces::link::{EmbeddedMeshLink, IdentifiableLink},
};

#[derive(Serialize, Deserialize, Debug)]
pub enum Link {
    Udp { socket_addr: SocketAddr },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    links: Vec<Link>,
}

#[derive(clap::Parser, Debug)]
pub struct Args {
    #[clap(short, long, default_value = "wayfinder0")]
    device_name: String,
    #[clap(short, long, default_value = "192.168.184.1")]
    ip_address: Ipv4Addr,
    #[clap(short, long, default_value = "255.255.255.0")]
    netmask: Ipv4Addr,
    #[clap(short, long, default_value = "var/conf/install.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let config: Config = toml::from_slice(std::fs::read_to_string(args.config)?.as_bytes())?;

    tracing::info!("Welcome to 🌊 Wayfinder");

    let mut join_set: JoinSet<anyhow::Result<()>> = JoinSet::new();

    let dev = DeviceBuilder::new()
        .layer(Layer::L2) // TAP mode for Ethernet frames
        .name(args.device_name)
        .ipv4(args.ip_address, args.netmask, None)
        .build_async()?;

    let mac_addr = dev.mac_address()?;
    tracing::info!("Starting wavefinder with MAC address: {:?}", mac_addr);

    let mut interfaces = vec![];

    for link in config.links {
        match link {
            Link::Udp { socket_addr } => {
                let udp_socket = UdpSocket::bind(socket_addr).await?;

                let (mut dp1, dp2) = tokio::io::duplex(1500);

                join_set.spawn(async move {
                    let mut buf = [0; 1500];
                    while let Ok(bytes) = udp_socket.recv(&mut buf).await {
                        let read = buf[..bytes].to_vec();

                        dp1.write_all(&read).await?;
                    }

                    bail!("Task should never complete");
                });

                interfaces.push(Box::new(IdentifiableLink {
                    link: dp2,
                    identifier: mac_addr,
                }) as Box<dyn EmbeddedMeshLink<_>>);
            }
        }
    }

    let mut wayfinder = CentralRouter::new(interfaces, mac_addr);

    let boot = Instant::now();

    let mut buffer = [0; 1500];

    loop {
        tokio::select! {
            Some(_) = join_set.join_next() => {
                bail!("Join Set Handle expectedly completed");
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                wayfinder.poll_and_route(boot.elapsed()).await;
            },
            Ok(bytes) = dev.recv(&mut buffer) => {

                match etherparse::Ethernet2Header::from_slice(&buffer[..bytes]) {
                    Ok((ether, _)) => {
                        if let Err(e) = wayfinder.dispatch_from_local(ether.destination, &buffer[..bytes]).await {
                            warn!("Failed to dispatch from local: {e:?}");
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse ethernet header: {e:?}");
                    }
                }
            }
        }
    }
}
