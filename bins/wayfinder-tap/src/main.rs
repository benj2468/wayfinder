use std::{net::SocketAddr, path::PathBuf, time::Instant};

use anyhow::bail;
use clap::Parser;
use core::net::Ipv4Addr;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UdpSocket, UnixListener, UnixStream},
    task::JoinSet,
};
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
    UnixServer { path: PathBuf },
    UnixClient { path: PathBuf },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(default)]
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
    #[clap(short, long, default_value = "var/conf/install.yml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let config: Config = serde_yaml::from_slice(std::fs::read_to_string(args.config)?.as_bytes())?;

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
                    let mut rx_buf = [0; 1500];
                    let mut tx_buf = [0; 1500];
                    tokio::select! {
                        Ok(bytes) = udp_socket.recv(&mut rx_buf) => {
                            let read = rx_buf[..bytes].to_vec();
                            dp1.write_all(&read).await?;
                        },
                        Ok(bytes) = dp1.read(&mut tx_buf) => {
                            let read = tx_buf[..bytes].to_vec();
                            udp_socket.send(&read).await?;
                        },
                    }

                    bail!("Task should never complete");
                });

                interfaces
                    .push(Box::new(IdentifiableLink::new(mac_addr, dp2))
                        as Box<dyn EmbeddedMeshLink<_>>);
            }
            Link::UnixServer { path } => {
                if std::fs::metadata(&path).is_ok() {
                    std::fs::remove_file(&path)?;
                }
                let listener = UnixListener::bind(&path)?;

                let (mut dp1, dp2) = tokio::io::duplex(1500);

                join_set.spawn(async move {
                    let mut rx_buf = [0; 1500];
                    let mut tx_buf = [0; 1500];
                    while let Ok((mut stream, _)) = listener.accept().await {
                        tokio::select! {
                            Ok(bytes) = stream.read(&mut rx_buf) => {
                                let read = rx_buf[..bytes].to_vec();
                                dp1.write_all(&read).await?;
                            },
                            Ok(read) = dp1.read(&mut tx_buf) => {
                                let read = tx_buf[..read].to_vec();
                                stream.write_all(&read).await?;
                            }
                        }
                    }

                    bail!("Task should never complete");
                });

                interfaces
                    .push(Box::new(IdentifiableLink::new(mac_addr, dp2))
                        as Box<dyn EmbeddedMeshLink<_>>);
            }
            Link::UnixClient { path } => {
                let stream = UnixStream::connect(&path).await?;

                interfaces.push(Box::new(IdentifiableLink::new(mac_addr, stream))
                    as Box<dyn EmbeddedMeshLink<_>>);
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
                tracing::trace!("received {} bytes", bytes);

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
