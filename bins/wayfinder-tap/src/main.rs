use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use core::net::Ipv4Addr;
use embedded_io_adapters::tokio_1::FromTokio;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UdpSocket, UnixListener, UnixStream},
    task::JoinSet,
};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, Layer};
use wayfinder::{CentralRouter, interfaces::link::IdentifiableLink};

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
                    loop {
                        tokio::select! {
                            Ok(bytes) = udp_socket.recv(&mut rx_buf) => {
                                dp1.write_all(&rx_buf[..bytes]).await?;
                            },
                            Ok(bytes) = dp1.read(&mut tx_buf) => {
                                udp_socket.send(&tx_buf[..bytes]).await?;
                            },
                        }
                    }
                });

                interfaces.push(IdentifiableLink::new(mac_addr, FromTokio::new(dp2)));
            }
            Link::UnixServer { path } => {
                if std::fs::metadata(&path).is_ok() {
                    std::fs::remove_file(&path)?;
                }
                let listener = UnixListener::bind(path)?;
                let (mut dp1, dp2) = tokio::io::duplex(1500);

                join_set.spawn(async move {
                    if let Ok((mut stream, _)) = listener.accept().await {
                        let mut rx_buf = [0; 1500];
                        let mut tx_buf = [0; 1500];
                        loop {
                            tokio::select! {
                                Ok(bytes) = stream.read(&mut rx_buf) => {
                                    if bytes == 0 { break; }
                                    dp1.write_all(&rx_buf[..bytes]).await?;
                                },
                                Ok(bytes) = dp1.read(&mut tx_buf) => {
                                    stream.write_all(&tx_buf[..bytes]).await?;
                                },
                            }
                        }
                    }
                    Ok(())
                });

                interfaces.push(IdentifiableLink::new(mac_addr, FromTokio::new(dp2)));
            }
            Link::UnixClient { path } => {
                let mut stream = UnixStream::connect(path).await?;
                let (mut dp1, dp2) = tokio::io::duplex(1500);

                join_set.spawn(async move {
                    let mut rx_buf = [0; 1500];
                    let mut tx_buf = [0; 1500];
                    loop {
                        tokio::select! {
                            Ok(bytes) = stream.read(&mut rx_buf) => {
                                if bytes == 0 { break; }
                                dp1.write_all(&rx_buf[..bytes]).await?;
                            },
                            Ok(bytes) = dp1.read(&mut tx_buf) => {
                                stream.write_all(&tx_buf[..bytes]).await?;
                            },
                        }
                    }
                    Ok(())
                });

                interfaces.push(IdentifiableLink::new(mac_addr, FromTokio::new(dp2)));
            }
        }
    }

    let mut router = CentralRouter::<[u8; 6]>::new(mac_addr);

    let start = std::time::Instant::now();

    join_set.spawn(async move {
        loop {
            let mut interface_refs: Vec<
                &mut IdentifiableLink<[u8; 6], FromTokio<tokio::io::DuplexStream>>,
            > = interfaces.iter_mut().collect();

            router
                .poll_and_route(&mut interface_refs, start.elapsed())
                .await;
            tokio::task::yield_now().await;
        }
    });

    // Bridging TAP device to local router dispatch
    // (This part would need more refactoring to use the new router dispatch API)

    while let Some(res) = join_set.join_next().await {
        res??;
    }

    Ok(())
}
