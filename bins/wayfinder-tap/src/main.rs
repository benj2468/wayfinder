use std::time::Instant;

use clap::Parser;
use tracing::warn;
use tracing_subscriber::EnvFilter;
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};
use wayfinder::{
    CentralRouter,
    interfaces::{engine::MeshRoutingEngine, link::EmbeddedMeshLink},
};

#[derive(clap::Parser, Debug)]
pub struct Args {
    #[clap(short, long, default_value = "fethwayfinder")]
    device_name: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    tracing::info!("Welcome to 🌊 Wayfinder");

    let dev = DeviceBuilder::new()
        .layer(Layer::L2) // TAP mode for Ethernet frames
        .name(args.device_name)
        .build_async()?;

    let mac_addr = dev.mac_address()?;

    let mut wayfinder = CentralRouter::new([], mac_addr);

    let boot = Instant::now();

    let mut buffer = [0; 1500];

    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                wayfinder.poll_and_route(boot.elapsed()).await;
            },
            Ok(bytes) = dev.recv(&mut buffer) => {

                // TOD(bjc) change this to mac addr
                match etherparse::Ethernet2Header::from_slice(&buffer[..bytes]) {
                    Ok((ether, _)) => {
                        wayfinder.dispatch_from_local(ether.destination, &buffer[..bytes]).await?;
                    }
                    Err(e) => {
                        warn!("Failed to parse ethernet header: {e:?}");
                    }
                }
            }
        }
    }
}
