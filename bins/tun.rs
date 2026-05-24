use std::net::Ipv4Addr;

use anyhow::bail;
use clap::Parser;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    task::JoinHandle,
};
use tracing::trace;
use tracing_subscriber::EnvFilter;
use tun_rs::AsyncDevice;

#[derive(Parser)]
pub struct Arguments {
    #[clap(long, default_value = "cap0")]
    tap_name: String,
    #[clap(long, default_value = "1500")]
    mtu: u16,
    #[clap(long, default_value = "192.168.184.1")]
    ip: Ipv4Addr,
    #[clap(long, default_value = "255.255.255.0")]
    netmask: Ipv4Addr,
}

struct TunDevice(AsyncDevice);

impl AsyncRead for TunDevice {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0
            .poll_recv(cx, buf.initialize_unfilled())
            .map(|r| r.map(|_| ()))
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Arguments::parse();

    let dev = tun_rs::DeviceBuilder::new()
        .layer(tun_rs::Layer::L2)
        .enable(true)
        .mtu(args.mtu)
        .ipv4(args.ip, args.netmask, None)
        .name(args.tap_name)
        .build_async()?;

    let (mut reader, _writer) = tokio::io::split(TunDevice(dev));

    let watcher: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let mut buf = vec![0; 65536];

        loop {
            let len = reader.read(&mut buf).await?;
            trace!("received: {}", len);
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            bail!("User cancelled");
        },
        res = watcher => {
            res??;
        }
    }

    Ok(())
}
