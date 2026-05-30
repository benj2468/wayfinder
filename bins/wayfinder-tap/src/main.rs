use std::{net::SocketAddr, path::PathBuf};

use bytes::Bytes;
use clap::Parser;
use core::net::Ipv4Addr;
use embedded_io_adapters::tokio_1::FromTokio;
use futures::{SinkExt, StreamExt, stream::FuturesOrdered};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket, UnixListener, UnixStream},
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, Layer};
use wayfinder::EgressInterface;
use wayfinder::interfaces::frame::{LinkFrameData, MeshIdentifier};
use wayfinder::{CentralRouter, interfaces::link::Link};
use wayfinder_protos::{
    service::{
        EgressDecisionData, LinkQualityEntryData, NeighborPathData, RouteResolutionData,
        RoutingEntryData, WayfinderDataProvider, WayfinderService,
    },
    wayfinder_v1alpha::{WayfinderRequest, WayfinderResponse},
};
use zerocopy::IntoBytes;

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub enum LinkConfig {
    Udp { socket_addr: SocketAddr },
    UnixServer { path: PathBuf },
    UnixClient { path: PathBuf },
}

/// Transport over which the management API is exposed.
#[derive(Serialize, Deserialize, Debug)]
pub enum ServerConfig {
    UnixSocket { path: PathBuf },
    Tcp { addr: SocketAddr },
    Udp { addr: SocketAddr },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(default)]
    links: Vec<LinkConfig>,
    server: Option<ServerConfig>,
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

// ── WayfinderDataProvider impl ────────────────────────────────────────────────
//
// Newtype so we can implement the external trait for the external CentralRouter.
struct RouterAdapter<'a>(&'a CentralRouter<[u8; 6]>);

impl WayfinderDataProvider for RouterAdapter<'_> {
    fn node_id(&self) -> Vec<u8> {
        self.0.self_ident().as_bytes().to_vec()
    }

    fn num_originators(&self) -> u32 {
        self.0.originator_table().len() as u32
    }

    fn routing_table(&self) -> Vec<RoutingEntryData> {
        self.0
            .originator_table()
            .iter()
            .map(|r| RoutingEntryData {
                destination: r.neighbor_ident.as_bytes().to_vec(),
                next_hop: r.best_next_hop.as_bytes().to_vec(),
                tq: r.max_tq as u32,
                last_seqno: r.last_seqno,
                paths: r
                    .paths
                    .iter()
                    .map(|p| NeighborPathData {
                        neighbor_id: p.neighbor_ident.as_bytes().to_vec(),
                        tq: p.last_tq as u32,
                        last_seqno: p.last_seqno,
                    })
                    .collect(),
            })
            .collect()
    }

    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        self.0
            .link_quality_records()
            .iter()
            .map(|r| LinkQualityEntryData {
                neighbor_id: r.neighbor.as_bytes().to_vec(),
                iface_idx: r.iface_idx as u32,
                ewma_quality: r.ewma_quality as u32,
                sample_count: r.sample_count,
            })
            .collect()
    }

    fn resolve_route(&self, destination: &[u8]) -> Option<RouteResolutionData> {
        // This deployment uses 6-byte MAC identifiers; reject anything else
        // so the management API returns a structured error rather than
        // silently routing to a zero-padded address.
        let dest: [u8; 6] = destination.try_into().ok()?;
        let (next_hop, egress) = self.0.resolve_route(dest);
        Some(RouteResolutionData {
            next_hop: next_hop.as_bytes().to_vec(),
            egress: egress.map(|e| match e {
                EgressInterface::All => EgressDecisionData::AllInterfaces,
                EgressInterface::Interface(idx) => EgressDecisionData::Interface(idx as u32),
            }),
        })
    }
}

// ── Query channel types ───────────────────────────────────────────────────────

type QueryTx = mpsc::Sender<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>;
type QueryRx = mpsc::Receiver<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>;

// ── Server helpers ────────────────────────────────────────────────────────────

/// Handle one stream-based connection (TCP or Unix socket) using
/// length-delimited framing (4-byte big-endian length prefix).
async fn serve_stream<S>(stream: S, query_tx: QueryTx) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut framed: Framed<S, LengthDelimitedCodec> =
        LengthDelimitedCodec::builder().new_framed(stream);

    while let Some(frame) = framed.next().await {
        let frame = frame?;
        let request = WayfinderRequest::decode(frame)?;
        let (resp_tx, resp_rx) = oneshot::channel();
        query_tx.send((request, resp_tx)).await?;
        let response = resp_rx.await?;
        let mut buf = Vec::new();
        response.encode(&mut buf)?;
        framed.send(Bytes::from(buf)).await?;
    }
    Ok(())
}

async fn run_tcp_server(addr: SocketAddr, query_tx: QueryTx) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("management API listening on TCP {addr}");
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::debug!("management connection from {peer}");
        let tx = query_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_stream(stream, tx).await {
                tracing::warn!("management stream error: {e}");
            }
        });
    }
}

async fn run_unix_server(path: PathBuf, query_tx: QueryTx) -> anyhow::Result<()> {
    if std::fs::metadata(&path).is_ok() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    tracing::info!("management API listening on unix socket {}", path.display());
    loop {
        let (stream, _) = listener.accept().await?;
        let tx = query_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_stream(stream, tx).await {
                tracing::warn!("management stream error: {e}");
            }
        });
    }
}

async fn run_udp_server(addr: SocketAddr, query_tx: QueryTx) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("management API listening on UDP {addr}");
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let request = match WayfinderRequest::decode(&buf[..len]) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("bad management request from {peer}: {e}");
                continue;
            }
        };
        let (resp_tx, resp_rx) = oneshot::channel();
        if query_tx.send((request, resp_tx)).await.is_err() {
            break;
        }
        if let Ok(response) = resp_rx.await {
            let mut out = Vec::new();
            if response.encode(&mut out).is_ok() {
                let _ = socket.send_to(&out, peer).await;
            }
        }
    }
    Ok(())
}

// ── main ──────────────────────────────────────────────────────────────────────

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
        .layer(Layer::L2)
        .name(args.device_name)
        .ipv4(args.ip_address, args.netmask, None)
        .build_async()?;

    let mac_addr = dev.mac_address()?;
    tracing::info!("Starting wayfinder with MAC address: {:?}", mac_addr);

    let mut interfaces = vec![];

    for link in config.links {
        match link {
            LinkConfig::Udp { socket_addr } => {
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

                interfaces.push(Link::new(FromTokio::new(dp2)));
            }
            LinkConfig::UnixServer { path } => {
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

                interfaces.push(Link::new(FromTokio::new(dp2)));
            }
            LinkConfig::UnixClient { path } => {
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

                interfaces.push(Link::new(FromTokio::new(dp2)));
            }
        }
    }

    // Optional management API server — queries are forwarded to the main loop
    // over a channel so the router is never shared across tasks.
    let (query_tx, mut query_rx): (QueryTx, QueryRx) = mpsc::channel(16);

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

    let mut router = CentralRouter::<[u8; 6]>::new(mac_addr);

    let start = std::time::Instant::now();

    let mut rx_buffer = [0u8; 1500];
    let mut tx_buffer = [0u8; 1500];

    // One iteration's worth of work, fully owned so that no borrow of the
    // rx/tx scratchpads or the interface set escapes the `select!`.
    struct LoopOutput {
        /// `(destination ident, protocol, serialized payload)` to transmit
        /// onto the mesh, chosen via `get_egress_interface`.
        mesh: Option<([u8; 6], u16, Vec<u8>)>,
        /// Inner frame to write back to the local TAP device.
        local: Option<Vec<u8>>,
    }

    loop {
        let output: LoopOutput = {
            let mut futures = interfaces
                .iter_mut()
                .enumerate()
                .map(|(i, iface)| async move { iface.receive().await.map(|frame| (i, frame)).ok() })
                .collect::<FuturesOrdered<_>>();

            tokio::select! {
                Some(Some((idx, frame))) = futures.next() => {
                    let rx = router.handle_frame(idx, frame, &mut tx_buffer);
                    LoopOutput {
                        mesh: rx.forward.map(|f| (f.dst, f.protocol, f.payload.to_vec())),
                        local: rx.deliver_local.map(|inner| inner.to_vec()),
                    }
                },
                Ok(len) = dev.recv(&mut rx_buffer) => {
                    // The TAP hands us a full Ethernet frame:
                    // [dst MAC:6][src MAC:6][ethertype:2][payload...].
                    // Route by the destination MAC, which *is* the mesh Ident,
                    // and carry the whole frame across the mesh untouched.
                    let eth = &rx_buffer[..len];
                    let mesh = if eth.len() >= 14 {
                        let mut dst_mac = [0u8; 6];
                        dst_mac.copy_from_slice(&eth[0..6]);
                        // The I/G bit (LSB of the first octet) marks multicast /
                        // broadcast destinations, which we flood across the mesh.
                        let dest = if dst_mac[0] & 0x01 != 0 {
                            <[u8; 6]>::BROADCAST
                        } else {
                            dst_mac
                        };
                        router
                            .handle_local(dest, eth, &mut tx_buffer)
                            .ok()
                            .map(|f| (f.dst, f.protocol, f.payload.to_vec()))
                    } else {
                        None
                    };
                    LoopOutput { mesh, local: None }
                },
                Some((request, resp_tx)) = query_rx.recv() => {
                    let response = WayfinderService::new(RouterAdapter(&router)).handle(request);
                    let _ = resp_tx.send(response);
                    LoopOutput { mesh: None, local: None }
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    LoopOutput {
                        mesh: router
                            .poll(start.elapsed(), &mut tx_buffer)
                            .map(|f| (f.dst, f.protocol, f.payload.to_vec())),
                        local: None,
                    }
                }
            }
        };

        // Hand any inner frame up to the local host by writing it to the TAP.
        if let Some(local) = output.local {
            dev.send(&local).await?;
        }

        // Dispatch any outgoing frame onto the mesh.
        if let Some((dst, protocol, payload)) = output.mesh {
            let data = LinkFrameData {
                dst,
                protocol,
                payload: &payload,
            };
            if let Some(egress) = router.get_egress_interface(dst) {
                match egress {
                    EgressInterface::All => {
                        for iface in interfaces.iter_mut() {
                            iface.send(mac_addr, &data).await?;
                        }
                    }
                    EgressInterface::Interface(iface_idx) => {
                        let iface = interfaces.get_mut(iface_idx).unwrap();
                        iface.send(mac_addr, &data).await?;
                    }
                }
            }
        }
    }
}
