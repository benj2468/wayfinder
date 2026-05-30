use std::{net::SocketAddr, path::PathBuf};

use bytes::Bytes;
use clap::Parser;
use core::net::Ipv4Addr;
use futures::{SinkExt, StreamExt, stream::FuturesOrdered};
use pretty_hex::pretty_hex;
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, UdpSocket, UnixDatagram},
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, Layer};
use wayfinder::CentralRouter;
use wayfinder::EgressInterface;
use wayfinder::interfaces::{
    frame::{LinkFrame, LinkFrameData, MeshIdentifier},
    link::LinkError,
};
use wayfinder_protos::{
    service::{
        EgressDecisionData, LinkQualityEntryData, NeighborPathData, RouteResolutionData,
        RoutingEntryData, WayfinderDataProvider, WayfinderService,
    },
    wayfinder_v1alpha::{WayfinderRequest, WayfinderResponse},
};
use zerocopy::{FromBytes, IntoBytes};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum LinkConfig {
    Udp {
        bind_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
}

/// Transport over which the management API is exposed.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ServerConfig {
    UnixSocket { path: PathBuf },
    Tcp { addr: SocketAddr },
    Udp { addr: SocketAddr },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TapConfig {
    pub device_name: String,
    pub ip_address: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    tap: TapConfig,
    #[serde(default)]
    links: Vec<LinkConfig>,
    #[serde(default)]
    server: Option<ServerConfig>,
}

#[derive(clap::Parser, Debug)]
pub struct Args {
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

// ── TAP abstraction ───────────────────────────────────────────────────────────
//
// Each mesh interface is a `Link` over an in-process duplex (the link-transport
// tasks bridge the real socket to it), so interfaces need no abstraction to be
// testable.  Only the local TAP device touches the kernel, so we hide it behind
// a trait that a fake can implement in unit tests.

/// The local end of the host network: read/write whole link-layer frames.
/// Abstracted so the event loop can be driven against a fake in tests instead
/// of a real kernel TUN/TAP device.
trait AsyncIo {
    /// Receive one frame from the device into `buf`, returning its length.
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Write one frame to the device.
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
}

impl AsyncIo for tun_rs::AsyncDevice {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::recv(self, buf).await
    }
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::send(self, buf).await
    }
}

pub struct Link {
    socket: UnixDatagram,
    buffer: [u8; 1500],
}

impl Link {
    pub fn new(socket: UnixDatagram) -> Self {
        Self {
            socket,
            buffer: [0u8; 1500],
        }
    }

    pub async fn receive<Ident: MeshIdentifier + 'static>(
        &mut self,
    ) -> Result<&LinkFrame<Ident>, LinkError> {
        // The socket is message-oriented (a datagram per frame), so a single
        // recv yields exactly one whole frame — no buffering or reassembly.
        let n = self.socket.recv(&mut self.buffer).await.map_err(|e| {
            tracing::error!("Error reading from socket: {:?}", e);
            LinkError::Io
        })?;
        LinkFrame::ref_from_bytes(&self.buffer[..n]).map_err(|_| LinkError::Io)
    }

    pub async fn send<Ident: MeshIdentifier + 'static>(
        &mut self,
        origin_ident: Ident,
        data: &LinkFrameData<'_, Ident>,
    ) -> Result<usize, LinkError> {
        let mut idx = 0;
        self.buffer[0..size_of::<Ident>()].copy_from_slice(origin_ident.as_bytes());
        idx += size_of::<Ident>();

        self.buffer[idx..(idx + size_of::<Ident>())].copy_from_slice(data.dst.as_bytes());
        idx += size_of::<Ident>();

        // Protocol is stored and compared native-endian throughout (matching
        // `LinkFrame`'s zerocopy reads and the engine's EtherType constants),
        // so write the native bytes — not big-endian.
        self.buffer[idx..(idx + size_of::<u16>())].copy_from_slice(data.protocol.as_bytes());
        idx += size_of::<u16>();

        self.buffer[idx..(idx + data.payload.len())].copy_from_slice(data.payload);
        idx += data.payload.len();

        tracing::trace!("Publishing from {:?} to {:?}", origin_ident, data.dst);
        tracing::trace!("{}", pretty_hex(&&self.buffer[..idx]));

        self.socket.send(&self.buffer[..idx]).await.map_err(|e| {
            tracing::error!("Error sending to socket: {:?}", e);
            LinkError::Io
        })?;

        Ok(idx)
    }

    pub fn read(&self, n: usize) -> &[u8] {
        &self.buffer[..n]
    }
}

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

async fn handle_connectionless(buf: &[u8], query_tx: QueryTx) -> anyhow::Result<Vec<u8>> {
    let request = WayfinderRequest::decode(buf)?;

    let (resp_tx, resp_rx) = oneshot::channel();
    query_tx.send((request, resp_tx)).await?;

    let response = resp_rx.await?;
    let mut out = Vec::new();
    response.encode(&mut out)?;
    Ok(out)
}

async fn run_unix_server(path: PathBuf, query_tx: QueryTx) -> anyhow::Result<()> {
    if std::fs::metadata(&path).is_ok() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixDatagram::bind(&path)?;
    tracing::info!("management API listening on unix socket {}", path.display());
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = listener.recv_from(&mut buf).await?;
        let response = handle_connectionless(&buf[..len], query_tx.clone()).await?;
        let _ = listener
            .send_to(&response, &peer.as_pathname().unwrap())
            .await;
    }
}

async fn run_udp_server(addr: SocketAddr, query_tx: QueryTx) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("management API listening on UDP {addr}");
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let response = handle_connectionless(&buf[..len], query_tx.clone()).await?;
        let _ = socket.send_to(&response, peer).await;
    }
}

// ── event loop ──────────────────────────────────────────────────────────────

/// All the long-lived state the router event loop operates on, bundled so that
/// [`EventLoop::run_once`] can be driven deterministically in tests (with a
/// fake [`AsyncIo`] and in-process [`MeshLink`]s) instead of from `main`.
struct EventLoop<Tap: AsyncIo> {
    /// The local host network device.
    tap: Tap,
    /// The mesh interfaces, indexed by interface index.
    interfaces: Vec<Link>,
    /// The routing engine for this node.
    router: CentralRouter<[u8; 6]>,
    /// Management-API queries forwarded from the server tasks.
    query_rx: QueryRx,
    /// This node's mesh identifier (its TAP MAC address).
    mac_addr: [u8; 6],
    /// Reference instant for periodic-broadcast timing.
    start: std::time::Instant,
    /// Receive scratchpad for frames read from the TAP.
    rx_buffer: [u8; 1500],
    /// Transmit scratchpad the router builds outgoing frames into.
    tx_buffer: [u8; 1500],
}

/// One iteration's worth of work, fully owned so that no borrow of the rx/tx
/// scratchpads or the interface set escapes the `select!`.
struct LoopOutput {
    /// `(destination ident, protocol, serialized payload)` to transmit onto
    /// the mesh, dispatched via `get_egress_interface`.
    mesh: Option<([u8; 6], u16, Vec<u8>)>,
    /// Inner frame to write back to the local TAP device.
    local: Option<Vec<u8>>,
}

impl<Tap: AsyncIo> EventLoop<Tap> {
    /// Run a single iteration: wait for whichever happens first — a frame from
    /// a mesh interface, a frame from the local TAP, a management query, or the
    /// periodic-broadcast timer — process it, then deliver any inner frame to
    /// the TAP and dispatch any outgoing frame onto the mesh.
    async fn run_once(&mut self) -> anyhow::Result<()> {
        // Destructure into disjoint field borrows so the `select!` can hold a
        // mutable borrow of the interfaces alongside the router and buffers.
        let EventLoop {
            tap,
            interfaces,
            router,
            query_rx,
            mac_addr,
            start,
            rx_buffer,
            tx_buffer,
        } = self;
        let mac_addr = *mac_addr;
        let start = *start;

        let output: LoopOutput = {
            let mut futures = interfaces
                .iter_mut()
                .enumerate()
                .map(|(i, iface)| async move { iface.receive().await.map(|frame| (i, frame)).ok() })
                .collect::<FuturesOrdered<_>>();

            tokio::select! {
                Some(Some((idx, frame))) = futures.next() => {
                    let rx = router.handle_frame(idx, frame, tx_buffer);
                    LoopOutput {
                        mesh: rx.forward.map(|f| (f.dst, f.protocol, f.payload.to_vec())),
                        local: rx.deliver_local.map(|inner| inner.to_vec()),
                    }
                },
                Ok(len) = tap.recv(rx_buffer) => {
                    tracing::debug!("tap received frame of length {}", len);
                    // The TAP hands us a full Ethernet frame:
                    // [dst MAC:6][src MAC:6][ethertype:2][payload...].  Route by
                    // the destination MAC — which *is* the mesh Ident — and
                    // carry the whole frame across the mesh untouched.
                    let eth = &rx_buffer[..len];
                    tracing::debug!("{}", pretty_hex::pretty_hex(&eth));
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
                            .handle_local(dest, eth, tx_buffer)
                            .ok()
                            .map(|f| (f.dst, f.protocol, f.payload.to_vec()))
                    } else {
                        None
                    };
                    LoopOutput { mesh, local: None }
                },
                Some((request, resp_tx)) = query_rx.recv() => {
                    let response = WayfinderService::new(RouterAdapter(&*router)).handle(request);
                    let _ = resp_tx.send(response);
                    LoopOutput { mesh: None, local: None }
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    LoopOutput {
                        mesh: router
                            .poll(start.elapsed(), tx_buffer)
                            .map(|f| (f.dst, f.protocol, f.payload.to_vec())),
                        local: None,
                    }
                }
            }
        };

        tracing::debug!("output: mesh={:?} local={:?}", output.mesh, output.local);

        // Hand any inner frame up to the local host by writing it to the TAP.
        if let Some(local) = output.local {
            tap.send(&local).await?;
        }

        // Dispatch any outgoing frame onto the mesh.
        if let Some((dst, protocol, payload)) = output.mesh {
            tracing::debug!(
                "mesh output: dst={:?} protocol={:?} payload={:?}",
                dst,
                protocol,
                payload
            );
            let data = LinkFrameData {
                dst,
                protocol,
                payload: &payload,
            };

            if let Some(egress) = router.get_egress_interface(dst) {
                tracing::debug!("egress: {:?}", egress);
                match egress {
                    EgressInterface::All => {
                        for iface in interfaces.iter_mut() {
                            iface.send(mac_addr, &data).await?;
                        }
                    }
                    EgressInterface::Interface(iface_idx) => {
                        if let Some(iface) = interfaces.get_mut(iface_idx) {
                            iface.send(mac_addr, &data).await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder::batman::wire::{
        BATADV_BCAST, BATADV_IV_OGM, BATADV_UNICAST, BatmanOgmPacket, BatmanUnicastPacket,
        ETH_P_BATMAN,
    };

    // ── fake TAP ───────────────────────────────────────────────────────────────

    /// A [`AsyncIo`] backed by channels so tests can inject frames "from the host"
    /// and inspect frames the router writes "to the host".
    struct FakeTap {
        inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        outbound: tokio::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl FakeTap {
        fn new() -> (Self, mpsc::Sender<Vec<u8>>) {
            let (tx, rx) = mpsc::channel(16);
            (
                Self {
                    inbound: tokio::sync::Mutex::new(rx),
                    outbound: tokio::sync::Mutex::new(Vec::new()),
                },
                tx,
            )
        }

        /// Frames the router has written to the TAP so far.
        async fn sent(&self) -> Vec<Vec<u8>> {
            self.outbound.lock().await.clone()
        }
    }

    impl AsyncIo for FakeTap {
        async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let frame = self.inbound.lock().await.recv().await;
            match frame {
                Some(f) => {
                    let n = f.len().min(buf.len());
                    buf[..n].copy_from_slice(&f[..n]);
                    Ok(n)
                }
                // Channel exhausted: stay pending so this select branch never
                // wins (the test always injects before driving run_once).
                None => std::future::pending().await,
            }
        }

        async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.lock().await.push(buf.to_vec());
            Ok(buf.len())
        }
    }

    // ── wire helpers ─────────────────────────────────────────────────────────

    /// Serialize a `LinkFrame<[u8;6]>`: `[src][dst][proto native][payload]`.
    /// Protocol is written native-endian to match how the link layer (and
    /// `build_frame` in the test harness) encodes it.
    fn link_wire(src: [u8; 6], dst: [u8; 6], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(&ETH_P_BATMAN.to_ne_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// Build a raw Ethernet frame: `[dst MAC][src MAC][ethertype][payload]`.
    fn eth_frame(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&dst);
        v.extend_from_slice(&src);
        v.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype, arbitrary here
        v.extend_from_slice(payload);
        v
    }

    /// Boilerplate for a single-interface router under test: the `EventLoop`
    /// plus the test-side handles for injecting/observing host and mesh frames.
    struct Harness {
        ev: EventLoop<FakeTap>,
        /// Inject frames as if they arrived from the host on the TAP.
        tap_in: mpsc::Sender<Vec<u8>>,
        /// The far end of the single mesh interface's duplex.
        far: tokio::net::UnixDatagram,
        /// Kept alive so the management-query channel stays open (its select
        /// branch must remain pending, not resolve to `None`).
        _qtx: QueryTx,
    }

    fn harness(mac: [u8; 6]) -> Harness {
        let (tap, tap_in) = FakeTap::new();
        let (near, far) = tokio::net::UnixDatagram::pair().unwrap();
        let (qtx, qrx) = mpsc::channel(1);
        Harness {
            ev: EventLoop {
                tap,
                interfaces: vec![Link::new(near)],
                router: CentralRouter::<[u8; 6]>::new(mac),
                query_rx: qrx,
                mac_addr: mac,
                start: std::time::Instant::now(),
                rx_buffer: [0u8; 1500],
                tx_buffer: [0u8; 1500],
            },
            tap_in,
            far,
            _qtx: qtx,
        }
    }

    impl Harness {
        async fn step(&mut self) {
            self.ev.run_once().await.unwrap();
        }
    }

    // ── tests ──────────────────────────────────────────────────────────────────

    /// A broadcast/multicast Ethernet frame from the host is wrapped as a
    /// BATMAN broadcast and flooded onto the mesh.
    #[tokio::test]
    async fn tap_broadcast_frame_floods_to_mesh() {
        let mac = [0xaa, 0, 0, 0, 0, 1];
        let mut h = harness(mac);

        h.tap_in
            .send(eth_frame([0xff; 6], mac, b"arp who-has"))
            .await
            .unwrap();
        h.step().await;

        // Read the frame that landed on the (single) mesh interface.
        let mut buf = [0u8; 1500];
        let n = h.far.recv(&mut buf).await.unwrap();
        assert!(n >= 15);
        // wire: [src:6][dst:6][proto:2][batman payload...]
        assert_eq!(&buf[6..12], &[0xff; 6], "link dst should be broadcast");
        assert_eq!(buf[14], BATADV_BCAST, "should be a BATMAN broadcast");
    }

    /// After learning a peer via its OGM, a unicast Ethernet frame to that
    /// peer's MAC is wrapped as a BATMAN unicast and routed to it.
    #[tokio::test]
    async fn tap_unicast_frame_routes_to_learned_peer() {
        let mac = [0xaa, 0, 0, 0, 0, 1];
        let peer = [0xbc, 0, 0, 0, 0, 2];
        let mut h = harness(mac);

        // 1) Peer announces itself via an OGM (delivered on the interface).
        let ogm = BatmanOgmPacket::<[u8; 6]> {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            tq: 255,
            seqno: 1u32.to_be(),
            orig: peer,
            prev_sender: peer,
        };
        h.far
            .send(&link_wire(peer, [0xff; 6], ogm.as_bytes()))
            .await
            .unwrap();
        h.step().await;
        // Drain the re-flooded OGM that run_once just put back on the wire.
        let mut scratch = [0u8; 1500];
        let _ = h.far.recv(&mut scratch).await.unwrap();

        // 2) Host sends a unicast frame to the peer's MAC.
        h.tap_in
            .send(eth_frame(peer, mac, b"hello peer"))
            .await
            .unwrap();
        h.step().await;

        let mut buf = [0u8; 1500];
        let n = h.far.recv(&mut buf).await.unwrap();
        assert!(n >= 23);
        assert_eq!(&buf[6..12], &peer, "link dst should be the (direct) peer");
        assert_eq!(buf[14], BATADV_UNICAST, "should be a BATMAN unicast");
        // BatmanUnicastPacket = [type:1][version:1][ttl:1][dest:6]; dest follows
        // the 14-byte link header + 3 header bytes => buf[17..23].
        assert_eq!(&buf[17..23], &peer, "unicast dest should be the peer");
    }

    /// A BATMAN unicast addressed to us is unwrapped and the inner frame is
    /// written to the local TAP.
    #[tokio::test]
    async fn mesh_unicast_for_self_is_written_to_tap() {
        let mac = [0xaa, 0, 0, 0, 0, 1];
        let peer = [0xbc, 0, 0, 0, 0, 2];
        let mut h = harness(mac);

        let inner = b"INNER ETHERNET FRAME FOR THE HOST";
        let hdr = BatmanUnicastPacket::<[u8; 6]> {
            packet_type: BATADV_UNICAST,
            version: 5,
            ttl: 50,
            dest: mac,
        };
        let mut batman = hdr.as_bytes().to_vec();
        batman.extend_from_slice(inner);
        h.far.send(&link_wire(peer, mac, &batman)).await.unwrap();

        h.step().await;

        let sent = h.ev.tap.sent().await;
        assert_eq!(sent.len(), 1, "exactly one frame delivered to the TAP");
        assert_eq!(sent[0], inner, "inner frame delivered to the host verbatim");
    }

    /// Two datagrams arriving back-to-back on one interface must be processed
    /// as two distinct frames. Regression test for `Link::receive` accumulating
    /// into its buffer across calls and concatenating frames.
    #[tokio::test]
    async fn two_frames_on_one_interface_stay_distinct() {
        let mac = [0xaa, 0, 0, 0, 0, 1];
        let peer = [0xbc, 0, 0, 0, 0, 2];
        let mut h = harness(mac);

        let inners: [&[u8]; 2] = [b"first frame!!", b"second frame!"];
        for inner in inners {
            let hdr = BatmanUnicastPacket::<[u8; 6]> {
                packet_type: BATADV_UNICAST,
                version: 5,
                ttl: 50,
                dest: mac,
            };
            let mut batman = hdr.as_bytes().to_vec();
            batman.extend_from_slice(inner);
            h.far.send(&link_wire(peer, mac, &batman)).await.unwrap();
        }

        h.step().await;
        h.step().await;

        let sent = h.ev.tap.sent().await;
        assert_eq!(
            sent,
            vec![inners[0].to_vec(), inners[1].to_vec()],
            "each frame must be delivered intact, not concatenated"
        );
    }
}
