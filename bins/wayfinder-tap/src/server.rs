//! The management-API server: the [`WayfinderDataProvider`] adapter over the
//! router, the query channel the event loop services, and the per-transport
//! listener loops (TCP, Unix datagram, UDP).

use std::{net::SocketAddr, path::PathBuf};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use prost::Message;
use tokio::{
    net::{TcpListener, UdpSocket, UnixDatagram},
    sync::{mpsc, oneshot},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use wayfinder::CentralRouter;
use wayfinder::EgressInterface;
use wayfinder_protos::{
    service::{
        EgressDecisionData, LinkQualityEntryData, NeighborPathData, RouteResolutionData,
        RoutingEntryData, WayfinderDataProvider,
    },
    wayfinder_v1alpha::{WayfinderRequest, WayfinderResponse},
};
use zerocopy::IntoBytes;

// ── WayfinderDataProvider impl ────────────────────────────────────────────────
//
// Newtype so we can implement the external trait for the external CentralRouter.

/// Adapts a borrowed [`CentralRouter`] to the management-API data provider trait.
pub(crate) struct RouterAdapter<'a>(pub(crate) &'a CentralRouter<[u8; 6]>);

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

/// Sender half of the channel server tasks use to forward queries to the loop.
pub(crate) type QueryTx = mpsc::Sender<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>;
/// Receiver half, owned by the event loop.
pub(crate) type QueryRx = mpsc::Receiver<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>;

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

/// Accept TCP connections and service each as a length-delimited stream.
pub(crate) async fn run_tcp_server(addr: SocketAddr, query_tx: QueryTx) -> anyhow::Result<()> {
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

/// Decode one connectionless request, forward it to the loop, and encode the reply.
async fn handle_connectionless(buf: &[u8], query_tx: QueryTx) -> anyhow::Result<Vec<u8>> {
    let request = WayfinderRequest::decode(buf)?;

    let (resp_tx, resp_rx) = oneshot::channel();
    query_tx.send((request, resp_tx)).await?;

    let response = resp_rx.await?;
    let mut out = Vec::new();
    response.encode(&mut out)?;
    Ok(out)
}

/// Serve the management API over a Unix datagram socket.
pub(crate) async fn run_unix_server(path: PathBuf, query_tx: QueryTx) -> anyhow::Result<()> {
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

/// Serve the management API over UDP.
pub(crate) async fn run_udp_server(addr: SocketAddr, query_tx: QueryTx) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("management API listening on UDP {addr}");
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let response = handle_connectionless(&buf[..len], query_tx.clone()).await?;
        let _ = socket.send_to(&response, peer).await;
    }
}
