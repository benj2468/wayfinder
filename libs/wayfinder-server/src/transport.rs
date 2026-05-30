//! The per-transport listener loops (TCP, Unix datagram, UDP) and the query
//! channel the event loop services.
//!
//! Queries are forwarded to the main loop over a channel so the router is never
//! shared across tasks. This module requires the `std` feature.

use std::{net::SocketAddr, path::PathBuf};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use prost::Message;
use tokio::{
    net::{TcpListener, UdpSocket, UnixDatagram},
    sync::{mpsc, oneshot},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use wayfinder_protos::wayfinder_v1alpha::{WayfinderRequest, WayfinderResponse};

/// Sender half of the channel server tasks use to forward queries to the loop.
pub type QueryTx = mpsc::Sender<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>;
/// Receiver half, owned by the event loop.
pub type QueryRx = mpsc::Receiver<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>;

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
pub async fn run_tcp_server(addr: SocketAddr, query_tx: QueryTx) -> anyhow::Result<()> {
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
pub async fn run_unix_server(path: PathBuf, query_tx: QueryTx) -> anyhow::Result<()> {
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
pub async fn run_udp_server(addr: SocketAddr, query_tx: QueryTx) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("management API listening on UDP {addr}");
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let response = handle_connectionless(&buf[..len], query_tx.clone()).await?;
        let _ = socket.send_to(&response, peer).await;
    }
}
