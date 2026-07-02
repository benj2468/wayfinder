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

/// One in-process management request: encoded [`WayfinderRequest`] bytes paired
/// with a one-shot channel the server replies on with encoded
/// [`WayfinderResponse`] bytes.
pub type ChannelRequest = (Bytes, oneshot::Sender<Bytes>);
/// Receiver half of the in-process channel server, owned by
/// [`run_channel_server`].
pub type ChannelServerRx = mpsc::Receiver<ChannelRequest>;
/// Sender half of the in-process channel server, held by a caller that wants to
/// issue management queries without going through a real socket (e.g. tests).
pub type ChannelServerTx = mpsc::Sender<ChannelRequest>;

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
        tracing::debug!(%peer, "management connection accepted");
        let tx = query_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_stream(stream, tx).await {
                tracing::warn!(error = ?e, "management stream error");
            }
        });
    }
}

/// Why [`handle_connectionless`] failed to produce a response.
#[derive(Debug)]
enum ConnectionlessError {
    /// The request bytes didn't decode as a [`WayfinderRequest`] — the
    /// peer's fault.  Safe to drop just this one datagram and keep serving
    /// others.
    Decode(prost::DecodeError),
    /// The router event loop is unreachable: its receiver was dropped, or it
    /// dropped the reply oneshot without responding (e.g. it panicked
    /// mid-request).  The server can no longer do anything useful and should
    /// stop, not keep silently discarding every future request.
    RouterGone,
}

/// Decode one connectionless request, forward it to the loop, and encode the reply.
async fn handle_connectionless(
    buf: &[u8],
    query_tx: QueryTx,
) -> Result<Vec<u8>, ConnectionlessError> {
    let request = WayfinderRequest::decode(buf).map_err(ConnectionlessError::Decode)?;

    let (resp_tx, resp_rx) = oneshot::channel();
    query_tx
        .send((request, resp_tx))
        .await
        .map_err(|_| ConnectionlessError::RouterGone)?;

    let response = resp_rx.await.map_err(|_| ConnectionlessError::RouterGone)?;
    let mut out = Vec::new();
    #[expect(
        clippy::expect_used,
        reason = "encoding into a growable Vec<u8> cannot fail (BufMut::remaining_mut is unbounded)"
    )]
    response
        .encode(&mut out)
        .expect("encoding into a growable Vec<u8> cannot fail");
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
        // A malformed datagram from any peer must not take down the server for
        // everyone else — log and move on to the next datagram instead of
        // propagating out of the loop.  A dead router, in contrast, means this
        // listener can no longer do anything useful, so that case still ends
        // the loop (visibly, via this function returning `Err`).
        let response = match handle_connectionless(&buf[..len], query_tx.clone()).await {
            Ok(response) => response,
            Err(ConnectionlessError::Decode(e)) => {
                tracing::trace!(error = ?e, "drop: malformed management request");
                continue;
            }
            Err(ConnectionlessError::RouterGone) => {
                anyhow::bail!("management router event loop is unreachable");
            }
        };
        // An unbound sender has no path to reply to; there's nothing to send the
        // response to, so just drop it.
        let Some(peer_path) = peer.as_pathname() else {
            tracing::trace!("dropping unix datagram reply: peer is unnamed");
            continue;
        };
        let _ = listener.send_to(&response, peer_path).await;
    }
}

/// Serve the management API over an in-process mpsc channel.
///
/// Mirrors the socket listeners but carries already-/still-encoded protobuf
/// bytes over a channel instead of a kernel transport, so a caller in the same
/// process (the integration tests) can exercise the full encode → forward →
/// decode path without binding a socket.  Each request is a `(bytes, reply)`
/// pair; the encoded response is sent back on `reply`.
pub async fn run_channel_server(mut rx: ChannelServerRx, query_tx: QueryTx) -> anyhow::Result<()> {
    while let Some((request, reply)) = rx.recv().await {
        // Same reasoning as `run_unix_server`/`run_udp_server`: a caller that
        // sends a malformed request must not take down the loop for everyone
        // else queued behind it.
        let response = match handle_connectionless(&request, query_tx.clone()).await {
            Ok(response) => response,
            Err(ConnectionlessError::Decode(e)) => {
                tracing::trace!(error = ?e, "drop: malformed management request");
                continue;
            }
            Err(ConnectionlessError::RouterGone) => {
                anyhow::bail!("management router event loop is unreachable");
            }
        };
        let _ = reply.send(Bytes::from(response));
    }
    Ok(())
}

/// Serve the management API over UDP.
pub async fn run_udp_server(addr: SocketAddr, query_tx: QueryTx) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("management API listening on UDP {addr}");
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        // Same reasoning as `run_unix_server`: a malformed datagram from any
        // peer must not take down the server for everyone else, but a dead
        // router still ends the loop visibly.
        let response = match handle_connectionless(&buf[..len], query_tx.clone()).await {
            Ok(response) => response,
            Err(ConnectionlessError::Decode(e)) => {
                tracing::trace!(error = ?e, "drop: malformed management request");
                continue;
            }
            Err(ConnectionlessError::RouterGone) => {
                anyhow::bail!("management router event loop is unreachable");
            }
        };
        let _ = socket.send_to(&response, peer).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use tokio::net::UnixDatagram;
    use tokio::sync::mpsc;
    use wayfinder_protos::wayfinder_v1alpha::{
        GetNodeInfoRequest, NodeInfo, WayfinderRequest, WayfinderResponse,
        wayfinder_request::Request, wayfinder_response::Response,
    };

    use super::*;

    /// A unique per-call socket path under the OS temp dir, so parallel test
    /// runs (and repeated calls within one test) never collide on `bind`.
    fn unique_socket_path(label: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wayfinder-server-test-{}-{label}-{n}.sock",
            std::process::id()
        ))
    }

    fn node_info_request_bytes() -> Vec<u8> {
        let request = WayfinderRequest {
            request: Some(Request::GetNodeInfo(GetNodeInfoRequest {})),
        };
        let mut buf = Vec::new();
        prost::Message::encode(&request, &mut buf).unwrap();
        buf
    }

    /// Answers every forwarded query with a canned `NodeInfo`, so a well-formed
    /// reply can be told apart from silence.
    fn spawn_echo(mut rx: QueryRx) {
        tokio::spawn(async move {
            while let Some((_, resp_tx)) = rx.recv().await {
                let response = WayfinderResponse {
                    response: Some(Response::NodeInfo(NodeInfo {
                        node_id: vec![1, 2, 3, 4, 5, 6],
                        num_originators: 7,
                    })),
                };
                let _ = resp_tx.send(response);
            }
        });
    }

    #[tokio::test]
    async fn unix_server_survives_unnamed_peer_and_malformed_datagram() {
        let server_path = unique_socket_path("server");

        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);
        tokio::spawn(run_unix_server(server_path.clone(), query_tx));
        tokio::time::sleep(Duration::from_millis(20)).await;

        // An unbound sender has no path for the server to reply to:
        // `peer.as_pathname()` is `None` on the receiving end, which used to
        // `unwrap()` and panic the whole server loop.
        let unbound = UnixDatagram::unbound().unwrap();
        unbound
            .send_to(&node_info_request_bytes(), &server_path)
            .await
            .unwrap();

        // Garbage bytes fail to decode as a `WayfinderRequest`; that must not
        // propagate out of the loop and kill the server for every other client
        // either.
        let garbage_client = UnixDatagram::bind(unique_socket_path("garbage")).unwrap();
        garbage_client
            .send_to(&[0xff, 0x00, 0xff], &server_path)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;

        // The server must still be alive: a well-formed, properly-bound request
        // gets a real reply.
        let client = UnixDatagram::bind(unique_socket_path("client")).unwrap();
        client
            .send_to(&node_info_request_bytes(), &server_path)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buf))
            .await
            .expect("server is still responding after bad input")
            .unwrap();
        let response: WayfinderResponse = prost::Message::decode(&buf[..len]).unwrap();
        assert!(matches!(response.response, Some(Response::NodeInfo(_))));
    }

    fn free_udp_addr() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    #[tokio::test]
    async fn udp_server_survives_malformed_datagram() {
        let addr = free_udp_addr();

        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);
        tokio::spawn(run_udp_server(addr, query_tx));
        tokio::time::sleep(Duration::from_millis(20)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Garbage bytes fail to decode as a `WayfinderRequest`; that must not
        // propagate out of the loop and kill the server for every other client.
        client.send_to(&[0xff, 0x00, 0xff], addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // The server must still be alive: a well-formed request still gets a
        // real reply.
        client
            .send_to(&node_info_request_bytes(), addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("server is still responding after bad input")
            .unwrap();
        let response: WayfinderResponse = prost::Message::decode(&buf[..len]).unwrap();
        assert!(matches!(response.response, Some(Response::NodeInfo(_))));
    }
}
