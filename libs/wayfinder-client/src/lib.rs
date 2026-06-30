//! Reusable client for the Wayfinder management API.
//!
//! Speaks the same prost envelope ([`WayfinderRequest`]/[`WayfinderResponse`])
//! the `wayfinder-server` listeners expect, over either:
//!
//! * **TCP** — a stream with 4-byte big-endian length-delimited framing
//!   (`tokio_util` [`LengthDelimitedCodec`]), matching `run_tcp_server`; or
//! * **Unix datagram** — one prost message per datagram (no length prefix),
//!   matching `run_unix_server`.
//!
//! Shared by `wayfinder-tui` and `wayfinderctl` so the wire framing and the
//! typed request methods live in exactly one place.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::{TcpStream, UnixDatagram};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use wayfinder_protos::wayfinder_v1alpha::{
    GetLinkQualityTableRequest, GetMetricsRequest, GetNodeInfoRequest, GetOgmScheduleRequest,
    GetRoutingTableRequest, GetSecurityStatusRequest, GetSecurityStatusResponse,
    GetThroughputRequest, GetTrustAnchorRequest, GetTrustAnchorResponse, LinkQualityTable,
    ListCertsRequest, ListCertsResponse, NodeInfo, NodeMetrics, OgmSchedule, ResolveRouteRequest,
    ResolveRouteResponse, RevokeNodeRequest, RoutingTable, SetAuthRequest, SubmitCsrRequest,
    SubmitCsrResponse, Throughput, WayfinderRequest, WayfinderResponse,
    wayfinder_request::Request as RequestKind, wayfinder_response::Response as ResponseKind,
};

/// Where to reach a node's management API: a TCP `host:port` or a Unix-datagram
/// socket path.  Parsed from a single connect string via [`FromStr`].
#[derive(Debug, Clone)]
pub enum ConnectTarget {
    /// TCP listener address (`ServerConfig::Tcp`).
    Tcp(SocketAddr),
    /// Unix datagram socket path (`ServerConfig::UnixSocket`).
    Unix(PathBuf),
}

impl FromStr for ConnectTarget {
    type Err = anyhow::Error;

    /// Parse a connect string.  A `unix:`-prefixed value, or one that looks like
    /// a filesystem path (starts with `/`, `./`, or `../`), is a Unix socket;
    /// anything else is parsed as an `IP:port` TCP address.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(path) = s.strip_prefix("unix:") {
            return Ok(ConnectTarget::Unix(PathBuf::from(path)));
        }
        if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
            return Ok(ConnectTarget::Unix(PathBuf::from(s)));
        }
        let addr = s.parse::<SocketAddr>().with_context(|| {
            format!("'{s}' is not an IP:port address or a unix: / path socket target")
        })?;
        Ok(ConnectTarget::Tcp(addr))
    }
}

/// The underlying transport a [`Client`] is connected over.
enum Conn {
    /// Length-delimited prost framing over a TCP stream.
    Tcp(Framed<TcpStream, LengthDelimitedCodec>),
    /// A connected Unix datagram socket bound to a private `local` path (removed
    /// on drop) so the server's `send_to(peer)` reply has somewhere to land.
    Unix {
        /// The bound-and-connected datagram socket.
        sock: UnixDatagram,
        /// The temporary client-side path, unlinked when the client drops.
        local: PathBuf,
    },
}

/// A connected management-API client over a single transport.
pub struct Client {
    conn: Conn,
}

impl Client {
    /// Connect to the management API at `target`.
    pub async fn connect(target: &ConnectTarget) -> anyhow::Result<Self> {
        match target {
            ConnectTarget::Tcp(addr) => {
                let stream = TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("connecting to tcp://{addr}"))?;
                let framed = LengthDelimitedCodec::builder().new_framed(stream);
                Ok(Self {
                    conn: Conn::Tcp(framed),
                })
            }
            ConnectTarget::Unix(path) => {
                // Bind a private client path so the server can reply: its
                // listener answers via `peer.as_pathname()`, which is only set
                // for a path-bound socket (not an unbound/abstract one).
                let local = unique_socket_path();
                let sock = UnixDatagram::bind(&local)
                    .with_context(|| format!("binding client socket {}", local.display()))?;
                sock.connect(path)
                    .with_context(|| format!("connecting to unix:{}", path.display()))?;
                Ok(Self {
                    conn: Conn::Unix { sock, local },
                })
            }
        }
    }

    /// Encode and send one request, then await and decode the single response.
    async fn request(&mut self, request: RequestKind) -> anyhow::Result<ResponseKind> {
        let envelope = WayfinderRequest {
            request: Some(request),
        };
        let mut buf = Vec::new();
        envelope.encode(&mut buf)?;

        let frame: Bytes = match &mut self.conn {
            Conn::Tcp(framed) => {
                framed.send(Bytes::from(buf)).await?;
                framed
                    .next()
                    .await
                    .ok_or_else(|| anyhow!("connection closed by server"))??
                    .freeze()
            }
            Conn::Unix { sock, .. } => {
                sock.send(&buf).await.context("sending request datagram")?;
                let mut rbuf = vec![0u8; 65535];
                let n = sock
                    .recv(&mut rbuf)
                    .await
                    .context("receiving response datagram")?;
                rbuf.truncate(n);
                Bytes::from(rbuf)
            }
        };

        let response = WayfinderResponse::decode(frame)?;
        match response.response {
            // Surface a server-side error as the call's error rather than an
            // "unexpected variant" mismatch in every typed method.
            Some(ResponseKind::Error(e)) => Err(anyhow!("server error: {}", e.message)),
            Some(other) => Ok(other),
            None => Err(anyhow!("server returned an empty response envelope")),
        }
    }

    /// Query basic identity and capacity information for the node.
    pub async fn node_info(&mut self) -> anyhow::Result<NodeInfo> {
        match self
            .request(RequestKind::GetNodeInfo(GetNodeInfoRequest {}))
            .await?
        {
            ResponseKind::NodeInfo(info) => Ok(info),
            other => Err(unexpected("NodeInfo", &other)),
        }
    }

    /// Query the full BATMAN originator (routing) table.
    pub async fn routing_table(&mut self) -> anyhow::Result<RoutingTable> {
        match self
            .request(RequestKind::GetRoutingTable(GetRoutingTableRequest {}))
            .await?
        {
            ResponseKind::RoutingTable(table) => Ok(table),
            other => Err(unexpected("RoutingTable", &other)),
        }
    }

    /// Query the per-(neighbor, interface) link-quality table.
    pub async fn link_quality_table(&mut self) -> anyhow::Result<LinkQualityTable> {
        match self
            .request(RequestKind::GetLinkQualityTable(
                GetLinkQualityTableRequest {},
            ))
            .await?
        {
            ResponseKind::LinkQualityTable(table) => Ok(table),
            other => Err(unexpected("LinkQualityTable", &other)),
        }
    }

    /// Query the current per-interface adaptive OGM emission schedule.
    pub async fn ogm_schedule(&mut self) -> anyhow::Result<OgmSchedule> {
        match self
            .request(RequestKind::GetOgmSchedule(GetOgmScheduleRequest {}))
            .await?
        {
            ResponseKind::OgmSchedule(schedule) => Ok(schedule),
            other => Err(unexpected("OgmSchedule", &other)),
        }
    }

    /// Query the current per-interface throughput estimates (smoothed
    /// bytes/sec and frames/sec per interface, plus node-wide totals).
    pub async fn throughput(&mut self) -> anyhow::Result<Throughput> {
        match self
            .request(RequestKind::GetThroughput(GetThroughputRequest {}))
            .await?
        {
            ResponseKind::Throughput(throughput) => Ok(throughput),
            other => Err(unexpected("Throughput", &other)),
        }
    }

    /// Query the node's aggregate health and topology metrics (uptime,
    /// neighbour count, table occupancy, TQ / path-diversity distribution).
    pub async fn node_metrics(&mut self) -> anyhow::Result<NodeMetrics> {
        match self
            .request(RequestKind::GetMetrics(GetMetricsRequest {}))
            .await?
        {
            ResponseKind::Metrics(metrics) => Ok(metrics),
            other => Err(unexpected("Metrics", &other)),
        }
    }

    /// Query this node's mesh authentication / security posture: whether auth is
    /// enabled, the mesh and own-cert header, and the per-originator
    /// verified / expiry / revoked state.
    pub async fn security_status(&mut self) -> anyhow::Result<GetSecurityStatusResponse> {
        match self
            .request(RequestKind::GetSecurityStatus(GetSecurityStatusRequest {}))
            .await?
        {
            ResponseKind::SecurityStatus(status) => Ok(status),
            other => Err(unexpected("SecurityStatus", &other)),
        }
    }

    /// Ask the node which next-hop neighbour and egress interface it would pick
    /// for a packet to `destination` (the raw identifier bytes, same encoding as
    /// [`NodeInfo::node_id`]).
    pub async fn resolve_route(
        &mut self,
        destination: Vec<u8>,
    ) -> anyhow::Result<ResolveRouteResponse> {
        match self
            .request(RequestKind::ResolveRoute(ResolveRouteRequest {
                destination,
            }))
            .await?
        {
            ResponseKind::ResolveRoute(resolution) => Ok(resolution),
            other => Err(unexpected("ResolveRoute", &other)),
        }
    }

    /// Update the authentication state of the client.
    pub async fn set_auth(
        &mut self,
        seed: &[u8],
        cert: &[u8],
        trust_anchor: &[u8],
    ) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetAuth(SetAuthRequest {
                seed: seed.to_vec(),
                cert: cert.to_vec(),
                trust_anchor: trust_anchor.to_vec(),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("SetAuth", &other)),
        }
    }

    /// Provider mode: fetch the mesh trust anchor (raw `TrustAnchor` bytes).
    pub async fn get_trust_anchor(&mut self) -> anyhow::Result<GetTrustAnchorResponse> {
        match self
            .request(RequestKind::GetTrustAnchor(GetTrustAnchorRequest {}))
            .await?
        {
            ResponseKind::TrustAnchor(resp) => Ok(resp),
            other => Err(unexpected("TrustAnchor", &other)),
        }
    }

    /// Provider mode: submit a certificate-signing request for `node_mac` bound
    /// to the given public keys, returning the issued cert and the trust anchor.
    pub async fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        enrollment_token: &str,
    ) -> anyhow::Result<SubmitCsrResponse> {
        match self
            .request(RequestKind::SubmitCsr(SubmitCsrRequest {
                node_mac: node_mac.to_vec(),
                ed_pubkey: ed_pubkey.to_vec(),
                x_pubkey: x_pubkey.to_vec(),
                enrollment_token: enrollment_token.to_string(),
            }))
            .await?
        {
            ResponseKind::SubmitCsr(resp) => Ok(resp),
            other => Err(unexpected("SubmitCsr", &other)),
        }
    }

    /// Provider mode: revoke `node_mac` from the mesh (the provider signs and
    /// floods a revocation record).
    pub async fn revoke_node(&mut self, node_mac: &[u8]) -> anyhow::Result<()> {
        match self
            .request(RequestKind::RevokeNode(RevokeNodeRequest {
                node_mac: node_mac.to_vec(),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("RevokeNode", &other)),
        }
    }

    /// Provider mode: list the certificates this provider has issued.
    pub async fn list_certs(&mut self) -> anyhow::Result<ListCertsResponse> {
        match self
            .request(RequestKind::ListCerts(ListCertsRequest {}))
            .await?
        {
            ResponseKind::ListCerts(resp) => Ok(resp),
            other => Err(unexpected("ListCerts", &other)),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Unlink the temporary client socket path so repeated invocations don't
        // litter the temp dir with dead sockets.
        if let Conn::Unix { local, .. } = &self.conn {
            let _ = std::fs::remove_file(local);
        }
    }
}

/// A process-unique path for a client-side Unix datagram socket.
fn unique_socket_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "wayfinder-client-{}-{}.sock",
        std::process::id(),
        n
    ))
}

/// Build an error for a response variant that does not match the request.
fn unexpected(want: &str, got: &ResponseKind) -> anyhow::Error {
    let got = match got {
        ResponseKind::NodeInfo(_) => "NodeInfo",
        ResponseKind::RoutingTable(_) => "RoutingTable",
        ResponseKind::LinkQualityTable(_) => "LinkQualityTable",
        ResponseKind::ResolveRoute(_) => "ResolveRoute",
        ResponseKind::OgmSchedule(_) => "OgmSchedule",
        ResponseKind::Throughput(_) => "Throughput",
        ResponseKind::Metrics(_) => "Metrics",
        ResponseKind::Error(_) => "Error",
        ResponseKind::Empty(_) => "Empty",
        ResponseKind::TrustAnchor(_) => "TrustAnchor",
        ResponseKind::SubmitCsr(_) => "SubmitCsr",
        ResponseKind::SecurityStatus(_) => "SecurityStatus",
        ResponseKind::ListCerts(_) => "ListCerts",
    };
    anyhow!("expected {want} response, got {got}")
}
