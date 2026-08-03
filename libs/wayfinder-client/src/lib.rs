//! Reusable client for the Wayfinder management API.
//!
//! Speaks the same prost envelope ([`WayfinderRequest`]/[`WayfinderResponse`])
//! the `wayfinder-server` expects, over the node's authenticated TLS transport:
//! a stream with 4-byte big-endian length-delimited framing (`tokio_util`
//! [`LengthDelimitedCodec`]), matching `serve_tls_server`. The client
//! authenticates by its mesh membership identity carried as an RFC 7250 raw
//! public key in the TLS handshake (see [`Client::connect_tls`]).
//!
//! Shared by `wayfinder-tui` and `wayfinderctl` so the wire framing and the
//! typed request methods live in exactly one place.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod tls;

use std::net::SocketAddr;

use anyhow::Context;
use anyhow::anyhow;
use bytes::Bytes;
use futures::SinkExt;
use futures::StreamExt;
use prost::Message;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_serial::SerialStream;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;
use wayfinder_protos::wayfinder_v1alpha::ApproveCsrRequest;
use wayfinder_protos::wayfinder_v1alpha::AuthenticateRequest;
use wayfinder_protos::wayfinder_v1alpha::DenyCsrRequest;
use wayfinder_protos::wayfinder_v1alpha::GetKeepAliveTableRequest;
use wayfinder_protos::wayfinder_v1alpha::GetLinkFeaturesTableRequest;
use wayfinder_protos::wayfinder_v1alpha::GetLinkQualityTableRequest;
use wayfinder_protos::wayfinder_v1alpha::GetMetricsRequest;
use wayfinder_protos::wayfinder_v1alpha::GetNodeInfoRequest;
use wayfinder_protos::wayfinder_v1alpha::GetOgmScheduleRequest;
use wayfinder_protos::wayfinder_v1alpha::GetRoutingTableRequest;
use wayfinder_protos::wayfinder_v1alpha::GetSecurityStatusRequest;
use wayfinder_protos::wayfinder_v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder_v1alpha::GetThroughputRequest;
use wayfinder_protos::wayfinder_v1alpha::GetTrustAnchorRequest;
use wayfinder_protos::wayfinder_v1alpha::GetTrustAnchorResponse;
use wayfinder_protos::wayfinder_v1alpha::KeepAliveTable;
use wayfinder_protos::wayfinder_v1alpha::LinkFeatures;
use wayfinder_protos::wayfinder_v1alpha::LinkFeaturesTable;
use wayfinder_protos::wayfinder_v1alpha::LinkQualityTable;
use wayfinder_protos::wayfinder_v1alpha::ListCertsRequest;
use wayfinder_protos::wayfinder_v1alpha::ListCertsResponse;
use wayfinder_protos::wayfinder_v1alpha::ListPendingCsrsRequest;
use wayfinder_protos::wayfinder_v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder_v1alpha::NodeInfo;
use wayfinder_protos::wayfinder_v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder_v1alpha::OgmSchedule;
use wayfinder_protos::wayfinder_v1alpha::ResolveRouteRequest;
use wayfinder_protos::wayfinder_v1alpha::ResolveRouteResponse;
use wayfinder_protos::wayfinder_v1alpha::RevokeNodeRequest;
use wayfinder_protos::wayfinder_v1alpha::RoutingTable;
use wayfinder_protos::wayfinder_v1alpha::RuntimeConfig;
use wayfinder_protos::wayfinder_v1alpha::SetAuthRequest;
use wayfinder_protos::wayfinder_v1alpha::SetConfigRequest;
use wayfinder_protos::wayfinder_v1alpha::SubmitCsrRequest;
use wayfinder_protos::wayfinder_v1alpha::SubmitCsrResponse;
use wayfinder_protos::wayfinder_v1alpha::Throughput;
use wayfinder_protos::wayfinder_v1alpha::TrickleConfig;
use wayfinder_protos::wayfinder_v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder_v1alpha::WayfinderResponse;
use wayfinder_protos::wayfinder_v1alpha::wayfinder_request::Request as RequestKind;
use wayfinder_protos::wayfinder_v1alpha::wayfinder_response::Response as ResponseKind;

/// The underlying transport a [`Client`] is connected over, carrying the same
/// 4-byte length-delimited prost framing regardless of medium.
///
/// Either the node's authenticated TLS stream ([`Client::connect_tls`]) or an
/// embedded node's unauthenticated serial port ([`Client::connect_serial`]); the
/// request/response path is identical over both, differing only in whether an
/// authentication handshake preceded it.
// Both variants are boxed. Measured: `Framed<TlsStream<TcpStream>, _>` is
// ~1250 bytes (rustls's connection/message-buffer state); `Framed<SerialStream,
// _>` alone is still ~225 bytes, which on its own already exceeds clippy's
// `large_enum_variant` threshold (200 bytes) — so `Serial` needs boxing
// regardless of `Tls`'s size, not just for symmetry.
enum Conn {
    /// Length-delimited framing over the node's authenticated TLS transport.
    Tls(Box<Framed<TlsStream<TcpStream>, LengthDelimitedCodec>>),
    /// Length-delimited framing over a raw serial port (embedded debug link).
    Serial(Box<Framed<SerialStream, LengthDelimitedCodec>>),
}

impl Conn {
    /// Send one already-encoded request frame over whichever transport backs
    /// this connection.
    async fn send(&mut self, frame: Bytes) -> anyhow::Result<()> {
        match self {
            Conn::Tls(framed) => framed.send(frame).await?,
            Conn::Serial(framed) => framed.send(frame).await?,
        }
        Ok(())
    }

    /// Await the next response frame, erroring if the peer closed the transport.
    async fn recv(&mut self) -> anyhow::Result<Bytes> {
        let frame = match self {
            Conn::Tls(framed) => framed.next().await,
            Conn::Serial(framed) => framed.next().await,
        };
        Ok(frame
            .ok_or_else(|| anyhow!("connection closed by server"))??
            .freeze())
    }
}

/// The credentials a client presents to a node's TLS management API.
///
/// The `seed` is the Ed25519 identity the client proves possession of in the
/// RFC 7250 handshake; `cert` is the membership certificate binding that key to
/// an admin identity. `cert` is empty when bootstrapping an un-enrolled node
/// (the client instead presents the node's *own* seed, which it holds).
#[derive(Clone)]
pub struct Identity {
    /// The client's 32-byte Ed25519 identity seed.
    pub seed: [u8; 32],
    /// The client's membership certificate as raw `MembershipCert` bytes, or
    /// empty to bootstrap.
    pub cert: Vec<u8>,
}

/// Everything a client needs to reach and authenticate to a node's TLS
/// management API: the listener address, the node's pinned public key, and the
/// client's own [`Identity`].  Assembled once (see [`Endpoint::load`]) and shared
/// by every binary that speaks to a node (the TUI and `wayfinderctl`), so the
/// endpoint-resolution logic — and its edge cases, like defaulting the pin to the
/// identity's own key — lives in exactly one place rather than being re-derived
/// per binary.
#[derive(Clone)]
pub struct Endpoint {
    /// The node's TLS listener address.
    pub addr: SocketAddr,
    /// The node's Ed25519 public key, pinned to defeat impersonation.
    pub node_key: [u8; 32],
    /// The client's identity: the seed it proves in the handshake and its
    /// membership cert (empty to bootstrap).
    pub identity: Identity,
}

impl Endpoint {
    /// Assemble an [`Endpoint`] from on-disk paths and CLI inputs: read the
    /// 32-byte identity seed from `identity_path`, the optional membership cert
    /// from `cert_path` (absent ⇒ bootstrap), and resolve the pinned node key
    /// from `node_key` when given, else default it to the identity's own public
    /// key (correct when bootstrapping a node with its own seed).
    pub fn load(
        addr: SocketAddr,
        identity_path: &std::path::Path,
        cert_path: Option<&std::path::Path>,
        node_key: Option<&str>,
    ) -> anyhow::Result<Self> {
        let seed: [u8; 32] = std::fs::read(identity_path)
            .with_context(|| format!("reading identity seed at {}", identity_path.display()))?
            .as_slice()
            .try_into()
            .map_err(|_| {
                anyhow!(
                    "identity seed at {} must be 32 bytes",
                    identity_path.display()
                )
            })?;
        let cert = cert_path
            .map(|path| {
                std::fs::read(path).with_context(|| format!("reading cert at {}", path.display()))
            })
            .transpose()?
            .unwrap_or_default();
        let node_key = match node_key {
            Some(hex) => parse_key32(hex).context("parsing --node-key")?,
            // Default to the identity's own public key: correct when
            // bootstrapping a node with its own seed, and a safe pin (the client
            // trusts itself).
            None => wayfinder_auth::Keypair::from_seed(&seed).ed_pubkey(),
        };
        Ok(Self {
            addr,
            node_key,
            identity: Identity { seed, cert },
        })
    }
}

/// Parse a 32-byte Ed25519 key from `s`, accepting either a colon-delimited or a
/// bare hex string, erroring if it is not exactly 32 bytes.  Shared by every
/// binary that takes a `--node-key`, so the accepted syntax is identical across
/// them.
pub fn parse_key32(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes: Vec<u8> = if s.contains(':') {
        s.split(':')
            .map(|byte| u8::from_str_radix(byte, 16))
            .collect::<Result<Vec<u8>, _>>()
            .with_context(|| format!("'{s}' is not a colon-delimited hex key"))?
    } else {
        if !s.len().is_multiple_of(2) {
            anyhow::bail!("hex key '{s}' must have an even number of digits");
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .with_context(|| format!("'{s}' is not a valid hex key"))?
    };
    bytes
        .as_slice()
        .try_into()
        .with_context(|| format!("'{s}' must be a 32-byte key, got {} bytes", bytes.len()))
}

/// A connected management-API client over a single transport.
pub struct Client {
    conn: Conn,
}

impl Client {
    /// Connect to a node's TLS management API and authenticate.
    ///
    /// The client presents `identity.seed`'s Ed25519 key as an RFC 7250 raw
    /// public key (the handshake proves possession) and pins the node to
    /// `node_key` so a man-in-the-middle can't impersonate it. After the
    /// handshake it sends its membership certificate (`identity.cert`; empty to
    /// bootstrap an un-enrolled node), which the node binds to the handshake key
    /// and authorizes via `decide_access`. Returns once authentication succeeds;
    /// a rejection surfaces as an error.
    pub async fn connect_tls(
        addr: SocketAddr,
        node_key: &[u8; 32],
        identity: &Identity,
    ) -> anyhow::Result<Self> {
        let config = crate::tls::client_config(&identity.seed, node_key)
            .map_err(|e| anyhow!("building management TLS client config: {e}"))?;
        let connector = TlsConnector::from(config);
        let tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to tls://{addr}"))?;
        // The raw-public-key verifier ignores the SNI name (identity is the
        // pinned key, not the hostname), so any syntactically valid name works.
        let server_name = ServerName::try_from("wayfinder-node")
            .map_err(|_| anyhow!("internal: static server name is invalid"))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake with the management API")?;
        let mut framed = LengthDelimitedCodec::builder().new_framed(tls);

        // Authenticate before issuing any request: the first frame carries the
        // membership cert bound to the handshake key.
        let auth = WayfinderRequest {
            request: Some(RequestKind::Authenticate(AuthenticateRequest {
                cert: identity.cert.clone(),
            })),
        };
        let mut buf = Vec::new();
        auth.encode(&mut buf)?;
        framed.send(Bytes::from(buf)).await?;

        let reply = framed
            .next()
            .await
            .ok_or_else(|| anyhow!("connection closed before authentication completed"))??;
        match WayfinderResponse::decode(reply)?.response {
            Some(ResponseKind::Empty(_)) => Ok(Self {
                conn: Conn::Tls(Box::new(framed)),
            }),
            Some(ResponseKind::Error(e)) => Err(anyhow!("authentication denied: {}", e.message)),
            other => Err(anyhow!("unexpected response to authentication: {other:?}")),
        }
    }

    /// Connect to an embedded node's **unauthenticated** management API over a
    /// serial port (e.g. the nRF52840's USB CDC-ACM management port, typically
    /// enumerating as `/dev/ttyACMX`), opened at `baud`.
    ///
    /// Unlike [`connect_tls`](Self::connect_tls), this transport carries no TLS
    /// and no membership authentication: the embedded server trusts the physical
    /// link and serves requests directly, so there is no handshake and no
    /// [`Identity`] to present. The wire framing — a 4-byte big-endian
    /// length-delimited prost envelope — is identical, so every typed request
    /// method works unchanged once connected.
    pub async fn connect_serial(path: &str, baud: u32) -> anyhow::Result<Self> {
        let serial = SerialStream::open(&tokio_serial::new(path, baud))
            .with_context(|| format!("opening serial port {path} at {baud} baud"))?;
        let framed = LengthDelimitedCodec::builder().new_framed(serial);
        Ok(Self {
            conn: Conn::Serial(Box::new(framed)),
        })
    }

    /// Encode and send one request, then await and decode the single response.
    async fn request(&mut self, request: RequestKind) -> anyhow::Result<ResponseKind> {
        let envelope = WayfinderRequest {
            request: Some(request),
        };
        let mut buf = Vec::new();
        envelope.encode(&mut buf)?;

        self.conn.send(Bytes::from(buf)).await?;
        let frame = self.conn.recv().await?;

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

    /// Query the current per-interface participation-feature state (the
    /// tx/rx OGM/data gates and keep-alive cadence set via
    /// [`set_link_features`](Client::set_link_features), or the interface's
    /// startup default).
    pub async fn link_features_table(&mut self) -> anyhow::Result<LinkFeaturesTable> {
        match self
            .request(RequestKind::GetLinkFeaturesTable(
                GetLinkFeaturesTableRequest {},
            ))
            .await?
        {
            ResponseKind::LinkFeaturesTable(table) => Ok(table),
            other => Err(unexpected("LinkFeaturesTable", &other)),
        }
    }

    /// Query the per-neighbor keep-alive heartbeat liveness table.
    pub async fn keepalive_table(&mut self) -> anyhow::Result<KeepAliveTable> {
        match self
            .request(RequestKind::GetKeepaliveTable(GetKeepAliveTableRequest {}))
            .await?
        {
            ResponseKind::KeepaliveTable(table) => Ok(table),
            other => Err(unexpected("KeepaliveTable", &other)),
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

    /// Set the Trickle/OGM emission bounds for one mesh interface at runtime.
    /// Applied in memory only — it does not persist across a restart. Resets
    /// the interface's live Trickle timer, discarding any backoff already
    /// grown toward the old bound — expect a burst of OGMs shortly after this
    /// call on a live interface. `iface_idx` must refer to an interface the
    /// node already has configured; this cannot provision a new one.
    pub async fn set_trickle_config(
        &mut self,
        iface_idx: u32,
        min_interval_ms: u32,
        max_interval_ms: u32,
    ) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    trickle: Some(TrickleConfig {
                        iface_idx,
                        min_interval_ms,
                        max_interval_ms,
                    }),
                    ..Default::default()
                }),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("SetConfig", &other)),
        }
    }

    /// Override one interface's participation features at runtime.  Each flag on
    /// `features` is independently optional: a `None` leaves that gate unchanged,
    /// so the caller flips only what it names (e.g. `tx_ogm: Some(false)` to
    /// silence OGM tx on a link this node only fronts).  Applied in memory only
    /// — it does not persist across a restart.  `features.iface_idx` must refer
    /// to an interface the node already has configured; this cannot provision a
    /// new one.
    pub async fn set_link_features(&mut self, features: LinkFeatures) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    link_features: Some(features),
                    ..Default::default()
                }),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("SetConfig", &other)),
        }
    }

    /// Switch lazy cert distribution on or off at runtime: whether this
    /// node's OGMs carry an 8-byte cert fingerprint instead of the full
    /// membership cert. Applied in memory only — it does not persist across
    /// a restart. A flag-day, wire-incompatible switch with un-upgraded auth
    /// nodes — see the design doc before flipping it on a live mesh.
    pub async fn set_lazy_cert_distribution(&mut self, enabled: bool) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    lazy_cert_distribution: Some(enabled),
                    ..Default::default()
                }),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("SetConfig", &other)),
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

    /// Provider mode: list the CSRs currently awaiting operator approval.
    pub async fn list_pending_csrs(&mut self) -> anyhow::Result<ListPendingCsrsResponse> {
        match self
            .request(RequestKind::ListPendingCsrs(ListPendingCsrsRequest {}))
            .await?
        {
            ResponseKind::ListPendingCsrs(resp) => Ok(resp),
            other => Err(unexpected("ListPendingCsrs", &other)),
        }
    }

    /// Provider mode: approve the pending CSR bound to `node_mac`, so the
    /// enrolling node collects its certificate on its next poll.
    pub async fn approve_csr(&mut self, node_mac: &[u8]) -> anyhow::Result<()> {
        match self
            .request(RequestKind::ApproveCsr(ApproveCsrRequest {
                node_mac: node_mac.to_vec(),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("ApproveCsr", &other)),
        }
    }

    /// Provider mode: deny the pending CSR bound to `node_mac`; the enrolling
    /// node observes a rejection on its next poll.
    pub async fn deny_csr(&mut self, node_mac: &[u8]) -> anyhow::Result<()> {
        match self
            .request(RequestKind::DenyCsr(DenyCsrRequest {
                node_mac: node_mac.to_vec(),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("DenyCsr", &other)),
        }
    }
}

/// Build an error for a response variant that does not match the request.
fn unexpected(want: &str, got: &ResponseKind) -> anyhow::Error {
    let got = match got {
        ResponseKind::NodeInfo(_) => "NodeInfo",
        ResponseKind::RoutingTable(_) => "RoutingTable",
        ResponseKind::LinkQualityTable(_) => "LinkQualityTable",
        ResponseKind::LinkFeaturesTable(_) => "LinkFeaturesTable",
        ResponseKind::KeepaliveTable(_) => "KeepaliveTable",
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
        ResponseKind::ListPendingCsrs(_) => "ListPendingCsrs",
    };
    anyhow!("expected {want} response, got {got}")
}
