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
use wayfinder_protos::wayfinder::v1alpha::ApproveCsrRequest;
use wayfinder_protos::wayfinder::v1alpha::AuthenticateRequest;
use wayfinder_protos::wayfinder::v1alpha::AuthenticateUserRequest;
use wayfinder_protos::wayfinder::v1alpha::AuthenticateUserResponse;
use wayfinder_protos::wayfinder::v1alpha::CreateUserRequest;
use wayfinder_protos::wayfinder::v1alpha::DenyCsrRequest;
use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicy;
use wayfinder_protos::wayfinder::v1alpha::GetKeepAliveTableRequest;
use wayfinder_protos::wayfinder::v1alpha::GetLinkFeaturesTableRequest;
use wayfinder_protos::wayfinder::v1alpha::GetLinkQualityTableRequest;
use wayfinder_protos::wayfinder::v1alpha::GetLogsRequest;
use wayfinder_protos::wayfinder::v1alpha::GetMetricsRequest;
use wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest;
use wayfinder_protos::wayfinder::v1alpha::GetOgmScheduleRequest;
use wayfinder_protos::wayfinder::v1alpha::GetRoutingTableRequest;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusRequest;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder::v1alpha::GetThroughputRequest;
use wayfinder_protos::wayfinder::v1alpha::GetTrustAnchorRequest;
use wayfinder_protos::wayfinder::v1alpha::GetTrustAnchorResponse;
use wayfinder_protos::wayfinder::v1alpha::KeepAliveTable;
use wayfinder_protos::wayfinder::v1alpha::LinkFeatures;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesTable;
use wayfinder_protos::wayfinder::v1alpha::LinkQualityTable;
use wayfinder_protos::wayfinder::v1alpha::ListCertsRequest;
use wayfinder_protos::wayfinder::v1alpha::ListCertsResponse;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsRequest;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder::v1alpha::ListUsersRequest;
use wayfinder_protos::wayfinder::v1alpha::ListUsersResponse;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder::v1alpha::OgmSchedule;
use wayfinder_protos::wayfinder::v1alpha::RemoveUserRequest;
use wayfinder_protos::wayfinder::v1alpha::ResolveRouteRequest;
use wayfinder_protos::wayfinder::v1alpha::ResolveRouteResponse;
use wayfinder_protos::wayfinder::v1alpha::RevokeNodeRequest;
use wayfinder_protos::wayfinder::v1alpha::RoutingTable;
use wayfinder_protos::wayfinder::v1alpha::RuntimeConfig;
use wayfinder_protos::wayfinder::v1alpha::SetAuthRequest;
use wayfinder_protos::wayfinder::v1alpha::SetConfigRequest;
use wayfinder_protos::wayfinder::v1alpha::SetLogLevelRequest;
use wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest;
use wayfinder_protos::wayfinder::v1alpha::SubmitCsrResponse;
use wayfinder_protos::wayfinder::v1alpha::Throughput;
use wayfinder_protos::wayfinder::v1alpha::TrickleConfig;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as RequestKind;
use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as ResponseKind;

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
            Some(ResponseKind::Error(e)) => Err(anyhow!(explain_auth_denial(
                &e.message,
                !identity.cert.is_empty()
            ))),
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

    /// Read recent log records from the node's in-memory ring, from `since_seq`
    /// onward and at most `max_records` of them (0 meaning the node's default
    /// batch size).
    ///
    /// Poll with the previous response's
    /// [`next_seq`](wayfinder_protos::wayfinder::v1alpha::LogRecords::next_seq)
    /// to see each record exactly once; pass 0 on a first poll to get whatever
    /// the node still retains. Check
    /// [`dropped`](wayfinder_protos::wayfinder::v1alpha::LogRecords::dropped) —
    /// non-zero means records were evicted before this poll reached them, and
    /// the gap should be shown rather than hidden.
    pub async fn logs(&mut self, since_seq: u64, max_records: u32) -> anyhow::Result<LogRecords> {
        match self
            .request(RequestKind::GetLogs(GetLogsRequest {
                since_seq,
                max_records,
            }))
            .await?
        {
            ResponseKind::Logs(logs) => Ok(logs),
            other => Err(unexpected("Logs", &other)),
        }
    }

    /// Change which log records the node emits, across every sink it writes to.
    /// Returns the directive spec now in force.
    ///
    /// `directives` is a `RUST_LOG`-style list (`info,batman=trace`); an empty
    /// string restores the node's default. A spec the node cannot parse comes
    /// back as an `Err` and leaves the node's filter unchanged.
    pub async fn set_log_level(&mut self, directives: &str) -> anyhow::Result<String> {
        match self
            .request(RequestKind::SetLogLevel(SetLogLevelRequest {
                directives: directives.to_string(),
            }))
            .await?
        {
            ResponseKind::LogFilter(filter) => Ok(filter.directives),
            other => Err(unexpected("LogFilter", &other)),
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

    /// Read the shared enrollment token a provider-mode node is applying.
    ///
    /// Separate from [`security_status`](Self::security_status) because that
    /// one is polled and this answer is a secret: asking is a discrete act the
    /// node logs, rather than a value riding every refresh into whatever holds
    /// the snapshot. Errors on a node that is not a provider — which is a
    /// different answer from "no token is required".
    ///
    /// Returns `None` when enrollment is open (no token), `Some` with the token
    /// otherwise; an empty token is not a state the node can report.
    pub async fn reveal_enrollment_token(&mut self) -> anyhow::Result<Option<String>> {
        use wayfinder_protos::wayfinder::v1alpha::RevealEnrollmentTokenRequest;
        use wayfinder_protos::wayfinder::v1alpha::reveal_enrollment_token_response::Admission;

        match self
            .request(RequestKind::RevealEnrollmentToken(
                RevealEnrollmentTokenRequest {},
            ))
            .await?
        {
            ResponseKind::EnrollmentToken(response) => match response.admission {
                Some(Admission::Token(token)) => Ok(Some(token)),
                Some(Admission::Open(_)) => Ok(None),
                // An absent oneof is what prost yields for a variant added
                // after this build: fail rather than read it as "open", which
                // would report an ungated mesh on no evidence.
                None => Err(anyhow::anyhow!(
                    "node reported an enrollment admission rule this client does not understand"
                )),
            },
            other => Err(unexpected("EnrollmentToken", &other)),
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

    /// Install a whole mesh identity on the node: its seed, its membership
    /// certificate and the mesh trust anchor.
    ///
    /// Pass an empty `seed` to certify the identity the node already has — see
    /// [`install_cert`](Self::install_cert), which is that call named for what
    /// it does.
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

    /// Certify the identity the node already holds: install `cert` and
    /// `trust_anchor` against the node's existing seed, which it keeps.
    ///
    /// This is how a node that enrolled online adopts the certificate it was
    /// issued. Its key — and therefore the MAC its peers know it by — does not
    /// change, so the node becomes a member of the mesh without moving on it.
    /// The certificate must of course be bound to that same key, or the node
    /// will hold a certificate it cannot sign for.
    pub async fn install_cert(&mut self, cert: &[u8], trust_anchor: &[u8]) -> anyhow::Result<()> {
        self.set_auth(&[], cert, trust_anchor).await
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
    /// membership cert. A flag-day, wire-incompatible switch with un-upgraded
    /// auth nodes — see the design doc before flipping it on a live mesh.
    ///
    /// Persisted by a node configured with a runtime state path, in memory
    /// only otherwise — the node's decision, not the caller's.
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

    /// Switch the node's fail-closed gate on or off at runtime: whether it
    /// stays inert on the mesh while it holds no membership cert.
    ///
    /// Turning it on for a node that has no cert takes that node off the mesh
    /// immediately — including, if this is the node serving your management
    /// connection, everything that reaches it *through* the mesh. Read
    /// [`security_status`](Client::security_status) first when not certain a
    /// cert is installed.
    ///
    /// Persisted by a node configured with a runtime state path, in memory
    /// only otherwise.
    pub async fn set_require_auth(&mut self, require: bool) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    require_auth: Some(require),
                    ..Default::default()
                }),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("SetConfig", &other)),
        }
    }

    /// Provider mode: update the node's enrollment policy — how a node asking
    /// to join the mesh is admitted.
    ///
    /// Each field of `policy` is independently optional; an unset field leaves
    /// that piece of the policy alone. Use
    /// [`EnrollmentPolicy::enrollment_token_update`] to change the shared
    /// token: `EnrollmentTokenCleared(true)` opens enrollment, and
    /// `EnrollmentToken(value)` gates it on `value`. Errors on a node that is
    /// not a provider, which has no enrollment policy to change.
    ///
    /// The policy is persisted by the authority alongside the certificates it
    /// governs, so it survives a restart.
    pub async fn set_enrollment_policy(&mut self, policy: EnrollmentPolicy) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    enrollment: Some(policy),
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

    /// Provider mode: exchange a user's credentials for a short-lived
    /// management certificate bound to the session keys given.
    ///
    /// Runs on the enrollment tier, so this is callable on a connection holding
    /// no certificate at all — which is what a client that has not logged in
    /// yet is. The password and code are sent over the authenticated TLS
    /// channel and never persisted by either side.
    pub async fn authenticate_user(
        &mut self,
        username: &str,
        password: &str,
        totp_code: &str,
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
    ) -> anyhow::Result<AuthenticateUserResponse> {
        match self
            .request(RequestKind::AuthenticateUser(AuthenticateUserRequest {
                username: username.to_string(),
                password: password.to_string(),
                totp_code: totp_code.to_string(),
                ed_pubkey: ed_pubkey.to_vec(),
                x_pubkey: x_pubkey.to_vec(),
            }))
            .await?
        {
            ResponseKind::AuthenticateUser(resp) => Ok(resp),
            other => Err(unexpected("AuthenticateUser", &other)),
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

    /// Provider mode: list the certificate authority's user accounts.
    ///
    /// Needs a full management grant — the roster of who may administer the
    /// mesh is not on the read-only tier.
    pub async fn list_users(&mut self) -> anyhow::Result<ListUsersResponse> {
        match self
            .request(RequestKind::ListUsers(ListUsersRequest {}))
            .await?
        {
            ResponseKind::ListUsers(resp) => Ok(resp),
            other => Err(unexpected("ListUsers", &other)),
        }
    }

    /// Provider mode: create a user account, returning the `otpauth://`
    /// enrolment URI for its second factor (empty when `no_totp`).
    ///
    /// The URI comes back exactly once. The authority cannot serve it again —
    /// the secret is not recoverable from it — so a caller that discards this
    /// value has created an account whose second factor nobody can enrol.
    ///
    /// `session_ttl_secs` of zero takes the authority's default.
    pub async fn create_user(
        &mut self,
        username: &str,
        password: &str,
        admin: bool,
        session_ttl_secs: u64,
        no_totp: bool,
    ) -> anyhow::Result<String> {
        match self
            .request(RequestKind::CreateUser(CreateUserRequest {
                username: username.to_string(),
                password: password.to_string(),
                admin,
                session_ttl_secs,
                no_totp,
            }))
            .await?
        {
            ResponseKind::CreateUser(resp) => Ok(resp.totp_enrolment_uri),
            other => Err(unexpected("CreateUser", &other)),
        }
    }

    /// Provider mode: remove a user account.
    ///
    /// Ends the account's ability to obtain *new* sessions. A certificate
    /// already issued to it keeps working until it expires or is revoked, so an
    /// account believed compromised needs [`revoke_node`](Self::revoke_node) as
    /// well as this.
    ///
    /// Errors when the name is not on file, and when it is the last account
    /// that can still administer the mesh — the authority refuses to leave
    /// itself with no administrator.
    pub async fn remove_user(&mut self, username: &str) -> anyhow::Result<()> {
        match self
            .request(RequestKind::RemoveUser(RemoveUserRequest {
                username: username.to_string(),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("RemoveUser", &other)),
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

/// Complete a TLS handshake against `addr` purely to learn the raw public key
/// the node presents, then hang up without sending a request.
///
/// This exists for one caller: the first connection to a node whose key is not
/// yet recorded, where the operator has to be shown a fingerprint before
/// anything can be pinned. It is the same bind SSH is in — there is no way to
/// ask a host what key it has except by asking the host — and the same
/// resolution: connect once, show the fingerprint, let a human decide.
///
/// **Nothing is trusted as a result.** The connection carries no request, its
/// key is verified only to the extent that the peer proved possession of it,
/// and the caller must confirm the value with a person before using it as a
/// pin. A programmatic caller that skips that confirmation has built an
/// unauthenticated management client.
pub async fn probe_node_key(addr: SocketAddr) -> anyhow::Result<[u8; 32]> {
    // An ephemeral identity: this connection issues no request, so what it
    // presents is never authorized against anything, and minting a throwaway
    // key avoids reaching for a real one to do it.
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);

    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let config = crate::tls::probing_client_config(&seed, seen.clone())
        .map_err(|e| anyhow!("building management TLS probe config: {e}"))?;
    let connector = TlsConnector::from(config);
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to tls://{addr}"))?;
    let server_name = ServerName::try_from("wayfinder-node")
        .map_err(|_| anyhow!("internal: static server name is invalid"))?;
    let _tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake with the management API")?;

    let key = seen
        .lock()
        .map_err(|_| anyhow!("internal: probe slot poisoned"))?
        .ok_or_else(|| anyhow!("the node completed a handshake without presenting a raw key"))?;
    Ok(key)
}

/// Build an error for a response variant that does not match the request.
fn unexpected(want: &str, got: &ResponseKind) -> anyhow::Error {
    let got = match got {
        ResponseKind::NodeInfo(_) => "NodeInfo",
        ResponseKind::EnrollmentToken(_) => "EnrollmentToken",
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
        ResponseKind::Logs(_) => "Logs",
        ResponseKind::LogFilter(_) => "LogFilter",
        ResponseKind::AuthenticateUser(_) => "AuthenticateUser",
        ResponseKind::ListUsers(_) => "ListUsers",
        ResponseKind::CreateUser(_) => "CreateUser",
    };
    anyhow!("expected {want} response, got {got}")
}

/// Turn a node's refusal into a message that names the likely cause.
///
/// The node answers every failed authentication with one deliberately generic
/// message, so that an unauthenticated peer cannot use the response to tell
/// wrong-key from revoked from expired from not-admin while probing with a
/// stolen certificate. That is the right call on the server, and it leaves the
/// bare message useless to a legitimate operator reading their own logs.
///
/// The gap is closed from this side instead: whether *this* client presented a
/// certificate is a fact it already knows, so saying so leaks nothing. Without
/// one, the connection is not refused outright — a client presenting no
/// certificate is admitted at the enrollment tier — so what it is short of is
/// the credential every other request needs. With one, the candidates are
/// listed rather than guessed between, because the client genuinely cannot tell
/// which check failed.
fn explain_auth_denial(server_message: &str, presented_cert: bool) -> String {
    let cause = if presented_cert {
        "the certificate presented is not an admin certificate, has expired, has been revoked, \
         or was issued by a different mesh root"
    } else {
        "no membership certificate was presented, so this connection is limited to \
         enrollment; anything else needs an admin certificate or the node's own key"
    };
    // The node's own wording is kept rather than replaced: a future server may
    // return something more specific, and this client's guess must not bury it.
    // It is dropped only when it is the generic message the prefix already says,
    // which would otherwise render as "authentication denied: authentication
    // denied".
    if server_message == "authentication denied" {
        format!("authentication denied by the node: {cause}")
    } else {
        format!("authentication denied by the node ({server_message}): {cause}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client that presented no certificate is admitted only for enrollment,
    /// so what it is short of is the credential everything else needs. That is
    /// by far the likeliest reason its requests are refused, and it is a fact
    /// about *this* client, so naming it leaks nothing the node withheld.
    #[test]
    fn a_denial_without_a_cert_names_the_enrollment_limit() {
        let explained = explain_auth_denial("authentication denied", false);

        assert!(
            explained.contains("no membership certificate"),
            "got: {explained}"
        );
        assert!(
            explained.contains("limited to enrollment"),
            "got: {explained}"
        );
    }

    /// With a certificate presented, the client cannot tell which of the
    /// several enrolled-path checks failed — the node deliberately answers with
    /// one generic message so an unauthenticated peer cannot probe. So the
    /// explanation lists the candidates rather than inventing a verdict.
    #[test]
    fn a_denial_with_a_cert_lists_the_candidate_causes() {
        let explained = explain_auth_denial("authentication denied", true);

        assert!(explained.contains("admin"), "got: {explained}");
        assert!(explained.contains("expired"), "got: {explained}");
        assert!(explained.contains("revoked"), "got: {explained}");
    }

    /// The node's own wording is preserved, so a future server that returns
    /// something more specific is not overwritten by this client's guess.
    #[test]
    fn the_nodes_message_is_preserved() {
        let explained = explain_auth_denial("mesh id mismatch", true);

        assert!(explained.contains("mesh id mismatch"), "got: {explained}");
    }

    /// The node's generic message is not repeated back alongside a prefix that
    /// says the same thing — "authentication denied: authentication denied"
    /// spends a whole log line saying nothing twice.
    #[test]
    fn the_generic_message_is_not_doubled() {
        let explained = explain_auth_denial("authentication denied", false);

        assert_eq!(
            explained.matches("authentication denied").count(),
            1,
            "got: {explained}"
        );
    }
}
