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

mod addr;
#[cfg(feature = "cli")]
mod args;
mod target;
mod tls;

pub use addr::NodeAddr;
#[cfg(feature = "cli")]
pub use args::ConnectArgs;
pub use target::ConnectTarget;
pub use wayfinder_clock_trust::ClockSync;
pub use wayfinder_clock_trust::ClockTrust;
/// Ask the host what it thinks of its own clock, under the given policy.
///
/// Re-exported under a qualified name — `read` alone says nothing at a call
/// site in another crate — mirroring `wayfinder-server`'s spelling of the same
/// re-export, so a reader who knows one knows the other.
pub use wayfinder_clock_trust::read as clock_sync;

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use bytes::Bytes;
use core::fmt;
use futures::SinkExt;
use futures::StreamExt;
use prost::Message;
use rustls::pki_types::ServerName;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_serial::SerialPort;
use tokio_serial::SerialStream;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;
use wayfinder_auth::MIN_PLAUSIBLE_UNIX;
use wayfinder_protos::service::NO_MEMBERSHIP_CERT;
use wayfinder_protos::wayfinder::v1alpha::Alarms;
use wayfinder_protos::wayfinder::v1alpha::ApproveCsrRequest;
use wayfinder_protos::wayfinder::v1alpha::AuthenticateRequest;
use wayfinder_protos::wayfinder::v1alpha::AuthenticateUserRequest;
use wayfinder_protos::wayfinder::v1alpha::AuthenticateUserResponse;
use wayfinder_protos::wayfinder::v1alpha::BeginUserRegistrationRequest;
use wayfinder_protos::wayfinder::v1alpha::BeginUserRegistrationResponse;
use wayfinder_protos::wayfinder::v1alpha::CancelPingRequest;
use wayfinder_protos::wayfinder::v1alpha::CancelPingResponse;
use wayfinder_protos::wayfinder::v1alpha::CompleteUserRegistrationRequest;
use wayfinder_protos::wayfinder::v1alpha::CreateUserInviteRequest;
use wayfinder_protos::wayfinder::v1alpha::CreateUserInviteResponse;
use wayfinder_protos::wayfinder::v1alpha::CreateUserRequest;
use wayfinder_protos::wayfinder::v1alpha::DenyCsrRequest;
use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicy;
use wayfinder_protos::wayfinder::v1alpha::GetAlarmsRequest;
use wayfinder_protos::wayfinder::v1alpha::GetKeepAliveTableRequest;
use wayfinder_protos::wayfinder::v1alpha::GetLinkFeaturesTableRequest;
use wayfinder_protos::wayfinder::v1alpha::GetLinkQualityTableRequest;
use wayfinder_protos::wayfinder::v1alpha::GetLogsRequest;
use wayfinder_protos::wayfinder::v1alpha::GetMetricsRequest;
use wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest;
use wayfinder_protos::wayfinder::v1alpha::GetOgmScheduleRequest;
use wayfinder_protos::wayfinder::v1alpha::GetOwnCertRequest;
use wayfinder_protos::wayfinder::v1alpha::GetOwnCertResponse;
use wayfinder_protos::wayfinder::v1alpha::GetRoutingTableRequest;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusRequest;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder::v1alpha::GetThroughputRequest;
use wayfinder_protos::wayfinder::v1alpha::GetTrustAnchorRequest;
use wayfinder_protos::wayfinder::v1alpha::GetTrustAnchorResponse;
use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;
use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentResponse;
use wayfinder_protos::wayfinder::v1alpha::KeepAliveTable;
use wayfinder_protos::wayfinder::v1alpha::LinkFeatures;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesTable;
use wayfinder_protos::wayfinder::v1alpha::LinkQualityTable;
use wayfinder_protos::wayfinder::v1alpha::ListCertsRequest;
use wayfinder_protos::wayfinder::v1alpha::ListCertsResponse;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsRequest;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder::v1alpha::ListUserInvitesRequest;
use wayfinder_protos::wayfinder::v1alpha::ListUserInvitesResponse;
use wayfinder_protos::wayfinder::v1alpha::ListUsersRequest;
use wayfinder_protos::wayfinder::v1alpha::ListUsersResponse;
use wayfinder_protos::wayfinder::v1alpha::ListVpnPeersRequest;
use wayfinder_protos::wayfinder::v1alpha::ListVpnPeersResponse;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder::v1alpha::OgmSchedule;
use wayfinder_protos::wayfinder::v1alpha::PingRequest;
use wayfinder_protos::wayfinder::v1alpha::PingResponse;
use wayfinder_protos::wayfinder::v1alpha::PingStatusRequest;
use wayfinder_protos::wayfinder::v1alpha::PingStatusResponse;
use wayfinder_protos::wayfinder::v1alpha::RemoveUserRequest;
use wayfinder_protos::wayfinder::v1alpha::RenewalProvider;
use wayfinder_protos::wayfinder::v1alpha::ResolveRouteRequest;
use wayfinder_protos::wayfinder::v1alpha::ResolveRouteResponse;
use wayfinder_protos::wayfinder::v1alpha::RevokeNodeRequest;
use wayfinder_protos::wayfinder::v1alpha::RevokeUserInviteRequest;
use wayfinder_protos::wayfinder::v1alpha::RevokeUserSessionsRequest;
use wayfinder_protos::wayfinder::v1alpha::RevokeVpnPeerRequest;
use wayfinder_protos::wayfinder::v1alpha::RoutingTable;
use wayfinder_protos::wayfinder::v1alpha::RuntimeConfig;
use wayfinder_protos::wayfinder::v1alpha::SetAuthRequest;
use wayfinder_protos::wayfinder::v1alpha::SetConfigRequest;
use wayfinder_protos::wayfinder::v1alpha::SetLogLevelRequest;
use wayfinder_protos::wayfinder::v1alpha::SetTimeRequest;
use wayfinder_protos::wayfinder::v1alpha::SetUserEnabledRequest;
use wayfinder_protos::wayfinder::v1alpha::SetUserPasswordRequest;
use wayfinder_protos::wayfinder::v1alpha::SetUserRoleRequest;
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
    /// The node's TLS listener address, host unresolved.
    pub addr: NodeAddr,
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
        addr: NodeAddr,
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

    /// Adopt, as this endpoint's credential, the membership certificate held by
    /// the node at `node_addr` — fetched from that node over its management
    /// API rather than read off a disk.
    ///
    /// This is what `--cert-from` does, and it exists because a node that
    /// enrolled once already holds its certificate: in a file under static
    /// auth, or in the runtime state a `SetAuth` install persisted. Without
    /// this, an operator wanting to *present* that certificate had to run a
    /// whole second enrollment to obtain a copy of it — a CSR round trip whose
    /// only product was a duplicate of something the node already had.
    ///
    /// Nothing about where this endpoint connects changes: [`addr`](Self::addr)
    /// and [`node_key`](Self::node_key) still name the far end, and the seed is
    /// untouched. Only the certificate presented on arrival is filled in.
    ///
    /// # Why the source node is pinned to this identity's own key
    ///
    /// The connection to `node_addr` presents this endpoint's seed with no
    /// certificate — the self-key bootstrap — and pins the node to that seed's
    /// own public key. There is no flag to point it elsewhere, and that is the
    /// security property rather than a convenience: a membership certificate is
    /// useful only to the holder of the key it names, so the only node with a
    /// certificate worth having here is the node whose seed this is. A pin that
    /// could be overridden would let a wrong — or hostile — address hand back a
    /// certificate this client would then go and present somewhere.
    ///
    /// A node presenting any other key therefore fails the handshake, which is
    /// the intended outcome and not a misconfiguration to work around.
    pub async fn load_cert_from_node(&mut self, node_addr: &NodeAddr) -> anyhow::Result<()> {
        // No certificate on this connection: the node is being asked on its own
        // behalf, by whoever holds its seed, which is the one credential a
        // node's local operator is guaranteed to have.
        let bootstrap = Identity {
            seed: self.identity.seed,
            cert: Vec::new(),
        };
        let pin = wayfinder_auth::Keypair::from_seed(&self.identity.seed).ed_pubkey();
        let mut client = Client::connect_tls(node_addr, &pin, &bootstrap)
            .await
            .with_context(|| format!("connecting to {node_addr} to read its certificate"))?;
        let pair = match client.own_cert().await {
            Ok(pair) => pair,
            // The node answered, and its answer was "I have none". That is a
            // state an operator fixes, not a failure to retry, so it is
            // rewritten into the instruction rather than left as a refusal the
            // caller has to interpret. Matched on the shared constant, which is
            // why that constant exists.
            Err(e) if e.to_string().contains(NO_MEMBERSHIP_CERT) => anyhow::bail!(
                "{node_addr} holds no membership certificate to present: it has an \
                 identity, but nothing has certified it yet. Enroll it first — \
                 `wayfinderctl enroll` where the node can reach the provider, or \
                 `csr request` / `csr submit` / `csr install` where it cannot."
            ),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("asking {node_addr} for the membership certificate it runs under")
                });
            }
        };
        check_usable(&pair, &pin, node_addr)?;
        self.identity.cert = pair.cert;
        Ok(())
    }
}

/// Check that a fetched [`GetOwnCertResponse`] is a credential this client can
/// actually present, before adopting it.
///
/// The pin already makes a *hostile* answer here unreachable: reaching this
/// point means the far end proved possession of the very seed being presented,
/// and anyone holding that seed already has the self-key tier on that node.
/// So this is not a trust boundary — it is the difference between a failure
/// that names what is wrong and one that does not. Without it a node that
/// answered with a certificate for some other key (a provisioning mistake, a
/// half-finished `SetAuth`, a corrupted store) would be adopted here and
/// refused at the *far* end, which answers a deliberately generic
/// "authentication denied" and leaves the operator with nothing to go on.
///
/// Two checks, and deliberately not a third:
///
/// * the certificate parses, and names the key this client will prove in the
///   handshake — the mismatch the far end would report as `KeyMismatch`;
/// * it belongs to the same mesh as the anchor served beside it, which is what
///   makes the response's "both halves together" invariant real rather than
///   merely asserted. This is the only reader that field has.
///
/// **Not** expiry, and not the root signature. Both are the far end's to
/// judge, and it is authoritative where this client is not: validating them
/// here would let a skewed clock on an operator's laptop refuse a certificate
/// the mesh accepts, turning a working flow into a confusing local failure.
fn check_usable(
    pair: &GetOwnCertResponse,
    pin: &[u8; 32],
    node_addr: &NodeAddr,
) -> anyhow::Result<()> {
    let cert = wayfinder_auth::MembershipCert::from_bytes(&pair.cert).ok_or_else(|| {
        anyhow!("{node_addr} returned {} bytes that are not a membership certificate this build can parse", pair.cert.len())
    })?;
    if &cert.ed_pubkey != pin {
        bail!(
            "{node_addr} returned a certificate for a different key than the identity              being presented, so nothing would accept it. The node is running under an              identity this client does not hold — check that --identity names that              node's own seed."
        );
    }
    let anchor = wayfinder_auth::TrustAnchor::from_bytes(&pair.trust_anchor)
        .ok_or_else(|| anyhow!("{node_addr} returned a trust anchor this build cannot parse"))?;
    let (cert_mesh, anchor_mesh) = (cert.mesh_id.get(), anchor.mesh_id);
    if cert_mesh != anchor_mesh {
        bail!(
            "{node_addr} returned a certificate for mesh {cert_mesh:#x} alongside the              anchor of mesh {anchor_mesh:#x}; the node's own credential does not hang              together, which is a fault on that node rather than a usable certificate."
        );
    }
    Ok(())
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
        addr: &NodeAddr,
        node_key: &[u8; 32],
        identity: &Identity,
    ) -> anyhow::Result<Self> {
        let config = crate::tls::client_config(&identity.seed, node_key)
            .map_err(|e| anyhow!("building management TLS client config: {e}"))?;
        let connector = TlsConnector::from(config);
        let tcp = TcpStream::connect(addr.connect_target())
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
        let mut serial = SerialStream::open(&tokio_serial::new(path, baud))
            .with_context(|| format!("opening serial port {path} at {baud} baud"))?;

        // Discard whatever the port was already holding before the first frame
        // goes out.
        //
        // A serial link has no connection to open, so there is no point at
        // which the two ends agree the stream starts — whatever the board said
        // before we arrived is still queued, and the framing has no marker to
        // resynchronise on. One stale byte offsets every 4-byte length prefix
        // that follows, and the symptom is not a decode failure but
        // `frame size too big`: the codec reads four bytes of someone else's
        // ASCII as a length. An ESP32 makes this the normal case rather than an
        // edge one — its ROM and second-stage bootloaders log ~1.2 KB to the
        // very UART the management API is served on, on every reset.
        //
        // Best-effort: a port that cannot be flushed is not a reason to refuse
        // to talk to it, and the failure it guards against is one this call
        // cannot detect anyway.
        let _ = serial.clear(tokio_serial::ClearBuffer::Input);

        // ...and then wait out whatever the *act of opening* set off.
        //
        // Flushing alone is not enough on an ESP32, and the reason is worth
        // stating because it cannot be designed around from this side: **on
        // Linux the kernel raises DTR when a tty is opened**, which is wired to
        // the auto-reset circuit on every ESP32 dev board, so connecting
        // reboots the node. `serialport`'s own `dtr_on_open` documentation says
        // as much — the pulse happens whatever the flag is set to. The board
        // then emits ~1.2 KB of ROM and second-stage bootloader logging onto
        // the very UART the management API is served on, arriving *after* the
        // flush and in front of the first response.
        //
        // So discard until the line has been quiet for `QUIET` — but not before
        // `SETTLE` has passed, however quiet it is. Both halves are needed and
        // the second is the unobvious one: a reset triggered by this very open
        // has not produced a single byte yet when the drain starts, so quiet
        // alone ends it immediately and the banner lands in front of the first
        // response anyway. Measured on an ESP32: first byte 16 ms after open,
        // last at ~300 ms, never a mid-stream gap over 9 ms.
        //
        // `DEADLINE` bounds a port that is simply always noisy, so a wrong
        // `--serial` argument fails rather than hanging here forever.
        //
        // The cost is `SETTLE` on every serial connect, including the nRF's
        // CDC-ACM port, which has no reset circuit and nothing to wait for.
        // That is a real half-second on a one-shot `wayfinderctl` call, and it
        // buys the difference between a transport that works and one that fails
        // on whichever invocation happens to follow a reset.
        const SETTLE: Duration = Duration::from_millis(400);
        const QUIET: Duration = Duration::from_millis(250);
        const DEADLINE: Duration = Duration::from_secs(3);
        let opened_at = Instant::now();
        let give_up_at = opened_at + DEADLINE;
        let mut scratch = [0u8; 512];
        let mut settled = false;
        while Instant::now() < give_up_at {
            match timeout(QUIET, serial.read(&mut scratch)).await {
                // Still talking: keep discarding.
                Ok(Ok(n)) if n > 0 => continue,
                // Quiet for a whole window, or the stream ended. Done only if
                // the board has also had long enough to start.
                _ if opened_at.elapsed() >= SETTLE => {
                    settled = true;
                    break;
                }
                // Not yet settled. Anything that resolved *ready* — an EOF, or
                // an I/O error the port returns without awaiting — would spin
                // here, so yield rather than re-poll it immediately.
                _ => tokio::time::sleep(QUIET).await,
            }
        }
        // Falling out of the loop on the deadline is a failure, not a default.
        // Returning a `Client` over a stream still mid-sentence just moves the
        // symptom: the next request dies inside the length codec with
        // `frame size too big`, which is the opaque error this whole drain
        // exists to stop anyone seeing.
        anyhow::ensure!(
            settled,
            "serial port {path} was still sending after {DEADLINE:?} and never went quiet; \
             it does not look like a wayfinder management port — is {path} the right device?"
        );
        let _ = serial.clear(tokio_serial::ClearBuffer::Input);

        let framed = LengthDelimitedCodec::builder().new_framed(serial);
        Ok(Self {
            conn: Conn::Serial(Box::new(framed)),
        })
    }

    /// Encode and send one request, then await and decode the single response.
    ///
    /// A well-formed error *response* comes back as a [`ServerError`] inside the
    /// `anyhow::Error`, so a caller can tell the node's considered "no" from the
    /// stream having broken underneath it. Everything else — an I/O failure on
    /// send or recv, a decode failure, an empty envelope — is an ordinary
    /// `anyhow` error and means the connection is suspect.
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
            // "unexpected variant" mismatch in every typed method. Typed rather
            // than a bare `anyhow!` so a caller can distinguish it by
            // `downcast_ref` instead of by matching on the rendered string —
            // see `ServerError`.
            Some(ResponseKind::Error(e)) => Err(ServerError { message: e.message }.into()),
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

    /// Read the node's alarm board: the conditions it currently believes are
    /// wrong.
    ///
    /// Unlike [`logs`](Self::logs) there is no cursor — the board is small,
    /// bounded and latched, so each poll takes the whole of it and a client
    /// needs no state between polls.
    ///
    /// Every row is reported, including ones that have gone quiet: check
    /// [`active`](wayfinder_protos::wayfinder::v1alpha::Alarm::active) against
    /// [`now_ms`](wayfinder_protos::wayfinder::v1alpha::Alarms::now_ms) to tell
    /// "firing now" from "fired recently and stopped". An empty board is the
    /// node saying nothing is wrong, not an absence of an answer.
    pub async fn alarms(&mut self) -> anyhow::Result<Alarms> {
        match self
            .request(RequestKind::GetAlarms(GetAlarmsRequest {}))
            .await?
        {
            ResponseKind::Alarms(alarms) => Ok(alarms),
            other => Err(unexpected("Alarms", &other)),
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

    /// Fetch the membership certificate this node is running under, with the
    /// trust anchor it chains to.
    ///
    /// The pair is public: a membership certificate is public-key material plus
    /// the root's signature over it, every field of which
    /// [`security_status`](Self::security_status) already reports, and the
    /// anchor is the key peers verify it against. What it saves is a
    /// second enrollment: a client holding the node's identity seed can present
    /// the node's own certificate elsewhere without asking a certificate
    /// authority to reissue one the node already has.
    ///
    /// Errors on a node that holds no certificate at all; the message is
    /// [`NO_MEMBERSHIP_CERT`](wayfinder_protos::service::NO_MEMBERSHIP_CERT),
    /// which is a state an operator can fix rather than a transport failure.
    pub async fn own_cert(&mut self) -> anyhow::Result<GetOwnCertResponse> {
        match self
            .request(RequestKind::GetOwnCert(GetOwnCertRequest {}))
            .await?
        {
            ResponseKind::OwnCert(resp) => Ok(resp),
            other => Err(unexpected("OwnCert", &other)),
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

    /// Ask the node to start a reachability-probe session against
    /// `destination` — the mesh's `ping`.
    ///
    /// The node runs the session; this returns straight away with the handle to
    /// poll [`ping_status`](Self::ping_status) with, alongside the settings
    /// actually in force after the node's defaults and caps. Pass 0 for any of
    /// `count`, `interval_ms`, `timeout_ms` or `payload_bytes` to take the
    /// node's default.
    ///
    /// A node runs one session at a time, so this displaces whatever was
    /// running — which is why the handle matters: an earlier caller's poll then
    /// reads as gone rather than as somebody else's numbers.
    pub async fn ping(
        &mut self,
        destination: Vec<u8>,
        count: u32,
        interval_ms: u32,
        timeout_ms: u32,
        payload_bytes: u32,
    ) -> anyhow::Result<PingResponse> {
        match self
            .request(RequestKind::Ping(PingRequest {
                destination,
                count,
                interval_ms,
                timeout_ms,
                payload_bytes,
            }))
            .await?
        {
            ResponseKind::Ping(started) => Ok(started),
            other => Err(unexpected("Ping", &other)),
        }
    }

    /// Read the status of the ping session `session_seq` names.
    ///
    /// An unset [`PingStatusResponse::session`] means the node is no longer
    /// running that session — it was displaced, or the node restarted — and is
    /// the signal to stop polling, not an error.
    pub async fn ping_status(&mut self, session_seq: u32) -> anyhow::Result<PingStatusResponse> {
        match self
            .request(RequestKind::PingStatus(PingStatusRequest { session_seq }))
            .await?
        {
            ResponseKind::PingStatus(status) => Ok(status),
            other => Err(unexpected("PingStatus", &other)),
        }
    }

    /// Stop the ping session `session_seq` names, and read back what it
    /// measured before it stopped.
    ///
    /// An unset [`CancelPingResponse::session`] means there was nothing of this
    /// caller's to stop — it had already finished, it was displaced, or it
    /// never started — and is success, not an error. Cancelling is what a
    /// client does on its way out, and a session that has already stopped is
    /// the outcome it wanted.
    pub async fn cancel_ping(&mut self, session_seq: u32) -> anyhow::Result<CancelPingResponse> {
        match self
            .request(RequestKind::CancelPing(CancelPingRequest { session_seq }))
            .await?
        {
            ResponseKind::CancelPing(cancelled) => Ok(cancelled),
            other => Err(unexpected("CancelPing", &other)),
        }
    }

    /// Install a whole mesh identity on the node: its seed, its membership
    /// certificate and the mesh trust anchor.
    ///
    /// Pass an empty `seed` to certify the identity the node already has — see
    /// [`install_cert`](Self::install_cert), which is that call named for what
    /// it does.
    ///
    /// `provider` is where the node renews this certificate before it lapses,
    /// and it is installed with the credential rather than configured on the
    /// node. **`None` clears whatever the node had recorded**, which is the
    /// right default for a caller that does not know the authority behind these
    /// bytes: a node that keeps renewing against the provider of a credential it
    /// no longer holds is worse off than one that waits for an operator. A
    /// caller that *does* know — anything that just talked to the provider —
    /// should say so.
    ///
    /// `installer_unix` is **this machine's** clock, and the only way an
    /// absolute time reaches a node that has none of its own (design 20 §4.7).
    /// It is not the issuer's: the certificate may have been minted weeks
    /// earlier and hand-carried, which is the intended out-of-band flow rather
    /// than an edge case. Pass [`stamp_unix`]'s value so a host that cannot
    /// vouch for its own clock sends the fail-closed zero — which drops *this
    /// machine's claim*, not the anchoring: the node takes the maximum of its
    /// current estimate, this value and the verified certificate's own
    /// `not_before`, so a zero simply leaves the CA-signed instant to carry it.
    pub async fn set_auth(
        &mut self,
        seed: &[u8],
        cert: &[u8],
        trust_anchor: &[u8],
        provider: Option<RenewalProvider>,
        installer_unix: u64,
    ) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetAuth(SetAuthRequest {
                seed: seed.to_vec(),
                cert: cert.to_vec(),
                trust_anchor: trust_anchor.to_vec(),
                // Boxed on the wire type (see the protos build script), so the
                // request enum stays small; the box is an encoding detail and
                // does not belong in this signature.
                provider: provider.map(Box::new),
                installer_unix,
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("SetAuth", &other)),
        }
    }

    /// Certify the identity the node already holds: install `cert` and
    /// `trust_anchor` against the node's existing seed, which it keeps, and
    /// record `provider` as where the node renews them.
    ///
    /// This is how a node that enrolled online adopts the certificate it was
    /// issued. Its key — and therefore the MAC its peers know it by — does not
    /// change, so the node becomes a member of the mesh without moving on it.
    /// The certificate must of course be bound to that same key, or the node
    /// will hold a certificate it cannot sign for.
    ///
    /// See [`set_auth`](Self::set_auth) for what a `None` provider means. An
    /// enroller has just spoken to the authority that issued these bytes and is
    /// exactly the caller that can name it.
    ///
    /// `installer_unix` carries this machine's clock, exactly as in
    /// [`set_auth`](Self::set_auth).
    pub async fn install_cert(
        &mut self,
        cert: &[u8],
        trust_anchor: &[u8],
        provider: Option<RenewalProvider>,
        installer_unix: u64,
    ) -> anyhow::Result<()> {
        self.set_auth(&[], cert, trust_anchor, provider, installer_unix)
            .await
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

    /// Provider mode: mint a one-time invitation for `username`.
    ///
    /// The returned token is **shown once**: the authority stores only a hash
    /// of it, so a caller that drops this response has to revoke the invitation
    /// and mint another. It belongs in the *fragment* of the registration URL
    /// (`https://…/register#<token>`) — a fragment never reaches a server, so it
    /// stays out of access logs, out of `Referer`, and out of reach of the link
    /// unfurlers that fetch any URL pasted into a chat app.
    ///
    /// Zero for `session_ttl_secs` or `invite_ttl_secs` takes the authority's
    /// own default.
    pub async fn create_user_invite(
        &mut self,
        username: &str,
        admin: bool,
        session_ttl_secs: u64,
        invite_ttl_secs: u64,
    ) -> anyhow::Result<CreateUserInviteResponse> {
        match self
            .request(RequestKind::CreateUserInvite(CreateUserInviteRequest {
                username: username.to_string(),
                admin,
                session_ttl_secs,
                invite_ttl_secs,
            }))
            .await?
        {
            ResponseKind::CreateUserInvite(resp) => Ok(resp),
            other => Err(unexpected("CreateUserInvite", &other)),
        }
    }

    /// Provider mode: the invitations on file, and the store's capacity.
    ///
    /// The field to read is each invitation's `started_at`: non-zero, with no
    /// account under that name, means somebody took the account's second factor
    /// and did not finish registering.
    pub async fn list_user_invites(&mut self) -> anyhow::Result<ListUserInvitesResponse> {
        match self
            .request(RequestKind::ListUserInvites(ListUserInvitesRequest {}))
            .await?
        {
            ResponseKind::ListUserInvites(resp) => Ok(resp),
            other => Err(unexpected("ListUserInvites", &other)),
        }
    }

    /// Provider mode: delete the invitation minted for `username`, at any
    /// status — including a started one, which is the case this exists for.
    pub async fn revoke_user_invite(&mut self, username: &str) -> anyhow::Result<()> {
        match self
            .request(RequestKind::RevokeUserInvite(RevokeUserInviteRequest {
                username: username.to_string(),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("RevokeUserInvite", &other)),
        }
    }

    /// Provider mode: redeem `token`, revealing the account's second factor and
    /// receiving the handle that alone can finish the registration.
    ///
    /// Runs on the enrollment tier, so this is callable on a connection holding
    /// no certificate at all — which is what somebody who does not have an
    /// account yet is.
    ///
    /// **This spends the invitation.** A caller that loses the returned handle
    /// cannot start again: the token is already gone, and the remedy is a fresh
    /// invitation from an administrator. Hold the handle somewhere a page
    /// refresh survives.
    pub async fn begin_user_registration(
        &mut self,
        token: &str,
    ) -> anyhow::Result<BeginUserRegistrationResponse> {
        match self
            .request(RequestKind::BeginUserRegistration(
                BeginUserRegistrationRequest {
                    token: token.to_string(),
                },
            ))
            .await?
        {
            ResponseKind::BeginUserRegistration(resp) => Ok(resp),
            other => Err(unexpected("BeginUserRegistration", &other)),
        }
    }

    /// Provider mode: finish a registration, creating the account.
    ///
    /// `totp_code` is computed against the secret the start revealed, and
    /// proves the authenticator actually holds it before the account depends on
    /// it. A wrong code is an error and does not spend the handle, so a mistyped
    /// one can simply be retried.
    pub async fn complete_user_registration(
        &mut self,
        handle: &str,
        password: &str,
        totp_code: &str,
    ) -> anyhow::Result<()> {
        match self
            .request(RequestKind::CompleteUserRegistration(
                CompleteUserRegistrationRequest {
                    handle: handle.to_string(),
                    password: password.to_string(),
                    totp_code: totp_code.to_string(),
                },
            ))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("CompleteUserRegistration", &other)),
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

    /// Provider mode: ask for this device's VPN join credential.
    ///
    /// Answered only for a connection carrying *this device's own* membership
    /// certificate — the request has no fields because the identity it mints
    /// for is the connection's. A management session (an operator's login, or
    /// the node's own key) is refused: neither is a device the coordination
    /// server can register.
    ///
    /// A provider with no VPN configured answers with an error saying so, which
    /// is the expected result on every deployment that does not run a tunnel —
    /// callers should treat it as "no VPN here", not as a failure.
    pub async fn get_vpn_enrollment(&mut self) -> anyhow::Result<GetVpnEnrollmentResponse> {
        match self
            .request(RequestKind::GetVpnEnrollment(GetVpnEnrollmentRequest {}))
            .await?
        {
            ResponseKind::VpnEnrollment(resp) => Ok(resp),
            other => Err(unexpected("GetVpnEnrollment", &other)),
        }
    }

    /// Provider mode: list the VPN peers the coordination server knows.
    pub async fn list_vpn_peers(&mut self) -> anyhow::Result<ListVpnPeersResponse> {
        match self
            .request(RequestKind::ListVpnPeers(ListVpnPeersRequest {}))
            .await?
        {
            ResponseKind::ListVpnPeers(resp) => Ok(resp),
            other => Err(unexpected("ListVpnPeers", &other)),
        }
    }

    /// Provider mode: remove a node's VPN registration, leaving its mesh
    /// membership alone.
    ///
    /// Idempotent: a MAC with no registration succeeds. This is the retry for a
    /// `revoke_node` whose VPN half failed.
    pub async fn revoke_vpn_peer(&mut self, node_mac: &[u8]) -> anyhow::Result<()> {
        match self
            .request(RequestKind::RevokeVpnPeer(RevokeVpnPeerRequest {
                node_mac: node_mac.to_vec(),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("RevokeVpnPeer", &other)),
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

    /// Provider mode: remove a user account **and** revoke every session
    /// certificate it holds.
    ///
    /// One act, not two. It used to end only the account's ability to obtain
    /// *new* sessions, leaving every certificate already issued working until it
    /// expired — so deleting a compromised account left the compromise running
    /// for up to that account's whole session lifetime.
    ///
    /// The revocations flood the mesh before this returns. An error naming what
    /// stopped them does **not** mean the removal was undone: the account is
    /// gone and its sessions are marked revoked in the authority's records, and
    /// what failed is the mesh being told.
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

    /// Provider mode: revoke every session certificate an account holds, leaving
    /// the account itself, and report how many were revoked.
    ///
    /// The difference from [`remove_user`](Self::remove_user) is the account:
    /// this ends what it is currently holding and leaves it able to sign in
    /// again. Reach for it when a device is lost and the person still has the
    /// job.
    ///
    /// **Zero is an ordinary success.** An account that has not signed in, or
    /// whose sessions were already revoked or have expired, has nothing left to
    /// end — that is an answer, not a failure to find it. `Err` covers a name
    /// that is not on file.
    pub async fn revoke_user_sessions(&mut self, username: &str) -> anyhow::Result<u32> {
        match self
            .request(RequestKind::RevokeUserSessions(RevokeUserSessionsRequest {
                username: username.to_string(),
            }))
            .await?
        {
            ResponseKind::RevokeUserSessions(r) => Ok(r.revoked),
            other => Err(unexpected("RevokeUserSessions", &other)),
        }
    }

    /// Provider mode: set an account's role, returning how many session
    /// certificates the change revoked and whether it changed anything.
    ///
    /// A demotion revokes the account's live sessions in the same act — the
    /// capability is stamped on the certificate, so an admin session outlives
    /// the account's demotion otherwise. A promotion revokes nothing.
    ///
    /// The second half of the answer is `unchanged`: the account was already in
    /// that role, so nothing was written. Not an error — a caller that states a
    /// role got the account it asked for — but an operator should not be shown a
    /// change that did not happen.
    pub async fn set_user_role(
        &mut self,
        username: &str,
        admin: bool,
    ) -> anyhow::Result<(u32, bool)> {
        match self
            .request(RequestKind::SetUserRole(SetUserRoleRequest {
                username: username.to_string(),
                admin,
            }))
            .await?
        {
            ResponseKind::SetUserRole(r) => Ok((r.revoked, r.unchanged)),
            other => Err(unexpected("SetUserRole", &other)),
        }
    }

    /// Provider mode: enable or disable an account, returning how many session
    /// certificates the change revoked and whether it changed anything.
    ///
    /// Disabling revokes the account's live sessions, so that "disabled" is a
    /// statement about access now rather than only about future sign-ins.
    /// Enabling revokes nothing and clears any lockout.
    pub async fn set_user_enabled(
        &mut self,
        username: &str,
        enabled: bool,
    ) -> anyhow::Result<(u32, bool)> {
        match self
            .request(RequestKind::SetUserEnabled(SetUserEnabledRequest {
                username: username.to_string(),
                enabled,
            }))
            .await?
        {
            ResponseKind::SetUserEnabled(r) => Ok((r.revoked, r.unchanged)),
            other => Err(unexpected("SetUserEnabled", &other)),
        }
    }

    /// Provider mode: replace an account's password, clearing any lockout.
    ///
    /// The administrative reset. It leaves the second factor alone and revokes
    /// nothing; [`Self::revoke_user_sessions`] is the act for a reset that
    /// answers a compromise.
    pub async fn set_user_password(
        &mut self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetUserPassword(SetUserPasswordRequest {
                username: username.to_string(),
                password: password.to_string(),
            }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("SetUserPassword", &other)),
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
    ///
    /// `cert_ttl_secs` is how long that certificate should be valid for, in
    /// seconds; `None` takes the provider's enrollment-policy default. The
    /// provider refuses a lifetime of zero or one past its cap, and leaves the
    /// request pending when it does.
    pub async fn approve_csr(
        &mut self,
        node_mac: &[u8],
        cert_ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self
            .request(RequestKind::ApproveCsr(ApproveCsrRequest {
                node_mac: node_mac.to_vec(),
                cert_ttl_secs,
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
pub async fn probe_node_key(addr: &NodeAddr) -> anyhow::Result<[u8; 32]> {
    // An ephemeral identity: this connection issues no request, so what it
    // presents is never authorized against anything, and minting a throwaway
    // key avoids reaching for a real one to do it.
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);

    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let config = crate::tls::probing_client_config(&seed, seen.clone())
        .map_err(|e| anyhow!("building management TLS probe config: {e}"))?;
    let connector = TlsConnector::from(config);
    let tcp = TcpStream::connect(addr.connect_target())
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
        ResponseKind::Ping(_) => "Ping",
        ResponseKind::PingStatus(_) => "PingStatus",
        ResponseKind::CancelPing(_) => "CancelPing",
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
        ResponseKind::Alarms(_) => "Alarms",
        ResponseKind::LogFilter(_) => "LogFilter",
        ResponseKind::AuthenticateUser(_) => "AuthenticateUser",
        ResponseKind::ListUsers(_) => "ListUsers",
        ResponseKind::CreateUser(_) => "CreateUser",
        ResponseKind::VpnEnrollment(_) => "VpnEnrollment",
        ResponseKind::ListVpnPeers(_) => "ListVpnPeers",
        ResponseKind::CreateUserInvite(_) => "CreateUserInvite",
        ResponseKind::ListUserInvites(_) => "ListUserInvites",
        ResponseKind::RevokeUserSessions(_) => "RevokeUserSessions",
        ResponseKind::SetUserRole(_) => "SetUserRole",
        ResponseKind::SetUserEnabled(_) => "SetUserEnabled",
        ResponseKind::BeginUserRegistration(_) => "BeginUserRegistration",
        ResponseKind::OwnCert(_) => "OwnCert",
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
         was issued by a different mesh root, or binds a MAC that is not the address its own \
         identity key derives (a credential minted before that rule, which must be re-issued)"
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

/// This host's wall clock in unix seconds, ready to stamp onto a node — or the
/// fail-closed **zero** when it cannot be vouched for, together with the
/// verdict that decided it.
///
/// The honesty of the whole anchoring scheme rests on the operator machine's
/// clock (design 20 §4.6), and a node with no clock of its own has no way to
/// second-guess what it is told. Two checks, catching two different wrong
/// clocks and both required:
///
/// * [`ClockSync`] asks whether anything is *disciplining* this clock — the
///   case of a host that booted before NTP reached it, whose reading is
///   plausible and hours out.
/// * [`MIN_PLAUSIBLE_UNIX`] catches a clock that was never set at all, which
///   reads as 1970 and *looks* like a valid instant.
///
/// Either failing yields the same zero, because to the node they are the same
/// fact: there is no usable time here. What the node drops is *this machine's
/// claim* — on a `SetAuth` the anchor is a maximum that still includes the
/// verified certificate's CA-signed `not_before`, so a zero stamp is not the
/// same as leaving the node undated; on a `SetTime`, whose entire content is
/// the claim, it is refused outright. Either way nothing moves the node
/// somewhere wrong, and — because a node with no clock still routes and still
/// verifies credentials (§4.2) — refusing to stamp costs at worst the anchor.
///
/// The verdict is returned alongside so a caller can *say* which it acted on.
/// A correctly-synchronised stock Ubuntu or Fedora machine commonly reads as
/// [`ClockSync::Unsynchronized`] because `chronyd` clears the kernel's
/// `STA_UNSYNC` bit only when its `rtcsync` directive is set, and nothing on an
/// operator's laptop sets it — so a refusal here has to be diagnostic rather
/// than merely a failure.
pub fn stamp_unix(trust: ClockTrust) -> (u64, ClockSync) {
    let sync = wayfinder_clock_trust::read(trust);
    if !sync.is_trusted() {
        return (0, sync);
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        // A system clock before the unix epoch is as unusable as one that was
        // never set, and lands in the same place.
        .unwrap_or(0);
    if secs < MIN_PLAUSIBLE_UNIX {
        (0, sync)
    } else {
        (secs, sync)
    }
}

impl Client {
    /// Anchor the node's wall clock at `installer_unix`, without re-issuing its
    /// certificate.
    ///
    /// The maintenance half of the same value `set_auth` carries: a board
    /// free-running on an internal RC oscillator drifts about 20 seconds a day,
    /// and one that lost its persisted checkpoint comes up with no estimate at
    /// all. Both are local, and making them go through the certificate
    /// authority would make it a participant in something it has no part in
    /// (design 20 §4.7).
    ///
    /// Pass [`stamp_unix`]'s value, not a raw host reading: a zero is the
    /// fail-closed stamp and the node leaves its estimate alone.
    pub async fn set_time(&mut self, installer_unix: u64) -> anyhow::Result<()> {
        match self
            .request(RequestKind::SetTime(SetTimeRequest { installer_unix }))
            .await?
        {
            ResponseKind::Empty(_) => Ok(()),
            other => Err(unexpected("SetTime", &other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **An untrusted clock yields a stamp of zero, not a host reading.**
    ///
    /// The whole of the client half of design 20 §4.6: a node with no clock of
    /// its own cannot second-guess the time it is handed, so a host that cannot
    /// vouch for its own must hand over nothing rather than its best guess.
    /// Zero is the value every credential path already refuses, so an old
    /// client and an undisciplined one fail the same way.
    #[test]
    fn an_untrusted_clock_stamps_zero() {
        let (stamp, sync) = stamp_unix(ClockTrust::Never);
        assert_eq!(stamp, 0, "verdict was {}", sync.name());
    }

    /// The opt-out reaches the host reading, which is what makes it an opt-out
    /// rather than a no-op — and the reading is past the plausibility floor on
    /// any machine that can build this.
    #[test]
    fn assuming_trust_stamps_the_host_reading() {
        let (stamp, _) = stamp_unix(ClockTrust::Assume);
        assert!(
            stamp >= wayfinder_auth::MIN_PLAUSIBLE_UNIX,
            "the build machine's clock reads before 2025: {stamp}"
        );
    }

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

/// A node's well-formed refusal of a request, as distinct from a transport or
/// decode failure.
///
/// The two need telling apart by anything that reacts to an error by dropping
/// the connection. A `ServerError` arrives *on a healthy stream* — the frame was
/// sent, a reply was read, and it said no — so the connection is fine and
/// reconnecting would achieve nothing. Anything else means the stream is
/// suspect and the client should be rebuilt.
///
/// That distinction used to be drawn by testing the rendered message for a
/// `"server error: "` prefix, which is a contract nothing enforced. The
/// [`Display`](fmt::Display) impl still renders exactly that prefix, so existing
/// message-matching callers are unaffected, but new code should
/// `downcast_ref::<ServerError>()` instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerError {
    /// The message the node sent. Deliberately the node's own wording: a
    /// refusal explains itself, and rephrasing it here would lose that.
    pub message: String,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server error: {}", self.message)
    }
}

impl std::error::Error for ServerError {}
