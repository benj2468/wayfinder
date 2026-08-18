//! The management-API transport: the authenticated TLS listener loop, the
//! in-process channel server, and the query channel the event loop services.
//!
//! Queries are forwarded to the main loop over a channel so the router is never
//! shared across tasks. This module requires the `std` feature.

use std::net::SocketAddr;

use bytes::Bytes;
use futures::SinkExt;
use futures::StreamExt;
use prost::Message;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;
use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder_protos::wayfinder::v1alpha::Empty;
use wayfinder_protos::wayfinder::v1alpha::ErrorResponse;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;
use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as RespKind;

use crate::MgmtAccess;
use crate::decide_access;

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

/// The router state a management connection is authorized against, snapshotted
/// once when the connection authenticates.
///
/// The serve task must not touch the router directly (it lives on another task),
/// so the router's auth-relevant state is projected into this value and the serve
/// task evaluates [`decide_access`] locally against it. Snapshotting at
/// connect time means a connection's authorization reflects the mesh state when
/// it opened.
pub struct AuthContext {
    /// The node's own Ed25519 identity key, for the bootstrap comparison
    /// (un-enrolled admission requires the handshake key to equal this).
    pub own_key: [u8; 32],
    /// The installed trust anchor, or `None` when the node is un-enrolled
    /// (bootstrap mode — self-key admission only).
    pub anchor: Option<TrustAnchor>,
    /// Node MACs with an active revocation as of the snapshot instant.
    pub revoked: Vec<Mac>,
    /// Current unix time (seconds), for certificate validity checks.
    pub now_unix: u64,
}

/// Encode and send one [`WayfinderResponse`] over the framed connection.
async fn send_response<S>(
    framed: &mut Framed<S, LengthDelimitedCodec>,
    response: RespKind,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let envelope = WayfinderResponse {
        response: Some(response),
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf)?;
    framed.send(Bytes::from(buf)).await?;
    Ok(())
}

/// Burst capacity for [`EnrollmentLimiter`]: a handful of submissions before
/// the rate limit engages, so a node's first genuine `SubmitCsr` (and a quick
/// retry or two) is never throttled.
const SUBMIT_CSR_BURST: f64 = 5.0;

/// Steady-state refill for [`EnrollmentLimiter`]: one token every 5 seconds —
/// matching `APPROVAL_POLL` in `bins/wayfinder-web/src/components/security.rs`,
/// the enrollment panel's re-submission cadence while a request is held for
/// approval, so a legitimate node polling indefinitely is never throttled at
/// steady state.
const SUBMIT_CSR_REFILL_PER_SEC: f64 = 1.0 / 5.0;

/// Distinct source addresses [`EnrollmentLimiter`] tracks at once. Past this,
/// the least-recently-touched bucket is evicted to make room for a new
/// source — safe to evict (unlike the held-CSR store this sits in front of):
/// the evicted source simply starts over with a full bucket, which is never
/// worse for it than being tracked, so eviction here hands an attacker
/// nothing. Bounding the map itself is still required, or an attacker with
/// many source addresses reproduces the exact unbounded-anonymous-growth
/// problem this limiter exists to bound.
const MAX_TRACKED_SOURCES: usize = 1024;

/// A token bucket for one source address: `tokens` refill continuously at
/// [`SUBMIT_CSR_REFILL_PER_SEC`] up to [`SUBMIT_CSR_BURST`], and a
/// [`SubmitCsr`](ReqKind::SubmitCsr) invocation costs one.
struct TokenBucket {
    tokens: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(now: std::time::Instant) -> Self {
        Self {
            tokens: SUBMIT_CSR_BURST,
            last_refill: now,
        }
    }

    /// Refill for elapsed time since the last touch, then attempt to spend
    /// one token. `true` ⇒ spent (the caller may proceed); `false` ⇒ empty
    /// (the caller must wait).
    fn try_consume(&mut self, now: std::time::Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * SUBMIT_CSR_REFILL_PER_SEC).min(SUBMIT_CSR_BURST);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-source rate limit on the enrollment tier's `SubmitCsr`, layered in
/// front of `authority.rs`'s `MAX_HELD_CSRS` count bound.
///
/// The two bounds are complementary, not redundant: the count cap stops the
/// held-CSR store from growing past a fixed size no matter how many distinct
/// sources contribute to it, but says nothing about how fast any *one*
/// source may contribute — which is what actually protects a legitimate
/// node's enrollment from being crowded out by a single flooding peer, and
/// what keeps that peer from burning through the shared cap on its own.
///
/// Keyed by IP, not the full socket address: a legitimate client opens a
/// fresh connection (and so a fresh ephemeral port) on every poll — see
/// `SUBMIT_CSR_REFILL_PER_SEC` — so keying by port as well would give every
/// poll its own untouched bucket and defeat the limiter entirely.
pub(crate) struct EnrollmentLimiter {
    buckets: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, TokenBucket>>,
}

impl Default for EnrollmentLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl EnrollmentLimiter {
    /// A fresh limiter with no sources tracked yet.
    fn new() -> Self {
        Self {
            buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Whether a `SubmitCsr` from `addr` may proceed right now. Consumes a
    /// token from `addr`'s bucket on success; a source with no bucket yet
    /// starts at full burst capacity.
    fn allow_submit_csr(&self, addr: std::net::IpAddr, now: std::time::Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| {
            // A poisoned lock here means an earlier call panicked while
            // holding it — recovering rather than propagating keeps this
            // connection's request from taking the whole listener down, but
            // that earlier panic is a real bug and must not vanish silently.
            tracing::error!(
                "enrollment rate-limiter mutex poisoned; recovering with last-known state"
            );
            e.into_inner()
        });
        if !buckets.contains_key(&addr) && buckets.len() >= MAX_TRACKED_SOURCES {
            // Evict whichever bucket was touched longest ago to make room —
            // see the type's doc for why this is safe.
            if let Some(&oldest) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_refill)
                .map(|(addr, _)| addr)
            {
                buckets.remove(&oldest);
            }
        }
        buckets
            .entry(addr)
            .or_insert_with(|| TokenBucket::new(now))
            .try_consume(now)
    }
}

/// Serve one already-TLS-authenticated management connection.
///
/// `peer_key` is the client's Ed25519 raw public key that the TLS handshake
/// proved possession of (RFC 7250). `peer_addr` is its IP, consulted only to
/// rate-limit `SubmitCsr` on an enrollment-tier (anonymous) connection — see
/// [`EnrollmentLimiter`]. The first frame must be an
/// [`AuthenticateRequest`](wayfinder_protos::wayfinder::v1alpha::AuthenticateRequest)
/// carrying the client's membership cert (empty on an un-enrolled node); it is
/// bound to `peer_key` and checked by [`decide_access`] against `ctx`. A grant
/// is acknowledged with an [`Empty`] response (which the client waits on) before
/// the normal request/response loop runs; a denial is answered with a generic
/// [`ErrorResponse`] and the connection closed.
///
/// Transport-agnostic over `S` so it serves a real `TlsStream` in production and
/// an in-memory duplex in tests — the TLS handshake itself is exercised
/// separately in [`crate::tls`].
pub(crate) async fn serve_authenticated_stream<S>(
    stream: S,
    peer_key: [u8; 32],
    peer_addr: std::net::IpAddr,
    limiter: std::sync::Arc<EnrollmentLimiter>,
    ctx: AuthContext,
    query_tx: QueryTx,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed: Framed<S, LengthDelimitedCodec> =
        LengthDelimitedCodec::builder().new_framed(stream);

    // The connection must authenticate before anything else.
    let Some(frame) = framed.next().await else {
        // Client disconnected before authenticating; nothing to serve.
        return Ok(());
    };
    // A framing or protobuf-decode failure on the very first frame is arbitrary
    // remote input (the peer need only complete the RPK handshake to reach
    // here), so drop it at trace rather than escalating to the connection-error
    // warn! — a malformed packet must not flood the logs.
    let frame = match frame {
        Ok(frame) => frame,
        Err(e) => {
            tracing::trace!(error = ?e, "drop: management framing error before auth");
            return Ok(());
        }
    };
    let request = match WayfinderRequest::decode(frame) {
        Ok(request) => request,
        Err(e) => {
            tracing::trace!(error = ?e, "drop: malformed first management frame");
            return Ok(());
        }
    };
    let cert_bytes = match request.request {
        Some(ReqKind::Authenticate(auth)) => auth.cert,
        _ => {
            send_response(
                &mut framed,
                RespKind::Error(ErrorResponse {
                    message: "first message on a management connection must be Authenticate".into(),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    // An empty cert means "bootstrap" (no membership cert yet); non-empty must
    // parse, else the connection is refused rather than served.
    let cert = if cert_bytes.is_empty() {
        None
    } else {
        match MembershipCert::from_bytes(&cert_bytes) {
            Some(cert) => Some(cert),
            None => {
                send_response(
                    &mut framed,
                    RespKind::Error(ErrorResponse {
                        message: "malformed membership certificate".into(),
                    }),
                )
                .await?;
                return Ok(());
            }
        }
    };

    let decision = decide_access(
        &peer_key,
        cert.as_ref(),
        ctx.anchor.as_ref(),
        &ctx.own_key,
        ctx.now_unix,
        |mac| ctx.revoked.contains(&mac),
    );
    if let MgmtAccess::Denied(reason) = decision {
        // A rejected management login is security-relevant and worth an
        // operator's attention, but is remotely triggerable, so cap it at warn.
        // The precise `reason` stays in this local log only: a generic message
        // goes over the wire so a not-yet-authenticated peer can't use the
        // response as an oracle (wrong-key vs revoked vs expired vs not-admin)
        // while probing with a stolen or revoked cert.
        tracing::warn!(?reason, "drop: management authentication denied");
        send_response(
            &mut framed,
            RespKind::Error(ErrorResponse {
                message: "authentication denied".into(),
            }),
        )
        .await?;
        return Ok(());
    }
    tracing::debug!(?decision, "management connection authenticated");
    // Acknowledge a successful authentication before serving requests.
    send_response(&mut framed, RespKind::Empty(Empty {})).await?;

    // Authenticated: serve requests until the peer hangs up.
    while let Some(frame) = framed.next().await {
        let request = WayfinderRequest::decode(frame?)?;
        // An enrollment-only connection may invoke just the enrollment
        // requests; anything else is refused here rather than reaching the
        // router. Unlike the connection-level denial above, the reason *is*
        // sent: this peer is admitted and the answer tells it nothing it could
        // not learn by trying, while a client that is merely misconfigured (an
        // admin identity that forgot its certificate) otherwise sees every
        // request fail with nothing to explain why.
        // The gate is total: a request this build cannot classify is refused,
        // not waved through. `permits` fails closed on a request kind it does
        // not know, and an absent oneof — what prost yields for a field number
        // added after this build — must fail closed the same way rather than
        // reach the router unexamined.
        let Some(req) = request.request.as_ref() else {
            tracing::warn!(
                key = ?peer_key,
                "drop: management request naming no request kind"
            );
            send_response(
                &mut framed,
                RespKind::Error(ErrorResponse {
                    message: "empty or unrecognised request".into(),
                }),
            )
            .await?;
            continue;
        };
        if !crate::authz::permits(decision, req) {
            // Security-relevant, and reachable by a party that presented no
            // certificate, so it is the operator's business that someone is
            // probing: `warn!`, with who and what, not `debug!`.
            tracing::warn!(
                key = ?peer_key,
                ?decision,
                "drop: request not permitted on this connection"
            );
            send_response(
                &mut framed,
                RespKind::Error(ErrorResponse {
                    message: "this connection is limited to enrollment (no admin \
                              certificate was verified on it); everything else needs an \
                              admin certificate or the node's own key"
                        .into(),
                }),
            )
            .await?;
            continue;
        }
        // A rate limit, not an admission decision: only the enrollment tier
        // is bounded, since a fully-granted connection already required a
        // real credential (an admin cert or the node's own key), which is
        // not the resource an anonymous flood is spending. See
        // `EnrollmentLimiter`.
        if matches!(decision, MgmtAccess::GrantedEnrollment)
            && matches!(req, ReqKind::SubmitCsr(_))
            && !limiter.allow_submit_csr(peer_addr, std::time::Instant::now())
        {
            tracing::warn!(
                key = ?peer_key,
                %peer_addr,
                "drop: enrollment-tier SubmitCsr rate limit exceeded"
            );
            send_response(
                &mut framed,
                RespKind::Error(ErrorResponse {
                    message: "too many enrollment requests from this source; wait before \
                              retrying"
                        .into(),
                }),
            )
            .await?;
            continue;
        }
        let (resp_tx, resp_rx) = oneshot::channel();
        query_tx.send((request, resp_tx)).await?;
        let response = resp_rx.await?;
        let mut buf = Vec::new();
        response.encode(&mut buf)?;
        framed.send(Bytes::from(buf)).await?;
    }
    Ok(())
}

/// The router-owned half of an [`AuthContext`]: the auth state the TLS accept
/// loop must read from the router (which lives on another task) to authorize a
/// connection. The clock is supplied by the accept loop itself (the system
/// clock); everything else here — including `own_key` — is read fresh from the
/// router loop on *every* connection rather than cached once.
///
/// `own_key` in particular must not be cached: it can change at runtime (a
/// `SetAuth` installing a new identity seed), and a connection presenting a
/// seed the node has since rotated away from must not keep getting
/// [`MgmtAccess::GrantedSelfKey`](crate::MgmtAccess::GrantedSelfKey) just
/// because the accept loop remembered an older value. Reading it fresh here,
/// the same way `anchor`/`revoked` already are, closes that window on the very
/// next connection rather than only at the next restart.
pub struct AuthSnapshot {
    /// This node's current management identity key — the handshake key that
    /// earns [`MgmtAccess::GrantedSelfKey`](crate::MgmtAccess::GrantedSelfKey).
    pub own_key: [u8; 32],
    /// The installed trust anchor, or `None` when the node is un-enrolled.
    pub anchor: Option<TrustAnchor>,
    /// Node MACs with an active revocation.
    pub revoked: Vec<Mac>,
}

/// Sender the TLS accept loop uses to ask the router loop for an
/// [`AuthSnapshot`]; the router replies on the enclosed one-shot.
pub type AuthSnapshotTx = mpsc::Sender<oneshot::Sender<AuthSnapshot>>;
/// Receiver half, serviced by the router event loop alongside [`QueryRx`].
pub type AuthSnapshotRx = mpsc::Receiver<oneshot::Sender<AuthSnapshot>>;

/// Current unix time in seconds, for certificate validity checks on the host.
///
/// Errors (rather than defaulting) if the host clock is before the Unix epoch:
/// `0` is the most-permissive value for a `not_after` comparison, so silently
/// substituting it would let an *expired* admin cert pass the expiry gate on a
/// mis-set clock. Failing here closes the connection instead — fail-closed.
fn now_unix() -> anyhow::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| {
            anyhow::anyhow!("system clock is before the Unix epoch; refusing to authorize: {e}")
        })
}

/// Accept TLS management connections on `listener`, authenticate each by its
/// RFC 7250 raw public key, and serve authorized ones.
///
/// The node presents `own_seed`'s Ed25519 key as its TLS identity; each client
/// presents its own raw key, which the handshake proves possession of. Per
/// connection the loop reads that key, snapshots the router's auth state via
/// `snapshot_tx`, and hands both to [`serve_authenticated_stream`], which makes
/// the [`decide_access`] decision. `own_seed` must be the node's persistent
/// identity seed and exists even before enrollment (bootstrap presents it).
///
/// `own_seed` here only builds the TLS identity this listener presents (fixed
/// for the listener's lifetime — rebuilding the TLS acceptor at runtime is a
/// separate concern from this fix). The comparison value for the *self-key*
/// grant is a different thing: it comes from the per-connection snapshot
/// (`AuthSnapshot::own_key`), not from `own_seed`, precisely so it tracks a
/// `SetAuth`-installed identity change without needing this listener to
/// restart.
pub async fn serve_tls_server(
    listener: TcpListener,
    own_seed: [u8; 32],
    snapshot_tx: AuthSnapshotTx,
    query_tx: QueryTx,
) -> anyhow::Result<()> {
    let config = crate::server_config(&own_seed)
        .map_err(|e| anyhow::anyhow!("building management TLS server config: {e}"))?;
    let acceptor = TlsAcceptor::from(config);
    // One limiter for the whole listener's lifetime, shared across every
    // spawned connection — a per-connection limiter would track nothing,
    // since the enrollment flow opens a fresh connection on every poll.
    let limiter = std::sync::Arc::new(EnrollmentLimiter::new());

    loop {
        let (tcp, peer) = listener.accept().await?;
        tracing::debug!(%peer, "management TLS connection accepted");
        let acceptor = acceptor.clone();
        let snapshot_tx = snapshot_tx.clone();
        let query_tx = query_tx.clone();
        let limiter = std::sync::Arc::clone(&limiter);
        tokio::spawn(async move {
            if let Err(e) =
                serve_tls_connection(acceptor, tcp, peer, snapshot_tx, query_tx, limiter).await
            {
                tracing::warn!(%peer, error = ?e, "management TLS connection error");
            }
        });
    }
}

/// Complete the TLS handshake, recover the client's raw public key, snapshot the
/// router's auth state, and serve the connection.
async fn serve_tls_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    snapshot_tx: AuthSnapshotTx,
    query_tx: QueryTx,
    limiter: std::sync::Arc<EnrollmentLimiter>,
) -> anyhow::Result<()> {
    let tls = acceptor.accept(tcp).await?;

    // Recover the client's Ed25519 identity from the raw public key it presented
    // in the handshake (which TLS just proved it holds the private half of).
    let peer_key = {
        let (_io, conn) = tls.get_ref();
        let spki = conn
            .peer_certificates()
            .and_then(<[_]>::first)
            .ok_or_else(|| anyhow::anyhow!("client presented no raw public key"))?;
        wayfinder_tls_mgmt::raw_ed25519_from_spki(spki.as_ref())
            .ok_or_else(|| anyhow::anyhow!("client key is not a raw Ed25519 public key"))?
    };

    // Snapshot the router's current auth state (own key + anchor + revocations).
    let (reply_tx, reply_rx) = oneshot::channel();
    snapshot_tx
        .send(reply_tx)
        .await
        .map_err(|_| anyhow::anyhow!("router loop unavailable for auth snapshot"))?;
    let snapshot = reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("router loop dropped the auth-snapshot request"))?;

    let ctx = AuthContext {
        own_key: snapshot.own_key,
        anchor: snapshot.anchor,
        revoked: snapshot.revoked,
        now_unix: now_unix()?,
    };
    serve_authenticated_stream(tls, peer_key, peer.ip(), limiter, ctx, query_tx).await
}

/// Bind the TCP listener the TLS management server accepts on, without serving
/// it.
///
/// Split out from [`serve_tls_server`] so a caller can bind every configured
/// listener up front -- surfacing a bind failure (e.g. address in use)
/// synchronously -- before spawning the accept loops and declaring itself
/// ready.
pub async fn bind_tcp_server(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("management API listening on TCP {addr}");
    Ok(listener)
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

/// Serve the management API over an in-process mpsc channel.
///
/// Mirrors the socket listeners but carries already-/still-encoded protobuf
/// bytes over a channel instead of a kernel transport, so a caller in the same
/// process (the integration tests) can exercise the full encode → forward →
/// decode path without binding a socket.  Each request is a `(bytes, reply)`
/// pair; the encoded response is sent back on `reply`.
pub async fn run_channel_server(mut rx: ChannelServerRx, query_tx: QueryTx) -> anyhow::Result<()> {
    while let Some((request, reply)) = rx.recv().await {
        // A caller that sends a malformed request must not take down the loop
        // for everyone else queued behind it.
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpStream;
    use tokio::sync::mpsc;
    use wayfinder::wayfinder_auth::Keypair;
    use wayfinder_protos::wayfinder::v1alpha::AuthenticateRequest;
    use wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest;
    use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
    use wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest;
    use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
    use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
    use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request;
    use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response;

    use super::*;

    /// A free TCP port on loopback, picked by asking the OS for one and
    /// releasing it immediately.
    fn free_tcp_addr() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    // These tests specify the bind/serve split needed so a caller (e.g.
    // `wayfinder-tap`'s `main`) can bind every listener synchronously, up
    // front, and only afterwards spawn the accept loops and signal readiness
    // -- rather than binding as a side effect of a spawned task, which races
    // readiness against the socket actually being live.

    #[tokio::test]
    async fn bind_tcp_server_accepts_before_any_serve_loop_runs() {
        let addr = free_tcp_addr();
        let _listener = bind_tcp_server(addr)
            .await
            .expect("bind must succeed on a free port");

        // The socket is already in LISTEN state at the OS level as soon as
        // `bind_tcp_server` returns -- no accept loop has been spawned yet, and
        // none is needed for the kernel to accept the connection into its
        // backlog.
        tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr))
            .await
            .expect("connect must not time out")
            .expect("connect must succeed against an already-bound listener");
    }

    #[tokio::test]
    async fn bind_tcp_server_reports_port_conflict_synchronously() {
        let addr = free_tcp_addr();
        let _held = std::net::TcpListener::bind(addr).unwrap();

        // The whole point of separating bind from serve: a conflict is
        // visible to the caller as soon as `bind_tcp_server` returns, not
        // only later when a spawned serve-loop future happens to be polled.
        assert!(bind_tcp_server(addr).await.is_err());
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
                        auth_locked: false,
                        runtime_config_active: false,
                    })),
                };
                let _ = resp_tx.send(response);
            }
        });
    }

    /// Encode a `WayfinderRequest` into a length-delimited frame payload.
    fn encode_request(request: Request) -> Bytes {
        let envelope = WayfinderRequest {
            request: Some(request),
        };
        let mut buf = Vec::new();
        envelope.encode(&mut buf).unwrap();
        Bytes::from(buf)
    }

    /// Drive `serve_authenticated_stream` over an in-memory duplex, returning a
    /// framed client handle and the server task's join handle.
    fn spawn_authenticated_server(
        peer_key: [u8; 32],
        ctx: AuthContext,
    ) -> (
        Framed<tokio::io::DuplexStream, LengthDelimitedCodec>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let peer_addr = std::net::Ipv4Addr::LOCALHOST.into();
        let limiter = std::sync::Arc::new(EnrollmentLimiter::new());
        let server = tokio::spawn(serve_authenticated_stream(
            server_io, peer_key, peer_addr, limiter, ctx, query_tx,
        ));
        (
            LengthDelimitedCodec::builder().new_framed(client_io),
            server,
        )
    }

    /// On an un-enrolled node, a client that proves the node's own key
    /// (bootstrap) is granted, then its subsequent requests are served.
    #[tokio::test]
    async fn authenticated_stream_bootstrap_grants_then_serves() {
        let key = [5u8; 32];
        let ctx = AuthContext {
            own_key: key, // bootstrap: handshake key equals the node's own key
            anchor: None, // un-enrolled
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(key, ctx);

        // Authenticate with an empty cert (bootstrap).
        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(ack.response, Some(Response::Empty(_))),
            "bootstrap authentication is acknowledged with Empty"
        );

        // A normal request is now served.
        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp.response, Some(Response::NodeInfo(_))));

        drop(client);
        let _ = server.await;
    }

    /// A request naming no request kind is refused rather than forwarded.
    ///
    /// This is the gate's fail-closed edge, and it is not hypothetical: an
    /// absent `oneof` is exactly what prost yields for a field number added
    /// after this build, so a newer client's unknown request reaches an older
    /// node looking like this. Forwarding it would be an authorization decision
    /// never taken — `permits` fails closed on a request kind it does not know,
    /// and it can only do that if it is asked.
    #[tokio::test]
    async fn a_request_naming_no_kind_is_refused_not_forwarded() {
        let ctx = AuthContext {
            own_key: [1u8; 32],
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server([2u8; 32], ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(Response::Empty(_))));

        // An envelope with no request inside it.
        let mut buf = Vec::new();
        WayfinderRequest { request: None }.encode(&mut buf).unwrap();
        client.send(Bytes::from(buf)).await.unwrap();

        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => assert!(
                e.message.contains("unrecognised"),
                "refused by the gate, not answered by the router: {}",
                e.message
            ),
            other => panic!("expected an error response, got {other:?}"),
        }

        drop(client);
        let _ = server.await;
    }

    /// A client that presents no membership cert is admitted — that is how a
    /// node with nothing yet submits the CSR that enrolls it — but the grant is
    /// enforced per request: an ordinary read is refused, with a message saying
    /// why, and the connection stays open for the enrollment it *may* do.
    #[tokio::test]
    async fn authenticated_stream_confines_a_stranger_to_enrollment() {
        let ctx = AuthContext {
            own_key: [1u8; 32],
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server([2u8; 32], ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(ack.response, Some(Response::Empty(_))),
            "an enrollment connection is acknowledged like any other"
        );

        // Anything but enrollment is refused, and says so rather than leaving a
        // misconfigured client to guess.
        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => assert!(
                e.message.contains("limited to enrollment"),
                "got: {}",
                e.message
            ),
            other => panic!("expected an error response, got {other:?}"),
        }

        // Still open: the refusal is of one request, not of the connection.
        client
            .send(encode_request(Request::SubmitCsr(
                SubmitCsrRequest::default(),
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            !matches!(&resp.response, Some(Response::Error(e)) if e.message.contains("limited to enrollment")),
            "SubmitCsr is the request an enrollment connection exists to make"
        );

        drop(client);
        let _ = server.await;
    }

    /// Looping `SubmitCsr` on the enrollment tier is rate-limited per source:
    /// a legitimate node's first handful of submissions are forwarded, and
    /// repeating past the burst capacity is refused by the gate rather than
    /// reaching the router. This bounds *how fast* one source may contribute
    /// to `authority.rs`'s held-CSR store; the store's own `MAX_HELD_CSRS`
    /// bounds how large it may grow overall — the two are complementary, and
    /// this test only exercises the rate half.
    #[tokio::test]
    async fn submit_csr_on_the_enrollment_tier_is_rate_limited_per_source() {
        let ctx = AuthContext {
            own_key: [1u8; 32], // un-enrolled ⇒ every other key is GrantedEnrollment
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server([2u8; 32], ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(Response::Empty(_))));

        // The burst capacity's worth of submissions are all forwarded (the
        // echo handler answers any forwarded query with a canned `NodeInfo`
        // — what's under test is whether the gate forwards the request at
        // all, not what comes back).
        for n in 0..SUBMIT_CSR_BURST as u32 {
            client
                .send(encode_request(Request::SubmitCsr(
                    SubmitCsrRequest::default(),
                )))
                .await
                .unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            assert!(
                !matches!(&resp.response, Some(Response::Error(e)) if e.message.contains("too many")),
                "submission {n} of the burst capacity was throttled early"
            );
        }

        // One more, immediately after exhausting the burst: refused.
        client
            .send(encode_request(Request::SubmitCsr(
                SubmitCsrRequest::default(),
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => {
                assert!(e.message.contains("too many"), "got: {}", e.message)
            }
            other => panic!("expected the rate limit to refuse this request, got {other:?}"),
        }

        // Still open: a rate-limit refusal is of one request, like every
        // other per-request refusal on this connection.
        client
            .send(encode_request(Request::GetTrustAnchor(
                wayfinder_protos::wayfinder::v1alpha::GetTrustAnchorRequest {},
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            !matches!(&resp.response, Some(Response::Error(_))),
            "GetTrustAnchor is not itself rate-limited"
        );

        drop(client);
        let _ = server.await;
    }

    /// The rate limit is genuinely per-*source*, proven through the real
    /// listener rather than by calling `EnrollmentLimiter` directly: a source
    /// that exhausts its burst does not throttle a second source connecting
    /// from a different address to the same listener. Loopback carries more
    /// than one address (`127.0.0.2` etc.), so this dials two real TCP
    /// connections from two different local addresses rather than trusting
    /// that isolation holds just because the data structure is keyed by
    /// `IpAddr` — the property that matters is that `peer.ip()` at the
    /// accept loop (`serve_tls_connection`) actually reaches the limiter
    /// keyed correctly, not just that the bucket type can do it in theory.
    #[tokio::test]
    async fn submit_csr_rate_limit_is_isolated_per_source_over_real_connections() {
        use tokio_rustls::TlsConnector;

        let server_seed = [7u8; 32];
        let server_key = Keypair::from_seed(&server_seed).ed_pubkey();

        let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<oneshot::Sender<AuthSnapshot>>(4);
        tokio::spawn(async move {
            while let Some(reply) = snapshot_rx.recv().await {
                let _ = reply.send(AuthSnapshot {
                    own_key: server_key,
                    anchor: None,
                    revoked: Vec::new(),
                });
            }
        });
        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tls_server(
            listener,
            server_seed,
            snapshot_tx,
            query_tx,
        ));

        async fn connect_and_submit_csr(
            server_addr: SocketAddr,
            server_key: [u8; 32],
            local_addr: std::net::IpAddr,
            count: u32,
        ) -> WayfinderResponse {
            let connector = TlsConnector::from(crate::tls::test_support::test_client_config(
                &[8u8; 32],
                &server_key,
            ));
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind((local_addr, 0).into()).unwrap();
            let tcp = socket.connect(server_addr).await.unwrap();
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let tls = connector.connect(server_name, tcp).await.unwrap();
            let mut client = LengthDelimitedCodec::builder().new_framed(tls);

            client
                .send(encode_request(Request::Authenticate(AuthenticateRequest {
                    cert: Vec::new(),
                })))
                .await
                .unwrap();
            client.next().await.unwrap().unwrap(); // the auth ack

            let mut last = None;
            for _ in 0..count {
                client
                    .send(encode_request(Request::SubmitCsr(
                        SubmitCsrRequest::default(),
                    )))
                    .await
                    .unwrap();
                last =
                    Some(WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap());
            }
            last.unwrap()
        }

        // Source A spends its entire burst, then one more: refused.
        let refused = connect_and_submit_csr(
            addr,
            server_key,
            std::net::Ipv4Addr::LOCALHOST.into(),
            SUBMIT_CSR_BURST as u32 + 1,
        )
        .await;
        match refused.response {
            Some(Response::Error(e)) => {
                assert!(e.message.contains("too many"), "got: {}", e.message)
            }
            other => panic!("expected source A's burst+1 to be refused, got {other:?}"),
        }

        // Source B, a different local address, connects fresh and its first
        // submission succeeds immediately — untouched by source A's flood.
        let admitted = connect_and_submit_csr(
            addr,
            server_key,
            std::net::Ipv4Addr::new(127, 0, 0, 2).into(),
            1,
        )
        .await;
        assert!(
            !matches!(&admitted.response, Some(Response::Error(e)) if e.message.contains("too many")),
            "a different source must not inherit another source's exhausted burst, got {:?}",
            admitted.response
        );
    }

    /// A fully-granted connection (admin or self-key) is exempt from the
    /// enrollment-tier rate limit: `EnrollmentLimiter` gates `SubmitCsr` only
    /// for `GrantedEnrollment`, so an admin enrolling many nodes on their
    /// behalf in quick succession — the very capability §3.1's
    /// proof-of-possession option was declined to preserve — is never
    /// throttled by it.
    #[tokio::test]
    async fn submit_csr_is_not_rate_limited_on_a_fully_granted_connection() {
        let ctx = AuthContext {
            own_key: [1u8; 32],
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        // The connection's own key: self-key/bootstrap, a full grant.
        let (mut client, server) = spawn_authenticated_server([1u8; 32], ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(Response::Empty(_))));

        for n in 0..(SUBMIT_CSR_BURST as u32 + 5) {
            client
                .send(encode_request(Request::SubmitCsr(
                    SubmitCsrRequest::default(),
                )))
                .await
                .unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            assert!(
                !matches!(&resp.response, Some(Response::Error(e)) if e.message.contains("too many")),
                "submission {n}, past what an enrollment-tier connection's burst would allow, was throttled on a full grant"
            );
        }

        drop(client);
        let _ = server.await;
    }

    /// A token bucket bursts to capacity, throttles once spent, tracks
    /// sources independently, and recovers after enough elapsed time for a
    /// refill — using synthetic instants so the test runs instantly rather
    /// than waiting on the real clock.
    #[test]
    fn enrollment_limiter_bursts_then_throttles_then_recovers() {
        let limiter = EnrollmentLimiter::new();
        let addr: std::net::IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
        let t0 = std::time::Instant::now();

        for n in 0..SUBMIT_CSR_BURST as u32 {
            assert!(limiter.allow_submit_csr(addr, t0), "burst slot {n}");
        }
        assert!(
            !limiter.allow_submit_csr(addr, t0),
            "burst capacity is exhausted"
        );

        // A different source has its own, untouched bucket.
        let other: std::net::IpAddr = std::net::Ipv4Addr::new(127, 0, 0, 2).into();
        assert!(limiter.allow_submit_csr(other, t0));

        // Enough elapsed time for exactly one refill: one more is allowed,
        // and only one.
        let t1 = t0 + std::time::Duration::from_secs_f64(1.0 / SUBMIT_CSR_REFILL_PER_SEC);
        assert!(limiter.allow_submit_csr(addr, t1));
        assert!(!limiter.allow_submit_csr(addr, t1));
    }

    /// The map backing the limiter is itself bounded: past
    /// `MAX_TRACKED_SOURCES` distinct addresses, tracking a new one evicts
    /// the least-recently-touched bucket rather than growing further —
    /// otherwise an attacker with many source addresses reproduces the exact
    /// unbounded-anonymous-growth problem this limiter exists to bound.
    #[test]
    fn enrollment_limiter_bounds_the_number_of_tracked_sources() {
        let limiter = EnrollmentLimiter::new();
        let t0 = std::time::Instant::now();
        let addr = |n: u32| std::net::IpAddr::from(std::net::Ipv4Addr::from(n));

        for n in 0..MAX_TRACKED_SOURCES as u32 {
            // Space each touch out in time so "least recently touched" is
            // unambiguous, and consume the full burst so a later re-touch of
            // the same address doesn't look like a fresh one.
            let t = t0 + std::time::Duration::from_secs(n as u64);
            for _ in 0..SUBMIT_CSR_BURST as u32 {
                assert!(limiter.allow_submit_csr(addr(n), t));
            }
        }
        assert_eq!(limiter.buckets.lock().unwrap().len(), MAX_TRACKED_SOURCES);

        // One more, brand new, source: room is made by evicting address 0,
        // the least-recently touched — and it is safe to do so, since that
        // just means address 0 starts over at full burst capacity next time.
        let t_new = t0 + std::time::Duration::from_secs(MAX_TRACKED_SOURCES as u64);
        assert!(limiter.allow_submit_csr(addr(MAX_TRACKED_SOURCES as u32), t_new));
        assert_eq!(
            limiter.buckets.lock().unwrap().len(),
            MAX_TRACKED_SOURCES,
            "the map itself never grows past the cap"
        );
        assert!(
            limiter.allow_submit_csr(addr(0), t_new),
            "the evicted source gets a fresh full bucket, not a permanently-empty one"
        );
    }

    /// The full stack over a real loopback TLS connection: a client presenting
    /// the node's own key (bootstrap) completes the RFC 7250 handshake, the
    /// accept loop recovers its key and snapshots the (un-enrolled) router, and
    /// authenticated requests are served. Exercises `serve_tls_server` end to end
    /// with a genuine `tokio-rustls` client.
    #[tokio::test]
    async fn tls_server_serves_a_bootstrapping_client_end_to_end() {
        use tokio_rustls::TlsConnector;

        let server_seed = [7u8; 32];
        let server_key = Keypair::from_seed(&server_seed).ed_pubkey();

        // Stand-in router loop: reports `server_seed`'s key as `own_key` (what
        // the real driver loop reports before any `SetAuth`), un-enrolled
        // (bootstrap), nothing revoked.
        let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<oneshot::Sender<AuthSnapshot>>(4);
        tokio::spawn(async move {
            while let Some(reply) = snapshot_rx.recv().await {
                let _ = reply.send(AuthSnapshot {
                    own_key: server_key,
                    anchor: None,
                    revoked: Vec::new(),
                });
            }
        });

        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tls_server(
            listener,
            server_seed,
            snapshot_tx,
            query_tx,
        ));

        // Client presents the node's own key (bootstrap) and pins the node key.
        let connector = TlsConnector::from(crate::tls::test_support::test_client_config(
            &server_seed,
            &server_key,
        ));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = connector.connect(server_name, tcp).await.unwrap();
        let mut client = LengthDelimitedCodec::builder().new_framed(tls);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(ack.response, Some(Response::Empty(_))),
            "bootstrap authentication succeeds over real TLS"
        );

        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp.response, Some(Response::NodeInfo(_))));
    }

    /// The self-key window closes on the *next connection* after a seed
    /// rotation, not only after a restart: `own_key` is read fresh from the
    /// router-loop snapshot per connection (see [`AuthSnapshot::own_key`]),
    /// so a client presenting a seed the node has since rotated away from no
    /// longer gets bootstrap access, while the newly-installed seed does.
    ///
    /// The TLS listener itself keeps presenting `server_seed`'s identity
    /// throughout (rebuilding the acceptor at runtime is a separate concern
    /// from this fix) — only the *authorization* comparison value changes,
    /// exactly as `SetAuth` installing a new seed would cause the real driver
    /// loop's snapshot responder to report.
    #[tokio::test]
    async fn a_rotated_identity_seed_stops_granting_self_key_on_the_next_connection() {
        use std::sync::Arc;
        use std::sync::Mutex;

        use tokio_rustls::TlsConnector;

        let server_seed = [7u8; 32];
        let server_key = Keypair::from_seed(&server_seed).ed_pubkey();
        let old_seed = [1u8; 32];
        let new_seed = [2u8; 32];
        let old_key = Keypair::from_seed(&old_seed).ed_pubkey();
        let new_key = Keypair::from_seed(&new_seed).ed_pubkey();

        // Stand-in router loop: reports whichever key is currently
        // "installed", exactly as the real driver's snapshot responder does
        // after a `SetAuth` updates the identity it tracks.
        let current_own_key = Arc::new(Mutex::new(old_key));
        let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<oneshot::Sender<AuthSnapshot>>(4);
        {
            let current_own_key = current_own_key.clone();
            tokio::spawn(async move {
                while let Some(reply) = snapshot_rx.recv().await {
                    let own_key = *current_own_key.lock().unwrap();
                    let _ = reply.send(AuthSnapshot {
                        own_key,
                        anchor: None,
                        revoked: Vec::new(),
                    });
                }
            });
        }

        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tls_server(
            listener,
            server_seed,
            snapshot_tx,
            query_tx,
        ));

        // Connect presenting `presented_seed`, authenticate with no cert
        // (bootstrap), and report whether the connection was actually granted
        // full access — a `GetNodeInfo` served rather than refused — which is
        // the only thing that tells self-key access apart from the
        // enrollment-only grant an anchorless node hands out to any stranger.
        async fn granted_full_access(
            addr: SocketAddr,
            presented_seed: &[u8; 32],
            server_key: &[u8; 32],
        ) -> bool {
            let connector = TlsConnector::from(crate::tls::test_support::test_client_config(
                presented_seed,
                server_key,
            ));
            let tcp = TcpStream::connect(addr).await.unwrap();
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let tls = connector.connect(server_name, tcp).await.unwrap();
            let mut client = LengthDelimitedCodec::builder().new_framed(tls);

            client
                .send(encode_request(Request::Authenticate(AuthenticateRequest {
                    cert: Vec::new(),
                })))
                .await
                .unwrap();
            let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            assert!(
                matches!(ack.response, Some(Response::Empty(_))),
                "an anchorless node admits every bootstrap connection, self-key or not"
            );

            client
                .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
                .await
                .unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            matches!(resp.response, Some(Response::NodeInfo(_)))
        }

        // Before rotation: the old seed is self-key, and gets full access.
        assert!(
            granted_full_access(addr, &old_seed, &server_key).await,
            "the old seed grants full access before rotation"
        );

        // Rotate: the router loop now reports the new key, as it would once
        // `SetAuth` installs `new_seed`.
        *current_own_key.lock().unwrap() = new_key;

        // After rotation: the OLD seed no longer earns full access — it falls
        // to the enrollment-only tier a stranger gets, same as any other key
        // that isn't the node's own.
        assert!(
            !granted_full_access(addr, &old_seed, &server_key).await,
            "the old seed must not still grant full access after rotation"
        );
        // ...and the NEW seed does, immediately, on the very next connection.
        assert!(
            granted_full_access(addr, &new_seed, &server_key).await,
            "the new seed grants full access right after rotation"
        );
    }

    /// Sending a normal request before authenticating is refused — the first
    /// frame must be Authenticate.
    #[tokio::test]
    async fn authenticated_stream_requires_authenticate_first() {
        let key = [5u8; 32];
        let ctx = AuthContext {
            own_key: key,
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(key, ctx);

        // Skip authentication and send a query first.
        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();

        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => {
                assert!(e.message.contains("Authenticate"), "got: {}", e.message)
            }
            other => panic!("expected an error response, got {other:?}"),
        }
        assert!(client.next().await.is_none());
        let _ = server.await;
    }

    /// On an *enrolled* node, a client presenting a valid admin membership cert
    /// bound to its handshake key is granted and then served — the production
    /// (non-bootstrap) authorization path over the wire, which the unit tests in
    /// `authz` exercise only in isolation.
    #[tokio::test]
    async fn authenticated_stream_enrolled_admin_grants_then_serves() {
        use wayfinder::wayfinder_auth::Authority;
        use zerocopy::IntoBytes;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let admin_kp = Keypair::from_seed(&[2u8; 32]);
        let admin_cert = authority.issue_admin_cert(
            Mac([0, 0, 0, 0, 0, 5]),
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
        );
        let ctx = AuthContext {
            own_key: [9u8; 32], // not the client's key: only the cert can admit it
            anchor: Some(authority.trust_anchor()),
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(admin_kp.ed_pubkey(), ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: admin_cert.as_bytes().to_vec(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(ack.response, Some(Response::Empty(_))),
            "a bound admin cert is granted on an enrolled node"
        );

        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp.response, Some(Response::NodeInfo(_))));

        drop(client);
        let _ = server.await;
    }

    /// On an enrolled node, a revoked admin's cert is refused over the wire even
    /// though it verifies and is key-bound: revocation dominates the admin bit.
    #[tokio::test]
    async fn authenticated_stream_denies_revoked_admin() {
        use wayfinder::wayfinder_auth::Authority;
        use zerocopy::IntoBytes;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let admin_kp = Keypair::from_seed(&[2u8; 32]);
        let admin_mac = Mac([0, 0, 0, 0, 0, 5]);
        let admin_cert = authority.issue_admin_cert(
            admin_mac,
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
        );
        let ctx = AuthContext {
            own_key: [9u8; 32],
            anchor: Some(authority.trust_anchor()),
            revoked: vec![admin_mac], // this admin's node is revoked
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(admin_kp.ed_pubkey(), ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: admin_cert.as_bytes().to_vec(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => assert!(e.message.contains("denied"), "got: {}", e.message),
            other => panic!("expected an error response, got {other:?}"),
        }
        assert!(
            client.next().await.is_none(),
            "connection is closed after a revoked admin is refused"
        );
        let _ = server.await;
    }

    /// A non-empty but unparseable membership cert is refused explicitly (not
    /// silently treated as "no cert" / bootstrap), and the connection closed.
    #[tokio::test]
    async fn authenticated_stream_denies_malformed_cert() {
        let ctx = AuthContext {
            own_key: [9u8; 32],
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server([2u8; 32], ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: vec![0xFF; 8], // not a valid MembershipCert
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => {
                assert!(e.message.contains("malformed"), "got: {}", e.message)
            }
            other => panic!("expected an error response, got {other:?}"),
        }
        assert!(client.next().await.is_none());
        let _ = server.await;
    }
}
