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
use tokio_util::codec::FramedRead;
use tokio_util::codec::FramedWrite;
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

/// The router state a management connection is authorized against, as of one
/// instant.
///
/// The serve task must not touch the router directly (it lives on another task),
/// so the router's auth-relevant state is projected into this value and the serve
/// task evaluates [`decide_access`] locally against it. It is re-read while the
/// connection is open — see [`AuthGate`] — because a connection has no bound and
/// a revocation, an expiry or a rotated seed must not have to wait for one.
pub struct AuthContext {
    /// The node's own Ed25519 identity key, for the bootstrap comparison
    /// (un-enrolled admission requires the handshake key to equal this), or
    /// `None` on a node with no identity seed — which has no own key, and so
    /// admits nobody by this path.
    pub own_key: Option<[u8; 32]>,
    /// The installed trust anchor, or `None` when the node is un-enrolled
    /// (bootstrap mode — self-key admission only).
    pub anchor: Option<TrustAnchor>,
    /// Node MACs with an active revocation as of the snapshot instant.
    pub revoked: Vec<Mac>,
    /// Current unix time (seconds), for certificate validity checks.
    pub now_unix: u64,
}

/// How long an open connection's authorization stands before it is decided
/// again.
///
/// The cost of a longer interval is the window in which a revoked or expired
/// credential still works; the cost of a shorter one is a round trip to the
/// router loop per request. A minute keeps `RevokeNode` meaningful on any human
/// timescale while making the check invisible next to a dashboard's per-second
/// poll.
const REVALIDATE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// How a serve task reads wall-clock time, for certificate validity.
///
/// Injected rather than called directly so a test can move a certificate past
/// its expiry, which is otherwise only observable by waiting.
pub(crate) type Clock = std::sync::Arc<dyn Fn() -> anyhow::Result<u64> + Send + Sync>;

/// Everything a serve task needs to decide — and re-decide — what a connection
/// may do: the channel to the router loop, the clock, and how long a decision
/// stands.
///
/// Authorization used to be decided once, at connect. A connection has no
/// bound, so that made `RevokeNode` a promise about *future* connections only:
/// an attacker holding one open session kept full access after every revocation
/// lever had been pulled, and an admin certificate that expired mid-session
/// stayed honoured.
pub(crate) struct AuthGate {
    /// Channel the router loop answers auth-snapshot requests on.
    snapshot_tx: AuthSnapshotTx,
    /// The clock certificate validity is judged against.
    clock: Clock,
    /// How long a decision stands before it is made again.
    revalidate_after: std::time::Duration,
}

impl AuthGate {
    /// The production gate: the real clock, and [`REVALIDATE_AFTER`].
    pub(crate) fn new(snapshot_tx: AuthSnapshotTx) -> Self {
        Self {
            snapshot_tx,
            clock: std::sync::Arc::new(now_unix),
            revalidate_after: REVALIDATE_AFTER,
        }
    }

    /// Ask the router loop for its current auth state and pair it with the
    /// current time.
    ///
    /// Every field is read fresh, including `own_key`: a seed the node has
    /// rotated away from stops earning the self-key tier here, not at the next
    /// restart.
    async fn context(&self) -> anyhow::Result<AuthContext> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.snapshot_tx
            .send(reply_tx)
            .await
            .map_err(|_| anyhow::anyhow!("router loop unavailable for auth snapshot"))?;
        let snapshot = reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("router loop dropped the auth-snapshot request"))?;
        Ok(AuthContext {
            own_key: snapshot.own_key,
            anchor: snapshot.anchor,
            revoked: snapshot.revoked,
            now_unix: (self.clock)()?,
        })
    }
}

/// Encode and send one [`WayfinderResponse`] over the framed connection.
async fn send_response<W>(
    framed: &mut FramedWrite<W, LengthDelimitedCodec>,
    response: RespKind,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let envelope = WayfinderResponse {
        response: Some(response),
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf)?;
    framed.send(Bytes::from(buf)).await?;
    Ok(())
}

/// Burst capacity for the enrollment limiter: a handful of submissions before
/// the rate limit engages, so a node's first genuine `SubmitCsr` (and a quick
/// retry or two) is never throttled.
const SUBMIT_CSR_BURST: f64 = 5.0;

/// Steady-state refill for the enrollment limiter: one token every 5 seconds —
/// matching `APPROVAL_POLL` in `bins/wayfinder-web/src/components/security.rs`,
/// the enrollment panel's re-submission cadence while a request is held for
/// approval, so a legitimate node polling indefinitely is never throttled at
/// steady state.
const SUBMIT_CSR_REFILL_PER_SEC: f64 = 1.0 / 5.0;

/// Distinct source addresses a [`SourceLimiter`] tracks at once. Past this,
/// the least-recently-touched bucket is evicted to make room for a new
/// source — safe to evict (unlike the held-CSR store this sits in front of):
/// the evicted source simply starts over with a full bucket, which is never
/// worse for it than being tracked, so eviction here hands an attacker
/// nothing. Bounding the map itself is still required, or an attacker with
/// many source addresses reproduces the exact unbounded-anonymous-growth
/// problem this limiter exists to bound.
const MAX_TRACKED_SOURCES: usize = 1024;

/// Burst capacity for the per-source *connection* limit: enough that an
/// operator's tooling opening several connections at once (a dashboard, a
/// `wayfinderctl` invocation, a TUI) is never delayed, while a peer opening
/// them in a loop is.
const CONNECT_BURST: f64 = 20.0;

/// Steady-state refill for the per-source connection limit. One every half
/// second is far above any legitimate cadence — the enrollment poll reconnects
/// every 5 seconds, and every other client holds one connection open — and far
/// below what a flood needs to be worth mounting.
const CONNECT_REFILL_PER_SEC: f64 = 2.0;

/// A token bucket for one source address: `tokens` refill continuously at the
/// owning limiter's rate up to its burst, and one admission costs one token.
struct TokenBucket {
    tokens: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(now: std::time::Instant, burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: now,
        }
    }

    /// Refill for elapsed time since the last touch, then attempt to spend
    /// one token. `true` ⇒ spent (the caller may proceed); `false` ⇒ empty
    /// (the caller must wait).
    fn try_consume(&mut self, now: std::time::Instant, burst: f64, refill_per_sec: f64) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(burst);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A per-source token-bucket rate limit, used for two different things a
/// stranger can spend: the enrollment tier's `SubmitCsr` (layered in front of
/// `authority.rs`'s `MAX_HELD_CSRS` count bound) and new connections to the
/// listener.
///
/// For enrollment the two bounds are complementary, not redundant: the count
/// cap stops the held-CSR store from growing past a fixed size no matter how
/// many distinct sources contribute to it, but says nothing about how fast any
/// *one* source may contribute — which is what actually protects a legitimate
/// node's enrollment from being crowded out by a single flooding peer, and
/// what keeps that peer from burning through the shared cap on its own.
///
/// Keyed by IP, not the full socket address: a legitimate client opens a
/// fresh connection (and so a fresh ephemeral port) on every poll — see
/// `SUBMIT_CSR_REFILL_PER_SEC` — so keying by port as well would give every
/// poll its own untouched bucket and defeat the limiter entirely.
pub(crate) struct SourceLimiter {
    buckets: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, TokenBucket>>,
    /// Tokens a source starts with, and the most it can bank.
    burst: f64,
    /// Tokens per second a source's bucket refills at.
    refill_per_sec: f64,
}

impl SourceLimiter {
    /// A fresh limiter with no sources tracked yet.
    fn new(burst: f64, refill_per_sec: f64) -> Self {
        Self {
            buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
            burst,
            refill_per_sec,
        }
    }

    /// The limiter guarding the enrollment tier's `SubmitCsr`.
    fn for_enrollment() -> Self {
        Self::new(SUBMIT_CSR_BURST, SUBMIT_CSR_REFILL_PER_SEC)
    }

    /// The limiter guarding new connections to the listener.
    fn for_connections() -> Self {
        Self::new(CONNECT_BURST, CONNECT_REFILL_PER_SEC)
    }

    /// Whether an action from `addr` may proceed right now. Consumes a
    /// token from `addr`'s bucket on success; a source with no bucket yet
    /// starts at full burst capacity.
    fn allow(&self, addr: std::net::IpAddr, now: std::time::Instant) -> bool {
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
            .or_insert_with(|| TokenBucket::new(now, self.burst))
            .try_consume(now, self.burst, self.refill_per_sec)
    }
}

/// How many connections that have not yet proved a credential may be open at
/// once, across every source.
///
/// Completing the RFC 7250 handshake proves possession of *a* key, not of an
/// authorized one — authorization is the application-layer step one frame
/// later — so every connection starts here, and a stranger can start as many as
/// this node will hold. Generous enough that no plausible fleet of operators
/// and enrolling nodes reaches it, small enough to bound the sockets and tasks
/// a single hostile peer can pin.
const MAX_UNCREDENTIALED_CONNECTIONS: usize = 64;

/// How long a peer has to complete the TLS handshake before it is dropped.
///
/// `acceptor.accept` waits for the client's half, so without this a connection
/// that opens and says nothing costs a socket and a task until the peer
/// relents — which is not a thing a peer mounting this does.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What a peer may consume before it has proved anything: the enrollment-tier
/// rate limit, the per-source connection rate limit, and the cap on concurrent
/// uncredentialed connections.
///
/// One instance per listener, shared by every connection it accepts — a
/// per-connection limiter would track nothing, since the flows these bound open
/// a fresh connection each time.
pub(crate) struct PreAuthLimits {
    /// Rate limit on the enrollment tier's `SubmitCsr`, per source.
    enrollment: SourceLimiter,
    /// Rate limit on new connections, per source.
    connects: SourceLimiter,
    /// Slots for connections that have not proved a credential.
    uncredentialed: std::sync::Arc<tokio::sync::Semaphore>,
}

impl PreAuthLimits {
    /// A fresh set of limits with nothing tracked and every slot free.
    pub(crate) fn new() -> Self {
        Self {
            enrollment: SourceLimiter::for_enrollment(),
            connects: SourceLimiter::for_connections(),
            uncredentialed: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_UNCREDENTIALED_CONNECTIONS,
            )),
        }
    }

    /// Admit a newly accepted connection from `addr`, or refuse it.
    ///
    /// `None` means the source is connecting too fast, or too many
    /// uncredentialed connections are already open. The caller drops the
    /// socket; there is no one to send an error to, since nothing has been
    /// negotiated yet.
    fn admit(&self, addr: std::net::IpAddr, now: std::time::Instant) -> Option<PreAuthGuard> {
        if !self.connects.allow(addr, now) {
            return None;
        }
        let permit = std::sync::Arc::clone(&self.uncredentialed)
            .try_acquire_owned()
            .ok()?;
        Some(PreAuthGuard(Some(permit)))
    }

    /// Whether a `SubmitCsr` from `addr` may proceed right now.
    fn allow_submit_csr(&self, addr: std::net::IpAddr, now: std::time::Instant) -> bool {
        self.enrollment.allow(addr, now)
    }
}

/// A connection's claim on an uncredentialed slot, held from accept until the
/// connection either proves a credential or ends.
///
/// Released early by [`PreAuthGuard::credentialed`], which is what keeps the
/// cap a bound on *strangers*: an admin's long-lived session must not be
/// counted against a number a flood of strangers can exhaust.
pub(crate) struct PreAuthGuard(Option<tokio::sync::OwnedSemaphorePermit>);

impl PreAuthGuard {
    /// Hand the slot back: this connection has proved a credential and is no
    /// longer part of the uncredentialed population.
    ///
    /// The enrollment tier deliberately does *not* call this — a peer admitted
    /// with no certificate at all is exactly the population being bounded.
    fn credentialed(&mut self) {
        self.0 = None;
    }
}

/// Serve one already-TLS-authenticated management connection.
///
/// `peer_key` is the client's Ed25519 raw public key that the TLS handshake
/// proved possession of (RFC 7250). `peer_addr` is its IP, consulted only to
/// rate-limit `SubmitCsr` on an enrollment-tier (anonymous) connection — see
/// [`PreAuthLimits`]. The first frame must be an
/// [`AuthenticateRequest`](wayfinder_protos::wayfinder::v1alpha::AuthenticateRequest)
/// carrying the client's membership cert (empty on an un-enrolled node); it is
/// bound to `peer_key` and checked by [`decide_access`] against the state
/// `gate` reads from the router loop. A grant is acknowledged with an [`Empty`]
/// response (which the client waits on) before the normal request/response loop
/// runs; a denial is answered with a generic [`ErrorResponse`] and the
/// connection closed.
///
/// The grant does not stand for the life of the connection: `gate` re-decides
/// it before serving a request once its interval has elapsed, and a changed
/// verdict — revoked, expired, or a rotated identity seed — closes the
/// connection with that same generic error. `guard` is this connection's claim
/// on an uncredentialed slot, handed back as soon as a credential is proved.
///
/// Transport-agnostic over `S` so it serves a real `TlsStream` in production and
/// an in-memory duplex in tests — the TLS handshake itself is exercised
/// separately in [`crate::tls`].
pub(crate) async fn serve_authenticated_stream<S>(
    stream: S,
    peer_key: [u8; 32],
    peer_addr: std::net::IpAddr,
    limits: std::sync::Arc<PreAuthLimits>,
    mut guard: PreAuthGuard,
    gate: AuthGate,
    query_tx: QueryTx,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read and write are framed separately so the length cap applies to one
    // direction only: [`crate::MAX_FRAME_LEN`] bounds what an unauthenticated
    // peer can make this node buffer, while a response — a host node's routing
    // table or log page — is routinely larger than any request and must not be
    // truncated by the same number.
    let (read_half, write_half) = tokio::io::split(stream);
    let mut requests: FramedRead<_, LengthDelimitedCodec> = FramedRead::new(
        read_half,
        LengthDelimitedCodec::builder()
            .max_frame_length(crate::MAX_FRAME_LEN)
            .new_codec(),
    );
    let mut responses: FramedWrite<_, LengthDelimitedCodec> =
        FramedWrite::new(write_half, LengthDelimitedCodec::new());

    // The connection must authenticate before anything else.
    let Some(frame) = requests.next().await else {
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
                &mut responses,
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
                    &mut responses,
                    RespKind::Error(ErrorResponse {
                        message: "malformed membership certificate".into(),
                    }),
                )
                .await?;
                return Ok(());
            }
        }
    };

    let ctx = gate.context().await?;
    let decision = authorize(&peer_key, cert.as_ref(), &ctx);
    if let MgmtAccess::Denied(reason) = decision {
        // A rejected management login is security-relevant and worth an
        // operator's attention, but is remotely triggerable, so cap it at warn.
        // The precise `reason` stays in this local log only: a generic message
        // goes over the wire so a not-yet-authenticated peer can't use the
        // response as an oracle (wrong-key vs revoked vs expired vs not-admin)
        // while probing with a stolen or revoked cert.
        tracing::warn!(?reason, "drop: management authentication denied");
        send_response(
            &mut responses,
            RespKind::Error(ErrorResponse {
                message: "authentication denied".into(),
            }),
        )
        .await?;
        return Ok(());
    }
    tracing::debug!(?decision, "management connection authenticated");
    // A connection that proved a credential is no longer part of the population
    // the stranger cap bounds — see `PreAuthGuard`. The enrollment tier
    // deliberately keeps its slot: a peer admitted with no certificate at all is
    // precisely what that cap is for.
    if matches!(
        decision,
        MgmtAccess::GrantedAdmin | MgmtAccess::GrantedSelfKey
    ) {
        guard.credentialed();
    }
    // Acknowledge a successful authentication before serving requests.
    send_response(&mut responses, RespKind::Empty(Empty {})).await?;

    // Authenticated: serve requests until the peer hangs up.
    let mut decided_at = std::time::Instant::now();
    while let Some(frame) = requests.next().await {
        // Re-decide before serving, not on a timer racing the loop: an idle
        // connection holding a revoked credential can do nothing with it, and
        // the moment it tries, this runs. A failure to reach the router loop or
        // read the clock closes the connection rather than extending the last
        // decision — fail-closed, the same way the connect-time path does.
        if decided_at.elapsed() >= gate.revalidate_after {
            let ctx = gate.context().await?;
            let current = authorize(&peer_key, cert.as_ref(), &ctx);
            if current != decision {
                // Revoked, expired, or a rotated seed. Same generic message as
                // the connect-time denial, for the same reason: the precise
                // cause stays in this node's log rather than telling a peer
                // which lever moved.
                tracing::warn!(
                    key = ?peer_key,
                    was = ?decision,
                    now = ?current,
                    "drop: management authorization changed under an open connection"
                );
                send_response(
                    &mut responses,
                    RespKind::Error(ErrorResponse {
                        message: "authentication denied".into(),
                    }),
                )
                .await?;
                return Ok(());
            }
            decided_at = std::time::Instant::now();
        }
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
                &mut responses,
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
            let message = match decision {
                MgmtAccess::GrantedViewer => {
                    "this connection is read-only (its certificate carries the viewer \
                     capability, not the admin one); mutations and the enrollment token \
                     need an admin certificate or the node's own key"
                }
                _ => {
                    "this connection is limited to enrollment (no admin \
                     certificate was verified on it); everything else needs an \
                     admin certificate or the node's own key"
                }
            };
            send_response(
                &mut responses,
                RespKind::Error(ErrorResponse {
                    message: message.into(),
                }),
            )
            .await?;
            continue;
        }
        // A rate limit, not an admission decision: only the enrollment tier
        // is bounded, since a fully-granted connection already required a
        // real credential (an admin cert or the node's own key), which is
        // not the resource an anonymous flood is spending. See
        // `PreAuthLimits`.
        if matches!(decision, MgmtAccess::GrantedEnrollment)
            && matches!(req, ReqKind::SubmitCsr(_))
            && !limits.allow_submit_csr(peer_addr, std::time::Instant::now())
        {
            tracing::warn!(
                key = ?peer_key,
                %peer_addr,
                "drop: enrollment-tier SubmitCsr rate limit exceeded"
            );
            send_response(
                &mut responses,
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
        responses.send(Bytes::from(buf)).await?;
    }
    Ok(())
}

/// Decide what a connection may do, given the key its handshake proved, the
/// certificate it presented, and the router state as of `ctx`.
///
/// One function so the connect-time decision and every revalidation of it are
/// the same decision — two call sites spelling out the same argument list is
/// how they drift.
fn authorize(peer_key: &[u8; 32], cert: Option<&MembershipCert>, ctx: &AuthContext) -> MgmtAccess {
    decide_access(
        peer_key,
        cert,
        ctx.anchor.as_ref(),
        ctx.own_key.as_ref(),
        ctx.now_unix,
        |mac| ctx.revoked.contains(&mac),
    )
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
    /// earns [`MgmtAccess::GrantedSelfKey`](crate::MgmtAccess::GrantedSelfKey)
    /// — or `None` when no identity seed is configured, which withholds that
    /// tier entirely rather than comparing against a sentinel.
    pub own_key: Option<[u8; 32]>,
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
    let limits = std::sync::Arc::new(PreAuthLimits::new());

    loop {
        let (tcp, peer) = listener.accept().await?;
        // Bound before spawning: a connection refused here has cost one accept,
        // and one that is not refused holds its slot until it authenticates or
        // ends.
        let Some(guard) = limits.admit(peer.ip(), std::time::Instant::now()) else {
            tracing::warn!(
                %peer,
                "drop: connection refused by the pre-authentication limits"
            );
            drop(tcp);
            continue;
        };
        tracing::debug!(%peer, "management TLS connection accepted");
        let acceptor = acceptor.clone();
        let snapshot_tx = snapshot_tx.clone();
        let query_tx = query_tx.clone();
        let limits = std::sync::Arc::clone(&limits);
        tokio::spawn(async move {
            if let Err(e) =
                serve_tls_connection(acceptor, tcp, peer, snapshot_tx, query_tx, limits, guard)
                    .await
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
    limits: std::sync::Arc<PreAuthLimits>,
    guard: PreAuthGuard,
) -> anyhow::Result<()> {
    // A peer that opens a connection and then says nothing would otherwise hold
    // this task and its socket indefinitely; the handshake itself is sub-second
    // on any working client.
    let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .map_err(|_| {
            anyhow::anyhow!("TLS handshake did not complete within {HANDSHAKE_TIMEOUT:?}")
        })??;

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

    serve_authenticated_stream(
        tls,
        peer_key,
        peer.ip(),
        limits,
        guard,
        AuthGate::new(snapshot_tx),
        query_tx,
    )
    .await
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
    use tokio_util::codec::Framed;
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
    fn spawn_echo(rx: QueryRx) {
        spawn_echo_of(rx, canned_node_info());
    }

    /// The well-formed reply `spawn_echo` answers with, distinguishable from
    /// silence.
    fn canned_node_info() -> Response {
        Response::NodeInfo(NodeInfo {
            node_id: vec![1, 2, 3, 4, 5, 6],
            num_originators: 7,
            auth_locked: false,
            runtime_config_active: false,
        })
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

    /// Answer every forwarded query with `response`, so a test can choose what
    /// comes back — a canned `NodeInfo`, or something deliberately large.
    fn spawn_echo_of(mut rx: QueryRx, response: Response) {
        tokio::spawn(async move {
            while let Some((_, resp_tx)) = rx.recv().await {
                let _ = resp_tx.send(WayfinderResponse {
                    response: Some(response.clone()),
                });
            }
        });
    }

    /// Answer every auth-snapshot request with the same state, the way a
    /// quiescent router loop would.
    fn spawn_snapshots(
        mut rx: mpsc::Receiver<oneshot::Sender<AuthSnapshot>>,
        own_key: Option<[u8; 32]>,
        anchor: Option<TrustAnchor>,
        revoked: Vec<Mac>,
    ) {
        tokio::spawn(async move {
            while let Some(reply) = rx.recv().await {
                let _ = reply.send(AuthSnapshot {
                    own_key,
                    anchor,
                    revoked: revoked.clone(),
                });
            }
        });
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
        spawn_authenticated_server_answering(peer_key, ctx, canned_node_info())
    }

    /// As [`spawn_authenticated_server`], with the response the stand-in router
    /// loop answers every query with.
    fn spawn_authenticated_server_answering(
        peer_key: [u8; 32],
        ctx: AuthContext,
        response: Response,
    ) -> (
        Framed<tokio::io::DuplexStream, LengthDelimitedCodec>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        spawn_gated_server_answering(peer_key, gate_returning(ctx), response)
    }

    /// A gate whose router state and clock never move — what a test that is
    /// about something other than revalidation wants.
    fn gate_returning(ctx: AuthContext) -> AuthGate {
        let now_unix = ctx.now_unix;
        let (snapshot_tx, snapshot_rx) = mpsc::channel(8);
        spawn_snapshots(snapshot_rx, ctx.own_key, ctx.anchor, ctx.revoked);
        AuthGate {
            snapshot_tx,
            clock: std::sync::Arc::new(move || Ok(now_unix)),
            revalidate_after: REVALIDATE_AFTER,
        }
    }

    /// Drive `serve_authenticated_stream` over an in-memory duplex against a
    /// caller-supplied gate.
    fn spawn_gated_server(
        peer_key: [u8; 32],
        gate: AuthGate,
    ) -> (
        Framed<tokio::io::DuplexStream, LengthDelimitedCodec>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        spawn_gated_server_answering(peer_key, gate, canned_node_info())
    }

    /// As [`spawn_gated_server`], with the response the stand-in router loop
    /// answers every query with.
    fn spawn_gated_server_answering(
        peer_key: [u8; 32],
        gate: AuthGate,
        response: Response,
    ) -> (
        Framed<tokio::io::DuplexStream, LengthDelimitedCodec>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo_of(query_rx, response);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let peer_addr = std::net::Ipv4Addr::LOCALHOST.into();
        let limits = std::sync::Arc::new(PreAuthLimits::new());
        let guard = limits
            .admit(peer_addr, std::time::Instant::now())
            .expect("a fresh limiter admits the first connection");
        let server = tokio::spawn(serve_authenticated_stream(
            server_io, peer_key, peer_addr, limits, guard, gate, query_tx,
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
            own_key: Some(key), // bootstrap: handshake key equals the node's own key
            anchor: None,       // un-enrolled
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
            own_key: Some([1u8; 32]),
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
            own_key: Some([1u8; 32]),
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
            own_key: Some([1u8; 32]), // un-enrolled ⇒ every other key is GrantedEnrollment
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
    /// listener rather than by calling `PreAuthLimits` directly: a source
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
                    own_key: Some(server_key),
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
    /// enrollment-tier rate limit: `PreAuthLimits` gates `SubmitCsr` only
    /// for `GrantedEnrollment`, so an admin enrolling many nodes on their
    /// behalf in quick succession — the very capability §3.1's
    /// proof-of-possession option was declined to preserve — is never
    /// throttled by it.
    #[tokio::test]
    async fn submit_csr_is_not_rate_limited_on_a_fully_granted_connection() {
        let ctx = AuthContext {
            own_key: Some([1u8; 32]),
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
        let limiter = SourceLimiter::for_enrollment();
        let addr: std::net::IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
        let t0 = std::time::Instant::now();

        for n in 0..SUBMIT_CSR_BURST as u32 {
            assert!(limiter.allow(addr, t0), "burst slot {n}");
        }
        assert!(!limiter.allow(addr, t0), "burst capacity is exhausted");

        // A different source has its own, untouched bucket.
        let other: std::net::IpAddr = std::net::Ipv4Addr::new(127, 0, 0, 2).into();
        assert!(limiter.allow(other, t0));

        // Enough elapsed time for exactly one refill: one more is allowed,
        // and only one.
        let t1 = t0 + std::time::Duration::from_secs_f64(1.0 / SUBMIT_CSR_REFILL_PER_SEC);
        assert!(limiter.allow(addr, t1));
        assert!(!limiter.allow(addr, t1));
    }

    /// The map backing the limiter is itself bounded: past
    /// `MAX_TRACKED_SOURCES` distinct addresses, tracking a new one evicts
    /// the least-recently-touched bucket rather than growing further —
    /// otherwise an attacker with many source addresses reproduces the exact
    /// unbounded-anonymous-growth problem this limiter exists to bound.
    #[test]
    fn enrollment_limiter_bounds_the_number_of_tracked_sources() {
        let limiter = SourceLimiter::for_enrollment();
        let t0 = std::time::Instant::now();
        let addr = |n: u32| std::net::IpAddr::from(std::net::Ipv4Addr::from(n));

        for n in 0..MAX_TRACKED_SOURCES as u32 {
            // Space each touch out in time so "least recently touched" is
            // unambiguous, and consume the full burst so a later re-touch of
            // the same address doesn't look like a fresh one.
            let t = t0 + std::time::Duration::from_secs(n as u64);
            for _ in 0..SUBMIT_CSR_BURST as u32 {
                assert!(limiter.allow(addr(n), t));
            }
        }
        assert_eq!(limiter.buckets.lock().unwrap().len(), MAX_TRACKED_SOURCES);

        // One more, brand new, source: room is made by evicting address 0,
        // the least-recently touched — and it is safe to do so, since that
        // just means address 0 starts over at full burst capacity next time.
        let t_new = t0 + std::time::Duration::from_secs(MAX_TRACKED_SOURCES as u64);
        assert!(limiter.allow(addr(MAX_TRACKED_SOURCES as u32), t_new));
        assert_eq!(
            limiter.buckets.lock().unwrap().len(),
            MAX_TRACKED_SOURCES,
            "the map itself never grows past the cap"
        );
        assert!(
            limiter.allow(addr(0), t_new),
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
                    own_key: Some(server_key),
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
                        own_key: Some(own_key),
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
            own_key: Some(key),
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
            own_key: Some([9u8; 32]), // not the client's key: only the cert can admit it
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
            own_key: Some([9u8; 32]),
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
            own_key: Some([9u8; 32]),
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

    /// A frame larger than the cap is refused rather than buffered.
    ///
    /// Reaching this point costs a peer nothing but an RPK handshake — there is
    /// no credential yet, authorization happens one frame later — so the buffer
    /// a stranger can make this node allocate is the whole exposure. The codec
    /// inherited `tokio-util`'s 8 MiB default, on a process that is also
    /// routing the mesh.
    #[tokio::test]
    async fn an_oversized_frame_is_refused_before_it_is_buffered() {
        let key = [5u8; 32];
        let ctx = AuthContext {
            own_key: Some(key),
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(key, ctx);

        client
            .send(Bytes::from(vec![0u8; crate::MAX_FRAME_LEN + 1]))
            .await
            .unwrap();

        assert!(
            client.next().await.is_none(),
            "the connection is closed rather than answered"
        );
        let _ = server.await;
    }

    /// The cap bounds what a peer can make this node *read*, not what the node
    /// may answer with.
    ///
    /// The two are not the same size at all: every request is a few hundred
    /// bytes, while a routing table or a page of logs from a host node runs to
    /// tens of kilobytes. Capping both directions with one number would trade a
    /// memory bound for a dashboard that cannot load.
    #[tokio::test]
    async fn a_response_larger_than_the_request_cap_is_still_sent() {
        let key = [5u8; 32];
        let ctx = AuthContext {
            own_key: Some(key),
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let big = Response::NodeInfo(NodeInfo {
            node_id: vec![7u8; crate::MAX_FRAME_LEN * 4],
            num_originators: 1,
            auth_locked: false,
            runtime_config_active: false,
        });
        let (mut client, server) = spawn_authenticated_server_answering(key, ctx, big);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(Response::Empty(_))));

        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        let Some(Response::NodeInfo(info)) = resp.response else {
            panic!("the oversized response was dropped: {resp:?}");
        };
        assert_eq!(info.node_id.len(), crate::MAX_FRAME_LEN * 4);

        drop(client);
        let _ = server.await;
    }

    /// Connections that have proved no credential are bounded in number.
    ///
    /// Completing the TLS handshake requires no credential — authorization is
    /// an application-layer step afterwards — so without this a stranger can
    /// hold as many connections open as the process has file descriptors.
    #[test]
    fn concurrent_uncredentialed_connections_are_bounded() {
        let limits = PreAuthLimits::new();
        let now = std::time::Instant::now();
        // A distinct source per connection, so the per-source rate limit is
        // never what refuses one — this is the concurrency cap's test, and a
        // flood worth bounding is spread across sources anyway.
        let source = |n: usize| std::net::IpAddr::from(std::net::Ipv4Addr::from(n as u32));

        let held: Vec<_> = (0..MAX_UNCREDENTIALED_CONNECTIONS)
            .map(|n| {
                limits
                    .admit(source(n), now)
                    .unwrap_or_else(|| panic!("connection {n} is within the cap"))
            })
            .collect();

        assert!(
            limits
                .admit(source(MAX_UNCREDENTIALED_CONNECTIONS), now)
                .is_none(),
            "past the cap, a new connection is refused rather than accepted"
        );

        drop(held);
        assert!(
            limits
                .admit(source(MAX_UNCREDENTIALED_CONNECTIONS), now)
                .is_some(),
            "and the slots come back when those connections end"
        );
    }

    /// A connection that proves a credential hands its slot back immediately,
    /// so a flood of strangers cannot lock out the operator.
    ///
    /// This is the whole reason the cap is on *uncredentialed* connections
    /// rather than on connections: an admin's session must not be counted
    /// against a bound a stranger can exhaust.
    #[test]
    fn a_credentialed_connection_returns_its_slot_at_once() {
        let limits = PreAuthLimits::new();
        let now = std::time::Instant::now();
        let source = |n: usize| std::net::IpAddr::from(std::net::Ipv4Addr::from(n as u32));
        let next = MAX_UNCREDENTIALED_CONNECTIONS;

        let mut held: Vec<_> = (0..MAX_UNCREDENTIALED_CONNECTIONS)
            .map(|n| limits.admit(source(n), now).expect("within the cap"))
            .collect();
        assert!(
            limits.admit(source(next), now).is_none(),
            "the cap is reached"
        );

        held[0].credentialed();
        assert!(
            limits.admit(source(next), now).is_some(),
            "an authenticated session no longer occupies an uncredentialed slot"
        );
    }

    /// Authenticating hands the uncredentialed slot back on the live serve
    /// path, not only in the guard's own unit test.
    ///
    /// The wiring is the part that rots: a guard that is taken at accept and
    /// never released early still compiles, still passes every other test here,
    /// and quietly turns the stranger cap into a cap on everyone.
    #[tokio::test]
    async fn an_authenticated_connection_frees_its_slot_on_the_serve_path() {
        let key = [5u8; 32];
        let ctx = AuthContext {
            own_key: Some(key), // bootstrap: a full grant
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let source = |n: usize| std::net::IpAddr::from(std::net::Ipv4Addr::from(n as u32));
        let now = std::time::Instant::now();
        let spare = MAX_UNCREDENTIALED_CONNECTIONS;

        let limits = std::sync::Arc::new(PreAuthLimits::new());
        // Every slot but one taken, then the connection under test takes the
        // last: the listener is now at its cap.
        let _held: Vec<_> = (0..MAX_UNCREDENTIALED_CONNECTIONS - 1)
            .map(|n| limits.admit(source(n), now).expect("within the cap"))
            .collect();
        let guard = limits
            .admit(source(spare - 1), now)
            .expect("the last slot is free");
        assert!(
            limits.admit(source(spare), now).is_none(),
            "the listener is at its cap before the connection authenticates"
        );

        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_authenticated_stream(
            server_io,
            key,
            source(spare - 1),
            std::sync::Arc::clone(&limits),
            guard,
            gate_returning(ctx),
            query_tx,
        ));
        let mut client = LengthDelimitedCodec::builder().new_framed(client_io);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(Response::Empty(_))));

        assert!(
            limits.admit(source(spare), now).is_some(),
            "the authenticated session no longer counts against the stranger cap"
        );

        drop(client);
        let _ = server.await;
    }

    /// New connections from one source are rate-limited, so a single flooding
    /// peer cannot churn through the cap above by connecting and disconnecting.
    #[test]
    fn new_connections_are_rate_limited_per_source() {
        let limits = PreAuthLimits::new();
        let now = std::time::Instant::now();
        let flooder: std::net::IpAddr = std::net::Ipv4Addr::new(203, 0, 113, 7).into();

        // Each admission is dropped immediately, so only the rate limit — not
        // the concurrency cap — can refuse anything here.
        for n in 0..(CONNECT_BURST as u32) {
            assert!(
                limits.admit(flooder, now).is_some(),
                "burst connection {n} is admitted"
            );
        }
        assert!(
            limits.admit(flooder, now).is_none(),
            "past the burst, the source is throttled"
        );
        assert!(
            limits
                .admit(std::net::Ipv4Addr::new(203, 0, 113, 8).into(), now)
                .is_some(),
            "another source does not inherit the throttle"
        );
        assert!(
            limits
                .admit(flooder, now + Duration::from_secs(10))
                .is_some(),
            "and the throttled source recovers as its bucket refills"
        );
    }

    /// A peer that connects and then says nothing is dropped rather than held.
    ///
    /// `acceptor.accept` waits for the client's half of the handshake, so
    /// without a timeout every silent connection is a task and a socket held
    /// until the peer goes away — which a peer with no intention of speaking
    /// never does.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_starts_the_handshake_is_dropped() {
        let addr = free_tcp_addr();
        let listener = bind_tcp_server(addr).await.unwrap();
        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);
        let (snapshot_tx, snapshot_rx) = mpsc::channel(8);
        spawn_snapshots(
            snapshot_rx,
            Some(Keypair::from_seed(&[1u8; 32]).ed_pubkey()),
            None,
            Vec::new(),
        );
        tokio::spawn(serve_tls_server(listener, [1u8; 32], snapshot_tx, query_tx));

        let mut silent = TcpStream::connect(addr).await.unwrap();

        // Nothing is ever written. The read completes — with zero bytes, the
        // end-of-stream a closed connection reports — once the handshake
        // timeout elapses.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(
            HANDSHAKE_TIMEOUT * 2,
            tokio::io::AsyncReadExt::read(&mut silent, &mut buf),
        )
        .await
        .expect("the server drops a silent peer rather than holding it")
        .expect("the connection is closed, not errored");
        assert_eq!(read, 0, "the server closed the connection");
    }

    /// A live connection whose state a test can move under it: the router's
    /// answer to an auth-snapshot request, and the clock the serve task reads.
    struct MovableState {
        snapshot: std::sync::Arc<std::sync::Mutex<AuthSnapshot>>,
        now: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl MovableState {
        /// Spawn a stand-in router loop answering with `snapshot`, and return
        /// both the handles to change it and the gate the serve task reads it
        /// through. `revalidate_after` is zero so every request revalidates,
        /// rather than making the test wait out the production interval.
        fn new(snapshot: AuthSnapshot, now_unix: u64) -> (Self, AuthGate) {
            let snapshot = std::sync::Arc::new(std::sync::Mutex::new(snapshot));
            let now = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(now_unix));

            let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<oneshot::Sender<AuthSnapshot>>(4);
            let served = std::sync::Arc::clone(&snapshot);
            tokio::spawn(async move {
                while let Some(reply) = snapshot_rx.recv().await {
                    let current = served.lock().unwrap();
                    let _ = reply.send(AuthSnapshot {
                        own_key: current.own_key,
                        anchor: current.anchor,
                        revoked: current.revoked.clone(),
                    });
                }
            });

            let clock = std::sync::Arc::clone(&now);
            let gate = AuthGate {
                snapshot_tx,
                clock: std::sync::Arc::new(move || {
                    Ok(clock.load(std::sync::atomic::Ordering::SeqCst))
                }),
                revalidate_after: Duration::ZERO,
            };
            (Self { snapshot, now }, gate)
        }

        fn revoke(&self, mac: Mac) {
            self.snapshot.lock().unwrap().revoked.push(mac);
        }

        fn set_now(&self, now_unix: u64) {
            self.now
                .store(now_unix, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// An admin certificate, the anchor it verifies against, and the key it is
    /// bound to.
    fn admin_credentials(mac: Mac, not_after: u64) -> (TrustAnchor, Keypair, Vec<u8>) {
        use wayfinder::wayfinder_auth::Authority;
        use zerocopy::IntoBytes;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let admin_kp = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_admin_cert(
            mac,
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            not_after,
        );
        let bytes = cert.as_bytes().to_vec();
        (authority.trust_anchor(), admin_kp, bytes)
    }

    /// Revoking a node ends its open management session, rather than only
    /// stopping the next one.
    ///
    /// This is what makes `RevokeNode` mean what an operator reading its name
    /// assumes: authorization was decided once at connect and a connection has
    /// no bound, so an attacker holding one open kept full access after every
    /// revocation lever had been pulled.
    #[tokio::test]
    async fn a_revocation_ends_an_open_session() {
        let mac = Mac([0, 0, 0, 0, 0, 5]);
        let (anchor, admin_kp, cert) = admin_credentials(mac, 200);
        let (state, gate) = MovableState::new(
            AuthSnapshot {
                own_key: Some([9u8; 32]),
                anchor: Some(anchor),
                revoked: Vec::new(),
            },
            100,
        );
        let (mut client, server) = spawn_gated_server(admin_kp.ed_pubkey(), gate);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert,
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(Response::Empty(_))));

        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(resp.response, Some(Response::NodeInfo(_))),
            "the session serves normally before the revocation"
        );

        state.revoke(mac);

        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        let Some(Response::Error(err)) = resp.response else {
            panic!("a revoked session must not keep being served: {resp:?}");
        };
        assert_eq!(
            err.message, "authentication denied",
            "and it says no more than the connect-time denial does"
        );
        assert!(
            client.next().await.is_none(),
            "the connection is closed, not merely refused one request"
        );
        let _ = server.await;
    }

    /// A certificate that expires mid-session stops being honoured, without
    /// waiting for the client to reconnect.
    ///
    /// Passive expiry is this design's primary revocation mechanism, so a
    /// session that outlives the credential that opened it is the one case
    /// where a short certificate lifetime buys nothing.
    #[tokio::test]
    async fn a_certificate_that_expires_mid_session_stops_being_honoured() {
        let mac = Mac([0, 0, 0, 0, 0, 5]);
        let (anchor, admin_kp, cert) = admin_credentials(mac, 200);
        let (state, gate) = MovableState::new(
            AuthSnapshot {
                own_key: Some([9u8; 32]),
                anchor: Some(anchor),
                revoked: Vec::new(),
            },
            100,
        );
        let (mut client, server) = spawn_gated_server(admin_kp.ed_pubkey(), gate);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert,
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(Response::Empty(_))));

        state.set_now(201);

        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(&resp.response, Some(Response::Error(e)) if e.message == "authentication denied"),
            "an expired certificate stops being honoured: {resp:?}"
        );
        assert!(client.next().await.is_none(), "and the session ends");
        let _ = server.await;
    }

    /// Revalidation that finds nothing changed leaves the session alone.
    ///
    /// The check runs on every request here (the production interval is
    /// `REVALIDATE_AFTER`), so a healthy admin session survives many rounds of
    /// it — a re-decision that drifted would close connections for no reason,
    /// which is the failure mode nobody would look for.
    #[tokio::test]
    async fn revalidation_leaves_an_unchanged_verdict_alone() {
        let mac = Mac([0, 0, 0, 0, 0, 5]);
        let (anchor, admin_kp, cert) = admin_credentials(mac, 200);
        let (_state, gate) = MovableState::new(
            AuthSnapshot {
                own_key: Some([9u8; 32]),
                anchor: Some(anchor),
                revoked: Vec::new(),
            },
            100,
        );
        let (mut client, server) = spawn_gated_server(admin_kp.ed_pubkey(), gate);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert,
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(Response::Empty(_))));

        for n in 0..5 {
            client
                .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
                .await
                .unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            assert!(
                matches!(resp.response, Some(Response::NodeInfo(_))),
                "request {n} after a revalidation round: {resp:?}"
            );
        }

        drop(client);
        let _ = server.await;
    }
}
