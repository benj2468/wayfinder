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
use wayfinder::wayfinder_auth::RevocationRecord;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder_protos::rpc::RateLimit;
use wayfinder_protos::rpc::rate_limit;
use wayfinder_protos::service::EnrollmentPolicyData;
use wayfinder_protos::service::RequestFacet;
use wayfinder_protos::service::audit_request;
use wayfinder_protos::service::enrollment_policy_data;
use wayfinder_protos::service::request_facet;
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
    /// The revocation records the router held as of the snapshot instant.
    ///
    /// Records rather than MACs — see [`AuthSnapshot::revoked`].
    pub revoked: Vec<RevocationRecord>,
    /// This node's own mesh address — see [`AuthSnapshot::own_mac`].
    ///
    /// No part of the access decision: [`decide_access`] never reads it. It
    /// travels here because the VPN handlers run on this task and the router
    /// is the only trustworthy source for it.
    pub own_mac: Mac,
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
            own_mac: snapshot.own_mac,
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

/// Burst capacity for the login limiter.
///
/// Sized for the node, not for a person. `bins/wayfinder-web` performs a login
/// server-side — `session.rs`'s `login` opens the anonymous connection from the
/// axum process, the browser never speaks this protocol — so everyone signing
/// in through one dashboard arrives from one address and spends one bucket.
/// What has to fit inside this number is therefore the whole dashboard's
/// sign-in wave against what the authority can actually serve: one Argon2id at
/// `ARGON2_MEMORY_KIB` at a time, so five already costs the better part of a
/// second during which `AUTHORITY_QUEUE_DEPTH` fills behind it. Enlarging it to
/// give a dashboard's population room re-opens, in proportion, the hole this
/// limiter exists to close.
const LOGIN_BURST: f64 = 5.0;

/// Steady-state refill for the login limiter: one attempt per second.
///
/// Far above any human cadence and far below what a flood needs to be worth
/// mounting. A separate bucket from the enrollment one rather than a shared
/// "anonymous" budget: `SUBMIT_CSR_REFILL_PER_SEC` is a token every five
/// seconds, tuned to the dashboard's approval poll, and a person retyping a
/// password would hit it — while a node polling for approval must not have its
/// budget spent by someone else's failed logins from the same address.
///
/// What this bucket is *not* is the defence against password guessing. That is
/// `users.rs`'s `LOCKOUT_THRESHOLD`, counted against the account rather than
/// the sender, and its own doc already names it the dominant half for exactly
/// that reason. A collapsed source address costs it nothing.
const LOGIN_REFILL_PER_SEC: f64 = 1.0;

/// Burst capacity for the invite-redemption limiter.
///
/// One bucket covers both `BeginUserRegistration` and
/// `CompleteUserRegistration`, unlike the split between logins and `SubmitCsr`:
/// those two are unrelated flows at unrelated cadences, while begin and
/// complete are two steps of *one* flow driven by one person. Separate budgets
/// would bound neither half of what a redemption actually costs.
///
/// Sized for that flow with room to fumble: a start, then a couple of
/// completions while somebody reads a code off their phone.
const REGISTRATION_BURST: f64 = 5.0;

/// Steady-state refill for the invite-redemption limiter: one attempt every two
/// seconds.
///
/// Slower than the login bucket because the flow behind it is rarer — an
/// account is registered once, where a person signs in daily — and because the
/// thing being bounded is worse. A `BeginUserRegistration` scans the invite
/// store and performs a durable write for every call, valid or not, and a
/// `CompleteUserRegistration` that gets past its handle and code checks spends
/// a full Argon2id. Both run on the authority's single command queue.
const REGISTRATION_REFILL_PER_SEC: f64 = 0.5;

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
///
/// **A shared frontend collapses the key, and that is understood here.**
/// `bins/wayfinder-web` speaks the management protocol from its own process, so
/// a dashboard presents one address for its whole population — logins, the
/// enrollment panel's submissions, and every session's connection alike.
/// Behind such a frontend each of these limiters is a node-wide cap rather than
/// a per-peer one. That is still the bound the node needs, because what
/// saturates the authority's queue is the arrival rate and not the sender's
/// identity, and the constants above are sized as node-wide caps for that
/// reason. What is genuinely given up is isolation: the people behind one
/// dashboard share fate, so one of them spending the bucket throttles the rest.
/// Restoring that has to happen in the frontend, the only party that sees a
/// browser's real address — never by letting the node take a source address
/// from a peer that has proved nothing.
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

    /// The limiter guarding the enrollment tier's `AuthenticateUser`.
    fn for_logins() -> Self {
        Self::new(LOGIN_BURST, LOGIN_REFILL_PER_SEC)
    }

    /// The limiter guarding the enrollment tier's two invite-redemption kinds.
    fn for_registrations() -> Self {
        Self::new(REGISTRATION_BURST, REGISTRATION_REFILL_PER_SEC)
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
    /// Rate limit on the enrollment tier's `AuthenticateUser`, per source.
    ///
    /// The costliest thing an uncredentialed peer can ask this node to do: a
    /// full Argon2id at `ARGON2_MEMORY_KIB` plus a durable write, which
    /// `spend_absent_user_work` deliberately charges for an unknown username
    /// too. The authority serves one command at a time, so unthrottled this is
    /// not merely wasted CPU — it holds the authority's queue full and every
    /// operator request on that facet answers "busy" for the duration.
    ///
    /// Per source in name; per *dashboard* for anyone signing in through
    /// `bins/wayfinder-web`, which is the common case rather than the exception
    /// — see [`SourceLimiter`] for why the bound survives that and what does
    /// not.
    logins: SourceLimiter,
    /// Rate limit on the enrollment tier's two invite-redemption kinds, per
    /// source, shared between them.
    ///
    /// Both are reachable with no credential and both reach the authority task:
    /// a start scans the invite store and writes durably whatever the token
    /// turns out to be, and a completion that passes its cheap checks spends a
    /// full Argon2id. One bucket rather than two because they are two steps of
    /// one flow at one person's cadence — see [`REGISTRATION_BURST`].
    registrations: SourceLimiter,
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
            logins: SourceLimiter::for_logins(),
            registrations: SourceLimiter::for_registrations(),
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

    /// Whether an `AuthenticateUser` from `addr` may proceed right now.
    fn allow_login(&self, addr: std::net::IpAddr, now: std::time::Instant) -> bool {
        self.logins.allow(addr, now)
    }

    /// Whether an invite redemption — either half — from `addr` may proceed
    /// right now.
    fn allow_registration(&self, addr: std::net::IpAddr, now: std::time::Instant) -> bool {
        self.registrations.allow(addr, now)
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

/// Send `request` to the owner that can answer it, and return its response.
///
/// This is the fork design 13 §3.2 is about, and it happens *here* — before
/// anything is sent — rather than by trying one owner and falling back. A
/// caller that discovers the owner from an error has already spent the wrong
/// queue's time, and on a node whose authority is mid-Argon2id that queue is
/// the one that stalls the mesh.
///
/// `SetConfig` is the one request that reaches both: it carries an enrollment
/// policy alongside router settings. The router half goes first, preserving the
/// order a single adapter applied them in, and the authority half is sent only
/// when the request actually names one — so a `SetConfig` with no enrollment
/// field never waits on the authority at all.
async fn serve_by_facet(
    request: &WayfinderRequest,
    query_tx: &QueryTx,
    authority_tx: Option<&crate::AuthorityTx>,
    router: Option<&crate::RouterHandle>,
) -> anyhow::Result<WayfinderResponse> {
    // Audited here and nowhere else on this path. The host no longer goes
    // through `WayfinderService::handle`, which is where the audit record used
    // to be emitted, so without this every management mutation and every secret
    // disclosure would stop being logged — and on the certificate authority, a
    // node reachable only over this API, that log ring *is* the audit trail.
    // Emitted before the fork so a request is recorded once, not once per half.
    audit_request(request);

    let Some(kind) = &request.request else {
        return forward_to_router(request, query_tx).await;
    };

    if let ReqKind::SetConfig(set_config) = kind {
        let enrollment = set_config
            .config
            .as_ref()
            .and_then(|c| c.enrollment.clone());
        // Validated *before* the router half runs, not on the way to the
        // authority. These rejections are properties of the request, and the
        // single-adapter path refused the whole `SetConfig` before applying
        // anything — so validating late would apply and durably persist
        // `require_auth` and then answer with the same bare error the operator
        // used to get when nothing had happened. Rejecting up front keeps the
        // request atomic, which is better than reporting a partial one.
        let enrollment = match enrollment.map(enrollment_policy_data).transpose() {
            Ok(enrollment) => enrollment,
            Err(message) => return Ok(error_response(&message)),
        };
        // The router half is forwarded with the enrollment field *removed*, not
        // merely ignored. A `RouterDataProvider` cannot apply it, and a request
        // it silently answers `Empty` to is a request the client believes was
        // applied — so the field is stripped here and the router half errors if
        // it ever sees one, which is what keeps the embedded path (whose only
        // caller is `WayfinderService::handle`, with no fork in front of it)
        // honest about not being a provider.
        let mut router_half = request.clone();
        if let Some(ReqKind::SetConfig(sc)) = &mut router_half.request
            && let Some(config) = sc.config.as_mut()
        {
            config.enrollment = None;
        }
        let response = forward_to_router(&router_half, query_tx).await?;
        // Only if the router half succeeded, and only if there is an enrollment
        // half to apply. Reporting the first error matches the ordering a single
        // adapter had: it applied the router fields before reaching the
        // authority, so a failure there never reached the authority either.
        let (Some(enrollment), Some(RespKind::Empty(_))) = (enrollment, &response.response) else {
            return Ok(response);
        };
        return Ok(set_enrollment_policy(enrollment, authority_tx).await);
    }

    match request_facet(kind) {
        RequestFacet::Authority => match authority_tx {
            Some(tx) => Ok(forward_to_authority(request, tx).await),
            // Answered here rather than by the router loop, which no longer has
            // an authority to produce this from.
            None => Ok(crate::not_a_provider_response()),
        },
        // Answered on *this* task, under a shared borrow of the router, rather
        // than by forwarding to the loop that forwards mesh frames. That is the
        // whole point of the read/write split: sixteen of the nineteen
        // router-facing answers never touch a byte of router state, and a
        // dashboard polling seven of them a second used to build every response
        // on the loop, one at a time, behind a depth-16 channel.
        //
        // Falls back to the channel when no handle was wired — the in-process
        // channel server and the tests that drive a stream directly — so the
        // handle is an optimisation a caller opts into, never a requirement for
        // correctness.
        RequestFacet::RouterRead => match router {
            Some(handle) => match handle.serve_read(request.clone()).await {
                Ok(response) => Ok(response),
                // The read half declined it, which for a `RouterRead` facet
                // should not happen. Forward rather than invent an error: a
                // disagreement between the table and the dispatcher is a bug to
                // be found in a log, not a request to be failed.
                Err(request) => {
                    tracing::warn!(
                        kind = wayfinder_protos::service::request_kind_name(kind),
                        "a RouterRead request was declined by the read dispatcher; forwarding"
                    );
                    forward_to_router(&request, query_tx).await
                }
            },
            None => forward_to_router(request, query_tx).await,
        },
        // A mutation stays on the loop, which is the only place a
        // `&mut CentralRouter` exists — and, for `SetAuth`, the only place the
        // identity-seed slot it writes back through does.
        RequestFacet::RouterWrite | RequestFacet::Transport => {
            forward_to_router(request, query_tx).await
        }
    }
}

/// Forward `request` to the task that owns the router and await its answer.
async fn forward_to_router(
    request: &WayfinderRequest,
    query_tx: &QueryTx,
) -> anyhow::Result<WayfinderResponse> {
    let (resp_tx, resp_rx) = oneshot::channel();
    query_tx.send((request.clone(), resp_tx)).await?;
    Ok(resp_rx.await?)
}

/// Forward `request` to the certificate authority's task and await its answer.
///
/// A full authority queue is answered, not waited on: an unbounded wait here is
/// how a queue full of logins becomes a queue full of stuck connections.
async fn forward_to_authority(
    request: &WayfinderRequest,
    authority_tx: &crate::AuthorityTx,
) -> WayfinderResponse {
    let (resp_tx, resp_rx) = oneshot::channel();
    if let Err(e) =
        authority_tx.try_send(crate::AuthorityCommand::Request(request.clone(), resp_tx))
    {
        return authority_send_failure(e);
    }
    match resp_rx.await {
        Ok(response) => response,
        // The authority dropped the reply without answering: it died mid-request.
        Err(_) => authority_died(),
    }
}

/// Answer a failed hand-off to the authority, distinguishing a full queue from
/// a dead one.
///
/// They are not the same condition and must not read the same: a full queue
/// clears on its own and "retry shortly" is honest, while a closed channel means
/// the authority task is gone for the life of the process and no amount of
/// retrying will help.
fn authority_send_failure(
    e: tokio::sync::mpsc::error::TrySendError<crate::AuthorityCommand>,
) -> WayfinderResponse {
    error_response(authority_send_failure_reason(e))
}

/// The sentence [`authority_send_failure`] answers with, for a caller that has
/// to wrap it in a larger one (a partially-applied `SetConfig`) rather than
/// send it as the whole response.
fn authority_send_failure_reason(
    e: tokio::sync::mpsc::error::TrySendError<crate::AuthorityCommand>,
) -> &'static str {
    match e {
        tokio::sync::mpsc::error::TrySendError::Full(_) => BUSY,
        tokio::sync::mpsc::error::TrySendError::Closed(_) => authority_died_reason(),
    }
}

/// Answer a request that reached a certificate authority which is no longer
/// running.
fn authority_died() -> WayfinderResponse {
    error_response(authority_died_reason())
}

/// The sentence [`authority_died`] answers with, logged as it is produced.
///
/// `error!`, not `warn!`: a provider node whose authority has stopped cannot
/// issue, enroll or revoke anything for the rest of the process's life, and it
/// keeps routing perfectly meanwhile — so nothing else about the node looks
/// wrong. An operator has to be told.
fn authority_died_reason() -> &'static str {
    tracing::error!(
        "the certificate-authority task is no longer running; this node cannot issue, enroll or revoke"
    );
    "this node's certificate authority is not running; it cannot serve enrollment, \
     logins or revocation until the node is restarted"
}

/// Apply the already-validated enrollment half of a `SetConfig` on the
/// authority task.
///
/// Every failure here is a *partial* application: the router half has been
/// applied and durably recorded by the time this runs, so none of these may be
/// answered with a bare error. That includes the no-authority case — "node is
/// not a certificate-authority provider" is a statement about the node's role,
/// and an operator reads it as a wholesale refusal.
async fn set_enrollment_policy(
    enrollment: EnrollmentPolicyData,
    authority_tx: Option<&crate::AuthorityTx>,
) -> WayfinderResponse {
    let Some(tx) = authority_tx else {
        return partial_set_config(crate::NOT_A_PROVIDER);
    };
    let (resp_tx, resp_rx) = oneshot::channel();
    if let Err(e) = tx.try_send(crate::AuthorityCommand::SetEnrollmentPolicy(
        enrollment, resp_tx,
    )) {
        return partial_set_config(authority_send_failure_reason(e));
    }
    match resp_rx.await {
        Ok(Ok(())) => WayfinderResponse {
            response: Some(RespKind::Empty(Empty {})),
        },
        Ok(Err(message)) => partial_set_config(&message),
        Err(_) => partial_set_config(authority_died_reason()),
    }
}

/// Restate a failed enrollment half so it cannot be read as "nothing happened".
///
/// By the time this is reached the router half of the `SetConfig` has already
/// been applied *and durably recorded*. An operator told only that the authority
/// refused would reasonably conclude the whole request was a no-op and retry it,
/// re-applying settings that are already live.
fn partial_set_config(detail: &str) -> WayfinderResponse {
    error_response(&alloc::format!(
        "the node settings in this request were applied and saved; the enrollment policy \
         was not: {detail}"
    ))
}

/// The answer when the authority cannot take more work right now.
///
/// A full queue clears on its own, so "retry shortly" is honest — unlike a
/// closed one, which means the task is gone for the life of the process and no
/// amount of retrying will help.
const BUSY: &str = "the certificate authority is busy; retry shortly";

/// A management error response carrying `message`.
fn error_response(message: &str) -> WayfinderResponse {
    WayfinderResponse {
        response: Some(RespKind::Error(ErrorResponse {
            message: message.to_string(),
        })),
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
/// The listener-wide services every connection is served with: the shared
/// pre-authentication limiter, the channel to the router loop, and the optional
/// VPN coordinator.
///
/// Bundled rather than passed as four more parameters because they travel
/// together and are identical for every connection a listener accepts — only
/// the socket, the peer's key and its `PreAuthGuard` differ per connection.
/// Cloning is cheap: an `Arc`, an `mpsc::Sender`, and an `Option<Arc<_>>`.
#[derive(Clone)]
pub(crate) struct ServeContext {
    /// Bounds the population of not-yet-credentialed connections, mesh-wide and
    /// per source IP, and rate-limits enrollment-tier `SubmitCsr`.
    pub(crate) limits: std::sync::Arc<PreAuthLimits>,
    /// Forwards a decoded request to the single task that owns the router.
    pub(crate) query_tx: QueryTx,
    /// Answers the VPN requests, or `None` on every deployment that runs no
    /// coordination server — which is the default, and every node that is not
    /// the certificate authority.
    pub(crate) vpn: Option<crate::vpn::SharedCoordinator>,
    /// Forwards an authority-facing request to the certificate authority's own
    /// task, or `None` on a node that runs no authority.
    ///
    /// A second channel and not a second use of `query_tx`, which is the point
    /// of the split: authority work and router work must not queue behind each
    /// other. See
    /// `docs/design/implemented/13-certificate-authority-off-the-router-loop.md`.
    pub(crate) authority_tx: Option<crate::AuthorityTx>,
    /// Serves the router *reads* under a shared borrow, on the connection's own
    /// task. `None` falls every read back onto `query_tx`, which is what the
    /// in-process channel server and the stream-level tests do.
    pub(crate) router: Option<crate::RouterHandle>,
}

/// The optional collaborators a management listener serves its connections
/// with: the VPN coordinator, the certificate authority's queue, and the shared
/// router handle.
///
/// One parameter rather than three, because they are one thing — *what this
/// node can additionally answer* — and because a listener signature that grew
/// to seven positional arguments, five of them `Option`, is exactly the
/// per-request illegibility this crate has been pulling apart. Every field is
/// independently optional and every combination is legitimate: a plain relay
/// wires none of them, a certificate authority wires all three.
///
/// [`Default`] is the plain-relay posture, so a caller adds only what it has.
#[derive(Clone, Default)]
pub struct ServerServices {
    /// Answers the three VPN requests, or `None` on every deployment that runs
    /// no coordination server — the default, and every node that is not the CA.
    /// Those answer with "not configured" rather than failing to parse, so a
    /// client can ask without knowing in advance.
    pub vpn: Option<crate::vpn::SharedCoordinator>,
    /// Forwards an authority-facing request to the certificate authority's own
    /// task, or `None` on a node that runs no authority.
    ///
    /// A second channel and not a second use of the query channel, which is the
    /// point of the split: authority work and router work must not queue behind
    /// each other. See
    /// `docs/design/implemented/13-certificate-authority-off-the-router-loop.md`.
    pub authority_tx: Option<crate::AuthorityTx>,
    /// Serves the router *reads* under a shared borrow on the connection's own
    /// task, instead of forwarding them to the driver's event loop.
    ///
    /// `None` sends every read down the query channel as before — correct, just
    /// serialised behind the loop — which is what a test driving a listener
    /// with no driver behind it does.
    pub router: Option<crate::RouterHandle>,
}

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
    mut guard: PreAuthGuard,
    gate: AuthGate,
    ctx: ServeContext,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ServeContext {
        limits,
        query_tx,
        vpn,
        authority_tx,
        router,
    } = ctx;
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
    // Kept beside `decision` and refreshed with it below, for the same reason
    // every other field is read fresh: it is the router's answer, and a serve
    // task that cached one from connect-time would be answering from a
    // snapshot rather than from the router.
    let mut own_mac = ctx.own_mac;
    let decision = authorize(&peer_key, cert.as_ref(), &ctx);
    if let MgmtAccess::Denied(reason) = decision {
        // A rejected management login is security-relevant and worth an
        // operator's attention, but is remotely triggerable, so cap it at warn.
        // The precise `reason` stays in this local log only: a generic message
        // goes over the wire so a not-yet-authenticated peer can't use the
        // response as an oracle (wrong-key vs revoked vs expired vs not-admin)
        // while probing with a stolen or revoked cert.
        tracing::warn!(?reason, "drop: management authentication denied");
        // And latch it, so it outlives the log ring. This is one of the two
        // conditions the alarm board was designed around: the evidence of
        // someone working through the front door is a stream of `warn!` lines,
        // and a stream is precisely what rolls that ring over.
        //
        // Subject is the key the peer *presented*, truncated — so one probing
        // key cannot mask another by folding into its row, and so a client sees
        // which credential was refused rather than only that one was. Not the
        // `reason`, which stays in the local log: the wire answer is
        // deliberately uninformative so a peer cannot use it as an oracle, and
        // an alarm a client reads is a wire answer.
        wayfinder_alarm::alarm!(
            wayfinder_alarm::Severity::Warning,
            wayfinder_alarm::AlarmKind::ManagementAuthFailures,
            wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&peer_key)),
            "cert_presented={}",
            cert.is_some()
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
            own_mac = ctx.own_mac;
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
            // Matched on the request first, because `GetVpnEnrollment` is the
            // one request the *admin* tier can be refused — so keying only on
            // the tier would tell an admin it "is limited to enrollment", which
            // is both false and points them at the wrong fix.
            let message = match (decision, req) {
                (_, ReqKind::GetVpnEnrollment(_)) => {
                    "a VPN credential is issued only to a device: an enrolled node presenting \
                     its own certificate, or a node connecting to itself with its own key. An \
                     operator's session certificate is a person, not a device, so there is no \
                     identity to issue one for"
                }
                (MgmtAccess::GrantedMember, _) => {
                    "this connection is an enrolled device (its certificate carries the \
                     member capability, not a management one); it may fetch its own VPN \
                     credential and nothing else"
                }
                // Ahead of the general viewer arm below, which speaks of
                // "mutations and the enrollment token" — exhaustive until
                // `GetLogs` became the first *read* a viewer is refused, and
                // actively misleading now: it points somebody whose read failed
                // at a fix for a write. Same reason `GetVpnEnrollment` has an
                // arm of its own above.
                (MgmtAccess::GrantedViewer, ReqKind::GetLogs(_)) => {
                    "the node's log ring is served to an admin certificate or the node's own \
                     key. It carries whatever the process logged rather than a chosen set of \
                     fields, which on a certificate authority includes the account records \
                     that name who may administer this mesh"
                }
                (MgmtAccess::GrantedViewer, _) => {
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
        //
        // One arm per costly uncredentialed kind, each with its own bucket:
        // the two cadences are unrelated (a node polling for approval every
        // five seconds, a person retyping a password), so a shared budget would
        // let either starve the other from behind the same address — which a
        // dashboard fronting both flows makes the ordinary case, not a NAT
        // coincidence.
        //
        // Which bucket a request spends is declared beside that request in
        // `rpc_table!`, not matched on here: the two facts a reader needs
        // together — "this request is reachable with no credential" and "this
        // is what it costs" — are then one line apart rather than in two files.
        let refusal = if matches!(decision, MgmtAccess::GrantedEnrollment) {
            let now = std::time::Instant::now();
            match rate_limit(req) {
                RateLimit::Unmetered => None,
                RateLimit::SubmitCsr => (!limits.allow_submit_csr(peer_addr, now)).then_some((
                    "SubmitCsr",
                    "too many enrollment requests from this source; wait before retrying",
                )),
                RateLimit::Login => (!limits.allow_login(peer_addr, now)).then_some((
                    "AuthenticateUser",
                    "too many login attempts from this source; wait before retrying",
                )),
                // Both halves of a redemption share one bucket: they are one
                // flow, and bounding either alone bounds nothing.
                RateLimit::Registration => {
                    (!limits.allow_registration(peer_addr, now)).then_some((
                        "UserRegistration",
                        "too many registration attempts from this source; wait before retrying",
                    ))
                }
            }
        } else {
            None
        };
        if let Some((kind, message)) = refusal {
            tracing::warn!(
                key = ?peer_key,
                %peer_addr,
                kind,
                "drop: enrollment-tier rate limit exceeded"
            );
            send_response(
                &mut responses,
                RespKind::Error(ErrorResponse {
                    message: message.into(),
                }),
            )
            .await?;
            continue;
        }
        // The VPN requests are answered here rather than by the router loop.
        // Two reasons, and either alone would be decisive: the router loop is
        // never told *who* is asking (the query channel carries a request and a
        // reply channel, nothing else), and `GetVpnEnrollment` mints a
        // credential for the caller's own identity — which only this layer
        // holds. They are also network I/O, and the router loop that would
        // otherwise await them is the loop emitting OGMs.
        if let Some(vpn_response) =
            serve_vpn_request(req, decision, cert.as_ref(), own_mac, vpn.as_ref()).await
        {
            send_response(&mut responses, vpn_response).await?;
            continue;
        }
        // A certificate authority must not revoke itself.
        //
        // Refused *here*, before the request reaches the authority, because
        // the authority signs and durably records a revocation before the
        // router is ever asked to flood it — so by the time anything could
        // notice, the act is irreversible. And what it would destroy is the
        // mesh's root of trust: the CA would go inert, partitioning whatever
        // it routes for, and clearing its auth state empties the anchor every
        // management connection is authorized against, dropping every admin to
        // the enrollment tier. No `ApproveCsr`, no `RevokeNode`, no account
        // administration, and nothing left that can enroll anybody — recovered
        // only from the CA's own identity seed.
        //
        // This layer is the one that knows: `own_mac` comes from the router,
        // which the authority task cannot see.
        if let Some(ReqKind::RevokeNode(revoke)) = &request.request
            && revoke.node_mac == own_mac.0
        {
            tracing::warn!("drop: refusing to revoke this node, which is the authority");
            send_response(
                &mut responses,
                RespKind::Error(ErrorResponse {
                    message: "this node is the certificate authority; revoking it would take the mesh's root of trust off the mesh and leave nobody able to enroll or re-admit anyone, including itself"
                        .into(),
                }),
            )
            .await?;
            continue;
        }
        // Nor may it enroll itself, which is the same rule on the way in.
        //
        // The authority's MAC-lock — one MAC, one key, until the certificate
        // expires — is read off the issued-cert log, and the CA's own
        // membership certificate is not in it: that identity is minted offline
        // with `wayfinderctl cert` and provisioned as a file the node's config
        // points at (`nix/machines/wayfinder-ca/common.nix`), or installed over
        // `SetAuth`; neither path records an enrollment. The one address on the
        // mesh whose impersonation matters most is therefore the one address
        // the lock has nothing on file to refuse against, and under
        // `auto_approve` an anonymous enrollment-tier caller could have a
        // root-signed certificate minted binding the CA's MAC to keys it chose:
        // the member tier, OGM signatures the mesh verifies as the authority's,
        // and the CA's own device registration on the tunnel via
        // `GetVpnEnrollment`.
        //
        // With approval required this is "only" a pending CSR — but one whose
        // queue entry is a bare MAC an operator has no reason to read as this
        // node's own. Refusing outright is what makes it unnecessary to notice.
        // `ApproveCsr` is guarded with it for that same reason and one more:
        // the held-CSR store is persisted, so a queue entry submitted before
        // this guard existed survives the upgrade that adds it, and
        // `approve_csr` re-signs from the stored keys without re-running any of
        // `submit_csr`'s checks.
        //
        // Here rather than in the authority, for the reason the revoke guard
        // above gives: `own_mac` comes from the router, which the authority
        // task cannot see. An *ordinary* node re-enrolling its own identity
        // does not come through here: its CSR names its own MAC but arrives at
        // the CA, whose `own_mac` is a different address.
        //
        // Gated on there being an authority, unlike the revoke guard above: on
        // a node that is not a provider the honest answer is
        // `not_a_provider_response`, and claiming to be the certificate
        // authority would send an operator looking for CA state on a machine
        // that has none.
        //
        // One request kind pair, because the enrollment tier has exactly one
        // mutation. Anything added to that tier in `rpc_table!` that names a
        // MAC needs a line here.
        let names_own_mac = match &request.request {
            Some(ReqKind::SubmitCsr(csr)) => csr.node_mac == own_mac.0,
            Some(ReqKind::ApproveCsr(approve)) => approve.node_mac == own_mac.0,
            _ => false,
        };
        if names_own_mac && authority_tx.is_some() {
            // The keys the caller wanted signed are the useful artifact here,
            // but they are also the thing not to write to a log ring; the MAC
            // and who asked are what an operator can act on. Reachable by an
            // anonymous enrollment-tier caller, so `warn!` rather than
            // `error!` — and bounded by the `SubmitCsr` rate limiter above
            // plus `PreAuthSlots`, so it is not a flooding vector.
            tracing::warn!(
                key = ?peer_key,
                %peer_addr,
                ?own_mac,
                "drop: refusing a CSR naming this node, which is the authority"
            );
            send_response(
                &mut responses,
                RespKind::Error(ErrorResponse {
                    message: "this node is the certificate authority; its own address is not \
                              enrollable, and a certificate issued for it would let the holder \
                              sign and route as the mesh's root of trust"
                        .into(),
                }),
            )
            .await?;
            continue;
        }
        let response =
            serve_by_facet(&request, &query_tx, authority_tx.as_ref(), router.as_ref()).await?;
        // Mesh revocation and VPN revocation are one operator action, so the
        // second half runs here once the first has succeeded. Ordered this way
        // deliberately: mesh membership is what actually grants routing trust,
        // so it goes first and a failure there leaves the tunnel alone rather
        // than stranding a node that is still a member.
        let response = match (&request.request, &response.response) {
            (Some(ReqKind::RevokeNode(revoke)), Some(RespKind::Empty(_))) => {
                revoke_vpn_alongside_mesh(&revoke.node_mac, vpn.as_ref(), response).await
            }
            _ => response,
        };
        let mut buf = Vec::new();
        response.encode(&mut buf)?;
        responses.send(Bytes::from(buf)).await?;
    }
    Ok(())
}

/// Answer one of the three VPN requests, or `None` if `req` is not one and the
/// router should serve it.
///
/// `permits` has already run, so reaching a given arm here means the tier was
/// authorized for it. The MAC a credential is minted for comes from the
/// connection's tier — see [`credential_mac`] — never from the request, which
/// is why `GetVpnEnrollmentRequest` carries no fields at all.
async fn serve_vpn_request(
    req: &ReqKind,
    decision: MgmtAccess,
    cert: Option<&MembershipCert>,
    own_mac: Mac,
    vpn: Option<&crate::vpn::SharedCoordinator>,
) -> Option<RespKind> {
    use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentResponse;
    use wayfinder_protos::wayfinder::v1alpha::ListVpnPeersResponse;
    use wayfinder_protos::wayfinder::v1alpha::VpnPeerStatus;

    let configured = match (req, vpn) {
        (
            ReqKind::GetVpnEnrollment(_) | ReqKind::ListVpnPeers(_) | ReqKind::RevokeVpnPeer(_),
            Some(vpn),
        ) => vpn,
        // Not a VPN request: the router serves it.
        (
            ReqKind::GetVpnEnrollment(_) | ReqKind::ListVpnPeers(_) | ReqKind::RevokeVpnPeer(_),
            None,
        ) => {
            return Some(vpn_error(&crate::vpn::VpnError::NotConfigured));
        }
        _ => return None,
    };

    Some(match req {
        ReqKind::GetVpnEnrollment(_) => {
            // Belt and braces with `permits`, which already confined this
            // request to the two tiers that name a device. The MAC below is
            // only meaningful because of what those tiers mean — a verified
            // certificate bound to this handshake, or the node's own address —
            // so re-stating the condition here keeps the two from drifting
            // apart silently if the policy is ever edited.
            let Some(mac) = credential_mac(decision, cert, own_mac) else {
                tracing::warn!("VPN enrollment refused: connection holds no device identity");
                return Some(RespKind::Error(ErrorResponse {
                    message: "a VPN credential is issued only to a device: an enrolled node \
                              presenting its own certificate, or a node connecting to itself \
                              with its own key"
                        .into(),
                }));
            };
            match configured.enroll(mac).await {
                Ok(enrollment) => {
                    // The MAC, never the key: this line records that a
                    // credential was minted and for whom, which is the whole
                    // audit value, while the key itself is a bearer secret.
                    tracing::info!(?mac, "minted a VPN enrollment credential");
                    RespKind::VpnEnrollment(GetVpnEnrollmentResponse {
                        vpn_login_server: enrollment.login_server,
                        vpn_preauth_key: enrollment.preauth_key,
                    })
                }
                Err(e) => {
                    tracing::warn!(?mac, error = %e, "VPN enrollment failed");
                    vpn_error(&e)
                }
            }
        }
        ReqKind::ListVpnPeers(_) => match configured.peers().await {
            Ok(peers) => RespKind::ListVpnPeers(ListVpnPeersResponse {
                peers: peers
                    .into_iter()
                    .map(|p| VpnPeerStatus {
                        node_mac: p.mac.map(|m| m.0.to_vec()).unwrap_or_default(),
                        raw_hostname: p.hostname,
                        tailscale_ip: p.address,
                        online: p.online,
                        last_seen_unix: p.last_seen_unix,
                        key_expiry_unix: p.key_expiry_unix,
                    })
                    .collect(),
            }),
            Err(e) => {
                tracing::warn!(error = %e, "listing VPN peers failed");
                vpn_error(&e)
            }
        },
        ReqKind::RevokeVpnPeer(revoke) => match mac_from_bytes(&revoke.node_mac) {
            Some(mac) => match configured.revoke(mac).await {
                Ok(()) => {
                    tracing::info!(?mac, "revoked a VPN registration");
                    RespKind::Empty(Empty {})
                }
                Err(e) => {
                    tracing::warn!(?mac, error = %e, "VPN revocation failed");
                    vpn_error(&e)
                }
            },
            None => RespKind::Error(ErrorResponse {
                message: "node_mac must be exactly 6 bytes".into(),
            }),
        },
        _ => return None,
    })
}

/// Remove `node_mac`'s VPN registration after its mesh membership has been
/// revoked, downgrading `mesh_response` to an error if that second half fails.
///
/// A partial revoke is not a security hole — tunnel reachability is not mesh
/// trust, and the mesh half (the half that matters) has already succeeded — but
/// reporting it as a clean success would leave an operator believing a node was
/// fully removed when its tunnel access remains. The error names the retry, and
/// `RevokeVpnPeer` is idempotent precisely so that retry converges.
async fn revoke_vpn_alongside_mesh(
    node_mac: &[u8],
    vpn: Option<&crate::vpn::SharedCoordinator>,
    mesh_response: WayfinderResponse,
) -> WayfinderResponse {
    let (Some(vpn), Some(mac)) = (vpn, mac_from_bytes(node_mac)) else {
        return mesh_response;
    };
    match vpn.revoke(mac).await {
        Ok(()) => mesh_response,
        Err(e) => {
            // A handled, retried failure of an outbound call to the
            // coordination server — not a fault originating in this node —
            // so `warn!`, matching every other `VpnError` log site in this
            // file rather than `error!`.
            tracing::warn!(
                ?mac,
                error = %e,
                "mesh revocation succeeded but VPN revocation failed; the node's tunnel \
                 access remains until this is retried"
            );
            WayfinderResponse {
                response: Some(RespKind::Error(ErrorResponse {
                    message: half_completed_revoke_message(mac),
                })),
            }
        }
    }
}

/// The message a half-completed revoke answers with. Split out so the sentence
/// an operator reads is in one place.
fn half_completed_revoke_message(mac: Mac) -> String {
    format!(
        "mesh membership for {mac:?} was revoked, but removing its VPN registration failed; \
         the node can no longer route but can still reach the tunnel. Retry with \
         `wayfinderctl vpn revoke`."
    )
}

/// The device identity a VPN credential is minted for on this connection, or
/// `None` if the connection holds no device identity at all.
///
/// Two tiers do, and the MAC comes from a different place for each — which is
/// the whole security property of the enrollment RPC, since the request itself
/// carries no fields to ask with.
///
/// * [`MgmtAccess::GrantedMember`]: the MAC in the presented certificate. The
///   tier is what makes it trustworthy — `decide_access` grants it only after
///   verifying that certificate against the anchor *and* checking that its key
///   is the one the handshake proved.
/// * [`MgmtAccess::GrantedSelfKey`]: `own_mac`, this node's own mesh address,
///   read from the router. Deliberately *not* the presented certificate: the
///   self-key tier is granted on the handshake key alone, before any
///   certificate is verified, so a `node_mac` read there would let whoever
///   holds a node's seed register a device under another node's Headscale user
///   — and that user name is the only record of the peer↔mesh-identity
///   mapping.
///
/// Every other tier is `None`: an operator's session certificate is a person
/// and a stranger holds nothing, so there is nothing to mint for.
fn credential_mac(
    decision: MgmtAccess,
    cert: Option<&MembershipCert>,
    own_mac: Mac,
) -> Option<Mac> {
    match decision {
        MgmtAccess::GrantedMember => Some(Mac(cert?.node_mac)),
        MgmtAccess::GrantedSelfKey => Some(own_mac),
        _ => None,
    }
}

/// A 6-byte MAC from wire bytes, or `None` if the length is wrong.
fn mac_from_bytes(bytes: &[u8]) -> Option<Mac> {
    bytes.try_into().ok().map(Mac)
}

/// Render a [`VpnError`](crate::vpn::VpnError) as a response.
///
/// "Not configured" is deliberately the same shape as a failure rather than a
/// distinct success: a client asking a CA that has no VPN gets a sentence
/// saying so, and the CLI treats it as "no VPN here" and finishes enrolling.
fn vpn_error(e: &crate::vpn::VpnError) -> RespKind {
    RespKind::Error(ErrorResponse {
        message: e.to_string(),
    })
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
        |cert| ctx.revoked.iter().any(|r| r.cancels(cert, ctx.now_unix)),
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
    /// The revocation records the router currently holds.
    ///
    /// The records themselves rather than the MACs they name, because a MAC
    /// can no longer answer "is this certificate cancelled?": a certificate
    /// issued after the revocation instant is a re-admission and survives it.
    /// Carrying the records keeps that judgement on the accept loop's side of
    /// the channel, which is the property this snapshot exists to preserve —
    /// no router borrow is taken to authorize a connection.
    pub revoked: Vec<RevocationRecord>,
    /// This node's own mesh address (`CentralRouter::self_ident`).
    ///
    /// The identity a
    /// [`MgmtAccess::GrantedSelfKey`](crate::MgmtAccess::GrantedSelfKey)
    /// connection's VPN credential is minted for. It comes from the router
    /// rather than from the certificate on the connection because that
    /// certificate is never verified on the self-key path — `decide_access`
    /// grants the tier on the handshake key alone, before it reaches the
    /// anchor — so a MAC read there would be a value the client chose. Not
    /// an `Option`: a router always has an address, whether or not it is
    /// enrolled.
    pub own_mac: Mac,
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
    serve_tls_server_with_vpn(
        listener,
        own_seed,
        snapshot_tx,
        query_tx,
        ServerServices::default(),
    )
    .await
}

/// [`serve_tls_server`], plus the VPN coordinator this listener answers the
/// VPN requests with.
///
/// `vpn` is `None` for every deployment that does not run a coordination server
/// — which is the default, and every node that is not the CA. Those answer the
/// three VPN requests with "not configured" rather than failing to parse them,
/// so a client can ask without knowing in advance.
///
/// `router` serves the router *reads* under a shared borrow, on the connection
/// task, instead of forwarding them to the driver's event loop. `None` sends
/// every read down `query_tx` as before — correct, just serialised behind the
/// loop — which is what the tests that drive a listener without a driver do.
pub async fn serve_tls_server_with_vpn(
    listener: TcpListener,
    own_seed: [u8; 32],
    snapshot_tx: AuthSnapshotTx,
    query_tx: QueryTx,
    services: ServerServices,
) -> anyhow::Result<()> {
    let ServerServices {
        vpn,
        authority_tx,
        router,
    } = services;
    // Which path the reads will take, said once at startup. A missing handle
    // is not an error — it is correct, just serialised behind the driver loop —
    // so nothing else would ever mention it, and "the dashboard feels slow
    // again" is not a diagnosis anyone can reach from the logs. Lifecycle fact,
    // once per listener: `info!`.
    match &router {
        Some(_) => tracing::info!(
            "management reads served off the driver loop (shared router handle wired)"
        ),
        None => tracing::info!(
            "no shared router handle; management reads are forwarded to the driver loop"
        ),
    }
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
        let ctx = ServeContext {
            limits: std::sync::Arc::clone(&limits),
            query_tx: query_tx.clone(),
            vpn: vpn.clone(),
            authority_tx: authority_tx.clone(),
            router: router.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = serve_tls_connection(acceptor, tcp, peer, snapshot_tx, guard, ctx).await
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
    guard: PreAuthGuard,
    ctx: ServeContext,
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
        guard,
        AuthGate::new(snapshot_tx),
        ctx,
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

    /// A stand-in certificate authority that answers every request with
    /// `Empty`, for harnesses whose subject is the connection task rather than
    /// the authority itself.
    fn spawn_stub_authority() -> crate::AuthorityTx {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::AuthorityCommand>(8);
        tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    crate::AuthorityCommand::Request(_, reply) => {
                        let _ = reply.send(WayfinderResponse {
                            response: Some(RespKind::Empty(Empty {})),
                        });
                    }
                    crate::AuthorityCommand::SetEnrollmentPolicy(_, reply) => {
                        let _ = reply.send(Ok(()));
                    }
                }
            }
        });
        tx
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
            clock_trusted: true,
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
        revoked: Vec<RevocationRecord>,
        own_mac: Mac,
    ) {
        tokio::spawn(async move {
            while let Some(reply) = rx.recv().await {
                let _ = reply.send(AuthSnapshot {
                    own_key,
                    anchor,
                    revoked: revoked.clone(),
                    own_mac,
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
        spawn_snapshots(
            snapshot_rx,
            ctx.own_key,
            ctx.anchor,
            ctx.revoked,
            ctx.own_mac,
        );
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
        spawn_gated_server_with_vpn(peer_key, gate, response, None)
    }

    /// As [`spawn_gated_server_answering`], but standing in for a node that is
    /// **not** a provider — no authority channel at all.
    ///
    /// The other harnesses all wire a stub authority, because their subject is
    /// the connection task's routing. A guard that must behave differently on a
    /// plain routing node needs the case they deliberately do not cover.
    fn spawn_gated_server_without_authority(
        peer_key: [u8; 32],
        gate: AuthGate,
    ) -> (
        Framed<tokio::io::DuplexStream, LengthDelimitedCodec>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo_of(query_rx, canned_node_info());
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let peer_addr = std::net::Ipv4Addr::LOCALHOST.into();
        let limits = std::sync::Arc::new(PreAuthLimits::new());
        let guard = limits
            .admit(peer_addr, std::time::Instant::now())
            .expect("a fresh limiter admits the first connection");
        let server = tokio::spawn(serve_authenticated_stream(
            server_io,
            peer_key,
            peer_addr,
            guard,
            gate,
            ServeContext {
                limits,
                query_tx,
                vpn: None,
                authority_tx: None,
                router: None,
            },
        ));
        (
            LengthDelimitedCodec::builder().new_framed(client_io),
            server,
        )
    }

    /// As [`spawn_gated_server_answering`], with the VPN coordinator the
    /// connection answers the VPN requests from.
    fn spawn_gated_server_with_vpn(
        peer_key: [u8; 32],
        gate: AuthGate,
        response: Response,
        vpn: Option<crate::vpn::SharedCoordinator>,
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
            server_io,
            peer_key,
            peer_addr,
            guard,
            gate,
            ServeContext {
                limits,
                query_tx,
                vpn,
                // These harnesses stand in for a provider node: the subject is
                // the connection task's routing, so the authority answers
                // trivially rather than being absent.
                authority_tx: Some(spawn_stub_authority()),
                // No shared handle: these harnesses have no driver, so reads go
                // down the query channel exactly as they did before it existed.
                router: None,
            },
        ));
        (
            LengthDelimitedCodec::builder().new_framed(client_io),
            server,
        )
    }

    /// A read is answered from the shared handle and **never reaches the query
    /// channel** — which is the whole point of wiring one in.
    ///
    /// Proved by giving the connection a query channel whose receiver is
    /// dropped: anything forwarded to the loop fails the send, so a read that
    /// took the old path could not be answered at all. The `GetNodeInfo` that
    /// comes back therefore came from the handle.
    #[tokio::test]
    async fn a_read_is_served_from_the_handle_and_never_reaches_the_loop() {
        let key = [11u8; 32];
        let ctx = AuthContext {
            own_key: Some(key),
            anchor: None,
            revoked: Vec::new(),
            now_unix: 0,
            own_mac: Mac([0, 0, 0, 0, 0, 9]),
        };

        // A live sender with a dead receiver: `forward_to_router` errors on the
        // send, so the loop path is not merely unused here, it is unusable.
        let (query_tx, query_rx) = mpsc::channel(16);
        drop(query_rx);

        let shared = std::sync::Arc::new(tokio::sync::RwLock::new(crate::SharedRouter::new(
            wayfinder::CentralRouter::new(Mac([0, 0, 0, 0, 0, 9])),
        )));
        let handle = crate::RouterHandle::new(shared, std::time::Instant::now());

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let peer_addr = std::net::Ipv4Addr::LOCALHOST.into();
        let limits = std::sync::Arc::new(PreAuthLimits::new());
        let guard = limits
            .admit(peer_addr, std::time::Instant::now())
            .expect("a fresh limiter admits the first connection");
        let server = tokio::spawn(serve_authenticated_stream(
            server_io,
            key,
            peer_addr,
            guard,
            gate_returning(ctx),
            ServeContext {
                limits,
                query_tx,
                vpn: None,
                authority_tx: None,
                router: Some(handle),
            },
        ));
        let mut client = LengthDelimitedCodec::builder().new_framed(client_io);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(ack.response, Some(RespKind::Empty(_))));

        client
            .send(encode_request(Request::GetNodeInfo(
                wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest {},
            )))
            .await
            .unwrap();
        let response = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match response.response {
            Some(RespKind::NodeInfo(info)) => assert_eq!(info.node_id, vec![0, 0, 0, 0, 0, 9]),
            other => panic!("expected NodeInfo served from the handle, got {other:?}"),
        }

        drop(client);
        let _ = server.await;
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            !matches!(&resp.response, Some(Response::Error(e)) if e.message.contains("too many")),
            "GetTrustAnchor is not itself rate-limited"
        );

        drop(client);
        let _ = server.await;
    }

    /// A login is rate-limited per source on the enrollment tier, for the same
    /// reason `SubmitCsr` is and more urgently.
    ///
    /// `AuthenticateUser` is reachable by any peer that completes the handshake
    /// with a self-generated key — no credential — and `spend_absent_user_work`
    /// makes an unknown username cost exactly what a known one does: a full
    /// Argon2id at `ARGON2_MEMORY_KIB` plus a durable write. The authority task
    /// serves one command at a time, so an unthrottled flood of logins does not
    /// merely waste CPU: it keeps the authority's queue permanently full, and
    /// every operator `ApproveCsr`, `ListCerts` or `RevokeNode` comes back
    /// "busy; retry shortly" for as long as the flood lasts. Design 13 §3.7.
    ///
    /// Its own bucket, not the enrollment one: `SUBMIT_CSR_REFILL_PER_SEC` is a
    /// token every five seconds, tuned to the dashboard's approval poll, and a
    /// person retyping a mistyped password would hit it.
    #[tokio::test]
    async fn authenticate_user_on_the_enrollment_tier_is_rate_limited_per_source() {
        let ctx = AuthContext {
            own_key: Some([1u8; 32]), // un-enrolled ⇒ every other key is GrantedEnrollment
            anchor: None,
            revoked: Vec::new(),
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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

        let login = || {
            encode_request(Request::AuthenticateUser(
                wayfinder_protos::wayfinder::v1alpha::AuthenticateUserRequest::default(),
            ))
        };

        // The burst is spent without being throttled: a person mistyping a
        // password a few times must not be locked out.
        for n in 0..LOGIN_BURST as u32 {
            client.send(login()).await.unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            assert!(
                !matches!(&resp.response, Some(Response::Error(_))),
                "login {n} of the burst capacity was refused: {:?}",
                resp.response
            );
        }

        // One more, immediately: refused before it can reach the authority.
        client.send(login()).await.unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => {
                assert!(e.message.contains("too many"), "got: {}", e.message)
            }
            other => panic!("expected the rate limit to refuse this login, got {other:?}"),
        }

        // A separate bucket from enrollment: spending every login token must
        // not throttle the `SubmitCsr` of a node that is genuinely enrolling.
        client
            .send(encode_request(Request::SubmitCsr(
                SubmitCsrRequest::default(),
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            !matches!(&resp.response, Some(Response::Error(_))),
            "the login limiter must not spend the enrollment limiter's tokens, got {:?}",
            resp.response
        );

        drop(client);
        let _ = server.await;
    }

    /// Redeeming an invite is rate-limited per source too, and both halves of
    /// the redemption share one bucket.
    ///
    /// Both are reachable with no credential, and both reach the authority
    /// task: a `BeginUserRegistration` scans the invite store and performs a
    /// durable write, and a `CompleteUserRegistration` that gets past its
    /// handle and TOTP checks spends a full Argon2id. Unbounded, either keeps
    /// the authority's single command queue full and every operator request on
    /// that facet answers "busy".
    ///
    /// One bucket rather than one each, unlike the split between logins and
    /// `SubmitCsr`: begin and complete are two steps of *one* flow at one
    /// human's cadence, so giving them separate budgets would bound neither
    /// half of what a redemption actually costs.
    #[tokio::test]
    async fn redeeming_an_invite_on_the_enrollment_tier_is_rate_limited_per_source() {
        use wayfinder_protos::wayfinder::v1alpha::BeginUserRegistrationRequest;
        use wayfinder_protos::wayfinder::v1alpha::CompleteUserRegistrationRequest;

        let ctx = AuthContext {
            own_key: Some([1u8; 32]), // un-enrolled ⇒ every other key is GrantedEnrollment
            anchor: None,
            revoked: Vec::new(),
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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

        let begin = || {
            encode_request(Request::BeginUserRegistration(
                BeginUserRegistrationRequest::default(),
            ))
        };
        let complete = || {
            encode_request(Request::CompleteUserRegistration(
                CompleteUserRegistrationRequest::default(),
            ))
        };

        // The burst is spent without throttling: somebody mistyping their TOTP
        // code a couple of times must be able to finish registering.
        for n in 0..REGISTRATION_BURST as u32 {
            client.send(begin()).await.unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            assert!(
                !matches!(&resp.response, Some(Response::Error(e)) if e.message.contains("too many")),
                "redemption {n} of the burst capacity was throttled early"
            );
        }

        // One more, immediately: refused before it can reach the authority —
        // and refused for the *other* half of the flow too, since they share a
        // bucket.
        for request in [begin(), complete()] {
            client.send(request).await.unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            match resp.response {
                Some(Response::Error(e)) => {
                    assert!(e.message.contains("too many"), "got: {}", e.message)
                }
                other => panic!("expected the rate limit to refuse this, got {other:?}"),
            }
        }

        // Its own bucket, though: a node genuinely enrolling, and a person
        // genuinely signing in, must not be throttled by somebody else's
        // registration attempts from behind the same address.
        for request in [
            encode_request(Request::SubmitCsr(SubmitCsrRequest::default())),
            encode_request(Request::AuthenticateUser(
                wayfinder_protos::wayfinder::v1alpha::AuthenticateUserRequest::default(),
            )),
        ] {
            client.send(request).await.unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            assert!(
                !matches!(&resp.response, Some(Response::Error(e)) if e.message.contains("too many")),
                "the registration limiter must not spend another limiter's tokens"
            );
        }

        drop(client);
        let _ = server.await;
    }

    /// A login on a fully-granted connection is not rate-limited: the tier
    /// already required a real credential, which is not the resource an
    /// anonymous flood is spending.
    #[tokio::test]
    async fn authenticate_user_is_not_rate_limited_on_a_fully_granted_connection() {
        use wayfinder::wayfinder_auth::Authority;
        use zerocopy::IntoBytes;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let admin_kp = Keypair::from_seed(&[2u8; 32]);
        let admin_cert = authority.issue_user_cert(
            admin_kp.derived_mac(),
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
            true,
        );
        let ctx = AuthContext {
            own_key: Some([9u8; 32]), // not the client's key: only the cert can admit it
            anchor: Some(authority.trust_anchor()),
            revoked: Vec::new(),
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
        assert!(matches!(ack.response, Some(Response::Empty(_))), "admin");

        for n in 0..(LOGIN_BURST as u32 + 5) {
            client
                .send(encode_request(Request::AuthenticateUser(
                    wayfinder_protos::wayfinder::v1alpha::AuthenticateUserRequest::default(),
                )))
                .await
                .unwrap();
            let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
            assert!(
                !matches!(&resp.response, Some(Response::Error(_))),
                "login {n} on a credentialed connection was refused: {:?}",
                resp.response
            );
        }

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
    ///
    /// Linux-only in practice, hence the `ignore`: the second source needs a
    /// second loopback address, and only Linux gives `127.0.0.0/8` to `lo`
    /// wholesale. macOS assigns `lo0` just `127.0.0.1`, so binding `127.0.0.2`
    /// fails with `EADDRNOTAVAIL` there. Ignored rather than `cfg`'d out so it
    /// stays visible in the test list, and so a macOS developer who wants it
    /// can have it: `sudo ifconfig lo0 alias 127.0.0.2 up`, then
    /// `cargo nextest run --run-ignored all -E 'test(submit_csr_rate_limit)'`.
    #[tokio::test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "needs a second loopback address (127.0.0.2); see the doc comment"
    )]
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
                    own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
                    own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
                        own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
        let admin_cert = authority.issue_user_cert(
            admin_kp.derived_mac(),
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
            true,
        );
        let ctx = AuthContext {
            own_key: Some([9u8; 32]), // not the client's key: only the cert can admit it
            anchor: Some(authority.trust_anchor()),
            revoked: Vec::new(),
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
        let admin_cert = authority.issue_user_cert(
            admin_mac,
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
            true,
        );
        let ctx = AuthContext {
            own_key: Some([9u8; 32]),
            anchor: Some(authority.trust_anchor()),
            // This admin's node is revoked: the record's instant is after the
            // certificate's `not_before` of 0, so it cancels it.
            revoked: vec![authority.revoke(admin_mac, 50, 200)],
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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

    /// A refused management login leaves an alarm behind, so the attempt
    /// outlives the log ring the `warn!` beside it lands in.
    ///
    /// This is one of the two conditions §1 of the alarm design is built around:
    /// somebody working through the front door produces exactly the stream of
    /// records that rolls that ring over, and an operator who attaches
    /// afterwards would otherwise find no trace of it.
    ///
    /// Asserted against the *process* board rather than a scoped one, unlike the
    /// detector tests in `wayfinder-driver-core`: the raise happens on the
    /// server task, and `with_board`'s scope is thread-local, so it would not
    /// reach it. Made robust instead by giving this client a key no other test
    /// uses and looking that subject up — the board is keyed by
    /// `(kind, subject)`, so the row is this test's alone.
    #[tokio::test]
    async fn a_refused_login_latches_an_alarm_naming_the_key_that_was_refused() {
        use wayfinder::wayfinder_auth::Authority;
        use zerocopy::IntoBytes;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        // A seed no other test in this process uses, so the subject below
        // identifies this attempt and nothing else.
        let admin_kp = Keypair::from_seed(&[0x7eu8; 32]);
        let admin_mac = Mac([0, 0, 0, 0, 0, 0x7e]);
        let admin_cert = authority.issue_user_cert(
            admin_mac,
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
            true,
        );
        let ctx = AuthContext {
            own_key: Some([9u8; 32]),
            anchor: Some(authority.trust_anchor()),
            revoked: vec![authority.revoke(admin_mac, 50, 200)],
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
            now_unix: 100,
        };
        let subject =
            wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&admin_kp.ed_pubkey()));
        assert!(
            !wayfinder_alarm::snapshot()
                .alarms
                .iter()
                .any(|a| a.subject == subject),
            "this key must be unused before the attempt, or the assertion below proves nothing"
        );

        let (mut client, server) = spawn_authenticated_server(admin_kp.ed_pubkey(), ctx);
        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: admin_cert.as_bytes().to_vec(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp.response, Some(Response::Error(_))));
        assert!(client.next().await.is_none());
        let _ = server.await;

        let raised = wayfinder_alarm::snapshot()
            .alarms
            .into_iter()
            .find(|a| a.subject == subject)
            .expect("the refusal is on the board");
        assert_eq!(
            raised.kind,
            wayfinder_alarm::AlarmKind::ManagementAuthFailures
        );
        assert_eq!(raised.severity, wayfinder_alarm::Severity::Warning);
        assert!(
            !raised.detail.contains("revoked"),
            "the wire answer is deliberately uninformative, and an alarm a \
             client reads is a wire answer"
        );
    }

    /// A non-empty but unparseable membership cert is refused explicitly (not
    /// silently treated as "no cert" / bootstrap), and the connection closed.
    #[tokio::test]
    async fn authenticated_stream_denies_malformed_cert() {
        let ctx = AuthContext {
            own_key: Some([9u8; 32]),
            anchor: None,
            revoked: Vec::new(),
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
            now_unix: 100,
        };
        let big = Response::NodeInfo(NodeInfo {
            node_id: vec![7u8; crate::MAX_FRAME_LEN * 4],
            num_originators: 1,
            auth_locked: false,
            runtime_config_active: false,
            clock_trusted: true,
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
            own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
            guard,
            gate_returning(ctx),
            ServeContext {
                limits: std::sync::Arc::clone(&limits),
                query_tx,
                vpn: None,
                authority_tx: None,
                router: None,
            },
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
            Mac([2, 0, 0, 0, 0, 1]),
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
    use wayfinder::wayfinder_auth::Authority;

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
                        own_mac: Mac([2, 0, 0, 0, 0, 1]),
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

        /// Revoke `mac` as of `instant`, signed by `authority` so the record
        /// is one the production path would actually accept.
        ///
        /// Takes the authority rather than fabricating a record because a
        /// revocation now has to be judged against the certificate it
        /// cancels — `instant` must be at or after that certificate's own
        /// `not_before`, or the record verifies and cancels nothing.
        fn revoke(&self, authority: &Authority, mac: Mac, instant: u64, not_after: u64) {
            self.snapshot
                .lock()
                .unwrap()
                .revoked
                .push(authority.revoke(mac, instant, not_after));
        }

        fn set_now(&self, now_unix: u64) {
            self.now
                .store(now_unix, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// An admin certificate, the anchor it verifies against, the key it is
    /// bound to, and the authority that issued it.
    ///
    /// The authority comes back because revoking this certificate now needs a
    /// record signed by the same root — a MAC on its own no longer says
    /// whether a given certificate is cancelled.
    ///
    /// Takes no address: a certificate's subject is the address its key derives
    /// (design 09 §5), so the caller reads the MAC back off the returned
    /// keypair rather than choosing one.
    fn admin_credentials(not_after: u64) -> (TrustAnchor, Keypair, Vec<u8>, Authority) {
        use zerocopy::IntoBytes;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let admin_kp = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_user_cert(
            admin_kp.derived_mac(),
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            not_after,
            true,
        );
        let bytes = cert.as_bytes().to_vec();
        (authority.trust_anchor(), admin_kp, bytes, authority)
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
        let (anchor, admin_kp, cert, authority) = admin_credentials(200);
        let mac = admin_kp.derived_mac();
        let (state, gate) = MovableState::new(
            AuthSnapshot {
                own_key: Some([9u8; 32]),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
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

        state.revoke(&authority, mac, 50, 200);

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
        let (anchor, admin_kp, cert, _authority) = admin_credentials(200);
        let (state, gate) = MovableState::new(
            AuthSnapshot {
                own_key: Some([9u8; 32]),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
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
        let (anchor, admin_kp, cert, _authority) = admin_credentials(200);
        let (_state, gate) = MovableState::new(
            AuthSnapshot {
                own_key: Some([9u8; 32]),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
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

    // ── VPN coordination ──────────────────────────────────────────────────

    /// A coordinator that records what it was asked and answers from a script,
    /// so a test can assert *which MAC* a credential was minted for — the whole
    /// security property of the enrollment RPC.
    #[derive(Default)]
    struct FakeCoordinator {
        enrolled: std::sync::Mutex<Vec<Mac>>,
        revoked: std::sync::Mutex<Vec<Mac>>,
        fail_revoke: bool,
    }

    impl crate::vpn::VpnCoordinator for FakeCoordinator {
        fn enroll(
            &self,
            mac: Mac,
        ) -> impl std::future::Future<
            Output = Result<crate::vpn::VpnEnrollment, crate::vpn::VpnError>,
        > + Send {
            self.enrolled.lock().unwrap().push(mac);
            std::future::ready(Ok(crate::vpn::VpnEnrollment {
                login_server: "https://vpn.example.net".into(),
                preauth_key: format!("key-for-{}", crate::vpn::hostname_for(mac)),
            }))
        }

        fn peers(
            &self,
        ) -> impl std::future::Future<
            Output = Result<Vec<crate::vpn::VpnPeer>, crate::vpn::VpnError>,
        > + Send {
            std::future::ready(Ok(vec![crate::vpn::VpnPeer {
                mac: Some(Mac([0, 0, 0, 0, 0, 9])),
                hostname: crate::vpn::hostname_for(Mac([0, 0, 0, 0, 0, 9])),
                address: "100.64.0.3".into(),
                online: true,
                last_seen_unix: 1_700_000_000,
                key_expiry_unix: 0,
            }]))
        }

        fn revoke(
            &self,
            mac: Mac,
        ) -> impl std::future::Future<Output = Result<(), crate::vpn::VpnError>> + Send {
            self.revoked.lock().unwrap().push(mac);
            std::future::ready(if self.fail_revoke {
                Err(crate::vpn::VpnError::Unreachable("down".into()))
            } else {
                Ok(())
            })
        }
    }

    /// An enrolled device, its certificate, and the anchor that verifies it —
    /// the fixture the VPN tests share.
    ///
    /// Takes no address: since the key↔address binding landed (design 09 §5) a
    /// device's MAC is a function of its key, so the caller reads it back off
    /// the returned keypair (`node.derived_mac()`) rather than choosing one.
    /// `seed` is what distinguishes one device from another, and so what
    /// distinguishes their addresses.
    fn enrolled_device(
        seed: u8,
    ) -> (
        wayfinder::wayfinder_auth::Keypair,
        MembershipCert,
        TrustAnchor,
        [u8; 32],
    ) {
        use wayfinder::wayfinder_auth::Authority;
        use wayfinder::wayfinder_auth::Keypair;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            0,
            10_000,
        );
        let ca_own = Keypair::from_seed(&[7u8; 32]).ed_pubkey();
        (node, cert, authority.trust_anchor(), ca_own)
    }

    /// Authenticate `client` with `cert` and consume the acknowledgement.
    async fn authenticate_with(
        client: &mut Framed<tokio::io::DuplexStream, LengthDelimitedCodec>,
        cert: &MembershipCert,
    ) {
        use zerocopy::IntoBytes;
        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: cert.as_bytes().to_vec(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(ack.response, Some(Response::Empty(_))),
            "expected an authentication acknowledgement, got {:?}",
            ack.response
        );
    }

    /// The end-to-end enrollment path: an enrolled device presenting its own
    /// certificate gets a credential minted **for the MAC in that certificate**,
    /// not for anything it asked for — the request has no fields to ask with.
    #[tokio::test]
    async fn a_member_gets_a_credential_minted_for_its_certified_mac() {
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let (node, cert, anchor, ca_own) = enrolled_device(2);
        let node_mac = node.derived_mac();
        let coordinator = std::sync::Arc::new(FakeCoordinator::default());
        let (mut client, _server) = spawn_gated_server_with_vpn(
            node.ed_pubkey(),
            gate_returning(AuthContext {
                own_key: Some(ca_own),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
                now_unix: 100,
            }),
            canned_node_info(),
            Some(coordinator.clone()),
        );

        authenticate_with(&mut client, &cert).await;
        client
            .send(encode_request(Request::GetVpnEnrollment(
                GetVpnEnrollmentRequest {},
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();

        let Some(Response::VpnEnrollment(enrollment)) = resp.response else {
            panic!("expected a VPN enrollment, got {:?}", resp.response);
        };
        assert_eq!(enrollment.vpn_login_server, "https://vpn.example.net");
        assert_eq!(
            enrollment.vpn_preauth_key,
            format!("key-for-{}", crate::vpn::hostname_for(node_mac))
        );
        assert_eq!(
            *coordinator.enrolled.lock().unwrap(),
            vec![node_mac],
            "the credential must be minted for the certificate's MAC"
        );
    }

    /// A connection that never proved a device identity is refused before the
    /// coordinator is reached — nothing is minted. This is the transport half
    /// of the policy `authz` states: an enrollment-tier client holding only the
    /// shared token cannot turn it into tunnel reachability.
    #[tokio::test]
    async fn an_enrollment_tier_client_mints_nothing() {
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let coordinator = std::sync::Arc::new(FakeCoordinator::default());
        let (mut client, _server) = spawn_gated_server_with_vpn(
            [9u8; 32],
            gate_returning(AuthContext {
                own_key: Some([7u8; 32]),
                anchor: None,
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
                now_unix: 100,
            }),
            canned_node_info(),
            Some(coordinator.clone()),
        );

        // No certificate: the enrollment tier.
        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let _ack = client.next().await.unwrap().unwrap();

        client
            .send(encode_request(Request::GetVpnEnrollment(
                GetVpnEnrollmentRequest {},
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(resp.response, Some(Response::Error(_))),
            "expected a refusal, got {:?}",
            resp.response
        );
        assert!(
            coordinator.enrolled.lock().unwrap().is_empty(),
            "nothing may be minted for a client that proved no device identity"
        );
    }

    /// The certificate authority's own case: a connection that proved the
    /// node's *own* key gets a credential minted for the node's own mesh
    /// address, read from the router — not from anything on the connection.
    ///
    /// The CA coordinates the tunnel and is also a node on it, and the only
    /// credential it can present to itself is its seed. Nothing else it holds
    /// would do: a certificate presented over a connection whose handshake key
    /// is already the node's own key is never verified (`decide_access`
    /// short-circuits to the self-key tier before it reaches the anchor), so
    /// the router is the only trustworthy source for the MAC here.
    #[tokio::test]
    async fn a_self_key_connection_mints_for_the_routers_own_mac() {
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let own_mac = Mac([2, 0, 0, 0, 0, 1]);
        let own_key = [7u8; 32];
        let coordinator = std::sync::Arc::new(FakeCoordinator::default());
        let (mut client, _server) = spawn_gated_server_with_vpn(
            own_key,
            gate_returning(AuthContext {
                own_key: Some(own_key),
                anchor: None,
                revoked: Vec::new(),
                own_mac,
                now_unix: 100,
            }),
            canned_node_info(),
            Some(coordinator.clone()),
        );

        // No certificate: whoever holds the seed presents the node's key and
        // nothing else, which is exactly what the CA's self-join does.
        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let _ack = client.next().await.unwrap().unwrap();

        client
            .send(encode_request(Request::GetVpnEnrollment(
                GetVpnEnrollmentRequest {},
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();

        let Some(Response::VpnEnrollment(enrollment)) = resp.response else {
            panic!("expected a VPN enrollment, got {:?}", resp.response);
        };
        assert_eq!(
            enrollment.vpn_preauth_key,
            format!("key-for-{}", crate::vpn::hostname_for(own_mac))
        );
        assert_eq!(
            *coordinator.enrolled.lock().unwrap(),
            vec![own_mac],
            "the credential must be minted for the router's own MAC"
        );
    }

    /// And it cannot be talked into minting for anyone else. A self-key
    /// connection may present any certificate it likes — that one is never
    /// verified on this path — so if the MAC came off the certificate, the
    /// holder of a node's seed could register a device under *another* node's
    /// Headscale user and break the peer↔mesh-identity correlation that
    /// `hostname_for` is the only record of.
    #[tokio::test]
    async fn a_self_key_connection_cannot_mint_for_another_nodes_mac() {
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let (_victim_node, victim_cert, _anchor, _ca_own) = enrolled_device(42);
        let own_mac = Mac([2, 0, 0, 0, 0, 1]);
        let own_key = [7u8; 32];
        let coordinator = std::sync::Arc::new(FakeCoordinator::default());
        let (mut client, _server) = spawn_gated_server_with_vpn(
            own_key,
            gate_returning(AuthContext {
                own_key: Some(own_key),
                anchor: None,
                revoked: Vec::new(),
                own_mac,
                now_unix: 100,
            }),
            canned_node_info(),
            Some(coordinator.clone()),
        );

        authenticate_with(&mut client, &victim_cert).await;
        client
            .send(encode_request(Request::GetVpnEnrollment(
                GetVpnEnrollmentRequest {},
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();

        assert!(
            matches!(resp.response, Some(Response::VpnEnrollment(_))),
            "expected a VPN enrollment, got {:?}",
            resp.response
        );
        assert_eq!(
            *coordinator.enrolled.lock().unwrap(),
            vec![own_mac],
            "a presented certificate must not choose the MAC on the self-key tier"
        );
    }

    /// Revoking a node's mesh membership removes its VPN registration in the
    /// same action, so an operator's one click does both.
    #[tokio::test]
    async fn mesh_revocation_also_revokes_the_vpn_registration() {
        use wayfinder_protos::wayfinder::v1alpha::RevokeNodeRequest;

        let target = Mac([2, 0, 0, 0, 0, 42]);
        let (_node, cert, anchor, ca_own) = enrolled_device(1);
        let coordinator = std::sync::Arc::new(FakeCoordinator::default());
        // An admin connection: the node's own key earns the full grant.
        let (mut client, _server) = spawn_gated_server_with_vpn(
            ca_own,
            gate_returning(AuthContext {
                own_key: Some(ca_own),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
                now_unix: 100,
            }),
            Response::Empty(wayfinder_protos::wayfinder::v1alpha::Empty {}),
            Some(coordinator.clone()),
        );
        let _ = &cert;

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let _ack = client.next().await.unwrap().unwrap();

        client
            .send(encode_request(Request::RevokeNode(RevokeNodeRequest {
                node_mac: target.0.to_vec(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();

        assert!(
            matches!(resp.response, Some(Response::Empty(_))),
            "a fully successful revoke reports success, got {:?}",
            resp.response
        );
        assert_eq!(*coordinator.revoked.lock().unwrap(), vec![target]);
    }

    /// A certificate authority refuses to revoke *itself*.
    ///
    /// Refused before the request reaches the authority, because the authority
    /// signs and durably records a revocation before the router is asked to
    /// flood it — so there is no later point at which this could be undone.
    /// What it would destroy is the mesh's root of trust: the CA goes inert,
    /// its anchor is cleared, and every admin connection drops to the
    /// enrollment tier, leaving nobody able to enroll or re-admit anyone.
    #[tokio::test]
    async fn the_authority_refuses_to_revoke_itself() {
        use wayfinder_protos::wayfinder::v1alpha::RevokeNodeRequest;

        let (own_node, _cert, anchor, ca_own) = enrolled_device(1);
        let own = own_node.derived_mac();
        let coordinator = std::sync::Arc::new(FakeCoordinator::default());
        let (mut client, _server) = spawn_gated_server_with_vpn(
            ca_own,
            gate_returning(AuthContext {
                own_key: Some(ca_own),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: own,
                now_unix: 100,
            }),
            Response::Empty(wayfinder_protos::wayfinder::v1alpha::Empty {}),
            Some(coordinator.clone()),
        );

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let _ack = client.next().await.unwrap().unwrap();

        client
            .send(encode_request(Request::RevokeNode(RevokeNodeRequest {
                node_mac: own.0.to_vec(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();

        let Some(Response::Error(err)) = resp.response else {
            panic!("revoking the authority itself must be refused: {resp:?}");
        };
        assert!(
            err.message.contains("certificate authority"),
            "the reason names why: {}",
            err.message
        );
        assert!(
            coordinator.revoked.lock().unwrap().is_empty(),
            "and nothing was revoked anywhere"
        );
    }

    /// A certificate authority must not enroll itself, either.
    ///
    /// The sibling of `the_authority_refuses_to_revoke_itself`, and the reason
    /// is sharper. The authority's own membership certificate is minted offline
    /// (`wayfinderctl cert`) and never enters the issued-cert log, so the log's
    /// MAC-lock — the guard that stops one MAC being claimed under a second key
    /// — has nothing on file to refuse against. Under `auto_approve` that let
    /// an anonymous enrollment-tier caller obtain a root-signed certificate
    /// binding the CA's own MAC to keys of its choosing: the member tier, OGM
    /// signatures accepted as the authority's, and the CA's own device
    /// registration on the tunnel.
    ///
    /// Refused at this layer for the same reason the revoke guard is: `own_mac`
    /// comes from the router, which the authority task cannot see.
    #[tokio::test]
    async fn the_authority_refuses_a_csr_naming_its_own_mac() {
        let own = Mac([2, 0, 0, 0, 0, 1]);
        let ctx = AuthContext {
            own_key: Some([1u8; 32]), // un-enrolled ⇒ the peer key is GrantedEnrollment
            anchor: None,
            revoked: Vec::new(),
            own_mac: own,
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

        client
            .send(encode_request(Request::SubmitCsr(SubmitCsrRequest {
                node_mac: own.0.to_vec(),
                ed_pubkey: vec![7u8; 32],
                x_pubkey: vec![8u8; 32],
                enrollment_token: String::new(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();

        let Some(Response::Error(err)) = resp.response else {
            panic!("a CSR naming the authority's own MAC must be refused: {resp:?}");
        };
        assert!(
            err.message.contains("certificate authority"),
            "the reason names why: {}",
            err.message
        );

        // Narrow, not blanket: every other MAC still enrolls. (The stub
        // authority answers every forwarded request with `Empty`; what is under
        // test is that the request reached the authority facet at all.)
        client
            .send(encode_request(Request::SubmitCsr(SubmitCsrRequest {
                node_mac: Mac([2, 0, 0, 0, 0, 2]).0.to_vec(),
                ed_pubkey: vec![7u8; 32],
                x_pubkey: vec![8u8; 32],
                enrollment_token: String::new(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            !matches!(&resp.response, Some(Response::Error(_))),
            "a CSR for another MAC was caught by the guard too: {resp:?}"
        );

        drop(client);
        let _ = server.await;
    }

    /// The guard is unconditional on the tier, not a rule about anonymous
    /// callers.
    ///
    /// Without this, narrowing the guard to `GrantedEnrollment` would keep
    /// `the_authority_refuses_a_csr_naming_its_own_mac` green while leaving an
    /// enrolled member — or an admin whose session certificate was stolen —
    /// able to have the CA's own identity re-certified. The two things this
    /// refuses to do are not the enrollment tier's to do, they are *nobody's*.
    ///
    /// Uses `enrolled_device` to reach a fully granted connection, the way
    /// `the_authority_refuses_to_revoke_itself` does.
    #[tokio::test]
    async fn a_csr_naming_the_authoritys_own_mac_is_refused_at_every_tier() {
        let (own_node, _cert, anchor, ca_own) = enrolled_device(1);
        let own = own_node.derived_mac();
        let (mut client, server) = spawn_authenticated_server(
            ca_own,
            AuthContext {
                own_key: Some(ca_own),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: own,
                now_unix: 100,
            },
        );

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let _ack = client.next().await.unwrap().unwrap();

        client
            .send(encode_request(Request::SubmitCsr(SubmitCsrRequest {
                node_mac: own.0.to_vec(),
                ed_pubkey: vec![7u8; 32],
                x_pubkey: vec![8u8; 32],
                enrollment_token: String::new(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        let Some(Response::Error(err)) = resp.response else {
            panic!("a fully granted connection enrolled the authority's own MAC: {resp:?}");
        };
        assert!(
            err.message.contains("certificate authority"),
            "the reason names why: {}",
            err.message
        );

        // `ApproveCsr` is guarded with it: the held-CSR store is persisted, so
        // an entry parked before this guard existed outlives the upgrade that
        // adds it, and `approve_csr` re-signs from the stored keys without
        // re-running `submit_csr`'s checks.
        client
            .send(encode_request(Request::ApproveCsr(
                wayfinder_protos::wayfinder::v1alpha::ApproveCsrRequest {
                    node_mac: own.0.to_vec(),
                },
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(&resp.response, Some(Response::Error(_))),
            "approving a queued CSR for the authority's own MAC was allowed: {resp:?}"
        );

        drop(client);
        let _ = server.await;
    }

    /// On a node that is not a provider the guard stays out of the way, so the
    /// caller gets the honest `not a provider` answer instead of being told
    /// this node is the certificate authority — which would send an operator
    /// hunting for CA state on a machine that has none.
    #[tokio::test]
    async fn a_non_provider_node_does_not_claim_to_be_the_authority() {
        let own = Mac([2, 0, 0, 0, 0, 1]);
        let ctx = AuthContext {
            own_key: Some([1u8; 32]),
            anchor: None,
            revoked: Vec::new(),
            own_mac: own,
            now_unix: 100,
        };
        // No authority channel: an ordinary routing node.
        let (mut client, server) =
            spawn_gated_server_without_authority([2u8; 32], gate_returning(ctx));

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let _ack = client.next().await.unwrap().unwrap();

        client
            .send(encode_request(Request::SubmitCsr(SubmitCsrRequest {
                node_mac: own.0.to_vec(),
                ed_pubkey: vec![7u8; 32],
                x_pubkey: vec![8u8; 32],
                enrollment_token: String::new(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        let Some(Response::Error(err)) = resp.response else {
            panic!("expected the not-a-provider refusal, got {resp:?}");
        };
        assert!(
            !err.message.contains("certificate authority"),
            "a node with no authority claimed to be one: {}",
            err.message
        );

        drop(client);
        let _ = server.await;
    }

    /// A revoke whose VPN half fails is reported as a failure, not as success.
    /// The mesh half has already taken effect (the node cannot route), but the
    /// tunnel access it still holds is exactly what an operator needs told.
    #[tokio::test]
    async fn a_half_completed_revoke_is_not_reported_as_success() {
        use wayfinder_protos::wayfinder::v1alpha::RevokeNodeRequest;

        let (_node, _cert, anchor, ca_own) = enrolled_device(1);
        let coordinator = std::sync::Arc::new(FakeCoordinator {
            fail_revoke: true,
            ..Default::default()
        });
        let (mut client, _server) = spawn_gated_server_with_vpn(
            ca_own,
            gate_returning(AuthContext {
                own_key: Some(ca_own),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
                now_unix: 100,
            }),
            Response::Empty(wayfinder_protos::wayfinder::v1alpha::Empty {}),
            Some(coordinator.clone()),
        );

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let _ack = client.next().await.unwrap().unwrap();

        client
            .send(encode_request(Request::RevokeNode(RevokeNodeRequest {
                node_mac: vec![2, 0, 0, 0, 0, 42],
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();

        let Some(Response::Error(err)) = resp.response else {
            panic!(
                "expected an error naming the retry, got {:?}",
                resp.response
            );
        };
        assert!(
            err.message.contains("VPN"),
            "the message must say which half failed: {:?}",
            err.message
        );
    }

    /// A CA with no VPN configured answers the VPN requests with a sentence
    /// saying so, rather than failing to parse them. That is what lets
    /// `wayfinderctl auth enroll` ask unconditionally and finish normally against a
    /// deployment that has no tunnel at all.
    #[tokio::test]
    async fn a_provider_without_vpn_says_so() {
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let (node, cert, anchor, ca_own) = enrolled_device(2);
        let (mut client, _server) = spawn_gated_server_with_vpn(
            node.ed_pubkey(),
            gate_returning(AuthContext {
                own_key: Some(ca_own),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
                now_unix: 100,
            }),
            canned_node_info(),
            None,
        );

        authenticate_with(&mut client, &cert).await;
        client
            .send(encode_request(Request::GetVpnEnrollment(
                GetVpnEnrollmentRequest {},
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();

        let Some(Response::Error(err)) = resp.response else {
            panic!("expected a 'not configured' error, got {:?}", resp.response);
        };
        assert!(
            err.message.contains("no VPN coordination configured"),
            "unexpected message: {:?}",
            err.message
        );
    }

    /// A refusal has to say the *right* thing, not merely refuse. Three tiers
    /// can be refused now, and the message keyed on the tier alone told an
    /// admin refused `GetVpnEnrollment` that its connection "is limited to
    /// enrollment" — false, and pointing at a fix that would not have helped.
    ///
    /// Pinned per case, because the failure mode is a *correct refusal with a
    /// misleading explanation*, which no assertion on the refusal itself
    /// catches.
    #[tokio::test]
    async fn a_refusal_explains_the_actual_reason() {
        use wayfinder::wayfinder_auth::Authority;
        use wayfinder_protos::wayfinder::v1alpha::GetRoutingTableRequest;
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let (node, cert, anchor, ca_own) = enrolled_device(2);

        // A real *admin* refused the device-scoped request: an operator's
        // session certificate, whose key is not this node's own key — a
        // connection proving the node's own key would be the self-key tier,
        // which is a device and is served. The message must name that
        // distinction, not claim the connection lacks an admin certificate.
        let operator = Authority::from_seed(&[1u8; 32], 0xABCD);
        let admin_kp = Keypair::from_seed(&[3u8; 32]);
        let admin_cert = operator.issue_user_cert(
            admin_kp.derived_mac(),
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
            true,
        );
        let (mut client, _server) = spawn_gated_server_with_vpn(
            admin_kp.ed_pubkey(),
            gate_returning(AuthContext {
                own_key: Some(ca_own),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
                now_unix: 100,
            }),
            canned_node_info(),
            Some(std::sync::Arc::new(FakeCoordinator::default())),
        );
        authenticate_with(&mut client, &admin_cert).await;
        client
            .send(encode_request(Request::GetVpnEnrollment(
                GetVpnEnrollmentRequest {},
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        let Some(Response::Error(err)) = resp.response else {
            panic!("expected a refusal, got {:?}", resp.response);
        };
        assert!(
            err.message.contains("session certificate is a person"),
            "an admin refused the device credential must be told why: {:?}",
            err.message
        );
        assert!(
            !err.message.contains("limited to enrollment"),
            "an admin must not be told it lacks an admin certificate: {:?}",
            err.message
        );

        // And a member refused a management request is told it is a device,
        // not that it is a stranger.
        let (mut member_client, _server2) = spawn_gated_server_with_vpn(
            node.ed_pubkey(),
            gate_returning(AuthContext {
                own_key: Some(ca_own),
                anchor: Some(anchor),
                revoked: Vec::new(),
                own_mac: Mac([2, 0, 0, 0, 0, 1]),
                now_unix: 100,
            }),
            canned_node_info(),
            None,
        );
        authenticate_with(&mut member_client, &cert).await;
        member_client
            .send(encode_request(Request::GetRoutingTable(
                GetRoutingTableRequest {},
            )))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(member_client.next().await.unwrap().unwrap()).unwrap();
        let Some(Response::Error(err)) = resp.response else {
            panic!("expected a refusal, got {:?}", resp.response);
        };
        assert!(
            err.message.contains("member capability"),
            "a member refused a management request must be told what it is: {:?}",
            err.message
        );
    }
}
