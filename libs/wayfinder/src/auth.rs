//! Opt-in OGM authentication, the control-plane half of mesh segregation.
//!
//! When a mesh enables authentication, every OGM carries two extra TVLV records
//! in its tail: the originator's membership certificate ([`TvlvType::Cert`]) and
//! an Ed25519 signature over the OGM's immutable identity fields
//! ([`TvlvType::OgmSig`]).  A receiver verifies the cert against its mesh trust
//! anchor and the signature against the cert's key, dropping anything that fails
//! — so an outsider (or a node from another mesh) cannot inject or forge OGMs,
//! and its topology never enters the routing table.
//!
//! This lives in the router (not the `batman` engine) so the engine stays free
//! of any crypto dependency: [`OgmAuth::augment_ogm`] post-processes the OGM the
//! engine builds, and [`OgmAuth::verify_ogm`] gates an incoming OGM *before* it
//! reaches the engine.  Because the engine preserves unknown TVLVs verbatim when
//! it re-floods, the cert/sig records propagate unchanged with no engine change.
//!
//! Only the *originator's* signature is checked here (one-to-many control
//! plane).  Directed data-plane frames are authenticated separately by a
//! pairwise tag keyed off the neighbor keys this module caches.
//!
//! **Scope (read before trusting this boundary):** this authenticates *OGMs*
//! and *directed* data-plane frames.  Directed frames carry the pairwise
//! trailer (see [`DIRECTED_TRAILER_LEN`]), which `strip_directed` verifies on
//! the way in.  Which sub-types those are is
//! `wayfinder_driver_core::required_proof`'s single decision — see its
//! doc for the current list and the reasoning per type, rather than a copy
//! here that can drift.  `BatmanPacketType::Bcast` is the notable exclusion:
//! flooded frames (ARP etc.) are **not** authenticated at all — a pairwise tag
//! cannot cover a one-to-many send — so an outsider can still inject a
//! broadcast flood on an auth-enabled mesh.
//!
//! What separates the two is the **BATMAN sub-type**, and nothing else.  In
//! particular it is not the link-layer destination: that field is chosen by
//! whoever sent the frame, while local delivery and relaying are decided from
//! the *inner* `dest`.  The rule is applied identically on ingress and egress
//! so the two halves cannot drift apart.

use batman::wire::BatmanOgmPacket;
use batman::wire::BatmanPacketType;
use batman::wire::BatmanTvlvHdr;
use batman::wire::TvlvType;
use batman::wire::find_tvlv;
use batman::wire::iter_tvlv;
use core::time::Duration;
use heapless::Vec as HVec;
use interfaces::frame::Mac;
use wayfinder_alarm::AlarmKind;
use wayfinder_alarm::NodeId;
use wayfinder_alarm::Severity;
use wayfinder_alarm::Subject;
use wayfinder_alarm::alarm;
use wayfinder_auth::AuthError;
use wayfinder_auth::Clocked;
use wayfinder_auth::Keypair;
use wayfinder_auth::MembershipCert;
use wayfinder_auth::RevocationRecord;
use wayfinder_auth::TAG_LEN;
use wayfinder_auth::TrustAnchor;
use wayfinder_auth::VerifiedCert;
use wayfinder_auth::frame_tag;
use wayfinder_auth::verify_frame_tag;
use wayfinder_auth::verify_signature;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// Fixed size of the BATMAN OGM header preceding the TVLV tail.
const OGM_HDR: usize = core::mem::size_of::<BatmanOgmPacket>();
/// Size of a TVLV record header.
const TVLV_HDR: usize = core::mem::size_of::<BatmanTvlvHdr>();
/// Byte offset of the OGM `seqno` field (after type/version/ttl/flags).
const SEQNO_OFF: usize = 4;
/// Byte offset of the OGM `orig` MAC field (after seqno).
const ORIG_OFF: usize = 8;
/// Byte offset of the OGM `tvlv_len` field (last two header bytes).
const TVLV_LEN_OFF: usize = OGM_HDR - 2;
/// Length of an Ed25519 signature.
const SIG_LEN: usize = 64;

/// Domain-separation prefix bound into the OGM signature so a signature can
/// never be confused with one over any other message type.
const SIG_DOMAIN: &[u8] = b"wf-ogm-sig-v1";

/// Domain-separation prefix bound into the keep-alive signature, distinct from
/// [`SIG_DOMAIN`] so a keep-alive signature can never be confused with (or
/// replayed as) an OGM signature over the same bytes.
const KEEPALIVE_SIG_DOMAIN: &[u8] = b"wf-keepalive-sig-v1";

/// Domain prefix for a fan-out multicast signature, distinct from every other
/// so one can never stand in for another: a frame signed to fan out on a
/// shared medium is not an OGM, a keep-alive, or a cert request, and none of
/// those can be replayed as one.
const FANOUT_SIG_DOMAIN: &[u8] = b"wf-mcast-fanout-sig-v1";

/// Bit set on the eight-byte counter a keep-alive carries, marking the trailer
/// as this build's rather than the coarse **time bucket** the previous one put
/// in the same eight bytes (design 20 §4.3, §6.2).
///
/// The trailer did not change size, only meaning, so a mixed mesh would
/// otherwise drop keep-alives between mismatched nodes with nothing to say why.
/// Every bucket the old build emitted was `now_unix / 30` — around 5.8e7 in
/// 2026, or zero on a node with no clock — so the top bit was always clear;
/// setting it here is enough for a receiver to name which of the two it is
/// holding, and to say so in the drop.
///
/// **Stripped before the counter reaches the replay guard.** The value on the
/// wire is tagged, but `accept_recv_counter` keys on `src` alone and shares one
/// high-water mark with directed and fan-out frames — feeding it a tagged
/// counter would push that mark past 2^63 and make every subsequent directed
/// frame look stale. The tag is a wire-format marker, not part of the sequence.
const KEEPALIVE_COUNTER_TAG: u64 = 1 << 63;

/// Length of the trailer [`OgmAuth::augment_keepalive`] appends: an 8-byte
/// big-endian replay counter (tagged with [`KEEPALIVE_COUNTER_TAG`]) followed
/// by the 64-byte signature.
///
/// Identical to [`FANOUT_TRAILER_LEN`], which is not a coincidence: a
/// keep-alive is now the fan-out shape — the sender's counter plus its
/// signature, checked against the certificate the receiver already holds.
const KEEPALIVE_TRAILER_LEN: usize = 8 + SIG_LEN;

/// Length of the directed-frame authentication trailer appended to unicast and
/// multicast frames when auth is enabled: an 8-byte big-endian replay counter
/// followed by the 16-byte pairwise tag.
pub const DIRECTED_TRAILER_LEN: usize = 8 + TAG_LEN;

/// Length of the **fan-out** authentication trailer, appended to a multicast
/// frame that one transmission carries to several next hops: the same 8-byte
/// big-endian replay counter followed by the sender's 64-byte Ed25519
/// signature.
///
/// A single transmission reaching three neighbours cannot carry three pairwise
/// tags, each derived from a different key — so the forwarding node signs with
/// its own instead, and every receiver verifies against the cert it already
/// holds for that hop. The counter is kept because `Mcast` already had a replay
/// guard; being one-to-many is no reason to lose it.
pub const FANOUT_TRAILER_LEN: usize = 8 + SIG_LEN;

/// The largest auth trailer a directed frame can carry, and so the space a
/// driver must reserve behind a staged frame before asking for it to be
/// authenticated.
///
/// A caller cannot know which form a frame will take until its sub-type (and,
/// for multicast, its `form` byte) has been classified, and reserving the
/// *smaller* of the two would leave a fan-out signature writing past the end of
/// the buffer. Reserving this always costs a multicast frame 48 bytes it may
/// not use; that is cheaper than the alternative by every measure that matters.
pub const MAX_TRAILER_LEN: usize = if FANOUT_TRAILER_LEN > DIRECTED_TRAILER_LEN {
    FANOUT_TRAILER_LEN
} else {
    DIRECTED_TRAILER_LEN
};

/// Maximum number of revocation records held in the local revocation set.
pub(crate) const MAX_REVOKED: usize = 32;
/// Maximum number of verified neighbor key records cached.
///
/// Also the ceiling on how many neighbors a node can hold at once, and so on
/// how many next-hop proofs it can owe at once. [`MAX_IN_PROGRESS_PROOF`] is
/// deliberately smaller than this — see there for why that is safe.
pub const MAX_NEIGHBOR_KEYS: usize = 64;

/// Length of the nonce in a next-hop proof challenge. One [`TAG_LEN`] block:
/// the nonce need not be secret, only unpredictable and non-repeating, and 128
/// bits of PRF output is far past any birthday concern for a value that is
/// consumed once.
pub const CHALLENGE_NONCE_LEN: usize = TAG_LEN;

/// Maximum next-hop proof challenges outstanding at once.
///
/// One entry per neighbor being proven, and a neighbor is only ever challenged
/// as a candidate next hop, so this can never usefully exceed the number of
/// originators the router can hold routes for.
///
/// It is a quarter of [`MAX_NEIGHBOR_KEYS`], so a node at full neighbor density
/// cannot hold a slot for every neighbor at once. That is deliberate, and it is
/// safe only because of the retry: [`issue_challenge`](OgmAuth::issue_challenge)
/// evicts the least-recently-issued entry rather than refusing, the evicted
/// challenge is then never answered, and an unanswered challenge is retried on
/// `BatmanEngine`'s ordinary backoff — so eviction costs a round trip, not a
/// route. What this table really bounds is concurrent proof *throughput*, and
/// the only requirement is that throughput stay above the rate at which proofs
/// come due for renewal.
///
/// That margin is measured, not assumed. At the maximum density a node can
/// reach (`MAX_NEIGHBOR_KEYS` mutual neighbors on one segment), 4, 8, 16 and 64
/// slots all converge identically — every neighbor proven ~11 s in, and no
/// route lost across the following two minutes — while a single slot never
/// converges at all, settling near two thirds of them permanently proven.
/// `attack_proof_starvation_by_neighbour_count` (`sim/scenarios/red_team.py`)
/// is what holds that end of the range down; note that it only fails for a
/// table small enough to fall under the renewal rate, so it is a guard against
/// gross mis-sizing rather than a tight bound.
pub const MAX_IN_PROGRESS_PROOF: usize = 16;

const _: () = assert!(
    MAX_IN_PROGRESS_PROOF <= crate::ORIGINATOR_CAPACITY,
    "more outstanding proofs than originators the router can route to is \
     unreachable state: a challenge is only ever issued for a candidate next hop"
);

/// Domain-separation prefix for the nonce PRF, keyed by this node's own secret
/// (see [`OgmAuth::nonce_prf_key`]) so the nonce sequence is unpredictable to
/// everyone else — a challenger whose next nonce can be guessed can have a
/// response pre-fetched for it, which defeats the whole exchange.
const NONCE_PRF_DOMAIN: &[u8] = b"wf-nexthop-nonce-v1";

/// Domain-separation prefix bound into a challenge response's context, ahead of
/// the responder's MAC.
///
/// This is what keeps a response from ever colliding with a directed-frame tag:
/// [`tag_directed`](OgmAuth::tag_directed) passes a bare 6-byte MAC as
/// `context`, so a context that is a domain *followed by* a MAC can never be
/// the same byte string, whatever counter or payload an attacker chooses.
const CHALLENGE_RESP_DOMAIN: &[u8] = b"wf-nexthop-resp-v1";

/// Length of a challenge response's `context`: the domain plus a 6-byte MAC.
const RESP_CONTEXT_LEN: usize = CHALLENGE_RESP_DOMAIN.len() + 6;

/// Length of a [`RevocationRecord`] on the wire.
const REVOKE_LEN: usize = core::mem::size_of::<RevocationRecord>();

/// How many of this node's own OGM emissions re-advertise a freshly learned
/// revocation before it goes quiet.  Active flooding is a bounded burst — long
/// enough to reach the whole mesh through normal OGM propagation — after which
/// passive cert expiry keeps the node out without perpetual OGM bloat.  The
/// record stays in the local set (still dropping the node) once the budget is
/// spent; only its re-advertisement stops.
const REVOKE_FLOOD_BUDGET: u8 = 6;

/// Maximum revocation records attached to a single OGM, bounding how much one
/// OGM can grow when several purges are in flight at once.
const MAX_REVOKE_PER_OGM: usize = 4;

/// Maximum concurrent outstanding lazy-cert-distribution fetch requests
/// tracked at once. Bounds the state a churning mesh (many simultaneous
/// fingerprint misses) can pin.
pub(crate) const MAX_IN_FLIGHT_CERT_REQUESTS: usize = 16;

/// Minimum spacing between retransmissions of the same outstanding
/// `CertReq` — the requester-side retry backstop for a dropped request or
/// reply (design doc §3.5): a pending-query list at the responder is the
/// primary optimization, but a lost packet anywhere must not wedge the fetch
/// forever.
///
/// Measured on [`OgmAuth::now`], the monotonic clock: this is a duration, and
/// a duration must not be perturbed by an NTP step — nor, more sharply, be
/// unmeasurable on a node that has no wall clock at all (design 20 §3(b)).
const CERT_REQUEST_RETRY: Duration = Duration::from_secs(5);

/// Maximum retransmission attempts for one outstanding `CertReq` before it is
/// abandoned. A live OGM stream simply raises the miss again on its next
/// Trickle emission if the need persists, so abandoning is not permanent.
const MAX_CERT_REQUEST_ATTEMPTS: u8 = 6;

/// Domain-separation prefix for a `CertReq`'s self-authenticating signature,
/// over `orig ‖ requester_mac` — distinct from [`SIG_DOMAIN`] (the OGM
/// signature) so the two can never be confused with one another.
const CERT_REQ_SIG_DOMAIN: &[u8] = b"wf-certreq-sig-v1";

/// Maximum concurrent parked pending `CertReply`s (responder side): verified
/// requesters this node has no route to yet.
pub(crate) const MAX_PENDING_REPLIES: usize = 16;

/// How long a parked pending reply is kept before it is evicted as stale.
/// Measured on the monotonic clock — see [`CERT_REQUEST_RETRY`].
const PENDING_REPLY_TTL: Duration = Duration::from_secs(30);

/// Minimum spacing between `CertReq`s this node will act on from the same
/// requester — bounds the verification/airtime cost a single member (even a
/// legitimate, self-authenticating one) can impose (design doc §8).
/// Measured on the monotonic clock — see [`CERT_REQUEST_RETRY`].
const CERT_REQ_RATE_LIMIT: Duration = Duration::from_secs(2);

/// One verified requester whose `CertReply` is parked because this node had
/// no route back to them at request time.
#[derive(Debug, Clone, Copy)]
struct PendingReply {
    /// The requester to reply to once a route appears.
    requester: Mac,
    /// The monotonic instant this entry was last (re)parked, for TTL
    /// eviction.
    parked: Duration,
}

/// One outstanding lazy-cert-distribution fetch: the originator whose cert is
/// needed, the fingerprint that triggered the fetch, the first hop to
/// (re)address the request to, and the retry bookkeeping.
#[derive(Debug, Clone, Copy)]
struct InFlightCertRequest {
    /// The originator whose cert is being fetched.
    orig: Mac,
    /// The fingerprint that triggered this fetch (the OGM's advertised
    /// value, not yet resolvable against the cache).
    fp: [u8; 8],
    /// The neighbor to (re)address the request to — the OGM's link source,
    /// which by construction has a route to `orig` (see design doc §3.2).
    first_hop: Mac,
    /// Retransmissions sent so far, bounded by [`MAX_CERT_REQUEST_ATTEMPTS`].
    attempts: u8,
    /// Earliest monotonic instant at which another retransmission is allowed.
    next_attempt: Duration,
}

/// Size of the reused scratch buffer for assembling the OGM signed message
/// (domain prefix + orig + seqno + certificate).  Generous over the ~180-byte
/// maximum so the buffer can be a fixed field rather than re-created per call.
const SIGN_SCRATCH_LEN: usize = 256;

/// Compile-time guarantee that the scratch buffer fits the largest signed
/// message, so a future certificate-layout growth is caught here rather than
/// silently rejecting every OGM at runtime (`signed_message` fails closed).
const _: () =
    assert!(SIGN_SCRATCH_LEN >= SIG_DOMAIN.len() + 6 + 4 + core::mem::size_of::<MembershipCert>());

/// What [`OgmAuth::cache_neighbor`] did with a verified certificate.
///
/// Returned rather than swallowed because a refusal is not a no-op for every
/// caller: one of them has already consumed an outstanding request by the time
/// it asks, and reporting success there would clear a retry that is still
/// needed. `#[must_use]` so a new call site has to make that decision rather
/// than inherit it.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cached {
    /// The keys are now in the neighbour table.
    Stored,
    /// Refused: a live member already holds that address under a different
    /// identity key. See [`OgmAuth::cache_neighbor`].
    RefusedLiveIdentity,
}

/// What the pairwise replay guard made of one frame's counter.
///
/// Three outcomes, not two, because [`Stale`](Self::Stale) and
/// [`NoSlot`](Self::NoSlot) are the same *verdict* (drop, for
/// [`verify_directed`](OgmAuth::verify_directed)) but completely different
/// *facts*, and the restart path acts on one and must not act on the other. A
/// `bool` collapsed them, so a first-ever frame from a new neighbour arriving
/// at a node whose table was full read as a peer replaying its own counters.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterVerdict {
    /// Strictly newer than the last accepted from this source, and recorded.
    Accepted,
    /// At or behind the high-water this node holds for the source: a replay,
    /// or a peer whose counter restarted. Which of the two it is cannot be told
    /// from the counter alone — that is what the next-hop proof nonce decides.
    Stale,
    /// No high-water is held for this source and none could be recorded:
    /// `recv_counters` is full. Says nothing about the counter itself, so it is
    /// never evidence of a restart.
    NoSlot,
}

/// One verified neighbor's keys, learned from its authenticated OGM cert.
///
/// At most one entry per MAC, and while an entry's certificate is live its
/// `cert.ed_pubkey` is pinned: a second certificate binding that address to a
/// different identity key is refused rather than admitted. See
/// [`cache_neighbor`](OgmAuth::cache_neighbor) for why, and for the two edges
/// that release the pin.
#[derive(Debug, Clone, Copy)]
pub struct NeighborKeys {
    /// The trusted facts from the neighbor's verified membership cert — its MAC,
    /// identity (Ed25519) and agreement (X25519) keys, and cert expiry. Held
    /// whole so the security view can report the expiry and the router can
    /// attribute signatures without a second lookup.
    pub cert: VerifiedCert,
    /// The symmetric pairwise key shared with this neighbor, derived once (from
    /// our secret and the cert's `x_pubkey`) when the neighbor is cached, and
    /// reused to tag/verify directed data-plane frames.
    pub pairwise_key: [u8; 32],
    /// The neighbor's raw certificate bytes, retained (not just the derived
    /// [`VerifiedCert`]) so a fingerprint-only OGM can be verified against the
    /// cached copy: [`signed_message`](OgmAuth::signed_message) needs the whole
    /// cert to reconstruct the signed message, which `VerifiedCert` alone
    /// cannot provide.
    pub raw_cert: MembershipCert,
    /// The `(seqno, signature)` of the last OGM from this neighbor that
    /// verified — the memo [`verify_ogm`](OgmAuth::verify_ogm) recognises its
    /// re-flooded copies by.
    ///
    /// Private, unlike the rest: it is evidence this node has already spent,
    /// not a fact about the neighbor. Together with `raw_cert` (the third and
    /// last thing the signature commits to) it pins the whole signed message,
    /// so a match means *this exact signature over this exact message* was
    /// checked — never that a different message is being trusted on an old
    /// verdict.
    ///
    /// One slot, holding the newest: a neighbor floods one seqno at a time, so
    /// that is what its copies are copies of. Someone interleaving *older*
    /// genuine copies can miss the memo every time and force the full check —
    /// which is exactly the cost this path had before the memo existed, so the
    /// worst case is unchanged rather than newly exposed.
    last_ogm: Option<([u8; 4], [u8; SIG_LEN])>,
}

/// One next-hop proof challenge this node has issued and not yet resolved.
struct OutstandingChallenge {
    /// The neighbor challenged — the candidate next hop being proven.
    neighbor: Mac,
    /// The nonce sent, which the response must be computed over.
    nonce: [u8; CHALLENGE_NONCE_LEN],
    /// The issuing node's challenge counter at the time, used purely to pick
    /// the least-recently-issued entry to evict when the table is full.
    issued_seq: u64,
}

/// The outcome of [`OgmAuth::verify_ogm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an OgmVerdict must be acted on: NeedCert requires triggering a cert fetch, distinct from Rejected"]
pub enum OgmVerdict {
    /// The OGM's signature verified against a trust-anchored cert (carried on
    /// the wire, or resolved from the cache via a matching fingerprint). The
    /// caller should let the OGM proceed to routing.
    Verified,
    /// The OGM must be dropped: malformed, wrong mesh, revoked, cert/anchor
    /// verification failed, or the signature did not verify.
    Rejected,
    /// The OGM carried a [`TvlvType::CertFp`] this node cannot resolve —
    /// either `orig` is unknown, or its fingerprint has changed (a
    /// rotation). This copy of the OGM is dropped (not forwarded); the
    /// caller should fetch the cert (see [`OgmAuth::build_cert_request`]) and
    /// let the *next* emission from `orig` verify and forward normally.
    NeedCert {
        /// The originator whose cert is needed.
        orig: Mac,
        /// The fingerprint this OGM advertised, so the fetch can be matched
        /// back to the OGM that triggered it once resolved.
        fp: [u8; 8],
    },
}

/// One known revocation plus its remaining re-flood budget.  The signed record
/// is retained so this node can both *enforce* the revocation (drop the named
/// node's frames) and *re-advertise* it on its own OGMs until the budget is
/// spent.
#[derive(Debug, Clone, Copy)]
struct KnownRevocation {
    /// The mesh-root-signed record, verified before it was stored.
    record: RevocationRecord,
    /// Remaining OGM emissions that will carry this record; counts down to 0.
    floods_left: u8,
}

/// Constructor for the default (host) capacities.
///
/// Kept in its own impl on the fully-defaulted type rather than on the generic
/// impl below: a struct's default const parameters do **not** drive inference in
/// expression position, so a generic `OgmAuth::new` would force every call site
/// to name its capacities (`E0284`). With `new` pinned here, existing callers
/// need no annotation, and a constrained node reaches for
/// [`with_capacities`](OgmAuth::with_capacities) instead.
impl OgmAuth {
    /// Build auth state from this node's keypair, its membership cert, and the
    /// mesh trust anchor, at the default capacities.
    pub fn new(keypair: Keypair, cert: MembershipCert, anchor: TrustAnchor) -> Self {
        Self::with_capacities(keypair, cert, anchor)
    }
}

/// Per-node OGM authentication state, held by the router when auth is enabled.
///
/// The table capacities are const-generic so a constrained node can trade mesh
/// scale for RAM: the neighbour cache alone is 64 × 272 bytes at host
/// capacities. All four parameters default to the module constants of the same
/// name, so `OgmAuth::new` keeps exactly the sizing it had before they existed.
///
/// Capacity is a purely **local** memory decision — it never reaches the wire,
/// so a host-profile node and a tiny-profile node interoperate unchanged.
/// Every bound enforced at runtime, and every occupancy metric's denominator,
/// reads these parameters rather than the module constants.
pub struct OgmAuth<
    const MAX_NEIGHBOR_KEYS: usize = { self::MAX_NEIGHBOR_KEYS },
    const MAX_REVOKED: usize = { self::MAX_REVOKED },
    const MAX_IN_FLIGHT_CERT_REQUESTS: usize = { self::MAX_IN_FLIGHT_CERT_REQUESTS },
    const MAX_PENDING_REPLIES: usize = { self::MAX_PENDING_REPLIES },
> {
    /// This node's key material, for signing its own OGMs.
    keypair: Keypair,
    /// This node's membership certificate, attached to its OGMs.
    cert: MembershipCert,
    /// The mesh trust anchor, against which incoming certs are verified.
    anchor: TrustAnchor,
    /// What this node knows about the wall clock, refreshed by the driver;
    /// the input to every certificate validity-window check.
    ///
    /// A *posture*, not a reading (design 20 §4.2). A host that can tell the
    /// time supplies [`Clocked::At`]; a board free-running from an anchor
    /// supplies [`Clocked::AtLeast`], a floor it can prove but not a point;
    /// a node with no usable clock supplies [`Clocked::Unknown`] and judges no
    /// window at all. The rule is "signature always, window when known" — the
    /// signature check is the real trust boundary and is entirely clock-free,
    /// while the window check is a revocation optimisation the mesh enforces
    /// collectively (§5.1).
    ///
    /// This was a bare `now_unix: u64` whose zero meant "no clock", which four
    /// sites read as *judge no window* and two read as *fail closed*; the
    /// half that was enforced was the half that partitioned the node (§2.2,
    /// Bug A). A type that cannot be read two ways is the fix.
    wall: Clocked,
    /// Current *monotonic* time, refreshed by the driver in the same breath as
    /// [`now_unix`](Self::now_unix), and the clock every **duration** in this
    /// module is measured on: retry backoff, rate limits, parked-reply TTL.
    ///
    /// Kept separate from the wall clock deliberately (design 20 §3(b)).
    /// Elapsed-time logic and absolute-time logic are different questions, and
    /// tangling them means the absence of absolute time disables bookkeeping
    /// that never needed it — which is exactly the denial `reclaim_bookkeeping`
    /// exists to prevent, live on every bare-metal node while the two shared
    /// one field. It is also simply more correct on a host: an NTP step must
    /// not perturb a rate limit.
    now: Duration,
    /// Revocations known to this node, learned from the management API or
    /// flooded in an OGM tail.  Their originators' OGMs are dropped even while
    /// the cert has not yet expired, and each is re-advertised on this node's
    /// own OGMs while its flood budget lasts.
    revocations: HVec<KnownRevocation, MAX_REVOKED>,
    /// Keys of neighbors whose OGMs have verified, for pairwise-key derivation
    /// and security observability.
    neighbors: HVec<NeighborKeys, MAX_NEIGHBOR_KEYS>,
    /// Reused scratch buffer for assembling the OGM signed message, so signing
    /// and verifying do not stack-allocate it on every call.
    sign_scratch: [u8; SIGN_SCRATCH_LEN],
    /// The node's **single** outgoing directed-frame counter, shared by every
    /// destination and by fan-out frames alike (design 17 §4.4).
    ///
    /// Per-destination counters worked while every directed frame had exactly
    /// one destination. A fan-out frame has none, and drawing its counter from
    /// any one recipient's space would hand the others a value below their own
    /// high-water mark, dropping a legitimate frame as a replay. One sequence
    /// avoids that with no receiver change at all: `accept_recv_counter` keys
    /// on `src` alone, and any subsequence of a strictly increasing sequence is
    /// strictly increasing.
    ///
    /// What it gives up is that a neighbour can infer this node's total
    /// directed-frame volume rather than only its own share — already visible
    /// to anyone on the medium.
    send_counter: u64,
    /// Per-neighbor highest accepted incoming counter (monotonic replay guard).
    recv_counters: HVec<(Mac, u64), MAX_NEIGHBOR_KEYS>,
    /// A verified revocation naming **this** node, held until the router
    /// drains it.
    ///
    /// Not in [`revocations`](Self::revocations) and never re-flooded: there
    /// is no third party to keep dropping frames from, and echoing our own
    /// death warrant would only spend a flood slot peers already spent. It
    /// sits here instead because the reaction is the router's — clearing the
    /// certificate and anchor, which `OgmAuth` cannot do to itself.
    ///
    /// Held rather than acted on immediately when the record is not yet in
    /// force or this node has no clock; see
    /// [`take_self_revoked`](Self::take_self_revoked).
    self_revocation: Option<RevocationRecord>,
    /// Set whenever a *new* revocation is ingested, signalling the router to
    /// snap the engine's Trickle timers back to `i_min` so the carrying OGM (and
    /// thus the emergency purge) floods promptly instead of waiting out the
    /// backed-off emission interval.  Drained by
    /// [`take_trickle_reset_hint`](Self::take_trickle_reset_hint).
    trickle_reset_hint: bool,
    /// Bumped whenever a cached neighbor's keys stop being reachable under the
    /// address they were reachable under — expiry, revocation, or a full-table
    /// overwrite taking a live slot.
    ///
    /// Exists purely so a caller can skip work when nothing changed:
    /// `CentralRouter::set_auth_time` reconciles the routing engine's next-hop
    /// proofs against this cache on *every* pass of a driver loop (which on the
    /// tokio shell is every frame), and that reconciliation is a scan of the
    /// proof table with a `neighbors` lookup per entry. Comparing one integer
    /// instead is the difference between paying that per frame and paying it
    /// per actual eviction.
    ///
    /// Deliberately a counter rather than a `take`-style boolean hint like
    /// [`trickle_reset_hint`](Self::trickle_reset_hint): a hint that the first
    /// reader clears silently starves a second one, and this is not a fact that
    /// belongs to whoever asks first. Wrapping is harmless — a caller compares
    /// for equality, and `u32` evictions between two passes of one loop is not
    /// reachable.
    key_generation: u32,
    /// Outstanding lazy-cert-distribution fetches this node has requested but
    /// not yet resolved, keyed by originator MAC (one entry per originator).
    in_flight: HVec<InFlightCertRequest, MAX_IN_FLIGHT_CERT_REQUESTS>,
    /// Verified `CertReq` requesters this node (the responder) has no route
    /// to yet, parked for opportunistic flush once one appears.
    pending_replies: HVec<PendingReply, MAX_PENDING_REPLIES>,
    /// Per-requester last-accepted-`CertReq` monotonic instant
    /// (responder-side rate limit), keyed by requester MAC.
    cert_req_rate: HVec<(Mac, Duration), MAX_NEIGHBOR_KEYS>,
    /// Monotonic counter feeding the nonce PRF, so no two challenges this node
    /// issues are ever over the same nonce.
    challenge_counter: u64,
    /// Next-hop proof challenges issued and not yet answered.
    in_progress: HVec<OutstandingChallenge, MAX_IN_PROGRESS_PROOF>,
    /// The `(sender, counter)` of the last next-hop proof response whose
    /// pairwise tag verified while its replay counter was *behind* this node's
    /// high-water for that sender — held between the tag check that tolerated
    /// it ([`verify_directed_nonce_fresh`](Self::verify_directed_nonce_fresh))
    /// and the nonce check that decides whether to believe it
    /// ([`verify_challenge_response`](Self::verify_challenge_response)).
    ///
    /// A peer that reboots keeps its identity — the seed is persisted — but not
    /// its [`send_counter`](Self::send_counter), which is memory only and
    /// restarts at zero. Its whole directed data plane is then behind this
    /// node's high-water and refused, and because a next-hop challenge and its
    /// response are themselves directed frames, the proof that would clear the
    /// state cannot get through either. That is the deadlock this field exists
    /// to break: the response is tolerated past the counter, and only a nonce
    /// this node issued and has never issued before decides whether the
    /// sequence is re-anchored.
    ///
    /// **One slot node-wide**, not one per neighbour, and safe at that size
    /// only because of how narrowly it lives: it is written by a
    /// nonce-fresh verification whose tag checked out (`None` when the counter
    /// was in sequence) and taken unconditionally by the very next
    /// [`verify_challenge_response`](Self::verify_challenge_response),
    /// whatever that call then decides. A frame whose tag does *not* verify
    /// leaves it alone, having proved nothing either way.
    ///
    /// What holds the two together is the caller: `strip_directed` →
    /// `CentralRouter::handle_rx` → `verify_challenge_response` is one frame's
    /// synchronous processing and the only path that reaches either function.
    /// Keep that pairing if this ever moves off the single-frame path — the
    /// slot is a return value wearing a field's clothes.
    ///
    /// In steady state the counter is in sequence, this is `None`, and the
    /// replay guard is untouched — a proof round must never become a periodic
    /// hole in it.
    restart_candidate: Option<(Mac, u64)>,
    /// Public-key operations (Ed25519 verifications, X25519 agreements) spent
    /// on the OGM verification path since boot.
    ///
    /// Not a metric — it is what pins the cost of
    /// [`verify_ogm`](Self::verify_ogm) in tests. A flooded OGM arrives once
    /// per neighbour on a shared segment, so the number that has to stay flat
    /// as a segment grows is *per distinct OGM*, not per copy; a test that
    /// only asserted verdicts could not tell the two apart.
    ogm_crypto_ops: u64,
    /// Certificates admitted while this node was judging no validity window —
    /// the direct measure of how much passive revocation-by-expiry is *not*
    /// being enforced here (design 20 §7).
    ///
    /// A count rather than a rate, and deliberately: what an operator wants is
    /// "has this node ever admitted a certificate it could not date", which a
    /// time-decayed rate answers with zero a minute after the fact. Saturates
    /// rather than wrapping — the distinction between "many" and "many plus
    /// one" is not one anybody acts on, but a counter that silently returned to
    /// zero would read as the healthy state.
    ///
    /// Counts *admissions*, not distinct certificates: a re-verified peer bumps
    /// it again. That is the honest reading — each admission is an occasion on
    /// which a window went unchecked.
    unjudged_admissions: u32,
}

impl<
    const MAX_NEIGHBOR_KEYS: usize,
    const MAX_REVOKED: usize,
    const MAX_IN_FLIGHT_CERT_REQUESTS: usize,
    const MAX_PENDING_REPLIES: usize,
> OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>
{
    /// Build auth state at *this* profile's capacities from the node's keypair,
    /// its membership cert, and the mesh trust anchor.
    ///
    /// [`new`](OgmAuth::new) is the same thing at the default capacities, and
    /// is what a host-sized node wants.
    pub fn with_capacities(keypair: Keypair, cert: MembershipCert, anchor: TrustAnchor) -> Self {
        Self {
            keypair,
            cert,
            anchor,
            wall: Clocked::Unknown,
            now: Duration::ZERO,
            revocations: HVec::new(),
            neighbors: HVec::new(),
            sign_scratch: [0u8; SIGN_SCRATCH_LEN],
            send_counter: 0,
            recv_counters: HVec::new(),
            self_revocation: None,
            trickle_reset_hint: false,
            key_generation: 0,
            in_flight: HVec::new(),
            pending_replies: HVec::new(),
            cert_req_rate: HVec::new(),
            challenge_counter: 0,
            restart_candidate: None,
            in_progress: HVec::new(),
            ogm_crypto_ops: 0,
            unjudged_admissions: 0,
        }
    }

    /// Take the latched revocation of *this* node, if one is in force.
    ///
    /// `None` — leaving the record latched for a later call — when:
    ///
    /// * no record naming this node has been ingested;
    /// * this node has **no clock** ([`Clocked::Unknown`]). It cannot judge the
    ///   record's window at all, and `verify_revocation`'s expiry test passes
    ///   everything at zero, so acting here would let a long-dead record no
    ///   live peer still holds brick a freshly booted board — with no way to
    ///   garbage-collect it, since that needs the clock it lacks;
    /// * the record has **already expired** (`not_after` is at or before the
    ///   clock). The clause above defers the judgement until a clock arrives;
    ///   this is the judgement. Without it that deferral merely postpones the
    ///   brick to the moment NTP lands, which is the long-dead-record case
    ///   verbatim. An expired record is dropped rather than held: no peer
    ///   enforces it any more, so it can never become live again;
    /// * the record's `not_before` has not arrived. Going inert early makes
    ///   this node a **black hole**: peers apply the same instant, so they
    ///   keep advertising and using routes through a node that has stopped
    ///   forwarding, with no route withdrawal to correct them. Worse than the
    ///   purge it is trying to perform.
    ///
    /// Drains on success, so the router acts exactly once.
    pub fn take_self_revoked(&mut self) -> Option<RevocationRecord> {
        let record = self.self_revocation?;
        if !self.wall.judges_windows() {
            return None;
        }
        let now = self.wall.unix_or_zero();
        if record.not_after.get() <= now {
            // Expired before this node could ever judge it. Drop it: holding it
            // would leave a record no peer enforces armed against a future
            // clock adjustment.
            tracing::debug!("auth: discarding a self-revocation that expired before it applied");
            self.self_revocation = None;
            return None;
        }
        if record.not_before.get() > now {
            return None;
        }
        self.self_revocation = None;
        Some(record)
    }

    /// A counter that changes whenever a cached neighbor's keys stop being
    /// reachable — see [`key_generation`](Self::key_generation).
    ///
    /// Read it, do the work, and remember the value; when it is unchanged on a
    /// later pass, nothing has been evicted in between and there is nothing to
    /// reconcile. Never read it as a *count* of evictions: it wraps, and
    /// several removals can share one bump.
    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }

    /// Take and clear the pending Trickle-reset hint: `true` if a new revocation
    /// was ingested since the last call, meaning the router should reset the
    /// engine's OGM timers so the purge re-floods at `i_min` without waiting for
    /// the backed-off emission interval.
    pub fn take_trickle_reset_hint(&mut self) -> bool {
        core::mem::take(&mut self.trickle_reset_hint)
    }

    /// Advance both of this node's clocks: `now` is monotonic (every duration
    /// in this module is measured on it) and `wall` is what the node knows
    /// about absolute time (certificate validity windows, revocation records).
    /// Called by the driver before serving traffic.  Also garbage-collects revocations whose
    /// `not_after` has passed: the cancelled cert has expired too, so passive
    /// expiry now covers the node and the record can be forgotten, freeing a
    /// slot in the bounded revocation set.
    ///
    /// The two are taken together rather than through separate setters because
    /// a caller that advanced one and not the other would silently reintroduce
    /// the tangle they were split to remove (design 20 §3). A node with no wall
    /// clock passes [`Clocked::Unknown`] and a real value for `now`; everything
    /// that does not need to know the year keeps working.
    ///
    /// **A router's clock is advanced through
    /// `CentralRouter::set_auth_time`, not here.** Evicting a lapsed member's
    /// keys is half an event: the routing engine's next-hop proofs were
    /// answered *with* those keys and have to go in the same breath, or
    /// selection keeps choosing a hop the data plane can no longer tag for
    /// (`docs/design/implemented/09-mesh-auth-gaps.md` §8.10). This stays
    /// public for tests and benches that drive an `OgmAuth` with no router
    /// around it.
    pub fn set_time(&mut self, now: Duration, wall: Clocked) {
        self.now = now;
        self.wall = wall;
        self.reclaim_bookkeeping();
        self.prune_expired();
        self.evict_expired_neighbors();
    }

    /// Reclaim the bounded tables whose entries age out on **elapsed** time:
    /// parked pending replies past their TTL, and in-flight cert requests
    /// whose retry budget is exhausted.
    ///
    /// Runs unconditionally, with no reference to the wall clock. That is the
    /// whole point (design 20 §2.2, Bug B): while this sat behind
    /// [`prune_expired`](Self::prune_expired)'s wall-clock guard, a node
    /// with no wall clock — every bare-metal node — never reclaimed anything,
    /// so a target that never answers (unreachable, or an attacker flooding
    /// `NeedCert` misses for fake originator MACs it never backs with a real
    /// reply) permanently pinned a slot: `build_cert_request` returns `None`
    /// before incrementing `attempts` once exhausted, so the entry sat at
    /// [`MAX_CERT_REQUEST_ATTEMPTS`] forever, and
    /// `MAX_IN_FLIGHT_CERT_REQUESTS` such dead entries permanently blocked
    /// fetching any further originator's cert.
    fn reclaim_bookkeeping(&mut self) {
        let now = self.now;
        self.pending_replies
            .retain(|p| now.saturating_sub(p.parked) < PENDING_REPLY_TTL);
        self.in_flight
            .retain(|r| r.attempts < MAX_CERT_REQUEST_ATTEMPTS);
    }

    /// Drop revocations that have passed their `not_after`.  A no-op under
    /// [`Clocked::Unknown`], since expiry cannot be judged without a real
    /// time; under [`Clocked::AtLeast`] the floor only ever *under*-reports
    /// expiry, so a record dropped here is provably dead.
    fn prune_expired(&mut self) {
        if !self.wall.judges_windows() {
            return;
        }
        let now = self.wall.unix_or_zero();
        let mut i = 0;
        while i < self.revocations.len() {
            if self.revocations[i].record.not_after.get() <= now {
                self.revocations.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Ingest a signed revocation record — from the management API (a local
    /// operator-initiated purge) or flooded in an OGM tail — verifying it
    /// against this node's trust anchor before acting on it.  On a *new*, valid
    /// record the named node's keys are evicted (so its directed frames stop
    /// verifying and we stop tagging frames to it) and the record is queued for
    /// re-advertisement on this node's OGMs, so the purge floods with normal
    /// control-plane traffic.  Returns `true` only when the record was newly
    /// recorded — `false` for an invalid record or one already known — so a
    /// caller can flood it exactly once and avoid amplification loops.
    pub fn ingest_revocation(&mut self, record: &RevocationRecord) -> bool {
        // Verification takes the clock: an already-expired record is refused by
        // the anchor itself (`AuthError::Expired`), so this loop never has to
        // remember to check the half of validity that bounds the set's size. A
        // `now_unix` of zero — no clock at all — expires nothing, which is the
        // behaviour a freshly booted board needs and had before.
        let mac = match self
            .anchor
            .verify_revocation(record, self.wall.unix_or_zero())
        {
            Ok(m) => m,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping a revocation that failed verification");
                return false;
            }
        };
        // A revocation of *this* node never joins the enforcement set and is
        // never re-flooded — peers enforce it against us, and echoing our own
        // death warrant would only spend a flood slot. It latches instead, for
        // the router to act on by clearing this state entirely.
        if mac.0 == self.cert.node_mac {
            // Only if it cancels the certificate this node is *currently*
            // running under. A record naming this MAC but predating this
            // certificate describes a membership that has already been
            // superseded by a re-admission, and acting on it would hand
            // anyone a kill switch: the OGM tail is not covered by the OGM
            // signature, so any record ever seen on the wire can be spliced
            // into a captured frame and replayed.
            if !record.cancels_cert_for(
                &self.cert.node_mac,
                self.cert.not_before.get(),
                // The enforcement window is judged in `take_self_revoked`,
                // against a clock this node may not have yet, so this asks
                // only the issuance question by evaluating "now" at the
                // record's own effective instant.
                record.not_before.get(),
            ) {
                tracing::trace!(
                    "drop: revocation names this node but cancels only a superseded certificate"
                );
                return false;
            }
            // Logged on the *transition* only. While a record is held — no
            // clock yet, or its instant not reached — this node is not yet
            // locked, so every replayed OGM tail carrying it re-enters here.
            // An unconditional `error!` would then be a remote-triggerable log
            // flood on a hot path, against CLAUDE.md and into the same bounded
            // `GetLogs` ring a dongle has already OOM'd on. The arming
            // transition itself is logged once by `apply_self_revocation`.
            let known = self
                .self_revocation
                .is_some_and(|held| held.not_before.get() >= record.not_before.get());
            if !known {
                tracing::error!(
                    node_mac = ?Mac(record.node_mac),
                    not_before = record.not_before.get(),
                    "auth: this node's mesh membership has been revoked"
                );
                // A later instant supersedes a held record; an earlier one must
                // not pull the arming instant backwards, which would arm this
                // node early and black-hole the peers still routing through it.
                self.self_revocation = Some(*record);
            }
            return false;
        }
        // Deduplicate on `(node_mac, not_before)`, not on the MAC alone.  Under
        // v1 a MAC was revoked or it was not, so a second record for a known MAC
        // was always redundant.  Under v2 it carries an issuance cut-off, so a
        // later record is *new information*: it is what re-revokes a node the
        // authority had re-admitted, whose held record no longer cancels the
        // certificate it now presents.  Dropping it at MAC granularity would
        // leave that node unrevokable until the first record passively expired.
        //
        // The later instant wins because it cancels a superset: every
        // certificate the earlier record reached was issued no later than it,
        // and so was issued before this one too.
        if let Some(slot) = self
            .revocations
            .iter_mut()
            .find(|r| r.record.node_mac == mac.0)
        {
            if record.not_before.get() <= slot.record.not_before.get() {
                // Genuinely redundant — the same record, or one already
                // superseded.  Do not re-arm the flood budget, or two nodes
                // could keep re-flooding each other's records forever.
                tracing::trace!("auth: dropping a revocation that is already known");
                return false;
            }
            // A strictly later instant supersedes the stored record in place,
            // re-arming the flood budget so the mesh learns of it.  That cannot
            // loop: `not_before` only ever increases here, so each re-flood is
            // driven by a record no peer has seen.
            tracing::info!(
                ?record,
                "auth: superseding a revocation with a later instant"
            );
            slot.record = *record;
            slot.floods_left = REVOKE_FLOOD_BUDGET;
            self.evict_neighbor(mac);
            self.trickle_reset_hint = true;
            return true;
        }
        let known = KnownRevocation {
            record: *record,
            floods_left: REVOKE_FLOOD_BUDGET,
        };
        tracing::info!(?record, "auth: ingested new revocation");
        if self.revocations.push(known).is_err() {
            // Set full.  Prefer evicting an already-expired entry (passive expiry
            // covers it); otherwise overwrite the most-quiescent live entry
            // (lowest remaining flood budget).  The `min_by_key` orders expired
            // (`not_after <= now` → `false`) before live, then by budget.  With
            // `MAX_REVOKED` *simultaneously live* revocations this still drops a
            // live one — a hard bound worth surfacing rather than hiding.
            let now = self.wall.unix_or_zero();
            tracing::debug!("auth: revocation set full; evicting an entry to admit a new purge");
            if let Some(slot) = self
                .revocations
                .iter_mut()
                .min_by_key(|r| (r.record.not_after.get() > now, r.floods_left))
            {
                *slot = known;
            }
        }
        self.evict_neighbor(mac);
        // A new purge: ask the router to accelerate OGM emission so it floods
        // promptly (set last, so only a genuinely new record triggers it).
        self.trickle_reset_hint = true;
        true
    }

    /// Whether `cert` is currently cancelled by a known revocation: a record
    /// naming the same MAC, whose enforcement window (`not_before ..
    /// not_after`, half-open) contains this node's clock, **and** which was issued at or
    /// after the certificate was.
    ///
    /// The last clause is why this takes the certificate rather than a MAC. A
    /// revocation cancels the credentials that existed when the authority
    /// signed it, not the MAC forever: a certificate issued *after* the
    /// revocation instant is a deliberate re-admission and survives, which is
    /// what lets a re-approved node rejoin under its own MAC instead of
    /// waiting out `not_after`. The tie resolves toward revoked — see
    /// [`RevocationRecord::not_before`].
    ///
    /// Outside the enforcement window — not yet effective, or expired (where
    /// the cancelled cert has also expired) — nothing is dropped on this basis.
    fn is_revoked(&self, cert: &VerifiedCert) -> bool {
        // Through the posture, not a bare reading. A node with no clock has
        // `unix_or_zero() == 0`, and no valid record has `not_before <= 0`
        // (`verify_revocation` refuses a zero instant), so the old spelling
        // enforced *nothing* on such a node — it evicted the named neighbour
        // once on ingest, which looks like it worked, then re-admitted them on
        // their next OGM. Design 20 §5.1 promises the opposite.
        self.revocations
            .iter()
            .any(|r| r.record.cancels_under(cert, self.wall))
    }

    /// The revocation records this node currently holds.
    ///
    /// The companion to [`revoked_macs`](Self::revoked_macs) for callers that
    /// must decide whether a *particular certificate* is cancelled — the
    /// management API's authorization path — rather than merely which MACs are
    /// named. A MAC alone can no longer answer that question, since a
    /// certificate issued after the revocation survives it.
    pub fn revocations(&self) -> impl Iterator<Item = &RevocationRecord> + '_ {
        self.revocations.iter().map(|r| &r.record)
    }

    /// Drop any cached neighbor state for `mac` so a revoked node can no longer
    /// participate in the directed data plane: its pairwise key is forgotten
    /// (directed frames from it stop verifying, and we stop tagging to it) and
    /// its replay counters are reset.
    fn evict_neighbor(&mut self, mac: Mac) {
        tracing::trace!("auth: evicting neighbor: {:?}", mac);
        if let Some(i) = self.neighbors.iter().position(|n| n.cert.mac == mac) {
            self.neighbors.swap_remove(i);
            self.key_generation = self.key_generation.wrapping_add(1);
        }
        if let Some(i) = self.recv_counters.iter().position(|(m, _)| *m == mac) {
            self.recv_counters.swap_remove(i);
        }
        // Same reason the counter row goes: a pending restart claim is
        // per-neighbour state about the address being evicted, and state that
        // outlives its subject is how a re-admitted peer gets anchored on a
        // pre-revocation counter.
        if matches!(self.restart_candidate, Some((m, _)) if m == mac) {
            self.restart_candidate = None;
        }
    }

    /// The MACs this node currently holds revocations for (for the security
    /// view / observability), regardless of whether their effective instant has
    /// been reached yet.
    ///
    /// **Observability only — this cannot answer whether a node is shunned.**
    /// Holding a record for a MAC no longer implies the node presenting that
    /// MAC is cancelled: one re-admitted with a certificate issued after the
    /// record's instant survives it. Use [`revocations`](Self::revocations)
    /// with [`RevocationRecord::cancels`] to decide enforcement, or
    /// [`macs_to_purge`](Self::macs_to_purge) to decide teardown.
    pub fn revoked_macs(&self) -> impl Iterator<Item = Mac> + '_ {
        self.revocations.iter().map(|r| Mac(r.record.node_mac))
    }

    /// The MACs whose routing state a landing revocation should tear down.
    ///
    /// Narrower than [`revoked_macs`](Self::revoked_macs), and the difference
    /// is the point: holding a record no longer means the named node is being
    /// shunned. A node the authority re-admitted presents a certificate issued
    /// after the record's instant, so the record does not cancel it — tearing
    /// down its originator entry and next-hop proofs every time some
    /// *unrelated* revocation arrived would cost it a re-proof cycle for
    /// nothing, undoing the immediate re-admission this exists to allow.
    ///
    /// A node is spared exactly when the cached certificate it re-verified
    /// under survives the record. One that has been evicted and not yet come
    /// back has no cached certificate and is still purged, which is the
    /// freshly-revoked case.
    pub fn macs_to_purge(&self) -> impl Iterator<Item = Mac> + '_ {
        self.revocations
            .iter()
            .map(|r| Mac(r.record.node_mac))
            .filter(|mac| self.is_shunned(*mac))
    }

    /// Whether the node at `mac` is currently shunned by a revocation this node
    /// holds — the question a security view is really asking, and the one
    /// [`revoked_macs`](Self::revoked_macs) can no longer answer.
    ///
    /// True when a held record cancels the certificate `mac` most recently
    /// verified under, or when no certificate is cached for it (the
    /// freshly-revoked case, whose cached entry ingestion evicted). False for a
    /// node re-admitted with a certificate issued after the record's instant:
    /// the record is still held and still listed, but it no longer bites.
    pub fn is_shunned(&self, mac: Mac) -> bool {
        self.revocations
            .iter()
            .filter(|r| r.record.node_mac == mac.0)
            .any(|r| {
                self.neighbors
                    .iter()
                    .find(|n| n.cert.mac == mac)
                    .is_none_or(|n| r.record.cancels_under(&n.cert, self.wall))
            })
    }

    /// When the revocation this node holds for `mac` stops being enforced
    /// (unix seconds), or `None` if it holds none.
    ///
    /// The companion to [`revoked_macs`](Self::revoked_macs), and the only
    /// date a revoked node has: ingesting a revocation evicts the cached
    /// neighbor entry that carries the certificate, so the cert expiry a
    /// security view would otherwise show is gone. Past this instant
    /// [`set_time`](Self::set_time) drops the record, and the node stops being
    /// reported as revoked at all.
    pub fn revocation_not_after(&self, mac: Mac) -> Option<u64> {
        self.revocations
            .iter()
            .find(|r| r.record.node_mac == mac.0)
            .map(|r| r.record.not_after.get())
    }

    /// This node's own membership certificate.
    ///
    /// Exposed so the router can ask whether a revocation it is latched under
    /// cancels the certificate about to be installed — the re-admission check
    /// in [`CentralRouter::set_auth`](crate::CentralRouter::set_auth).
    pub fn cert(&self) -> &MembershipCert {
        &self.cert
    }

    /// This node's own trust anchor (for the security view / observability).
    pub fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }

    /// The keys of neighbors whose OGMs have verified.
    pub fn neighbors(&self) -> &[NeighborKeys] {
        &self.neighbors
    }

    /// Occupancy of the verified-neighbor cert cache (`used`, `capacity`):
    /// how many other members' certs this node currently holds, out of
    /// [`MAX_NEIGHBOR_KEYS`]. Backs the cert-store metric — a cache
    /// perpetually near capacity signals more distinct neighbors (or more
    /// churn) than the node is provisioned for.
    pub fn cert_store_occupancy(&self) -> (usize, usize) {
        (self.neighbors.len(), MAX_NEIGHBOR_KEYS)
    }

    /// Occupancy of the requester-side in-flight lazy-cert-fetch table
    /// (`used`, `capacity`): outstanding [`build_cert_request`](Self::build_cert_request)
    /// fetches not yet resolved by [`ingest_cert_reply`](Self::ingest_cert_reply),
    /// out of [`MAX_IN_FLIGHT_CERT_REQUESTS`].
    pub fn in_flight_cert_requests_occupancy(&self) -> (usize, usize) {
        (self.in_flight.len(), MAX_IN_FLIGHT_CERT_REQUESTS)
    }

    /// Occupancy of the responder-side parked-reply table (`used`,
    /// `capacity`): verified `CertReq` requesters this node has no route to
    /// yet, awaiting the opportunistic flush, out of [`MAX_PENDING_REPLIES`].
    pub fn pending_cert_replies_occupancy(&self) -> (usize, usize) {
        (self.pending_replies.len(), MAX_PENDING_REPLIES)
    }

    /// Look up a cached neighbor's raw certificate and its fingerprint by MAC.
    /// `None` if no verified OGM from `mac` is currently cached (never seen, or
    /// evicted under churn — see [`cache_neighbor`](Self::cache_neighbor)).
    /// This is the store lazy cert distribution resolves an OGM's
    /// [`TvlvType::CertFp`] against: a fingerprint match here lets the OGM
    /// verify from the cached bytes with zero cert bytes on the wire.
    pub fn neighbor_cert(&self, mac: Mac) -> Option<(MembershipCert, [u8; 8])> {
        self.live_neighbor(mac)
            .map(|n| (n.raw_cert, n.raw_cert.fingerprint()))
    }

    /// This node's own membership certificate (for the security view: mesh id,
    /// bound MAC, and expiry).
    pub fn own_cert(&self) -> &MembershipCert {
        &self.cert
    }

    /// The wall-clock instant (unix seconds) the auth clock was last set to, for
    /// computing "expires in" in the security view.  Zero when this node has no
    /// usable clock, and a *floor* rather than a reading when it is
    /// free-running from an anchor — see [`wall`](Self::wall) for which.
    pub fn now_unix(&self) -> u64 {
        self.wall.unix_or_zero()
    }

    /// Certificates admitted while this node was judging no validity window —
    /// the direct measure of how much passive revocation-by-expiry is not
    /// being enforced here (design 20 §7).
    ///
    /// Counts *admissions*, not distinct certificates, and every verified OGM
    /// re-caches its originator — so under a sustained [`Clocked::Unknown`]
    /// this tracks OGM receptions rather than peers. Read it as "has this node
    /// been routing on credentials it could not date, and roughly how much",
    /// not as a population count. See [`wall`](Self::wall) for the posture it
    /// is counting.
    pub fn unjudged_admissions(&self) -> u32 {
        self.unjudged_admissions
    }

    /// What this node knows about the wall clock, for the paths that must not
    /// round three states down to one number: certificate verification, and
    /// the management API's honest report of the posture.
    pub fn wall(&self) -> Clocked {
        self.wall
    }

    /// Whether a *usable* pairwise key is held for `mac` — the precondition
    /// every directed frame to it depends on.
    ///
    /// "Usable" is [`live_neighbor`](Self::live_neighbor)'s judgement, so this
    /// answers `false` for a neighbor never cached, one whose certificate has
    /// lapsed, one dropped by a revocation, and one evicted from a full cache
    /// alike — *however* the key went, which is the point: nothing reconciling
    /// against this has to enumerate the ways, and the ways are not a closed
    /// set.
    ///
    /// An unclocked node ([`Clocked::Unknown`]) judges no validity window at all, so
    /// a lapsed certificate still reads live there —
    /// [`live_neighbor`](Self::live_neighbor)'s escape hatch. That is right for
    /// this caller too: a node that cannot tell the time must not tear down its
    /// own routes on a guess.
    ///
    /// Spelled as its own predicate rather than
    /// `neighbor_x_pubkey(mac).is_some()`, which is exactly equivalent today:
    /// that phrasing asks about one *field* that happens to sit beside the
    /// pairwise key, where what is being asked is whether the data plane can
    /// still tag at all — the same question
    /// [`tag_directed`](Self::tag_directed) asks. Exists so the routing engine
    /// can keep its next-hop proofs in step with this cache without depending
    /// on it — see `BatmanEngine::retain_proven` and
    /// `docs/design/implemented/09-mesh-auth-gaps.md` §8.10.
    pub fn has_live_key(&self, mac: Mac) -> bool {
        self.live_neighbor(mac).is_some()
    }

    /// The X25519 key of a verified neighbor, for pairwise data-plane keying.
    pub fn neighbor_x_pubkey(&self, mac: Mac) -> Option<[u8; 32]> {
        self.live_neighbor(mac).map(|n| n.cert.x_pubkey)
    }

    /// Authenticate a directed (unicast/mcast) frame addressed to next-hop
    /// `dst`: take the next per-neighbor counter and write the trailer
    /// `[counter:u64 BE][tag:16]` into `trailer`, returning its length.  `frame`
    /// is the batman payload the tag covers.  Returns `None` (and the caller must
    /// not send the frame) if we have no verified pairwise key for `dst` (no OGM
    /// accepted from it yet), the trailer is too small, or no counter can be
    /// allocated — never emit an untagged or counter-reused directed frame.
    ///
    /// Our own MAC is bound into the tag as the sender context so the frame
    /// cannot be reflected back to us as if it came from `dst` (the pairwise key
    /// is symmetric — see [`frame_tag`](wayfinder_auth::frame_tag)).
    pub fn tag_directed(&mut self, dst: Mac, frame: &[u8], trailer: &mut [u8]) -> Option<usize> {
        if trailer.len() < DIRECTED_TRAILER_LEN {
            return None;
        }
        let key = self.live_neighbor(dst).map(|n| n.pairwise_key)?;
        let src_mac = self.cert.node_mac;
        let counter = self.next_send_counter()?;
        let tag = frame_tag(&key, counter, &src_mac, frame);
        trailer[..8].copy_from_slice(&counter.to_be_bytes());
        trailer[8..DIRECTED_TRAILER_LEN].copy_from_slice(&tag);
        Some(DIRECTED_TRAILER_LEN)
    }

    /// Sign a multicast frame that one transmission will carry to **several**
    /// next hops, writing the trailer `[counter:u64 BE][sig:64]` into `trailer`
    /// and returning its length.
    ///
    /// This is the fan-out half of design 17 §4.4. A pairwise tag is derived
    /// from one neighbour's key, so it cannot cover an audience of three; the
    /// forwarding node vouches for the frame with its own signature instead,
    /// and each receiver checks it against the cert it already holds. That is
    /// the same trust model, not a weaker one — `plan_dispatch` already re-tags
    /// every directed frame it forwards, so directed traffic is vouched for hop
    /// by hop rather than end to end either way.
    ///
    /// The signature covers the whole frame, header and destination list
    /// included, which is what makes routing on an in-band list safe: a hop
    /// cannot rewrite the list without its successor rejecting the frame.
    ///
    /// Returns `None` (and the caller must not send the frame) if the trailer
    /// is too small or no counter can be allocated — never an unsigned or
    /// counter-reused fan-out frame.
    pub fn sign_fanout(&mut self, frame: &[u8], trailer: &mut [u8]) -> Option<usize> {
        if trailer.len() < FANOUT_TRAILER_LEN {
            return None;
        }
        let counter = self.next_send_counter()?;
        let msg = Self::fanout_message(counter, frame);
        let sig = self.keypair.sign(&msg);
        trailer[..8].copy_from_slice(&counter.to_be_bytes());
        trailer[8..FANOUT_TRAILER_LEN].copy_from_slice(&sig);
        Some(FANOUT_TRAILER_LEN)
    }

    /// Verify a fan-out multicast `trailer` from neighbor `src`.
    ///
    /// Goes through the same live-neighbour lookup as
    /// [`verify_directed`](Self::verify_directed), so a node whose OGM has not
    /// been accepted — and one whose keys `evict_neighbor` dropped on
    /// revocation — cannot be believed. Returns `false` (drop) on a malformed
    /// trailer, an unknown sender, a bad signature, or a replayed counter.
    pub fn verify_fanout(&mut self, src: Mac, frame: &[u8], trailer: &[u8]) -> bool {
        if trailer.len() != FANOUT_TRAILER_LEN {
            tracing::trace!("auth: dropping fan-out frame with malformed trailer");
            return false;
        }
        let Some(key) = self.live_neighbor(src).map(|n| n.cert.ed_pubkey) else {
            tracing::trace!("auth: dropping fan-out frame from an unverified neighbor");
            return false;
        };
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&trailer[..8]);
        let counter = u64::from_be_bytes(counter_bytes);

        let msg = Self::fanout_message(counter, frame);
        let mut sig = [0u8; SIG_LEN];
        sig.copy_from_slice(&trailer[8..FANOUT_TRAILER_LEN]);
        if !wayfinder_auth::verify_signature(&key, &msg, &sig) {
            tracing::trace!("auth: dropping fan-out frame with an invalid signature");
            return false;
        }
        // The same monotonic guard the pairwise form uses, against the same
        // per-source high-water mark — which is exactly why the send counter
        // is one sequence rather than one per destination.
        if self.accept_recv_counter(src, counter) != CounterVerdict::Accepted {
            tracing::trace!("auth: dropping fan-out frame with a replayed/stale counter");
            return false;
        }
        true
    }

    /// Build the canonical signed message for a fan-out multicast frame: the
    /// domain prefix followed by a digest of the counter and the frame.
    ///
    /// **The frame is hashed, not copied.** An earlier cut built `domain ‖
    /// counter ‖ frame` in a fixed 256-byte stack scratch, which silently
    /// capped a signable frame at 226 bytes — and a multicast frame is a whole
    /// encapsulated Ethernet frame, so every multicast that matters sat above
    /// that cap. Signing failed, the frame was dropped, and because the merge
    /// had already claimed those destination groups no directed copy went out
    /// either: every listener behind the hop got nothing, silently. Hashing
    /// makes the signed message a fixed size whatever the frame's length, and
    /// removes the scratch buffer from the embedded stack along with it.
    fn fanout_message(counter: u64, frame: &[u8]) -> [u8; FANOUT_SIG_DOMAIN.len() + 32] {
        let mut msg = [0u8; FANOUT_SIG_DOMAIN.len() + 32];
        msg[..FANOUT_SIG_DOMAIN.len()].copy_from_slice(FANOUT_SIG_DOMAIN);
        msg[FANOUT_SIG_DOMAIN.len()..]
            .copy_from_slice(&wayfinder_auth::fanout_digest(counter, frame));
        msg
    }

    /// Verify a directed frame's `trailer` from neighbor `src`: check the
    /// pairwise tag over `frame` and that the counter is strictly newer than the
    /// last accepted from `src` (replay defense), updating it on success.
    /// Returns `false` (drop) if we have no key for `src`, the trailer is
    /// malformed, the tag is invalid, or the counter is a replay.
    pub fn verify_directed(&mut self, src: Mac, frame: &[u8], trailer: &[u8]) -> bool {
        let Some(counter) = self.verify_directed_tag(src, frame, trailer) else {
            return false;
        };
        match self.accept_recv_counter(src, counter) {
            CounterVerdict::Accepted => true,
            CounterVerdict::Stale => {
                tracing::trace!("auth: dropping directed frame with a replayed/stale counter");
                false
            }
            CounterVerdict::NoSlot => {
                tracing::trace!("auth: dropping directed frame, replay-counter table full");
                false
            }
        }
    }

    /// [`verify_directed`](Self::verify_directed) for the one directed frame
    /// whose freshness does not come from the replay counter: a **next-hop
    /// proof response**, which is bound to a nonce this node issued, has never
    /// issued before, and consumes on use.
    ///
    /// The tag is checked exactly as it is for any other directed frame — this
    /// is not a weaker verifier, and an outsider still cannot produce one. What
    /// it does not do is *refuse* a counter that is behind this node's
    /// high-water for `src`. It notes it instead, as a
    /// `restart_candidate`, and leaves the verdict to
    /// [`verify_challenge_response`](Self::verify_challenge_response), which
    /// re-anchors the sequence only if the nonce checks out.
    ///
    /// Why the exemption is safe here and nowhere else: a captured response is
    /// worthless against the next challenge (the nonce is fresh and this node
    /// chose it, and `issue_challenge` replaces any nonce still outstanding),
    /// so replaying one buys an attacker a tag verification and nothing more.
    /// A captured *unicast* has no such binding, which is why
    /// `wayfinder_driver_core`'s `required_proof` keeps every other directed
    /// sub-type — the challenge included, since its nonce proves nothing to its
    /// receiver — on the full guard.
    ///
    /// An **in-sequence** counter is still spent, exactly as
    /// [`verify_directed`](Self::verify_directed) would spend it. A settled
    /// mesh re-proves every path neighbour about once per emission interval, so
    /// a proof round that reset the guard would be a hole in it that reopened
    /// on a timer.
    ///
    /// **Enforces its own precondition** rather than trusting the caller. It is
    /// `pub`, its safety rests entirely on `frame` really being a proof
    /// response, and the classifier that guarantees that lives in another
    /// crate. So the sub-type is re-read here and anything else is handed
    /// straight to [`verify_directed`](Self::verify_directed): a
    /// misclassification, a widened match arm, or a third-party
    /// `OgmAuthOps` implementation then cannot open the replay guard on the
    /// unicast data plane.
    pub fn verify_directed_nonce_fresh(&mut self, src: Mac, frame: &[u8], trailer: &[u8]) -> bool {
        if frame.first().copied() != Some(BatmanPacketType::NextHopResponse.as_u8()) {
            tracing::trace!(?src, "auth: nonce-fresh verify asked for a non-proof frame");
            return self.verify_directed(src, frame, trailer);
        }
        let Some(counter) = self.verify_directed_tag(src, frame, trailer) else {
            // Deliberately leaves any standing candidate alone: this frame
            // never authenticated, so it is not evidence about anything,
            // including about whether an earlier claim is still current.
            return false;
        };
        match self.accept_recv_counter(src, counter) {
            CounterVerdict::Accepted => {
                self.restart_candidate = None;
                true
            }
            // The only state a restart can present as. Recorded only while a
            // challenge to `src` is actually outstanding: a candidate that
            // could never be redeemed is a slot an attacker occupies for free
            // by replaying any captured response.
            CounterVerdict::Stale => {
                if self.in_progress.iter().any(|c| c.neighbor == src) {
                    tracing::trace!(
                        ?src,
                        counter,
                        "auth: proof response behind the replay high-water; awaiting its nonce"
                    );
                    self.restart_candidate = Some((src, counter));
                } else {
                    tracing::trace!(
                        ?src,
                        counter,
                        "drop: stale-counter proof response with no challenge outstanding"
                    );
                    self.restart_candidate = None;
                    return false;
                }
                true
            }
            // Not evidence of a restart — there is no high-water to be behind.
            // Fails closed exactly as `verify_directed` does, because a frame
            // whose counter cannot be recorded cannot be re-anchored either.
            CounterVerdict::NoSlot => {
                tracing::trace!(?src, "drop: proof response, replay-counter table full");
                false
            }
        }
    }

    /// The half of [`verify_directed`](Self::verify_directed) that both
    /// verifiers share: check the trailer's shape and its pairwise tag over
    /// `frame`, returning the counter it carried.
    ///
    /// `None` — drop the frame — when we hold no live key for `src`, the
    /// trailer is malformed, or the tag does not verify. Deliberately says
    /// nothing about replay: that is the one decision the two callers make
    /// differently, so it is the one thing this does not decide for them.
    fn verify_directed_tag(&mut self, src: Mac, frame: &[u8], trailer: &[u8]) -> Option<u64> {
        if trailer.len() != DIRECTED_TRAILER_LEN {
            tracing::trace!("auth: dropping directed frame with malformed tag trailer");
            return None;
        }
        let Some(key) = self.live_neighbor(src).map(|n| n.pairwise_key) else {
            tracing::trace!("auth: dropping directed frame from an unverified neighbor");
            return None;
        };
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&trailer[..8]);
        let counter = u64::from_be_bytes(counter_bytes);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&trailer[8..DIRECTED_TRAILER_LEN]);
        // The sender's MAC is the bound context, so a frame this node authored
        // cannot be reflected back to it as if from `src`.
        if !verify_frame_tag(&key, counter, &src.0, frame, &tag) {
            tracing::trace!("auth: dropping directed frame with an invalid tag");
            return None;
        }
        Some(counter)
    }

    /// Allocate the next outgoing directed-frame counter (starting at 1).
    ///
    /// **One sequence for every destination and for fan-out frames alike** —
    /// see [`send_counter`](Self::send_counter). Fails closed, returning `None`
    /// rather than reusing a counter, if it would wrap,
    /// since a `(key, counter)` reuse with the static pairwise key would make
    /// tags replayable.
    fn next_send_counter(&mut self) -> Option<u64> {
        self.send_counter = self.send_counter.checked_add(1)?;
        Some(self.send_counter)
    }

    /// Accept `counter` from `src` only if strictly newer than the last accepted
    /// (monotonic replay guard), recording it on success.  The first frame from
    /// a neighbor is accepted and recorded.
    ///
    /// Returns *which* of the two refusals applies, not just that one did — see
    /// [`CounterVerdict`]. Only [`Accepted`](CounterVerdict::Accepted) admits a
    /// frame; a caller that treats the other two alike is free to, and
    /// [`verify_directed`](Self::verify_directed) does.
    fn accept_recv_counter(&mut self, src: Mac, counter: u64) -> CounterVerdict {
        if let Some(e) = self.recv_counters.iter_mut().find(|(m, _)| *m == src) {
            if counter <= e.1 {
                return CounterVerdict::Stale;
            }
            e.1 = counter;
            return CounterVerdict::Accepted;
        }
        if self.recv_counters.push((src, counter)).is_ok() {
            CounterVerdict::Accepted
        } else {
            CounterVerdict::NoSlot
        }
    }

    /// Build the canonical signed message for an OGM: a domain prefix followed
    /// by the immutable identity bytes (originator MAC and sequence number, as
    /// they appear on the wire) and the originator's certificate.  Mutable
    /// per-hop fields (ttl, tq) are deliberately excluded so the signature
    /// survives forwarding.  Returns the filled prefix of `out`.
    ///
    /// Excluding the mutable `tq` is only *safe* because the engine clamps an
    /// advertised TQ by the locally-measured link quality to the sender (the
    /// `local_quality` argument to `BatmanEngine::handle_rx`): a member replaying
    /// a victim's signed OGM with an inflated TQ still can't advertise a path
    /// better than its real link.  Keep that clamp if this exclusion stays.
    fn signed_message<'a>(
        orig: &[u8; 6],
        seqno: &[u8; 4],
        cert_bytes: &[u8],
        out: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let total = SIG_DOMAIN.len() + orig.len() + seqno.len() + cert_bytes.len();
        let buf = out.get_mut(..total)?;
        let (a, rest) = buf.split_at_mut(SIG_DOMAIN.len());
        a.copy_from_slice(SIG_DOMAIN);
        let (b, rest) = rest.split_at_mut(orig.len());
        b.copy_from_slice(orig);
        let (c, d) = rest.split_at_mut(seqno.len());
        c.copy_from_slice(seqno);
        d.copy_from_slice(cert_bytes);
        Some(&out[..total])
    }

    /// Append this node's cert and OGM signature to an OGM the engine has just
    /// built in `buf[..len]`, returning the new length.  Updates the header's
    /// `tvlv_len` to cover the added records.  Returns `None` if the OGM is
    /// malformed or `buf` lacks room for the additions.
    ///
    /// Emits the full cert ([`TvlvType::Cert`]) on every OGM. Use
    /// [`augment_ogm_lazy`](Self::augment_ogm_lazy) instead when
    /// `lazy_cert_distribution` is enabled, to emit an 8-byte fingerprint
    /// instead — see that method for details; the two are otherwise
    /// identical (same signed message, same revocation attachment).
    pub fn augment_ogm(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        self.augment_ogm_with_cert_record(buf, len, false)
    }

    /// The lazy-cert-distribution counterpart to
    /// [`augment_ogm`](Self::augment_ogm): appends an 8-byte cert
    /// fingerprint ([`TvlvType::CertFp`]) instead of the full 156-byte cert,
    /// cutting the dominant per-OGM airtime cost on a mesh where receivers
    /// already hold (or can fetch on demand) the sender's cert. The `OgmSig`
    /// signature is still computed over the *full* cert bytes exactly as
    /// [`augment_ogm`](Self::augment_ogm) does — only the on-the-wire
    /// representation of the cert differs, not what is signed — so a
    /// verifier reconstructs the same signed message from whichever cert its
    /// cache holds for the fingerprint. Otherwise identical: same TVLV/
    /// signature failure modes, same revocation attachment.
    pub fn augment_ogm_lazy(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        self.augment_ogm_with_cert_record(buf, len, true)
    }

    /// Shared implementation for [`augment_ogm`](Self::augment_ogm) and
    /// [`augment_ogm_lazy`](Self::augment_ogm_lazy): identical in every way
    /// except which TVLV record represents the cert on the wire — the full
    /// [`TvlvType::Cert`] or the 8-byte [`TvlvType::CertFp`] fingerprint,
    /// selected by `lazy`. A plain `bool` rather than a `TvlvType` parameter
    /// deliberately, since this function only ever writes one of these two
    /// specific records — a `TvlvType` parameter would let a caller pass any
    /// other variant and silently fall through to "full cert."
    fn augment_ogm_with_cert_record(
        &mut self,
        buf: &mut [u8],
        len: usize,
        lazy: bool,
    ) -> Option<usize> {
        if len < OGM_HDR {
            return None;
        }
        // Copy of our cert so its bytes don't hold a borrow of `self` while the
        // reused `sign_scratch` field is borrowed below (MembershipCert is Copy).
        let cert = self.cert;
        let cert_bytes = cert.as_bytes();
        let fingerprint = cert.fingerprint();
        // The signature always covers the *full* cert, regardless of which
        // TVLV shape carries it on the wire (see this method's doc comment).
        let (cert_record_type, cert_record_value): (TvlvType, &[u8]) = if lazy {
            (TvlvType::CertFp, &fingerprint)
        } else {
            (TvlvType::Cert, cert_bytes)
        };

        // Sign over the immutable identity (orig + seqno, as on the wire) + cert.
        let mut orig = [0u8; 6];
        orig.copy_from_slice(&buf[ORIG_OFF..ORIG_OFF + 6]);
        let mut seqno = [0u8; 4];
        seqno.copy_from_slice(&buf[SEQNO_OFF..SEQNO_OFF + 4]);
        let signature = {
            let signed = Self::signed_message(&orig, &seqno, cert_bytes, &mut self.sign_scratch)?;
            self.keypair.sign(signed)
        };

        let cert_record = TVLV_HDR + cert_record_value.len();
        let sig_record = TVLV_HDR + SIG_LEN;
        let added = cert_record + sig_record;
        let new_len = len.checked_add(added)?;
        if new_len > buf.len() {
            return None;
        }
        // Reject (rather than wrap) if the additions would overflow the u16
        // `tvlv_len` field — checked up front, before writing anything.
        let old_tvlv_len = u16::from_be_bytes([buf[TVLV_LEN_OFF], buf[TVLV_LEN_OFF + 1]]);
        let mut tvlv_len = u16::try_from(added)
            .ok()
            .and_then(|a| old_tvlv_len.checked_add(a))?;

        let mut off = len;
        off = Self::write_tvlv(buf, off, cert_record_type, cert_record_value);
        off = Self::write_tvlv(buf, off, TvlvType::OgmSig, &signature);

        // Attach pending revocations (budgeted) so an emergency purge floods
        // with this node's normal OGM traffic.  Bounded by both
        // `MAX_REVOKE_PER_OGM` and the remaining buffer / `tvlv_len` headroom so
        // an OGM cannot grow without limit; a record that does not fit this OGM
        // keeps its budget for the next one.
        let revoke_record = TVLV_HDR + REVOKE_LEN;
        let mut attached = 0;
        for kr in self.revocations.iter_mut() {
            if attached >= MAX_REVOKE_PER_OGM {
                break;
            }
            if kr.floods_left == 0 {
                continue;
            }
            if off + revoke_record > buf.len() {
                break;
            }
            let Some(next_tvlv_len) = u16::try_from(revoke_record)
                .ok()
                .and_then(|a| tvlv_len.checked_add(a))
            else {
                break;
            };
            off = Self::write_tvlv(buf, off, TvlvType::Revoke, kr.record.as_bytes());
            tvlv_len = next_tvlv_len;
            kr.floods_left -= 1;
            attached += 1;
        }

        // Grow the header's tvlv_len to cover every record appended above.
        buf[TVLV_LEN_OFF..TVLV_LEN_OFF + 2].copy_from_slice(&tvlv_len.to_be_bytes());

        Some(off)
    }

    /// Write one TVLV record (header + value) at `off`, returning the next
    /// offset.  The caller must have ensured the buffer has room.
    fn write_tvlv(buf: &mut [u8], off: usize, tvlv_type: TvlvType, value: &[u8]) -> usize {
        debug_assert!(
            value.len() <= u16::MAX as usize,
            "TVLV value exceeds u16 length"
        );
        let hdr = BatmanTvlvHdr {
            tvlv_type: tvlv_type.as_u8(),
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        buf[off..off + TVLV_HDR].copy_from_slice(hdr.as_bytes());
        let vstart = off + TVLV_HDR;
        buf[vstart..vstart + value.len()].copy_from_slice(value);
        vstart + value.len()
    }

    /// Verify an incoming OGM's authentication, caching the originator's keys
    /// on success.  Accepts either shape of cert TVLV: a legacy
    /// [`TvlvType::Cert`] (the full cert, carried on the wire) or a lazy
    /// [`TvlvType::CertFp`] (an 8-byte fingerprint, resolved against the
    /// cached cert for `orig` — see [`OgmVerdict::NeedCert`] when it cannot
    /// be resolved). Either way the signature is checked the same way, over
    /// the *whole* cert bytes (wire or cached) — the fingerprint only selects
    /// which cert to check against, it is never itself a trust boundary.
    pub fn verify_ogm(&mut self, payload: &[u8]) -> OgmVerdict {
        if payload.len() < OGM_HDR {
            tracing::trace!("auth: dropping OGM shorter than its header");
            return OgmVerdict::Rejected;
        }
        let tail = &payload[OGM_HDR..];

        let Some(sig_bytes) = find_tvlv(tail, TvlvType::OgmSig) else {
            tracing::trace!("auth: dropping OGM missing signature TVLV");
            return OgmVerdict::Rejected;
        };
        if sig_bytes.len() != SIG_LEN {
            tracing::trace!("auth: dropping OGM with malformed signature TVLV length");
            return OgmVerdict::Rejected;
        }

        let mut orig = [0u8; 6];
        orig.copy_from_slice(&payload[ORIG_OFF..ORIG_OFF + 6]);

        // Resolve the cert bytes to check the signature against: carried on
        // the wire (legacy), or looked up from the cache by fingerprint
        // (lazy).  `cached_cert_holder` exists only to extend the lifetime of
        // the owned copy the cache lookup returns, so `cert_bytes` can borrow
        // it in the lazy branch exactly like it borrows `tail` in the legacy
        // one.
        let cached_cert_holder: MembershipCert;
        let cert_bytes: &[u8] = if let Some(cb) = find_tvlv(tail, TvlvType::Cert) {
            cb
        } else if let Some(fp_bytes) = find_tvlv(tail, TvlvType::CertFp) {
            let Ok(fp) = <[u8; 8]>::try_from(fp_bytes) else {
                tracing::trace!("auth: dropping OGM with malformed fingerprint TVLV length");
                return OgmVerdict::Rejected;
            };
            match self.neighbor_cert(Mac(orig)) {
                Some((cached, cached_fp)) if cached_fp == fp => {
                    cached_cert_holder = cached;
                    cached_cert_holder.as_bytes()
                }
                _ => {
                    tracing::trace!("auth: fingerprint miss/rotation; cert fetch needed");
                    return OgmVerdict::NeedCert {
                        orig: Mac(orig),
                        fp,
                    };
                }
            }
        } else {
            // Unauthenticated OGM under an auth-enabled mesh (e.g. another mesh).
            tracing::trace!("auth: dropping OGM missing cert/fingerprint TVLV");
            return OgmVerdict::Rejected;
        };

        let Ok((cert, _)) = MembershipCert::ref_from_prefix(cert_bytes) else {
            tracing::trace!("auth: dropping OGM with malformed membership certificate");
            return OgmVerdict::Rejected;
        };

        let mut seqno = [0u8; 4];
        seqno.copy_from_slice(&payload[SEQNO_OFF..SEQNO_OFF + 4]);
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(sig_bytes);

        // A flood arrives once per neighbor on a shared segment, and a
        // forwarder rewrites only unsigned fields (TTL, TQ) — so every copy
        // carries the same certificate and the same signature over the same
        // message.  Verifying each copy from scratch would make a node's
        // crypto load the square of the segment's size; recognising the ones
        // already checked keeps it linear.
        //
        // Everything skipped below is a *pure* function of bytes this node has
        // already run it on: the anchor never changes for the life of this
        // state, so the same certificate bytes yield the same verdict and the
        // same pairwise key, and the same signature over the same message
        // yields the same answer.  What is not skipped is everything that can
        // change *since* then — the validity window and revocation — which is
        // re-judged per frame below.
        let known = self
            .neighbors
            .iter()
            .find(|n| n.cert.mac.0 == orig && n.raw_cert.as_bytes() == cert_bytes)
            .copied();

        let (verified, pairwise_key, signature_already_checked) = match known {
            Some(known) => {
                // `verify_cert`'s window check, against the clock as it is now
                // rather than as it was when this certificate was admitted.
                let not_before = known.raw_cert.not_before.get();
                let not_after = known.raw_cert.not_after.get();
                if self.wall.proves_before(not_before) || self.wall.proves_past(not_after) {
                    tracing::trace!(
                        "auth: dropping OGM whose cached certificate is outside its validity window"
                    );
                    return OgmVerdict::Rejected;
                }
                let same_ogm = known.last_ogm == Some((seqno, signature));
                (known.cert, known.pairwise_key, same_ogm)
            }
            None => {
                self.ogm_crypto_ops += 1;
                let verified = match self.anchor.verify_cert(cert, self.wall) {
                    Ok(v) => v,
                    Err(e) => {
                        // A `MacKeyMismatch` is not an ordinary verification
                        // failure and must not present as one. Every other
                        // variant here describes a certificate that is forged,
                        // foreign, or out of date — things an outsider produces
                        // and an operator can do nothing about. This one is a
                        // *misissuance*: the mesh root genuinely signed a
                        // certificate binding a key to an address it does not
                        // derive, which means either an authority issued twice
                        // for one address or the anchor is no longer under sole
                        // control. Nothing is broken by the time it is refused,
                        // which is exactly why it has to be said out loud.
                        //
                        // Without this the condition is silent: the OGM is
                        // dropped at `trace!`, and the attacker's *directed*
                        // frames then raise `UnauthenticatedTraffic` against the
                        // **victim's** address — filing a root compromise as the
                        // victim being slow to enrol. This is the alarm §8.9's
                        // `cache_neighbor` refusal used to raise, before the
                        // key↔address binding moved the refusal earlier; the
                        // signal moves with it.
                        //
                        // Storm-safe by construction: the board coalesces on
                        // `(kind, subject)`, so a flood is one row and a count.
                        if e == AuthError::MacKeyMismatch {
                            Self::report_identity_conflict(Mac(cert.node_mac), &cert.ed_pubkey);
                        }
                        tracing::trace!(error = ?e, "auth: dropping OGM whose certificate failed verification");
                        return OgmVerdict::Rejected;
                    }
                };
                self.ogm_crypto_ops += 1;
                let pairwise_key = self.keypair.pairwise_key(&verified.x_pubkey);
                (verified, pairwise_key, false)
            }
        };

        // The cert must be bound to the OGM's claimed originator, and not revoked.
        if verified.mac.0 != orig {
            tracing::trace!("auth: dropping OGM whose cert MAC does not match the originator");
            return OgmVerdict::Rejected;
        }
        if self.is_revoked(&verified) {
            tracing::trace!("auth: dropping OGM from a revoked originator");
            return OgmVerdict::Rejected;
        }

        // The signature is computed over the full `cert_bytes`, so any
        // padding past the 156-byte cert (which `ref_from_prefix` ignores)
        // changes the signed message and fails below — the cert length is
        // implicitly pinned by the signature.  On the lazy path `cert_bytes`
        // is always exactly 156 bytes (a `MembershipCert::as_bytes()`), so
        // this only bites the legacy wire path, unchanged from before.
        if !signature_already_checked {
            let ed_pubkey = verified.ed_pubkey;
            let signature_ok =
                match Self::signed_message(&orig, &seqno, cert_bytes, &mut self.sign_scratch) {
                    Some(signed) => {
                        self.ogm_crypto_ops += 1;
                        verify_signature(&ed_pubkey, signed, &signature)
                    }
                    None => {
                        tracing::trace!("auth: dropping OGM, signed-message buffer too small");
                        return OgmVerdict::Rejected;
                    }
                };
            if !signature_ok {
                tracing::trace!("auth: dropping OGM with an invalid signature");
                return OgmVerdict::Rejected;
            }
        }

        // Deliberately discarded: a refusal does not change this OGM's verdict.
        // The certificate really is CA-signed and its signature really does
        // check out, so this stays a decision about what the node *caches*.
        //
        // Since issue #16 (design 09 §5) landed, a certificate cannot name an
        // address its key does not derive, so a second *certified* key for one
        // address no longer reaches here at all — `verify_cert` refuses it
        // first. What survives for this to catch is a `derive_mac` collision:
        // 46 bits, negligible by accident and days of GPU time on purpose, but
        // the layering is cheap and the failure it prevents is a live member's
        // data plane going dark.
        let _ = self.cache_neighbor(NeighborKeys {
            cert: verified,
            pairwise_key,
            raw_cert: *cert,
            last_ogm: Some((seqno, signature)),
        });

        // Fold in any revocation records this OGM carries — each independently
        // signed by the mesh root — so an emergency purge floods alongside
        // normal OGM traffic.  Done only after the carrying OGM verified, so
        // an outsider cannot drive this path, and last so a revocation of the
        // *originator itself* (carried in a forwarded copy) still records.
        self.ingest_revocations_from_tail(tail);
        OgmVerdict::Verified
    }

    /// Build the canonical signed message for a keep-alive: a domain prefix,
    /// this node's MAC, and the tagged replay counter exactly as it appears on
    /// the wire.
    ///
    /// Mirrors [`signed_message`](Self::signed_message)'s shape but with its
    /// own domain separator and no cert — the receiver checks the signature
    /// against its neighbor cache instead of a cert carried on the wire (see
    /// [`verify_keepalive`](Self::verify_keepalive)). Returns the filled
    /// prefix of `out`.
    ///
    /// The **tagged** bytes are signed, not the stripped counter, so
    /// [`KEEPALIVE_COUNTER_TAG`] cannot be flipped off in flight to make a
    /// current keep-alive present as a legacy one.
    fn keepalive_signed_message<'a>(
        src: &[u8; 6],
        counter: &[u8; 8],
        out: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let total = KEEPALIVE_SIG_DOMAIN.len() + src.len() + counter.len();
        let buf = out.get_mut(..total)?;
        let (a, rest) = buf.split_at_mut(KEEPALIVE_SIG_DOMAIN.len());
        a.copy_from_slice(KEEPALIVE_SIG_DOMAIN);
        let (b, c) = rest.split_at_mut(src.len());
        b.copy_from_slice(src);
        c.copy_from_slice(counter);
        Some(&out[..total])
    }

    /// Append a signed liveness trailer to a keep-alive heartbeat the engine
    /// has just built in `buf[..len]`: an 8-byte replay counter and a 64-byte
    /// Ed25519 signature over it and this node's own MAC. Unlike
    /// [`augment_ogm`](Self::augment_ogm), no cert or fingerprint is attached
    /// — a keep-alive is only ever exchanged with a neighbor whose OGM (and
    /// thus cert) this node has already verified and cached, and
    /// [`verify_keepalive`](Self::verify_keepalive) checks against that cache
    /// rather than identity carried on the wire, so resending it on every
    /// heartbeat would be pure overhead.
    ///
    /// The counter comes from [`send_counter`](Self::send_counter), the node's
    /// single outgoing sequence, shared with directed and fan-out frames.
    /// Keep-alives carry no sequence number of their own
    /// ([`batman::wire::BatmanKeepAlivePacket`] is deliberately minimal), and
    /// this is what bounds replay of a captured, genuinely-signed heartbeat:
    /// a monotonic high-water mark, which is both strictly tighter than the
    /// 30-second window it replaces and needs no clock on either end
    /// (design 20 §4.3).
    ///
    /// Returns `None` — and the caller must not send the frame — if `buf`
    /// lacks room for the trailer or no counter can be allocated. Never an
    /// unsigned or counter-reused keep-alive.
    pub fn augment_keepalive(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        let new_len = len.checked_add(KEEPALIVE_TRAILER_LEN)?;
        if new_len > buf.len() {
            return None;
        }
        let src = self.cert.node_mac;
        let counter = (self.next_send_counter()? | KEEPALIVE_COUNTER_TAG).to_be_bytes();
        let signature = {
            let signed = Self::keepalive_signed_message(&src, &counter, &mut self.sign_scratch)?;
            self.keypair.sign(signed)
        };
        buf[len..len + 8].copy_from_slice(&counter);
        buf[len + 8..new_len].copy_from_slice(&signature);
        Some(new_len)
    }

    /// Verify an incoming keep-alive's [`augment_keepalive`] trailer, claimed
    /// to be from `src`. Checks, in order: the trailer is this build's format
    /// rather than the superseded time bucket; `src`'s cert is cached (from a
    /// previously-verified OGM — a neighbor never OGM-verified fails closed,
    /// the same as an unresolvable OGM fingerprint) and has not expired under
    /// this node's clock posture; `src` is not revoked; the signature itself;
    /// and finally the replay counter. Returns `true` only if every check
    /// passes.
    ///
    /// The counter is checked **after** the signature, matching
    /// [`verify_fanout`](Self::verify_fanout): admitting it earlier would let
    /// anyone on the medium advance this node's high-water mark for `src` with
    /// a forged trailer, and that mark is shared with `src`'s directed frames.
    pub fn verify_keepalive(&mut self, src: Mac, payload: &[u8]) -> bool {
        let Some(trailer_start) = payload.len().checked_sub(KEEPALIVE_TRAILER_LEN) else {
            tracing::trace!(?src, "auth: drop: keep-alive shorter than its auth trailer");
            return false;
        };
        let trailer = &payload[trailer_start..];
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&trailer[..8]);
        let tagged = u64::from_be_bytes(counter_bytes);
        if tagged & KEEPALIVE_COUNTER_TAG == 0 {
            // A peer still emitting the pre-design-20 time bucket. Named
            // rather than left to fail as a signature mismatch, which is what
            // an operator would otherwise have to diagnose from.
            tracing::trace!(?src, "auth: drop: legacy time-bucket keep-alive trailer");
            return false;
        }
        let counter = tagged & !KEEPALIVE_COUNTER_TAG;
        let Some(neighbor) = self.neighbors.iter().find(|n| n.cert.mac == src).copied() else {
            tracing::trace!(?src, "auth: drop: keep-alive from an unverified neighbor");
            return false;
        };
        if self.wall.proves_past(neighbor.cert.not_after) {
            tracing::trace!(?src, "auth: drop: keep-alive whose cached cert has expired");
            return false;
        }
        if self.is_revoked(&neighbor.cert) {
            tracing::trace!(?src, "auth: drop: keep-alive from a revoked neighbor");
            return false;
        }
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&trailer[8..KEEPALIVE_TRAILER_LEN]);
        let signed_ok =
            match Self::keepalive_signed_message(&src.0, &counter_bytes, &mut self.sign_scratch) {
                Some(signed) => verify_signature(&neighbor.cert.ed_pubkey, signed, &signature),
                None => false,
            };
        if !signed_ok {
            tracing::trace!(?src, "auth: drop: keep-alive with an invalid signature");
            return false;
        }
        if self.accept_recv_counter(src, counter) != CounterVerdict::Accepted {
            tracing::trace!(?src, counter, "auth: drop: replayed keep-alive counter");
            return false;
        }
        true
    }

    /// On a fingerprint miss/mismatch for `orig` (an [`OgmVerdict::NeedCert`]),
    /// decide whether to (re)send a `CertReq` now, and if so, write its
    /// self-authenticating body — this node's own cert followed by an
    /// Ed25519 signature over `orig ‖ our_mac` — into `buf`, returning its
    /// length.  Dedups against an already in-flight request for the same
    /// `orig`: suppressed (returns `None`) while its retry backoff has not
    /// yet elapsed, once its retry budget
    /// ([`MAX_CERT_REQUEST_ATTEMPTS`]) is exhausted, or when the in-flight
    /// table is full and this is a new originator. `first_hop` is the
    /// neighbor to address the request to — the requester has no route to
    /// `orig` yet (that is exactly why this is being called), so the caller
    /// must seed it with the OGM's actual link source (design doc §3.2).
    pub fn build_cert_request(
        &mut self,
        orig: Mac,
        fp: [u8; 8],
        first_hop: Mac,
        buf: &mut [u8],
    ) -> Option<usize> {
        if let Some(existing) = self.in_flight.iter_mut().find(|r| r.orig == orig) {
            if existing.fp != fp {
                // A further rotation arrived before the previous fetch
                // resolved: restart tracking for the new target.
                existing.fp = fp;
                existing.attempts = 0;
                existing.next_attempt = Duration::ZERO;
            }
            if self.now < existing.next_attempt {
                return None; // still within backoff
            }
            if existing.attempts >= MAX_CERT_REQUEST_ATTEMPTS {
                tracing::debug!(?orig, "auth: cert-request retry budget exhausted");
                return None;
            }
            existing.attempts += 1;
            existing.next_attempt = self.now.saturating_add(CERT_REQUEST_RETRY);
            existing.first_hop = first_hop;
        } else {
            let entry = InFlightCertRequest {
                orig,
                fp,
                first_hop,
                attempts: 1,
                next_attempt: self.now.saturating_add(CERT_REQUEST_RETRY),
            };
            if self.in_flight.push(entry).is_err() {
                tracing::debug!(?orig, "auth: in-flight cert-request table full");
                return None;
            }
        }

        let mut msg = [0u8; CERT_REQ_SIG_DOMAIN.len() + 12];
        msg[..CERT_REQ_SIG_DOMAIN.len()].copy_from_slice(CERT_REQ_SIG_DOMAIN);
        msg[CERT_REQ_SIG_DOMAIN.len()..CERT_REQ_SIG_DOMAIN.len() + 6].copy_from_slice(&orig.0);
        msg[CERT_REQ_SIG_DOMAIN.len() + 6..].copy_from_slice(&self.cert.node_mac);
        let signature = self.keypair.sign(&msg);

        let cert_bytes = self.cert.as_bytes();
        let total = cert_bytes.len() + signature.len();
        let out = buf.get_mut(..total)?;
        out[..cert_bytes.len()].copy_from_slice(cert_bytes);
        out[cert_bytes.len()..].copy_from_slice(&signature);
        Some(total)
    }

    /// Ingest a `CertReply` body (a raw [`MembershipCert`]) delivered locally
    /// to this node.  Verifies it against the trust anchor, confirms it
    /// answers an outstanding in-flight request for that MAC (so an
    /// unsolicited or spoofed reply cannot poison the cache), caches it, and
    /// clears the in-flight entry.  Returns `true` only when the cert was
    /// newly cached — a `false` return means the reply was dropped and, if
    /// still needed, the requester-side retry in
    /// [`build_cert_request`](Self::build_cert_request) is the backstop.
    pub fn ingest_cert_reply(&mut self, body: &[u8]) -> bool {
        let Ok((cert, _)) = MembershipCert::ref_from_prefix(body) else {
            tracing::trace!("auth: dropping malformed cert reply");
            return false;
        };
        let verified = match self.anchor.verify_cert(cert, self.wall) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping cert reply that failed verification");
                return false;
            }
        };
        let Some(pos) = self
            .in_flight
            .iter()
            .position(|r| r.orig.0 == verified.mac.0)
        else {
            tracing::trace!("auth: dropping cert reply that answers no outstanding request");
            return false;
        };
        // Cache *before* clearing the in-flight entry, and only clear it if the
        // cache took the certificate. A refused reply has not answered the
        // request — so dropping the entry here would both report success and
        // delete the retry backstop this function's contract promises, letting
        // whoever raced the reply in consume every fetch attempt for that MAC.
        let pairwise_key = self.keypair.pairwise_key(&verified.x_pubkey);
        let mac = verified.mac;
        if self.cache_neighbor(NeighborKeys {
            cert: verified,
            pairwise_key,
            raw_cert: *cert,
            // No OGM of theirs has been verified through this cert yet.
            last_ogm: None,
        }) == Cached::RefusedLiveIdentity
        {
            tracing::trace!(?mac, "auth: dropping cert reply for a contested address");
            return false;
        }
        self.in_flight.swap_remove(pos);
        true
    }

    /// Verify an incoming `CertReq` body (the requester's own cert followed
    /// by a signature over `our_mac ‖ requester_mac`) delivered locally to
    /// this node — i.e. this node *is* the originator whose cert was
    /// requested (the terminal case; an intermediate holder answering early
    /// is a deferred optimization, design doc §3.1/open-decision #1).
    /// Verifies the requester's cert against the trust anchor and the
    /// self-authenticating signature against that cert's own key (proving
    /// they hold the matching private key), rate-limits repeated requests
    /// from the same MAC ([`CERT_REQ_RATE_LIMIT`], §8), and caches the
    /// requester's cert (a free, verified exchange that also lets this node
    /// verify the requester's own OGMs sooner). Returns the requester's MAC
    /// on success, or `None` (dropped, `trace!`-logged) on any failure —
    /// the caller must not answer or park a pending reply in that case.
    pub fn verify_cert_request(&mut self, body: &[u8]) -> Option<Mac> {
        let cert_len = core::mem::size_of::<MembershipCert>();
        if body.len() != cert_len + SIG_LEN {
            tracing::trace!("auth: dropping malformed cert request body");
            return None;
        }
        let (cert_bytes, sig_bytes) = body.split_at(cert_len);
        let Ok((cert, _)) = MembershipCert::ref_from_prefix(cert_bytes) else {
            tracing::trace!("auth: dropping cert request with malformed requester cert");
            return None;
        };
        let verified = match self.anchor.verify_cert(cert, self.wall) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping cert request whose requester cert failed verification");
                return None;
            }
        };
        let requester = verified.mac;

        if self.is_revoked(&verified) {
            tracing::trace!("auth: dropping cert request from a revoked requester");
            return None;
        }

        // Proof-of-possession *before* touching the rate limiter: a cert's
        // bytes are not secret (broadcast on every OGM, or fetchable), so
        // anyone can replay a real member's cert with a garbage signature.
        // Checking the signature first means only someone who actually
        // holds the requester's private key can consume their rate-limit
        // slot — otherwise an attacker could keep a named member's slot
        // permanently "hot" with forged requests and deny their genuine
        // ones, inverting the rate limiter's whole purpose (§8).
        let mut msg = [0u8; CERT_REQ_SIG_DOMAIN.len() + 12];
        msg[..CERT_REQ_SIG_DOMAIN.len()].copy_from_slice(CERT_REQ_SIG_DOMAIN);
        msg[CERT_REQ_SIG_DOMAIN.len()..CERT_REQ_SIG_DOMAIN.len() + 6]
            .copy_from_slice(&self.cert.node_mac);
        msg[CERT_REQ_SIG_DOMAIN.len() + 6..].copy_from_slice(&requester.0);
        let mut sig = [0u8; SIG_LEN];
        sig.copy_from_slice(sig_bytes);
        if !verify_signature(&verified.ed_pubkey, &msg, &sig) {
            tracing::trace!(
                "auth: dropping cert request with an invalid self-authentication signature"
            );
            return None;
        }

        // The identity check goes *before* the rate limiter, for the same
        // reason proof-of-possession does. `requester` is taken from the
        // presented certificate, so a second CA-signed certificate for a live
        // member's address arrives here naming *that member* — and a limiter
        // spent on it is the real member's slot, denying their genuine
        // requests for `CERT_REQ_RATE_LIMIT` at a time. Checking first
        // means a contested address costs the member nothing.
        if self.identity_conflict(requester, &verified.ed_pubkey) {
            Self::report_identity_conflict(requester, &verified.ed_pubkey);
            return None;
        }

        if !self.accept_cert_request_rate(requester) {
            tracing::trace!(?requester, "auth: rate-limiting repeated cert request");
            return None;
        }

        let pairwise_key = self.keypair.pairwise_key(&verified.x_pubkey);
        // Cannot be refused: `identity_conflict` was just checked above, and
        // nothing between here and there mutates the neighbour table.
        let _ = self.cache_neighbor(NeighborKeys {
            cert: verified,
            pairwise_key,
            raw_cert: *cert,
            // No OGM of theirs has been verified through this cert yet.
            last_ogm: None,
        });
        Some(requester)
    }

    /// Accept a `CertReq` from `requester` only if at least
    /// [`CERT_REQ_RATE_LIMIT`] has passed since the last one accepted
    /// from them, recording the acceptance on success. The first request
    /// from a requester is always accepted.
    fn accept_cert_request_rate(&mut self, requester: Mac) -> bool {
        if let Some(entry) = self.cert_req_rate.iter_mut().find(|(m, _)| *m == requester) {
            if self.now.saturating_sub(entry.1) < CERT_REQ_RATE_LIMIT {
                return false;
            }
            entry.1 = self.now;
            return true;
        }
        if self.cert_req_rate.push((requester, self.now)).is_err() {
            // Table full: overwrite the first entry rather than refusing a
            // legitimate new requester outright (bounded, simple eviction —
            // mirrors `cache_neighbor`'s table-full policy).
            tracing::debug!("auth: cert-request rate-limit table full; evicting an entry");
            if let Some(first) = self.cert_req_rate.first_mut() {
                *first = (requester, self.now);
            }
        }
        true
    }

    /// Whether a `CertReply` to `requester` is currently parked, pending a
    /// route becoming available.
    pub fn has_pending_reply(&self, requester: Mac) -> bool {
        self.pending_replies
            .iter()
            .any(|p| p.requester == requester)
    }

    /// Park (or refresh) a verified requester's reply, to be sent once a
    /// route to them appears. Bounded ([`MAX_PENDING_REPLIES`]) and TTL'd
    /// ([`PENDING_REPLY_TTL`], garbage-collected by
    /// [`set_time`](Self::set_time)); the requester's own retry
    /// ([`build_cert_request`](Self::build_cert_request) backoff) is the
    /// backstop if this node is never flushed or the entry is evicted.
    pub fn park_pending_reply(&mut self, requester: Mac) {
        if let Some(entry) = self
            .pending_replies
            .iter_mut()
            .find(|p| p.requester == requester)
        {
            entry.parked = self.now;
            return;
        }
        let entry = PendingReply {
            requester,
            parked: self.now,
        };
        if self.pending_replies.push(entry).is_err() {
            // Table full: overwrite the first (bounded, simple eviction).
            tracing::debug!("auth: pending-reply table full; evicting an entry");
            if let Some(first) = self.pending_replies.first_mut() {
                *first = entry;
            }
        }
    }

    /// Clear a parked pending reply, once it has been sent.
    pub fn clear_pending_reply(&mut self, requester: Mac) {
        if let Some(i) = self
            .pending_replies
            .iter()
            .position(|p| p.requester == requester)
        {
            self.pending_replies.swap_remove(i);
        }
    }

    /// Parse and ingest every [`TvlvType::Revoke`] record in an OGM `tail`.
    /// Each is independently verified by
    /// [`ingest_revocation`](Self::ingest_revocation) against the trust anchor,
    /// so a malformed or forged record is simply ignored.
    fn ingest_revocations_from_tail(&mut self, tail: &[u8]) {
        // `tail` is part of the caller's payload, disjoint from `self`, so the
        // borrow held by the iterator coexists with ingesting into `self`.
        for value in iter_tvlv(tail, TvlvType::Revoke) {
            if let Ok((rec, _)) = RevocationRecord::ref_from_prefix(value) {
                self.ingest_revocation(rec);
            }
        }
    }

    /// The cached keys for `mac`, treating an expired certificate as absent.
    ///
    /// Every neighbor lookup goes through this rather than scanning
    /// `self.neighbors` directly. Verifying an OGM caches the peer's
    /// certificate *and* the pairwise key derived from it, and nothing on that
    /// path prunes a lapsed entry (`cache_neighbor` overwrites in place or
    /// refuses; it never expires) — so without an expiry check here, a peer whose
    /// enrollment has lapsed keeps a working link-local data plane long after
    /// its route is gone. Certificate expiry is this mesh's passive
    /// revocation mechanism; it has to actually revoke something.
    ///
    /// An entry is dropped only when the posture can **prove** its
    /// `not_after` has passed, so a node that cannot tell the time judges
    /// nothing and a node free-running from a floor judges only what its floor
    /// establishes. A node that cannot tell the time must not tear down its own
    /// routes on a guess (design 20 §4.2), and its clocked peers enforce the
    /// expiry on its behalf (§5.1).
    fn live_neighbor(&self, mac: Mac) -> Option<&NeighborKeys> {
        self.neighbors
            .iter()
            .find(|n| n.cert.mac == mac && !self.wall.proves_past(n.cert.not_after))
    }

    // --- next-hop proof: challenge/response ----------------------------
    //
    // An OGM's signature attests its *originator*; nothing in it attests the
    // *forwarder*, so a next hop would otherwise be installed on the strength
    // of possessing bytes anyone can copy off the air. These three calls are
    // how a candidate next hop proves it is really there: the challenger picks
    // a fresh nonce, and only a node holding the pairwise key for the MAC it
    // claims can answer. See `docs/design/implemented/09-mesh-auth-gaps.md` §4.

    /// The PRF key for nonce derivation: this node's pairwise key *with
    /// itself*.
    ///
    /// A nonce must be unpredictable to everyone else, and there is no entropy
    /// source in `no_std` here (`getrandom` is a `std`-only dependency of
    /// `wayfinder-auth`). Diffie-Hellman against our own public key yields a
    /// value only the holder of our secret can compute, with no new dependency
    /// and no RNG to plumb through every board.
    fn nonce_prf_key(&self) -> [u8; 32] {
        self.keypair.pairwise_key(&self.keypair.x_pubkey())
    }

    /// Build the `context` a challenge response is tagged under: the domain
    /// followed by the *responder's* MAC.
    ///
    /// The MAC is bound in for the reason [`frame_tag`] documents — the
    /// pairwise key is symmetric across both directions, so without the
    /// sender's identity an `A→B` response would be interchangeable with a
    /// `B→A` one.
    fn resp_context(responder: &[u8; 6]) -> [u8; RESP_CONTEXT_LEN] {
        let mut ctx = [0u8; RESP_CONTEXT_LEN];
        ctx[..CHALLENGE_RESP_DOMAIN.len()].copy_from_slice(CHALLENGE_RESP_DOMAIN);
        ctx[CHALLENGE_RESP_DOMAIN.len()..].copy_from_slice(responder);
        ctx
    }

    /// Issue a next-hop proof challenge to `neighbor`, returning the nonce to
    /// put on the wire and recording it as outstanding.
    ///
    /// Returns `None` — fails closed — when `neighbor` is not a verified,
    /// unexpired member, since there would be no key to check an answer
    /// against. A second challenge to a neighbor already outstanding replaces
    /// it: only the newest nonce is ever accepted, so a response in flight for
    /// the superseded one is correctly refused.
    pub fn issue_challenge(&mut self, neighbor: Mac) -> Option<[u8; CHALLENGE_NONCE_LEN]> {
        // Fail closed for an unverified or lapsed peer, on the same
        // `live_neighbor` rule every other pairwise lookup goes through.
        self.live_neighbor(neighbor)?;

        let seq = self.challenge_counter.checked_add(1)?;
        self.challenge_counter = seq;
        let nonce = frame_tag(&self.nonce_prf_key(), seq, NONCE_PRF_DOMAIN, &neighbor.0);

        let entry = OutstandingChallenge {
            neighbor,
            nonce,
            issued_seq: seq,
        };
        if let Some(existing) = self.in_progress.iter_mut().find(|c| c.neighbor == neighbor) {
            *existing = entry;
        } else if self.in_progress.push(entry).is_err() {
            // Table full. Evict the least-recently-issued rather than refusing:
            // a churn of candidate next hops must not be able to lock out proof
            // of a legitimate one.
            let oldest = self
                .in_progress
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| c.issued_seq)
                .map(|(i, _)| i)?;
            self.in_progress[oldest] = OutstandingChallenge {
                neighbor,
                nonce,
                issued_seq: seq,
            };
        }
        Some(nonce)
    }

    /// Answer a next-hop proof challenge from `challenger` over `nonce`,
    /// returning the tag to send back.
    ///
    /// Returns `None` when `nonce` is not exactly [`CHALLENGE_NONCE_LEN`]
    /// bytes (malformed rather than silently tagged as given — the same
    /// explicit check [`verify_challenge_response`](Self::verify_challenge_response)
    /// applies to its `tag` argument) or when `challenger` is not a
    /// verified, unexpired member — there is no pairwise key to answer
    /// under, and answering an outsider would tell it nothing but cost this
    /// node work.
    pub fn answer_challenge(&self, challenger: Mac, nonce: &[u8]) -> Option<[u8; TAG_LEN]> {
        if nonce.len() != CHALLENGE_NONCE_LEN {
            tracing::trace!("auth: dropping challenge with a malformed nonce");
            return None;
        }
        let key = self.live_neighbor(challenger)?.pairwise_key;
        let ctx = Self::resp_context(&self.cert.node_mac);
        // The nonce carries the freshness, so the counter argument is unused
        // here; the domain in `ctx` is what separates this from a directed tag.
        Some(frame_tag(&key, 0, &ctx, nonce))
    }

    /// Verify a challenge response claimed to come from `neighbor`, against the
    /// nonce this node actually issued to it.
    ///
    /// Consumes the outstanding challenge on success, so one response proves
    /// liveness exactly once: accepting a replay would let an attacker that
    /// observed a single exchange keep a route alive without the neighbor ever
    /// participating again.
    pub fn verify_challenge_response(&mut self, neighbor: Mac, tag: &[u8]) -> bool {
        // Taken up front, before any early return, so a claim can never outlive
        // the frame that raised it. The alternative — taking it beside the
        // re-anchor below — leaves a stale `(mac, counter)` standing on every
        // failure path, to be redeemed later against a counter that is no
        // longer current.
        let claim = self.restart_candidate.take();
        let Ok(tag) = <[u8; TAG_LEN]>::try_from(tag) else {
            tracing::trace!("auth: dropping challenge response with a malformed tag");
            return false;
        };
        let Some(idx) = self.in_progress.iter().position(|c| c.neighbor == neighbor) else {
            tracing::trace!("auth: dropping challenge response with nothing outstanding");
            return false;
        };
        let nonce = self.in_progress[idx].nonce;
        let Some(key) = self.live_neighbor(neighbor).map(|n| n.pairwise_key) else {
            tracing::trace!("auth: dropping challenge response from an unverified neighbor");
            return false;
        };

        let ctx = Self::resp_context(&neighbor.0);
        if !verify_frame_tag(&key, 0, &ctx, &nonce, &tag) {
            tracing::trace!("auth: dropping challenge response with an invalid tag");
            return false;
        }
        self.in_progress.swap_remove(idx);
        // `neighbor` has just proved it is live *now* and holds the pairwise
        // key, against a nonce nobody could have predicted. That is the only
        // evidence this node ever gets that a peer restarted rather than that
        // its frames are being replayed, so it is where a stale replay
        // high-water is re-anchored — to the counter the proving frame actually
        // carried, so the sequence resumes at the peer's real position rather
        // than being opened from zero.
        //
        // A claim naming anyone else belongs to a frame this exchange is not
        // about; it was consumed above and is discarded here.
        if let Some((mac, counter)) = claim
            && mac == neighbor
        {
            // `warn!`, not `debug!`: rewinding a replay guard is a
            // security-relevant weakening of this node's own defences (see
            // `anchor_recv_counter`), and `debug!` is off in normal operation.
            // It clears CLAUDE.md's bar for the level — an outsider cannot
            // reach it (a valid pairwise tag *and* an unpredictable nonce are
            // needed) and it is paced by this node's own challenge cadence, so
            // it is neither remote-driven nor hot-path. A peer that produces
            // one every round is not a reboot, and that is exactly what an
            // operator should be able to see.
            if self.anchor_recv_counter(neighbor, counter) {
                tracing::warn!(
                    ?neighbor,
                    counter,
                    "auth: replay high-water rewound for a peer that proved a restart"
                );
            } else {
                tracing::warn!(
                    ?neighbor,
                    counter,
                    "auth: no replay-counter slot to re-anchor a restarted peer; its directed traffic stays refused"
                );
            }
        }
        true
    }

    /// Force `src`'s replay high-water to `counter`, whether that moves it
    /// forward or back.
    ///
    /// The deliberate opposite of [`accept_recv_counter`](Self::accept_recv_counter),
    /// which only ever advances. Reachable from one place —
    /// [`verify_challenge_response`](Self::verify_challenge_response), after a
    /// peer has proved liveness against a fresh nonce — because moving a
    /// high-water backwards is exactly what an attacker replaying a captured
    /// frame would want, and a nonce it cannot predict is the only thing that
    /// distinguishes the two.
    ///
    /// Re-anchoring does mean the frames captured from `src`'s **previous** boot
    /// session become replayable again: their counters sit above the restarted
    /// peer's, so the guard admits them. And the cost does not stop at the
    /// replay — injecting one *advances* the high-water back past the restarted
    /// peer's real position, so the genuine peer is refused again until the next
    /// proof round re-anchors it. A captured frame is therefore a repeatable
    /// denial of service against a member that has just rebooted, for as long as
    /// an attacker holds one and stays on the medium.
    ///
    /// That is inherent to a counter the peer keeps in memory under a pairwise
    /// key that outlives its reboot — the same `(key, counter)` reuse
    /// [`next_send_counter`](Self::next_send_counter) refuses to *create* by
    /// wrapping, though note it cannot detect this case, which is a different
    /// mechanism for the same class of problem. Two things would close it, and
    /// neither belongs in this change: a per-boot epoch bound into the tag (a
    /// wire change), or a `send_counter` persisted beside the identity seed (a
    /// flash write per directed frame or per batch, on a board that has to
    /// survive an unclean power cut). What is bought in the meantime is a peer
    /// that can rejoin at all: without this the guard refuses a rebooted
    /// member's every directed frame until it has re-spent every counter it
    /// spent before, which is not a recovery.
    ///
    /// Returns whether the anchor was actually stored. `false` means `src` had
    /// no row and `recv_counters` is full, so nothing changed and the peer stays
    /// refused — the caller must say so rather than report a re-anchor that did
    /// not happen. Not reachable through the restart path as written (a
    /// [`Stale`](CounterVerdict::Stale) verdict means the row exists), which is
    /// why it is reported rather than handled.
    #[must_use]
    fn anchor_recv_counter(&mut self, src: Mac, counter: u64) -> bool {
        if let Some(e) = self.recv_counters.iter_mut().find(|(m, _)| *m == src) {
            e.1 = counter;
            return true;
        }
        self.recv_counters.push((src, counter)).is_ok()
    }

    /// Drop every cached neighbor whose certificate has expired.
    ///
    /// [`live_neighbor`](Self::live_neighbor) already makes an expired entry
    /// unusable; this reclaims the slot it occupies, so a long-lived node's
    /// bounded neighbor table cannot fill with lapsed members and start
    /// evicting live ones. Evicts exactly what
    /// [`live_neighbor`](Self::live_neighbor) treats as gone — nothing under
    /// [`Clocked::Unknown`] — so the two cannot disagree about what is live.
    fn evict_expired_neighbors(&mut self) {
        if !self.wall.judges_windows() {
            return;
        }
        let wall = self.wall;
        let before = self.neighbors.len();
        self.neighbors
            .retain(|n| !wall.proves_past(n.cert.not_after));
        if self.neighbors.len() != before {
            self.key_generation = self.key_generation.wrapping_add(1);
            // Reported here, at the branch point, because this is the only
            // place that still knows *why* a key went. Whatever reconciles
            // against the result (`BatmanEngine::retain_proven`) deliberately
            // cannot tell expiry from a cache eviction, so its own record
            // cannot say "renew this member's certificate" — and that is the
            // actionable half. Bounded: once per member per validity period.
            tracing::debug!(
                dropped = before - self.neighbors.len(),
                "auth: evicted neighbor keys whose certificates have lapsed"
            );
        }
    }

    /// Insert or refresh a verified neighbor's keys.
    ///
    /// One address, one identity, for as long as that identity's certificate
    /// is live. A second CA-signed certificate for a MAC this node already
    /// holds a *live* entry for, under a different `ed_pubkey`, is refused
    /// rather than allowed to overwrite it — the entry carries the pairwise
    /// key, that key is symmetric ECDH, and replacing it severs the real
    /// member's directed data plane in both directions at once. One misissued
    /// certificate would otherwise be a total, sustained denial of a named
    /// member's authenticated traffic (gap-4A).
    ///
    /// # This rule is now defense in depth, and what it guards is a collision
    ///
    /// Since design 09 §5's key↔address binding landed, `verify_cert` refuses
    /// any certificate whose subject is not the address its `ed_pubkey`
    /// derives. Two *different* keys therefore cannot both hold certificates
    /// for one address, so the second certificate this rule was written to
    /// refuse never reaches here at all — it is rejected at verification, which
    /// is where `AlarmKind::IdentityConflict` is now raised from.
    ///
    /// What survives is the one case the binding cannot exclude: a `derive_mac`
    /// collision, two distinct identity keys hashing to one 46-bit address.
    /// Negligible by accident (7.1e-9 at 1,000 nodes) and days of GPU time on
    /// purpose. The rule is kept because it is a few lines and the failure it
    /// prevents is a named member's data plane going dark; it is not kept
    /// because anything routinely exercises it. Read everything below as a
    /// description of that residual, not of a live threat — and note that the
    /// tests reach it by building the colliding entry by hand, because it can
    /// no longer be minted (`colliding_neighbor`).
    ///
    /// **Revocation is where this node and its authority deliberately diverge.**
    /// The authority keeps a revoked MAC locked (its `find` matches on the
    /// validity window and pointedly not on the `revoked` flag, because reading
    /// the flag there once handed a revoked node's address to whoever asked
    /// next). This node does the opposite and frees the address on
    /// `evict_neighbor` — because a receiver that kept the lock would refuse
    /// the re-admission its own authority had deliberately signed.
    ///
    /// No new bookkeeping is needed to release the pin, and deliberately so —
    /// three mechanisms that already exist compose into it:
    ///
    /// - ingesting a revocation calls [`evict_neighbor`](Self::evict_neighbor),
    ///   so a revoked member leaves no entry for this rule to collide with;
    /// - a lapsed certificate is dropped by
    ///   [`evict_expired_neighbors`](Self::evict_expired_neighbors) and treated
    ///   as absent by [`live_neighbor`](Self::live_neighbor), so the address is
    ///   free once the window is out;
    /// - re-admission after a revocation is already modelled by
    ///   [`RevocationRecord::cancels`].
    ///
    /// Two edges are decided here rather than inherited:
    ///
    /// - **An unset clock admits the new key.** `live_neighbor` calls
    ///   everything live under [`Clocked::Unknown`], so mirroring it would leave an
    ///   unclocked node pinning an address *forever* on an entry it cannot
    ///   judge. Such a node cannot judge certificate validity in the first
    ///   place, and the authority itself fails closed on a zero clock rather
    ///   than locking addresses on one.
    ///
    ///   **The cost is that this rule does not protect a node under
    ///   [`Clocked::Unknown`]**, which since design 20 is a *supported running
    ///   state* rather than an unreachable one: a board with no anchor routes
    ///   and admits peers on their signatures. What keeps it latent rather than
    ///   exploitable is narrower than it used to be — no board constructs an
    ///   `OgmAuth` at all, because a bare-metal node cannot hold a membership
    ///   credential until #52 persists one.
    ///
    ///   An *anchored* board is [`Clocked::AtLeast`], which judges windows, so
    ///   the rule does apply there and closes as boards gain anchors. It stays
    ///   open for an unanchored one, and the candidate if that ever matters is
    ///   a rule keyed on *recency* — the shared uptime clock every target
    ///   already has — which needs a per-entry timestamp `NeighborKeys` does
    ///   not carry, and at 64 × 272 bytes that is a real budget on exactly the
    ///   node it would protect.
    /// - **The comparison is on `ed_pubkey` alone**, matching the authority's
    ///   issued-certificate lock. An agreement-key-only rotation is something
    ///   the CA will sign for a live member, so a rule keyed on anything wider
    ///   would reject a certificate this mesh's own authority had just issued.
    ///   Note what that leaves: such a rotation *does* move the pairwise key,
    ///   so it is the identity that is pinned here, not the data-plane key.
    ///
    /// One residual worth naming — and note it is a residual of the *collision*
    /// case now, not of an attacker holding a certificate:
    ///
    /// - **It is first-writer-wins.** Whoever is cached first owns the address
    ///   for the life of its certificate, and at each release point (expiry, a
    ///   revocation, a reboot, or the table-full eviction below) it is briefly
    ///   open. Before the binding this was a real exposure, because an attacker
    ///   could hold a certificate for the victim's address and flood for that
    ///   boundary. It can no longer obtain one, so what remains is the ordering
    ///   between two genuine colliding members — and the alarm is what makes
    ///   the collision visible either way.
    fn cache_neighbor(&mut self, keys: NeighborKeys) -> Cached {
        if self.identity_conflict(keys.cert.mac, &keys.cert.ed_pubkey) {
            Self::report_identity_conflict(keys.cert.mac, &keys.cert.ed_pubkey);
            return Cached::RefusedLiveIdentity;
        }
        if !self.wall.judges_windows() {
            // Counted here rather than in `verify_cert`, which is in another
            // crate and has no state to count into — and here is the point of
            // *admission*, which is what the number is about. Saturating: see
            // the field.
            self.unjudged_admissions = self.unjudged_admissions.saturating_add(1);
        }

        if let Some(slot) = self
            .neighbors
            .iter_mut()
            .find(|n| n.cert.mac == keys.cert.mac)
        {
            *slot = keys;
        } else if self.neighbors.push(keys).is_err() {
            // Table full: overwrite the first entry rather than dropping the
            // freshly verified neighbor (bounded, simple eviction).
            //
            // Note what this does *not* do: the slot it takes may hold a live
            // member, and replacing that entry severs its data plane exactly
            // the way the refusal above exists to prevent. An adversary who
            // can fill the table — which costs a certificate per slot, so a
            // mass misissuance rather than the single one this rule is scoped
            // to — can therefore still push a live member out and then take
            // its address. Left as it is deliberately: refusing to evict a
            // live entry instead would mean a full table could never admit a
            // new neighbor, which is a worse and more easily reached denial.
            // See the MR for #48 and the follow-up it names.
            if let Some(first) = self.neighbors.first_mut() {
                *first = keys;
                // The displaced member's keys are gone under its own address —
                // the same loss expiry inflicts, to be reconciled the same way
                // (see `key_generation`). This is the path that makes that
                // counter's consumer a *reconciliation* rather than an expiry
                // handler: no clock is involved here at all.
                self.key_generation = self.key_generation.wrapping_add(1);
            }
        }
        Cached::Stored
    }

    /// Whether caching a certificate binding `mac` to `ed_pubkey` would be
    /// refused because a **live** cached member already holds that address
    /// under a different identity key.
    ///
    /// Split out from [`cache_neighbor`](Self::cache_neighbor) because
    /// [`verify_cert_request`](Self::verify_cert_request) has to ask the
    /// question *before* it spends the requester's rate-limit slot — see the
    /// note there.
    ///
    /// [`Clocked::Unknown`] answers `false`: a node that cannot judge validity
    /// cannot tell a live holder of an address from a lapsed one, so it has no
    /// grounds to call a second identity a conflict.
    /// [`cache_neighbor`](Self::cache_neighbor)'s doc has the argument, and the
    /// security cost that comes with it. Under design 20 §4.2 this stops being
    /// an accident of sentinel choice and becomes a stated rule.
    fn identity_conflict(&self, mac: Mac, ed_pubkey: &[u8; 32]) -> bool {
        if !self.wall.judges_windows() {
            return false;
        }
        self.neighbors.iter().any(|n| {
            n.cert.mac == mac
                && !self.wall.proves_past(n.cert.not_after)
                && n.cert.ed_pubkey != *ed_pubkey
        })
    }

    /// Record a refused second identity for `mac`, on both channels.
    ///
    /// Nothing is broken by the time this fires, which is exactly why it needs
    /// saying: an operator seeing only the dropped certificate would be looking
    /// at what presents as unexplained route flapping, with the real
    /// explanation — an authority that issued twice for one address — nowhere
    /// in view.
    ///
    /// `trace!` for the log line, not `debug!`: an attacker holding the losing
    /// certificate drives this once per frame at whatever rate it sends, and
    /// the refused certificate never enters the `known` memo, so *every* copy
    /// arrives here. A `debug!` would mean that raising the runtime filter to
    /// investigate the alarm fills the bounded `GetLogs` ring with this one
    /// line and evicts the context the operator went looking for.
    ///
    /// The alarm is the operator-facing half and is storm-safe where the log
    /// line is not: the board coalesces on `(kind, subject)`, and
    /// `SharedBoard` mirrors only a new or escalated raise into the log — so a
    /// flood is one row with a count and exactly one `warn!`.
    ///
    /// `Warning`, not `Critical`: the mesh is carrying traffic exactly as
    /// configured, and the refusal is why.
    fn report_identity_conflict(mac: Mac, refused: &[u8; 32]) {
        tracing::trace!(
            ?mac,
            "auth: dropping a second identity key for a live member's address"
        );
        alarm!(
            Severity::Warning,
            AlarmKind::IdentityConflict,
            Subject::Node(NodeId::new(&mac.0)),
            "refused_key={}",
            NodeId::new(refused)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use batman::wire::BATMAN_VERSION;
    use batman::wire::BatmanKeepAlivePacket;
    use batman::wire::BatmanOgmPacket;
    use batman::wire::BatmanPacketType;
    use wayfinder_auth::Authority;

    /// The address the identity seeded with `n` derives.
    ///
    /// Not the compact `00:00:00:00:00:n` this used to be: since the key↔address
    /// binding landed (design 09 §5) a certificate's subject *is* the address
    /// its key derives, so a fixture that numbered addresses independently of
    /// the keys it mints could not produce a certificate that verifies. The
    /// module's `member`/`verified_cert` helpers already paired seed `n` with
    /// `mac(n)` almost everywhere, so pairing them here fixes the whole module
    /// at once — and makes the mismatch impossible to write by accident.
    fn mac(n: u8) -> Mac {
        Keypair::from_seed(&[n; 32]).derived_mac()
    }

    /// Build a bare OGM (header only, no TVLV) for `orig` into a fresh buffer,
    /// returning `(buf, len)` with generous trailing capacity for augmentation.
    fn bare_ogm(orig: Mac, seqno: u32) -> ([u8; 512], usize) {
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: BATMAN_VERSION,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        let mut buf = [0u8; 512];
        buf[..OGM_HDR].copy_from_slice(ogm.as_bytes());
        (buf, OGM_HDR)
    }

    /// Build a bare keep-alive body (header only, no auth trailer) into a fresh
    /// buffer, returning `(buf, len)` with generous trailing capacity for
    /// augmentation.
    fn bare_keepalive() -> ([u8; 128], usize) {
        let pkt = BatmanKeepAlivePacket {
            packet_type: BatmanPacketType::Keepalive.as_u8(),
            version: BATMAN_VERSION,
        };
        let mut buf = [0u8; 128];
        let len = core::mem::size_of::<BatmanKeepAlivePacket>();
        buf[..len].copy_from_slice(pkt.as_bytes());
        (buf, len)
    }

    /// An authority and a member node's auth state, sharing the same anchor.
    fn member(authority: &Authority, seed: u8, m: Mac, valid_to: u64) -> OgmAuth {
        let kp = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), 0, valid_to);
        let mut auth = OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(Duration::from_secs(100), Clocked::At(100));
        auth
    }

    /// A neighbour entry for the identity seeded `seed`, but *addressed* at
    /// `at` — the `derive_mac` collision the §8.9 identity lock now exists for.
    ///
    /// Since the key↔address binding landed (design 09 §5) a certificate cannot
    /// name an address its key does not derive, so a second *certified* key for
    /// one address is refused by `verify_cert` before `cache_neighbor` ever sees
    /// it. The lock survives as defense in depth over exactly one residual: two
    /// distinct identity keys hashing to one 46-bit address. That cannot be
    /// minted (it would need a preimage), so it is built here by hand — a
    /// genuine verified certificate with its subject rewritten, which is the
    /// same state a real collision would produce.
    fn colliding_neighbor(
        authority: &Authority,
        seed: u8,
        at: Mac,
        valid_to: u64,
        holder: &OgmAuth,
    ) -> NeighborKeys {
        let kp = Keypair::from_seed(&[seed; 32]);
        let raw =
            authority.issue_cert(kp.derived_mac(), kp.ed_pubkey(), kp.x_pubkey(), 0, valid_to);
        let mut cert = authority
            .trust_anchor()
            .verify_cert(&raw, Clocked::At(100))
            .expect("the colliding key's own certificate is perfectly valid");
        // The collision itself: the same key, reached at another address.
        cert.mac = at;
        NeighborKeys {
            pairwise_key: holder.keypair.pairwise_key(&cert.x_pubkey),
            cert,
            raw_cert: raw,
            last_ogm: None,
        }
    }

    /// A [`VerifiedCert`] for `m` issued at `issued_at`, for the tests that
    /// exercise [`OgmAuth::is_revoked`] directly rather than driving it
    /// through [`OgmAuth::verify_ogm`].
    fn verified_cert(authority: &Authority, seed: u8, m: Mac, issued_at: u64) -> VerifiedCert {
        let kp = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), issued_at, 1_000_000);
        authority
            .trust_anchor()
            .verify_cert(&cert, Clocked::At(issued_at))
            .expect("a freshly issued cert verifies at its own issuance instant")
    }

    /// [`member`] with an explicit issuance instant and clock, for the
    /// revocation-by-invalidity-date tests: which side of a revocation's
    /// instant a certificate was issued on is the whole question there, and
    /// [`member`]'s hardcoded `not_before` of 0 cannot express it.
    fn member_issued_at(
        authority: &Authority,
        seed: u8,
        m: Mac,
        issued_at: u64,
        valid_to: u64,
        wall: Clocked,
    ) -> OgmAuth {
        let kp = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), issued_at, valid_to);
        let mut auth = OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(Duration::from_secs(wall.unix_or_zero()), wall);
        auth
    }

    /// Exchange one signed OGM each way, so both nodes hold the other's
    /// verified certificate and the pairwise key derived from it — the
    /// precondition for any pairwise operation between them.
    fn admit_each_other(x: &mut OgmAuth, x_mac: Mac, y: &mut OgmAuth, y_mac: Mac) {
        let (mut buf, len) = bare_ogm(x_mac, 7);
        let len = x.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(y.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let (mut buf, len) = bare_ogm(y_mac, 7);
        let len = y.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(x.verify_ogm(&buf[..len]), OgmVerdict::Verified);
    }

    /// **Gap 3.** Certificate expiry is the mesh's *passive* revocation
    /// mechanism — the one that bounds the damage from a leaked key with no
    /// network involved. It has to actually revoke something.
    ///
    /// Verifying an OGM caches the peer's `VerifiedCert` *and* the pairwise
    /// key derived from it, and nothing on that path prunes a lapsed entry
    /// (`cache_neighbor` refuses or overwrites, it never expires). Without
    /// an expiry check on the lookup path, a peer whose enrollment has lapsed
    /// keeps a working link-local data plane indefinitely: its route ages out,
    /// but any neighbor that already admitted it goes on tagging and accepting
    /// its directed frames.
    #[test]
    fn an_expired_neighbor_can_no_longer_tag_or_verify_directed_frames() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        // b admits a while a's cert is valid.
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        assert!(
            b.tag_directed(mac(2), b"frame", &mut trailer).is_some(),
            "a live neighbor is taggable"
        );

        // a's certificate lapses.
        b.set_time(Duration::from_secs(2000), Clocked::At(2000));

        assert!(
            b.tag_directed(mac(2), b"frame", &mut trailer).is_none(),
            "an expired neighbor must not be taggable"
        );
        assert!(
            !b.verify_directed(mac(2), b"frame", &trailer),
            "nor may a frame claiming to come from it be accepted"
        );
        assert_eq!(
            b.neighbor_x_pubkey(mac(2)),
            None,
            "nor may its key be handed out"
        );
        assert!(
            b.neighbor_cert(mac(2)).is_none(),
            "nor may its certificate still resolve"
        );
    }

    /// The expired entry is reclaimed, not merely ignored: the neighbor table
    /// is bounded, and a long-lived node whose peers' certs rotate through
    /// would otherwise fill it with dead entries and start evicting live ones.
    #[test]
    fn expired_neighbors_are_evicted_from_the_table() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert_eq!(b.neighbors().len(), 1);

        b.set_time(Duration::from_secs(2000), Clocked::At(2000));
        assert!(
            b.neighbors().is_empty(),
            "the slot is reclaimed, not just made unusable"
        );
    }

    /// A node with no clock cannot judge expiry, so it must not be read as
    /// "everything has expired". An embedded node has no wall-clock source at
    /// all today, so this is the live case, not a corner.
    #[test]
    fn an_unset_clock_evicts_nothing() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        b.set_time(Duration::from_secs(0), Clocked::Unknown);
        assert_eq!(b.neighbors().len(), 1, "an unset clock judges nothing");
        assert!(b.neighbor_cert(mac(2)).is_some());
    }

    /// **A node with no clock admits a member whose certificate is valid, and
    /// keeps admitting them on the cached-certificate fast path.**
    ///
    /// The replacement for `an_unclocked_node_cannot_admit_a_member_certified_by_a_real_authority`,
    /// which characterised what design 20 §4.2 exists to change. Both nodes
    /// hold certificates shaped the way a real authority issues them — a
    /// `not_before` of a real Unix timestamp — and the receiver has no clock,
    /// which is the permanent condition of every board today.
    ///
    /// The *second* OGM is the half that is Bug A (§2.2). The first goes
    /// through `verify_cert`; the second takes `verify_ogm`'s cached-cert fast
    /// path, which re-checked the same window against the raw clock and so
    /// rejected every OGM from a neighbour it had already admitted. Two
    /// codepaths asking one question have to agree, and only an explicit
    /// posture makes them.
    #[test]
    fn an_unclocked_node_admits_a_member_and_keeps_admitting_them() {
        const ISSUED_AT: u64 = 1_700_000_000;
        const A_YEAR: u64 = 365 * 24 * 60 * 60;

        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member_issued_at(
            &authority,
            2,
            mac(2),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::At(ISSUED_AT),
        );
        // The receiver: same mesh, same shape of certificate, no clock.
        let mut b = member_issued_at(
            &authority,
            3,
            mac(3),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::Unknown,
        );

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Verified,
            "an unclocked node admits a member whose certificate is valid right now"
        );
        assert_eq!(b.neighbors().len(), 1, "and learns their keys");

        // The fast path: a fresh seqno from a neighbour whose certificate is
        // already cached, so the window is re-checked without re-verifying.
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Verified,
            "the cached-certificate fast path must judge the window the same way"
        );
    }

    /// **A node with no clock still enforces an active revocation.**
    ///
    /// Design 20 §5.1 promises exactly this — "an all-board segment keeps
    /// active revocation and loses passive" — and §6.1 lists active revocation
    /// under *Unchanged*. It is the one guarantee the design says survives a
    /// node that cannot tell the time, and the whole argument for advisory
    /// windows being safe rests on it.
    ///
    /// It has to be asserted here because the path only became *reachable*
    /// when §4.2 opened it: before, an unclocked node refused every
    /// certificate at `verify_cert`, so a revoked peer was dropped for having
    /// no admissible certificate rather than for being revoked, and the
    /// revocation gate behind it was never consulted.
    #[test]
    fn an_unclocked_node_still_enforces_an_active_revocation() {
        const ISSUED_AT: u64 = 1_700_000_000;
        const A_YEAR: u64 = 365 * 24 * 60 * 60;

        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member_issued_at(
            &authority,
            2,
            mac(2),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::At(ISSUED_AT),
        );
        let mut b = member_issued_at(
            &authority,
            3,
            mac(3),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::Unknown,
        );

        // The board holds a root-signed revocation naming a's certificate.
        let record = authority.revoke(mac(2), ISSUED_AT + 10, ISSUED_AT + A_YEAR);
        assert!(b.ingest_revocation(&record), "the record is admitted");

        // ...so a's OGM must be refused, and must stay refused: ingesting the
        // record evicts the neighbour once, which looks like it worked. The
        // next OGM is where a broken gate re-admits them.
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Rejected,
            "an unclocked node must not route for a node it holds a revocation for"
        );
        assert!(
            b.neighbors().is_empty(),
            "and must not re-cache the revoked peer's keys"
        );
        assert!(b.is_shunned(mac(2)), "the security view must say so too");
    }

    /// The other side of the same rule: a certificate issued *after* the
    /// revocation instant is a deliberate re-admission and survives, on a node
    /// with no clock exactly as on one with a clock.
    ///
    /// This is what stops "treat a held record as in force" from becoming
    /// "this address is banned forever": the cancellation test compares two
    /// CA-signed instants, and needs no clock to do it.
    #[test]
    fn an_unclocked_node_admits_a_certificate_issued_after_the_revocation() {
        const ISSUED_AT: u64 = 1_700_000_000;
        const A_YEAR: u64 = 365 * 24 * 60 * 60;

        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member_issued_at(
            &authority,
            3,
            mac(3),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::Unknown,
        );
        let record = authority.revoke(mac(2), ISSUED_AT + 10, ISSUED_AT + A_YEAR);
        assert!(b.ingest_revocation(&record));

        // Re-admitted: a fresh certificate whose `not_before` is past the
        // revocation instant.
        let mut a = member_issued_at(
            &authority,
            2,
            mac(2),
            ISSUED_AT + 20,
            ISSUED_AT + A_YEAR,
            Clocked::At(ISSUED_AT + 20),
        );
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Verified,
            "a re-issued certificate is not cancelled, clock or no clock"
        );
    }

    /// A node with no clock reports a lapsed neighbour's key as live.
    ///
    /// The pairwise data plane is keyed off `live_neighbor`, so treating
    /// "cannot judge" as "expired" would tear down the node's own links on a
    /// guess. An unclocked node judges no window at all (design 20 §4.2), and
    /// its clocked peers enforce the expiry on its behalf (§5.1).
    #[test]
    fn an_unclocked_node_reports_a_lapsed_neighbour_live() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert!(b.has_live_key(mac(2)));

        // Well past a's not_after of 1000 — but b cannot prove it.
        b.set_time(Duration::from_secs(5000), Clocked::Unknown);
        assert!(
            b.has_live_key(mac(2)),
            "a node that cannot tell the time must not tear down its own routes"
        );

        // The control: the same instant, known.
        b.set_time(Duration::from_secs(5000), Clocked::At(5000));
        assert!(!b.has_live_key(mac(2)), "a known instant does judge it");
    }

    /// A lower bound past a cached neighbour's `not_after` still expires it:
    /// `AtLeast` gives up not-yet-validity, not expiry.
    #[test]
    fn a_lower_bound_past_a_neighbours_expiry_still_evicts_it() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        b.set_time(Duration::from_secs(2000), Clocked::AtLeast(2000));
        assert!(
            b.neighbors().is_empty(),
            "a floor past not_after proves the neighbour's certificate has lapsed"
        );
    }

    /// A node augments its OGM; a peer on the same mesh accepts it and learns
    /// the originator's keys.
    /// A node augments its OGM; a peer on the same mesh accepts it and learns
    /// the originator's keys.
    #[test]
    fn signed_ogm_verifies_for_same_mesh() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");

        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert_eq!(b.neighbors().len(), 1);
        assert_eq!(b.neighbor_x_pubkey(mac(2)), Some(a.cert.x_pubkey));
    }

    /// A flooded OGM reaches a node once per neighbour on a shared segment —
    /// every copy carrying the same originator, seqno, certificate and
    /// signature, since none of the fields a forwarder rewrites (TTL, TQ) are
    /// signed. Verifying each copy from scratch makes a node's crypto load the
    /// *square* of the segment's size: at `MAX_NEIGHBOR_KEYS` mutual
    /// neighbours that is ~4k verifications per Trickle round instead of ~64,
    /// which no board can carry.
    ///
    /// So a repeat of an OGM already verified costs no public-key operation at
    /// all. This is memoisation of a pure function, not a relaxed check: the
    /// key covers every byte the signature commits to, and anything that
    /// differs by one bit takes the slow path below.
    #[test]
    fn a_repeated_ogm_copy_costs_no_public_key_operations() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        let after_first = b.ogm_crypto_ops;

        // The same OGM again, as a neighbour's re-flood of it delivers it.
        for _ in 0..8 {
            assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        }
        assert_eq!(
            b.ogm_crypto_ops, after_first,
            "a copy of an already-verified OGM must not re-run any public-key operation"
        );
    }

    /// The next seqno from a neighbour already admitted is a genuinely new
    /// signed message, so its signature must be verified — but its certificate
    /// is the same bytes already verified against the anchor, and the pairwise
    /// key already derived from it. Only the signature costs anything.
    #[test]
    fn a_new_seqno_from_a_known_neighbor_verifies_only_its_signature() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        let after_first = b.ogm_crypto_ops;

        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert_eq!(
            b.ogm_crypto_ops - after_first,
            1,
            "a known neighbour's next OGM costs one signature check, not a \
             re-verified certificate and a re-derived pairwise key too"
        );
    }

    /// The memo is keyed on the signature, so an attacker who replays a
    /// verified originator/seqno pair under a signature of its own is still
    /// refused — and pays the full verification, rather than being handed a
    /// verdict some earlier honest frame earned.
    #[test]
    fn a_forged_signature_on_a_verified_seqno_is_still_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        let after_first = b.ogm_crypto_ops;

        buf[len - 1] ^= 0xff; // same orig and seqno, a signature nobody signed
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
        assert!(
            b.ogm_crypto_ops > after_first,
            "a signature that is not the memoised one must be checked, not assumed"
        );
    }

    /// Expiry is judged per frame, not per distinct OGM: a copy arriving after
    /// the originator's certificate lapses is refused even though an identical
    /// copy verified while it was live. The memo shortcuts the *evidence*, not
    /// the validity window it was evidence for.
    #[test]
    fn a_repeated_copy_is_rejected_once_the_certificate_expires() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        b.set_time(Duration::from_secs(2000), Clocked::At(2000));
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// Likewise for revocation: a repeat of the very OGM that admitted a node
    /// is refused once that node is revoked.
    #[test]
    fn a_repeated_copy_is_rejected_once_the_originator_is_revoked() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let record = authority.revoke(mac(2), 50, 1000);
        assert!(b.ingest_revocation(&record));
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// A verified neighbor carries its cert's expiry, so the security view can
    /// report when each originator's membership lapses.
    #[test]
    fn verified_neighbor_carries_cert_expiry() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 4242);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");

        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        let n = b.neighbors().first().expect("one neighbor");
        assert_eq!(n.cert.mac, mac(2));
        assert_eq!(n.cert.not_after, 4242, "neighbor's cert expiry is recorded");
    }

    /// An unauthenticated OGM (no cert/sig TVLVs) is rejected when auth is on.
    #[test]
    fn unauthenticated_ogm_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let (buf, len) = bare_ogm(mac(2), 7);
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// A tampered signature fails verification.
    #[test]
    fn tampered_signature_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        buf[len - 1] ^= 0xff; // flip a signature byte
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// An OGM from a node holding a cert for a *different* MAC than the
    /// originator field is rejected (no cert/orig confusion).
    #[test]
    fn cert_mac_must_match_originator() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        // `a` holds a cert for mac(2) but stamps mac(9) as the OGM originator.
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let (mut buf, len) = bare_ogm(mac(9), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// A node from another mesh (different trust anchor) is rejected — the
    /// segregation property at the OGM layer.
    #[test]
    fn foreign_mesh_ogm_rejected() {
        let ours = Authority::from_seed(&[1; 32], 0xABCD);
        let theirs = Authority::from_seed(&[9; 32], 0xABCD);
        let mut foreign = member(&theirs, 2, mac(2), 1000);
        let mut b = member(&ours, 3, mac(3), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = foreign.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// An expired cert (now past not_after) is rejected.
    #[test]
    fn expired_cert_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        b.set_time(Duration::from_secs(2000), Clocked::At(2000)); // past a's not_after = 1000
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// A revoked originator is dropped even with a still-valid signature/cert.
    #[test]
    fn revoked_originator_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let record = authority.revoke(mac(2), 50, 1000);
        assert!(b.ingest_revocation(&record));
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// A revocation whose effective instant (`not_before`) is still in the
    /// future does not yet drop the node — passive timing is honoured.
    #[test]
    fn future_revocation_not_yet_effective() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000); // now_unix = 100
        let record = authority.revoke(mac(2), 500, 1000); // effective at 500 > 100
        assert!(b.ingest_revocation(&record));
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        // Not yet effective, so the OGM is still accepted.
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        // Once the clock reaches the effective instant, the node is dropped.
        b.set_time(Duration::from_secs(500), Clocked::At(500));
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// A certificate issued *after* the revocation instant is not cancelled by
    /// it: the authority re-admitted the node, and a revocation only cancels
    /// what existed when it was signed.  This is what lets a re-approved node
    /// rejoin under its own MAC instead of waiting out `not_after` — which,
    /// since a node's MAC is the address its identity key derives, is the only
    /// way back that does not also rotate its identity.
    #[test]
    fn a_certificate_issued_after_the_revocation_is_not_cancelled() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        // a's certificate is issued at 600, after the revocation instant 500.
        let mut a = member_issued_at(&authority, 2, mac(2), 600, 100_000, Clocked::At(700));
        let mut b = member_issued_at(&authority, 3, mac(3), 0, 100_000, Clocked::At(700));

        let record = authority.revoke(mac(2), 500, 100_000);
        assert!(b.ingest_revocation(&record));

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Verified,
            "a certificate issued after the revocation instant survives it"
        );
    }

    /// The tie — a certificate whose `not_before` is exactly the revocation
    /// instant — resolves toward *revoked*.  A revocation is a security
    /// control, and re-admission is a deliberate act the authority can stamp a
    /// second later; the reverse reading would leave a same-second hole.
    #[test]
    fn a_certificate_issued_at_the_revocation_instant_is_cancelled() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member_issued_at(&authority, 2, mac(2), 500, 100_000, Clocked::At(700));
        let mut b = member_issued_at(&authority, 3, mac(3), 0, 100_000, Clocked::At(700));

        let record = authority.revoke(mac(2), 500, 100_000);
        assert!(b.ingest_revocation(&record));

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Rejected,
            "the tie goes to revoked"
        );
    }

    /// The whole re-admission sequence, in the order it actually happens: a
    /// peer is trusted, revoked, and then re-approved under the *same MAC*
    /// with a fresh certificate — and is trusted again without waiting out
    /// `not_after`.
    ///
    /// Worth its own test because the three steps interact through the
    /// neighbour cache: ingesting the revocation evicts the cached
    /// certificate, so the re-issued one is verified fresh rather than being
    /// shadowed by the cancelled copy. A test that only ever ingests the
    /// revocation first would never exercise that.
    #[test]
    fn a_re_approved_node_is_trusted_again_under_the_same_mac() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut old = member_issued_at(&authority, 2, mac(2), 0, 100_000, Clocked::At(700));
        let mut b = member_issued_at(&authority, 3, mac(3), 0, 100_000, Clocked::At(700));

        // Trusted to begin with, which also caches its certificate on `b`.
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = old.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // Revoked at 500, which cancels the certificate issued at 0.
        let record = authority.revoke(mac(2), 500, 100_000);
        assert!(b.ingest_revocation(&record));
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = old.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);

        // Re-approved: the same key and the same MAC, a certificate issued
        // after the revocation instant.
        let mut readmitted =
            member_issued_at(&authority, 2, mac(2), 600, 100_000, Clocked::At(700));
        let (mut buf, len) = bare_ogm(mac(2), 9);
        let len = readmitted.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Verified,
            "a re-approved node routes again immediately, without waiting out not_after"
        );
        // And the record is still held — it just no longer cancels anything
        // this node presents.
        assert!(b.revoked_macs().any(|m| m == mac(2)));
    }

    /// A node that was revoked, re-admitted, and then misbehaved again can be
    /// revoked a second time.
    ///
    /// The first record no longer cancels the re-admitted certificate — that is
    /// the whole point of the issuance cut-off — so the second record is the
    /// only thing standing between the mesh and the node. Dropping it as
    /// "already known" would leave the node permanently unrevokable until the
    /// *first* record passively expires.
    #[test]
    fn a_re_admitted_node_can_be_revoked_a_second_time() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member_issued_at(&authority, 3, mac(3), 0, 100_000, Clocked::At(700));

        // Revoked at 500, cancelling the certificate issued at 0.
        let first = authority.revoke(mac(2), 500, 100_000);
        assert!(b.ingest_revocation(&first));

        // Re-admitted at 600, and routing again.
        let mut readmitted =
            member_issued_at(&authority, 2, mac(2), 600, 100_000, Clocked::At(700));
        let (mut buf, len) = bare_ogm(mac(2), 9);
        let len = readmitted.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // Revoked again at 650, which does cancel the certificate issued at 600.
        let second = authority.revoke(mac(2), 650, 100_000);
        assert!(
            b.ingest_revocation(&second),
            "a revocation naming an already-revoked MAC at a later instant is new information"
        );

        let (mut buf, len) = bare_ogm(mac(2), 10);
        let len = readmitted.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Rejected,
            "the second revocation must cancel the re-admitted certificate"
        );
    }

    /// A re-admitted node keeps its routing state when an *unrelated* revocation
    /// lands.
    ///
    /// `macs_to_purge` is what a landing revocation tears down. It must not
    /// name a node whose current certificate survives its held record, or every
    /// unrelated purge would cost that node a next-hop re-proof cycle — the
    /// opposite of the immediate re-admission this change exists to allow.
    #[test]
    fn a_re_admitted_node_is_not_purged_by_an_unrelated_revocation() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member_issued_at(&authority, 3, mac(3), 0, 100_000, Clocked::At(700));

        // Node 2 revoked at 500, then re-admitted with a cert issued at 600 and
        // re-verified, so `b` caches the surviving certificate.
        assert!(b.ingest_revocation(&authority.revoke(mac(2), 500, 100_000)));
        let mut readmitted =
            member_issued_at(&authority, 2, mac(2), 600, 100_000, Clocked::At(700));
        let (mut buf, len) = bare_ogm(mac(2), 9);
        let len = readmitted.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        assert!(
            !b.macs_to_purge().any(|m| m == mac(2)),
            "a re-admitted node's routing state must survive an unrelated purge"
        );
        // The record is still held, so the MAC-only view still names it — which
        // is exactly why that view must not drive the teardown.
        assert!(b.revoked_macs().any(|m| m == mac(2)));

        // A genuinely revoked node is still purged.
        assert!(b.ingest_revocation(&authority.revoke(mac(4), 500, 100_000)));
        assert!(b.macs_to_purge().any(|m| m == mac(4)));
    }

    /// A certificate issued *before* the revocation instant is cancelled — the
    /// ordinary case, stated alongside its two boundary siblings so the three
    /// read as one specification.
    #[test]
    fn a_certificate_issued_before_the_revocation_is_cancelled() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member_issued_at(&authority, 2, mac(2), 400, 100_000, Clocked::At(700));
        let mut b = member_issued_at(&authority, 3, mac(3), 0, 100_000, Clocked::At(700));

        let record = authority.revoke(mac(2), 500, 100_000);
        assert!(b.ingest_revocation(&record));

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// An invalid (forged) revocation is ignored: `ingest_revocation` returns
    /// false and the targeted node keeps routing.
    #[test]
    fn forged_revocation_ignored() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let attacker = Authority::from_seed(&[7; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let forged = attacker.revoke(mac(2), 50, 1000);
        assert!(!b.ingest_revocation(&forged));
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
    }

    /// Ingesting the same revocation twice records it once and reports the
    /// second as already-known, so a re-flood does not amplify.
    #[test]
    fn duplicate_revocation_recorded_once() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let record = authority.revoke(mac(2), 50, 1000);
        assert!(b.ingest_revocation(&record));
        assert!(!b.ingest_revocation(&record));
        assert_eq!(b.revoked_macs().filter(|m| *m == mac(2)).count(), 1);
    }

    /// A revocation learned by one node floods to a peer through the OGM tail:
    /// `a` ingests a purge of node 9, attaches it to its OGM, and `b` records it
    /// just from verifying that OGM — no direct API call on `b`.
    #[test]
    fn revocation_floods_through_ogm_tail() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let record = authority.revoke(mac(9), 50, 1000);
        assert!(a.ingest_revocation(&record));

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        // The OGM now carries the revocation TVLV; verifying it on `b` ingests it.
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert!(b.revoked_macs().any(|m| m == mac(9)));
    }

    /// The re-flood budget is finite: after `REVOKE_FLOOD_BUDGET` OGM emissions
    /// the record stops being attached, but the node stays revoked locally.
    #[test]
    fn revoke_flood_budget_is_finite() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let record = authority.revoke(mac(9), 50, 1000);
        assert!(a.ingest_revocation(&record));

        // Drain the budget; each emission should carry the revoke TVLV.
        for seqno in 0..REVOKE_FLOOD_BUDGET as u32 {
            let (mut buf, len) = bare_ogm(mac(2), seqno);
            let len = a.augment_ogm(&mut buf, len).unwrap();
            assert!(
                find_tvlv(&buf[OGM_HDR..len], TvlvType::Revoke).is_some(),
                "emission {seqno} should still carry the revocation"
            );
        }
        // Budget spent: the next OGM no longer carries it.
        let (mut buf, len) = bare_ogm(mac(2), 99);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert!(find_tvlv(&buf[OGM_HDR..len], TvlvType::Revoke).is_none());
        // But the node is still locally revoked.
        assert!(a.revoked_macs().any(|m| m == mac(9)));
    }

    /// Revoking a verified neighbor evicts its pairwise key, so directed frames
    /// to it can no longer be tagged (the data-plane half of the purge).
    #[test]
    fn revocation_evicts_neighbor_pairwise_key() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        // a can tag a frame for b before the revocation.
        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        assert!(a.tag_directed(mac(3), b"f", &mut trailer).is_some());

        // Revoke b on a; a forgets b's key and can no longer tag to it.
        let record = authority.revoke(mac(3), 50, 1000);
        assert!(a.ingest_revocation(&record));
        assert!(a.tag_directed(mac(3), b"f", &mut trailer).is_none());
    }

    /// A revocation naming *this* node is never stored in the enforcement set
    /// and never re-flooded — peers enforce it against us, and carrying our own
    /// death warrant would only spend a flood slot. What it does instead is
    /// latch, for the router to act on.
    #[test]
    fn self_revocation_latches_instead_of_being_stored() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let record = authority.revoke(mac(2), 50, 1000); // a's own MAC
        assert!(!a.ingest_revocation(&record));
        assert_eq!(a.revoked_macs().count(), 0, "not in the enforcement set");
        assert_eq!(
            a.take_self_revoked().map(|r| r.node_mac),
            Some(record.node_mac),
            "but latched for the router to act on"
        );
        assert_eq!(
            a.take_self_revoked().map(|r| r.node_mac),
            None,
            "and drained exactly once"
        );
    }

    /// A revocation naming this node but cancelling only a *superseded*
    /// certificate is ignored: it was issued before the certificate this node
    /// now runs under, so it says nothing about the current one.
    ///
    /// This is what makes a replayed record harmless after a re-admission —
    /// the OGM tail carrying it is not covered by the OGM signature, so an
    /// attacker can splice any record they have ever seen into a captured
    /// frame.
    #[test]
    fn a_revocation_of_a_superseded_certificate_does_not_latch() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        // This node's certificate was issued at 600, after the record's 500.
        let mut a = member_issued_at(&authority, 2, mac(2), 600, 100_000, Clocked::At(700));
        let stale = authority.revoke(mac(2), 500, 100_000);
        assert!(!a.ingest_revocation(&stale));
        assert_eq!(a.take_self_revoked().map(|r| r.node_mac), None);
    }

    /// A self-revocation whose effective instant has not arrived is held, not
    /// acted on: going inert early makes this node a black hole, because peers
    /// are still advertising routes through it until the same instant.
    #[test]
    fn self_revocation_waits_for_its_effective_instant() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member_issued_at(&authority, 2, mac(2), 0, 100_000, Clocked::At(100));
        let record = authority.revoke(mac(2), 500, 100_000);
        assert!(!a.ingest_revocation(&record));
        assert_eq!(
            a.take_self_revoked().map(|r| r.node_mac),
            None,
            "not yet in force"
        );

        a.set_time(Duration::from_secs(500), Clocked::At(500));
        assert_eq!(
            a.take_self_revoked().map(|r| r.node_mac),
            Some(record.node_mac),
            "the clock reaching the instant arms it"
        );
    }

    /// A node whose clock has never been set does not self-revoke: it cannot
    /// judge the record's window at all, and `verify_revocation`'s expiry test
    /// passes everything at zero, so a long-dead record would otherwise brick
    /// a freshly booted board.
    #[test]
    fn self_revocation_waits_for_a_clock() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[2; 32]);
        let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), kp.x_pubkey(), 0, 100_000);
        let mut a = OgmAuth::new(kp, cert, authority.trust_anchor()); // no set_time
        let record = authority.revoke(mac(2), 500, 100_000);
        assert!(!a.ingest_revocation(&record));
        assert_eq!(
            a.take_self_revoked().map(|r| r.node_mac),
            None,
            "no clock, no judgement"
        );

        a.set_time(Duration::from_secs(600), Clocked::At(600));
        assert_eq!(
            a.take_self_revoked().map(|r| r.node_mac),
            Some(record.node_mac)
        );
    }

    /// A replayed *older* record must not pull the arming instant backwards.
    ///
    /// The OGM tail is not covered by the OGM signature, so any record ever
    /// seen on the wire can be spliced into a captured frame and replayed. If
    /// an older instant overwrote a held newer one, that replay would arm this
    /// node early — black-holing the peers still routing through it, which is
    /// exactly what the instant gate exists to prevent.
    #[test]
    fn an_older_replayed_self_revocation_does_not_pull_the_instant_backwards() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[2; 32]);
        let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), kp.x_pubkey(), 0, 100_000);
        let mut a = OgmAuth::new(kp, cert, authority.trust_anchor());
        a.set_time(Duration::from_secs(400), Clocked::At(400));

        // Held: its instant is still in the future.
        assert!(!a.ingest_revocation(&authority.revoke(mac(2), 1_000, 100_000)));
        assert_eq!(a.take_self_revoked().map(|r| r.node_mac), None);

        // An older record, replayed. It must not replace the held one.
        assert!(!a.ingest_revocation(&authority.revoke(mac(2), 500, 100_000)));

        a.set_time(Duration::from_secs(600), Clocked::At(600));
        assert_eq!(
            a.take_self_revoked().map(|r| r.node_mac),
            None,
            "a replayed older record must not arm this node ahead of the instant it was given"
        );

        // The originally-held instant still governs.
        a.set_time(Duration::from_secs(1_000), Clocked::At(1_000));
        assert!(a.take_self_revoked().is_some());
    }

    /// A record that has already expired by the time the clock arrives must not
    /// fire.
    ///
    /// The clockless gate defers the judgement; it must not skip it. Without an
    /// expiry check the gate merely postpones the brick to the moment NTP
    /// lands — which is precisely the "long-dead record no live peer still
    /// holds" case it exists to prevent.
    #[test]
    fn a_self_revocation_expired_before_the_clock_arrives_does_not_fire() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[2; 32]);
        let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), kp.x_pubkey(), 0, 100_000);
        let mut a = OgmAuth::new(kp, cert, authority.trust_anchor()); // no set_time
        // Verified at `now_unix == 0`, where nothing expires, so it latches.
        let record = authority.revoke(mac(2), 500, 700);
        assert!(!a.ingest_revocation(&record));

        // The clock arrives long after the record's window closed.
        a.set_time(Duration::from_secs(5_000), Clocked::At(5_000));
        assert_eq!(
            a.take_self_revoked().map(|r| r.node_mac),
            None,
            "a record that expired before this node could judge it must not brick it"
        );
    }

    /// **A node with no clock enforces a held revocation it cannot place in
    /// time, including one whose `not_before` is still ahead.**
    ///
    /// This inverts what the test here used to assert, and the inversion is
    /// deliberate (design 20 §5.1). The old rule read as "timing is honoured
    /// rather than failing open", but on a node with `now == 0` it was not
    /// honouring timing — `verify_revocation` refuses a zero `not_before`, so
    /// *no* record ever satisfied `not_before <= 0` and such a node enforced
    /// nothing at all, ever. That was invisible while an unclocked node also
    /// refused every certificate; §4.2 opened that door and made it live.
    ///
    /// Enforcing early is the right direction of error for a revocation, and
    /// the asymmetry is the opposite of a certificate's: admitting a
    /// certificate slightly early is benign, while *failing* to drop a revoked
    /// peer is the harm the mechanism exists to prevent. The cost is bounded —
    /// the record is root-signed, the authority has already decided, and
    /// `names_cert` means only the credential it was aimed at is affected.
    #[test]
    fn a_node_with_no_clock_enforces_a_revocation_it_cannot_place_in_time() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[3; 32]);
        let cert = authority.issue_cert(mac(3), kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);
        // Note: no set_time, so the posture is `Unknown`.
        let mut b = OgmAuth::new(kp, cert, authority.trust_anchor());

        let record = authority.revoke(mac(2), 500, 1000); // effective at 500
        assert!(b.ingest_revocation(&record));
        assert!(
            b.is_revoked(&verified_cert(&authority, 2, mac(2), 0)),
            "a node that cannot place the window must enforce, not ignore"
        );

        // The control: a node that *can* place it honours the window exactly as
        // before — `At` is untouched by this rule.
        let kp = Keypair::from_seed(&[4; 32]);
        let cert = authority.issue_cert(mac(4), kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);
        let mut clocked = OgmAuth::new(kp, cert, authority.trust_anchor());
        clocked.set_time(Duration::from_secs(100), Clocked::At(100));
        assert!(clocked.ingest_revocation(&record));
        assert!(
            !clocked.is_revoked(&verified_cert(&authority, 2, mac(2), 0)),
            "at 100, the record's 500 has not arrived and a clocked node knows it"
        );
    }

    /// A floor that has already passed a record's `not_after` proves it spent,
    /// so an `AtLeast` node stops enforcing it — the half of the window a floor
    /// genuinely can judge.
    #[test]
    fn a_floor_past_a_revocations_end_stops_enforcing_it() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[3; 32]);
        let cert = authority.issue_cert(mac(3), kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);
        let mut b = OgmAuth::new(kp, cert, authority.trust_anchor());
        b.set_time(Duration::ZERO, Clocked::AtLeast(600));

        let record = authority.revoke(mac(2), 500, 1000);
        assert!(b.ingest_revocation(&record));
        assert!(
            b.is_revoked(&verified_cert(&authority, 2, mac(2), 0)),
            "a floor inside the window enforces"
        );

        // Past `not_after`: provably spent, so it stops applying — and
        // `prune_expired` will reclaim the slot on the next advance.
        b.set_time(Duration::ZERO, Clocked::AtLeast(1_000));
        assert!(
            !b.is_revoked(&verified_cert(&authority, 2, mac(2), 0)),
            "a floor at or past not_after proves the record spent"
        );
    }

    /// Once a revocation's `not_after` passes, `set_time` garbage-collects it,
    /// freeing the slot — the bound on how long a record is retained.
    #[test]
    fn expired_revocation_is_garbage_collected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1_000_000); // now_unix = 100
        let record = authority.revoke(mac(2), 50, 1000);
        assert!(b.ingest_revocation(&record));
        assert_eq!(b.revoked_macs().count(), 1);
        // Advance past not_after: the record is pruned on the clock update.
        b.set_time(Duration::from_secs(1001), Clocked::At(1001));
        assert_eq!(b.revoked_macs().count(), 0);
    }

    /// The set reports *when* a held revocation stops being enforced, not only
    /// that one is held. That instant is what tells an operator how long a node
    /// will keep reading as revoked, and it is otherwise nowhere: the
    /// revocation evicts the neighbor entry that carries the cert expiry, so a
    /// revoked row has no other date on it.
    #[test]
    fn revocation_not_after_reports_the_enforcement_window() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1_000_000); // now_unix = 100
        assert_eq!(b.revocation_not_after(mac(2)), None, "none held yet");

        let record = authority.revoke(mac(2), 50, 1000);
        assert!(b.ingest_revocation(&record));
        assert_eq!(b.revocation_not_after(mac(2)), Some(1000));
        assert_eq!(
            b.revocation_not_after(mac(9)),
            None,
            "a MAC we never revoked"
        );

        // Pruned at expiry: the window goes with the record it described.
        b.set_time(Duration::from_secs(1001), Clocked::At(1001));
        assert_eq!(b.revocation_not_after(mac(2)), None);
    }

    /// A new revocation raises the Trickle-reset hint (so the router accelerates
    /// OGM emission); draining clears it, and a duplicate raises nothing.
    #[test]
    fn new_revocation_raises_trickle_reset_hint() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        assert!(
            !b.take_trickle_reset_hint(),
            "no hint before any revocation"
        );

        let record = authority.revoke(mac(2), 50, 1000);
        assert!(b.ingest_revocation(&record));
        assert!(
            b.take_trickle_reset_hint(),
            "a new purge must request a reset"
        );
        assert!(
            !b.take_trickle_reset_hint(),
            "the hint is cleared once taken"
        );

        // A duplicate is not new, so it must not re-trigger a reset.
        assert!(!b.ingest_revocation(&record));
        assert!(!b.take_trickle_reset_hint());
    }

    /// An already-expired revocation is ignored on ingest rather than stored.
    #[test]
    fn already_expired_revocation_ignored() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        b.set_time(Duration::from_secs(2000), Clocked::At(2000));
        let record = authority.revoke(mac(2), 50, 1000); // not_after 1000 < now 2000
        assert!(!b.ingest_revocation(&record));
        assert_eq!(b.revoked_macs().count(), 0);
    }

    /// Augmentation preserves an existing TVLV tail (e.g. mcast) and the
    /// signature still verifies — cert/sig are appended, not overwriting.
    #[test]
    fn augment_preserves_existing_tvlv_tail() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        // Hand-build an OGM with a small pre-existing TVLV record in the tail.
        let (mut buf, mut len) = bare_ogm(mac(2), 7);
        len = HostAuth::write_tvlv(&mut buf, len, batman::wire::TvlvType::Mcast, &[1, 2, 3, 4]);
        let mcast_record = TVLV_HDR + 4;
        buf[TVLV_LEN_OFF..TVLV_LEN_OFF + 2].copy_from_slice(&(mcast_record as u16).to_be_bytes());

        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        // The mcast TVLV is still findable after the appended records.
        assert_eq!(
            find_tvlv(&buf[OGM_HDR..len], batman::wire::TvlvType::Mcast),
            Some(&[1, 2, 3, 4][..])
        );
    }

    /// `augment_ogm_lazy` writes a `CertFp` TVLV (not `Cert`) with no cert
    /// bytes on the wire, yet a first-time receiver (nothing cached yet)
    /// correctly reports `NeedCert` — it cannot verify a fingerprint it has
    /// no cert for — with the right fingerprint for a subsequent fetch.
    #[test]
    fn augment_ogm_lazy_emits_fingerprint_not_cert() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm_lazy(&mut buf, len).unwrap();

        // No Cert TVLV at all — only the 8-byte fingerprint.
        assert!(find_tvlv(&buf[OGM_HDR..len], TvlvType::Cert).is_none());
        assert_eq!(
            find_tvlv(&buf[OGM_HDR..len], TvlvType::CertFp),
            Some(&a.cert.fingerprint()[..])
        );

        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::NeedCert {
                orig: mac(2),
                fp: a.cert.fingerprint(),
            }
        );
    }

    /// Once the receiver has cached the sender's cert (e.g. via a prior
    /// fetch), a lazily-augmented OGM verifies from the cache — the
    /// steady-state, zero-cert-bytes-on-the-wire path.
    #[test]
    fn augment_ogm_lazy_verifies_against_cache() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        // Prime the cache with one legacy-format OGM.
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // Every subsequent OGM can be lazy.
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = a.augment_ogm_lazy(&mut buf, len).unwrap();
        assert!(find_tvlv(&buf[OGM_HDR..len], TvlvType::Cert).is_none());
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
    }

    /// `augment_ogm_lazy` still attaches pending revocations, exactly like
    /// `augment_ogm` — the lazy cert-distribution switch does not disable
    /// the revocation-flooding mechanism.
    #[test]
    fn augment_ogm_lazy_still_floods_revocations() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let record = authority.revoke(mac(9), 50, 1000);
        assert!(a.ingest_revocation(&record));

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm_lazy(&mut buf, len).unwrap();
        assert!(find_tvlv(&buf[OGM_HDR..len], TvlvType::Revoke).is_some());
    }

    /// Exchange OGMs both ways so `a` and `b` each cache the other's verified
    /// pairwise key (a precondition for tagging/verifying directed frames).
    fn mutual_verify(a: &mut OgmAuth, a_mac: Mac, b: &mut OgmAuth, b_mac: Mac) {
        let (mut buf, len) = bare_ogm(a_mac, 1);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        let (mut buf, len) = bare_ogm(b_mac, 1);
        let len = b.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(a.verify_ogm(&buf[..len]), OgmVerdict::Verified);
    }

    /// A directed frame tagged for a verified neighbor verifies on the other end
    /// (the no-handshake pairwise key agreement carries through).
    #[test]
    fn directed_tag_roundtrips() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let frame = b"dst|src|proto|unicast payload";
        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        let n = a.tag_directed(mac(3), frame, &mut trailer).expect("tag");
        assert_eq!(n, DIRECTED_TRAILER_LEN);
        assert!(b.verify_directed(mac(2), frame, &trailer));
    }

    /// **One per-sender counter sequence, not one per destination**
    /// (design 17 §4.4).
    ///
    /// A fan-out frame addresses several next hops with one transmission, so
    /// it has no single destination whose counter space to draw from. Drawing
    /// from any one recipient's would hand the others a value below their own
    /// high-water mark and get a legitimate frame dropped as a replay.
    ///
    /// Receivers need no change for this: `accept_recv_counter` already keys
    /// its high-water mark on `src` alone, and any subsequence of a strictly
    /// increasing sequence is strictly increasing — so a neighbour sees
    /// monotonic counters whether it received every frame or one in ten. This
    /// test is the second half of that argument: each peer accepts its own
    /// sparse subsequence without complaint.
    #[test]
    fn directed_counters_come_from_one_per_sender_sequence() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut c = member(&authority, 4, mac(4), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));
        mutual_verify(&mut a, mac(2), &mut c, mac(4));

        let counter_of = |t: &[u8]| u64::from_be_bytes(t[..8].try_into().unwrap());

        // Alternate destinations; the counters must be one strictly increasing
        // run across both, not two runs that restart.
        let mut seen = Vec::new();
        for dst in [mac(3), mac(4), mac(3), mac(4)] {
            let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
            a.tag_directed(dst, b"frame", &mut trailer).expect("tag");
            seen.push(counter_of(&trailer));
        }
        assert!(
            seen.windows(2).all(|w| w[1] > w[0]),
            "one sequence across every destination, got {seen:?}"
        );

        // And each peer accepts the sparse subsequence it actually receives.
        for (i, dst) in [mac(3), mac(4), mac(3), mac(4)].iter().enumerate() {
            let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
            a.tag_directed(*dst, b"frame", &mut trailer).unwrap();
            let peer = if *dst == mac(3) { &mut b } else { &mut c };
            assert!(
                peer.verify_directed(mac(2), b"frame", &trailer),
                "peer {i} must accept its own subsequence"
            );
        }
    }

    /// **The fan-out form** (design 17 §4.4): a single transmission reaching
    /// several neighbours cannot carry one pairwise tag per recipient, each
    /// derived from a different key, so the forwarding node signs with its own
    /// key and each receiver verifies against the cert it already holds.
    #[test]
    fn fanout_signature_roundtrips_for_a_known_member() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let frame = b"an mcast frame naming three destinations";
        let mut trailer = [0u8; FANOUT_TRAILER_LEN];
        let n = a.sign_fanout(frame, &mut trailer).expect("sign");
        assert_eq!(n, FANOUT_TRAILER_LEN);
        assert!(b.verify_fanout(mac(2), frame, &trailer));
    }

    /// **A fan-out signature must work on a real frame, not just a tiny one.**
    ///
    /// The first cut built the signed message in a `SIGN_SCRATCH_LEN` (256 B)
    /// stack buffer, which caps the frame at 226 bytes once the domain and
    /// counter are accounted for. Every multicast that matters — mDNS, SSDP,
    /// RTP, anything carrying a real Ethernet frame — is larger than that, so
    /// signing returned `None`, the frame was dropped, and (because the merge
    /// had already claimed those groups) no directed copy went out either.
    /// Every listener behind that hop got nothing.
    #[test]
    fn fanout_signature_covers_a_full_size_frame() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        // Comfortably past both the old 226-byte ceiling and a 1500-byte MTU.
        let frame = [0xa5u8; 2000];
        let mut trailer = [0u8; FANOUT_TRAILER_LEN];
        a.sign_fanout(&frame, &mut trailer)
            .expect("a full-size frame must be signable");
        assert!(b.verify_fanout(mac(2), &frame, &trailer));

        // And a single flipped byte anywhere in it still fails.
        let mut tampered = frame;
        tampered[1500] ^= 0x01;
        assert!(!b.verify_fanout(mac(2), &tampered, &trailer));
    }

    /// An outsider's signature is rejected: verification goes through the same
    /// neighbour-key lookup `verify_directed` uses, so a node with no accepted
    /// OGM — and a revoked one, whose keys `evict_neighbor` drops — has no way
    /// to be believed.
    #[test]
    fn fanout_signature_from_an_unknown_node_is_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        // Deliberately *no* mutual_verify: b has never accepted an OGM from a.

        let frame = b"frame";
        let mut trailer = [0u8; FANOUT_TRAILER_LEN];
        a.sign_fanout(frame, &mut trailer).expect("sign");
        assert!(!b.verify_fanout(mac(2), frame, &trailer));
    }

    /// A tampered frame fails the signature — which is what lets a
    /// destination list be routed on in-band: the proof covers the whole
    /// frame, header and list included, so a hop cannot rewrite the routing
    /// without its successor noticing.
    #[test]
    fn a_tampered_frame_fails_the_fanout_signature() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let mut trailer = [0u8; FANOUT_TRAILER_LEN];
        a.sign_fanout(b"original frame", &mut trailer).unwrap();
        assert!(!b.verify_fanout(mac(2), b"tampered frame", &trailer));
    }

    /// The fan-out form keeps the replay guard the pairwise form has. Dropping
    /// it because the frame is now one-to-many would regress a protection
    /// `Mcast` already had.
    #[test]
    fn fanout_replay_is_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let mut trailer = [0u8; FANOUT_TRAILER_LEN];
        a.sign_fanout(b"frame", &mut trailer).unwrap();
        assert!(b.verify_fanout(mac(2), b"frame", &trailer));
        assert!(
            !b.verify_fanout(mac(2), b"frame", &trailer),
            "the same counter must not be accepted twice"
        );
    }

    /// **Domain separation.** A fan-out signature is over its own domain
    /// prefix, so it can never be replayed as an OGM signature or a keep-alive
    /// — and an OGM signature can never stand in for one here.
    #[test]
    fn a_fanout_signature_is_not_an_ogm_signature() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let frame = b"frame";
        let mut fanout = [0u8; FANOUT_TRAILER_LEN];
        a.sign_fanout(frame, &mut fanout).unwrap();

        // The signature half alone, pasted under a pairwise-tag trailer, is
        // not a pairwise tag either.
        let mut as_tag = [0u8; DIRECTED_TRAILER_LEN];
        as_tag[..8].copy_from_slice(&fanout[..8]);
        as_tag[8..].copy_from_slice(&fanout[8..8 + TAG_LEN]);
        assert!(!b.verify_directed(mac(2), frame, &as_tag));
    }

    /// A tampered directed frame fails the tag check.
    #[test]
    fn directed_tampered_frame_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        a.tag_directed(mac(3), b"original frame", &mut trailer)
            .unwrap();
        assert!(!b.verify_directed(mac(2), b"tampered frame", &trailer));
    }

    /// Replaying a directed frame with the same counter is rejected.
    #[test]
    fn directed_replay_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let frame = b"unicast payload";
        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        a.tag_directed(mac(3), frame, &mut trailer).unwrap();
        assert!(b.verify_directed(mac(2), frame, &trailer));
        assert!(
            !b.verify_directed(mac(2), frame, &trailer),
            "a replayed counter must be rejected"
        );
    }

    /// An out-of-order (stale-counter) directed frame is rejected once a newer
    /// counter has been accepted.
    #[test]
    fn directed_stale_counter_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let frame = b"payload";
        let mut t1 = [0u8; DIRECTED_TRAILER_LEN];
        let mut t2 = [0u8; DIRECTED_TRAILER_LEN];
        a.tag_directed(mac(3), frame, &mut t1).unwrap(); // counter 1
        a.tag_directed(mac(3), frame, &mut t2).unwrap(); // counter 2
        assert!(b.verify_directed(mac(2), frame, &t2)); // accept the newer one
        assert!(
            !b.verify_directed(mac(2), frame, &t1),
            "an older counter is stale once a newer one is accepted"
        );
    }

    /// Tagging for or verifying from a node we have not verified an OGM from is
    /// refused — no pairwise key exists.
    #[test]
    fn directed_unverified_neighbor_refused() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        // No OGM exchange: neither has the other's key.

        let frame = b"payload";
        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        assert!(a.tag_directed(mac(3), frame, &mut trailer).is_none());
        assert!(!b.verify_directed(mac(2), frame, &trailer));
    }

    /// A frame A authored for B cannot be reflected back to A as if it came from
    /// B, even though the pairwise key is symmetric — the sender MAC is bound
    /// into the tag.
    #[test]
    fn directed_frame_cannot_be_reflected_to_sender() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let frame = b"payload";
        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        // A tags a frame for B (sender context = A).
        a.tag_directed(mac(3), frame, &mut trailer).unwrap();
        // Reflect that exact frame back to A claiming it came from B: rejected,
        // because A recomputes the tag with B as the sender context.
        assert!(
            !a.verify_directed(mac(3), frame, &trailer),
            "an A->B frame must not verify as a B->A frame"
        );
    }

    /// A keep-alive signed by a node whose OGM the receiver has already
    /// verified (and thus cached the cert for) verifies, with no cert or
    /// fingerprint carried on the wire.
    #[test]
    fn keepalive_signature_verifies_for_cached_neighbor() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).expect("augment");

        assert!(b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A tampered keep-alive signature fails verification.
    #[test]
    fn keepalive_tampered_signature_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();
        buf[len - 1] ^= 0xff; // flip a signature byte
        assert!(!b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A keep-alive from a neighbor whose OGM has never been verified (so no
    /// cert is cached for it) is rejected — fails closed rather than trusting
    /// an unverifiable claim.
    #[test]
    fn keepalive_from_unverified_neighbor_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        // No OGM exchange: b has not cached a's cert.

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();
        assert!(!b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A keep-alive from a revoked neighbor is dropped even with a valid
    /// signature over a still-cached cert.
    #[test]
    fn keepalive_from_revoked_neighbor_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));
        let record = authority.revoke(mac(2), 50, 1000);
        assert!(b.ingest_revocation(&record));

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();
        assert!(!b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A keep-alive is rejected once the sender's cached cert has expired on
    /// the verifier's clock, even though its replay counter is perfectly
    /// fresh — cert expiry and replay freshness are independent checks.
    #[test]
    fn keepalive_with_expired_cached_cert_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 131); // cert expires shortly after signing
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive(); // a signs at now_unix = 100
        let len = a.augment_keepalive(&mut buf, len).unwrap();

        b.set_time(Duration::from_secs(140), Clocked::At(140)); // past a's not_after = 131
        assert!(!b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// **A keep-alive crosses between a clocked node and an unclocked one, in
    /// both directions.**
    ///
    /// The interoperability claim design 20 §4.3 rests on, and the pair that
    /// could not both pass under the time bucket: an unclocked sender signed
    /// bucket 0, which every clocked receiver read as astronomically stale,
    /// and computed `now_bucket` 0 itself, so every real bucket a clocked peer
    /// sent looked like the future. Both directions failed, and no amount of
    /// local skipping could rescue it — the bucket is a *signature input
    /// carried on the wire*, not a local policy check, which is why the
    /// mechanism had to be replaced rather than made advisory.
    #[test]
    fn a_keepalive_crosses_between_a_clocked_node_and_an_unclocked_one() {
        const ISSUED_AT: u64 = 1_700_000_000;
        const A_YEAR: u64 = 365 * 24 * 60 * 60;

        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        // The board: a real certificate, no clock at all.
        let mut board = member_issued_at(
            &authority,
            2,
            mac(2),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::Unknown,
        );
        // The host: the same mesh, and it knows the time.
        let mut host = member_issued_at(
            &authority,
            3,
            mac(3),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::At(ISSUED_AT + 60),
        );
        mutual_verify(&mut board, mac(2), &mut host, mac(3));

        let (mut buf, len) = bare_keepalive();
        let len = board.augment_keepalive(&mut buf, len).expect("augment");
        assert!(
            host.verify_keepalive(mac(2), &buf[..len]),
            "a clocked node must accept an unclocked peer's keep-alive"
        );

        let (mut buf, len) = bare_keepalive();
        let len = host.augment_keepalive(&mut buf, len).expect("augment");
        assert!(
            board.verify_keepalive(mac(3), &buf[..len]),
            "an unclocked node must accept a clocked peer's keep-alive"
        );
    }

    /// A captured keep-alive replayed at its recipient is refused on the
    /// counter — a high-water mark, which bounds replay strictly harder than
    /// the 30-second window it replaces as well as needing no clock.
    #[test]
    fn keepalive_replay_is_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1_000_000);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();
        assert!(b.verify_keepalive(mac(2), &buf[..len]));
        assert!(
            !b.verify_keepalive(mac(2), &buf[..len]),
            "the same keep-alive must not verify twice"
        );

        // ...and a fresh one still does.
        let (mut fresh, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut fresh, len).unwrap();
        assert!(b.verify_keepalive(mac(2), &fresh[..len]));
    }

    /// Keep-alives draw from the **same** outgoing counter as directed and
    /// fan-out frames, and mixing the three does not make any of them look
    /// stale.
    ///
    /// This is the property that let the trailer change cost no receiver
    /// change at all (design 20 §4.3): `accept_recv_counter` keys on `src`
    /// alone, and any subsequence of a strictly increasing sequence is
    /// strictly increasing, so a third class drawing from one sequence is just
    /// another subsequence.
    #[test]
    fn keepalives_share_one_counter_sequence_with_directed_frames() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1_000_000);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let frame = [0xAAu8; 32];
        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];

        for _ in 0..3 {
            let (mut buf, len) = bare_keepalive();
            let len = a.augment_keepalive(&mut buf, len).unwrap();
            assert!(b.verify_keepalive(mac(2), &buf[..len]));

            let n = a.tag_directed(mac(3), &frame, &mut trailer).unwrap();
            assert!(
                b.verify_directed(mac(2), &frame, &trailer[..n]),
                "a directed frame interleaved with keep-alives is not stale"
            );
        }
    }

    /// **The format tag is a signed input, not just a wire marker.**
    ///
    /// `keepalive_signed_message` covers the *tagged* bytes, so flipping
    /// `KEEPALIVE_COUNTER_TAG` in flight breaks the signature. Without that,
    /// the tag would be a free-floating bit an attacker could set on a captured
    /// pre-design-20 keep-alive to make it present as this build's format —
    /// and every other test on this path would still pass, because they all
    /// build their frames through `augment_keepalive`, which always sets it.
    #[test]
    fn the_keepalive_format_tag_is_covered_by_the_signature() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1_000_000);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();
        let trailer_start = len - KEEPALIVE_TRAILER_LEN;

        // Clear the tag and nothing else. If the signature covered only the
        // stripped counter this would still verify — as a *legacy* trailer,
        // which is precisely the frame the tag exists to tell apart.
        buf[trailer_start] &= 0x7f;
        assert!(
            !b.verify_keepalive(mac(2), &buf[..len]),
            "clearing the format tag must break the signature that covers it"
        );

        // The control: restoring the bit restores a frame that verifies, so the
        // refusal above is the tag and not some other damage.
        buf[trailer_start] |= 0x80;
        assert!(b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A keep-alive carrying the **old** time-bucket trailer is refused, and
    /// distinguishably so.
    ///
    /// The eight bytes did not change size, only meaning, so a mixed mesh
    /// would otherwise drop keep-alives between mismatched nodes with nothing
    /// to say why (design 20 §6.2). The high bit is set on every counter this
    /// build puts on the wire and clear on every bucket the previous one did,
    /// which is enough for a receiver to name what it is holding. Stripped
    /// before the counter reaches the replay guard, so the tagged value never
    /// enters the sequence directed frames share.
    #[test]
    fn a_legacy_time_bucket_trailer_is_refused() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1_000_000);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();
        assert!(
            buf[len - KEEPALIVE_TRAILER_LEN] & 0x80 != 0,
            "every counter this build emits carries the format tag"
        );

        // What the previous build put here: a bucket, whose high bit is clear.
        // Signed by `a` over the bucket bytes, exactly as the old build did, so
        // this frame is *only* refusable on its format — a test that left the
        // signature broken would pass whether the tag check ran or not, and
        // would keep passing if the tag check were removed entirely.
        let trailer_start = len - KEEPALIVE_TRAILER_LEN;
        let bucket = (100u64 / 30).to_be_bytes();
        let mut scratch = [0u8; SIGN_SCRATCH_LEN];
        let signed = <OgmAuth>::keepalive_signed_message(&mac(2).0, &bucket, &mut scratch)
            .expect("scratch fits");
        let sig = a.keypair.sign(signed);
        buf[trailer_start..trailer_start + 8].copy_from_slice(&bucket);
        buf[trailer_start + 8..len].copy_from_slice(&sig);

        assert!(
            !b.verify_keepalive(mac(2), &buf[..len]),
            "a legacy time-bucket trailer must not be admitted even when its own \
             signature is perfectly valid"
        );
    }

    /// The counter of certificates admitted without a window check moves only
    /// when a window actually went unchecked.
    ///
    /// The metric §7 asks for, and one whose failure mode is silence: reading
    /// zero forever is exactly what an operator would expect from a healthy
    /// node, so a counter that never increments is indistinguishable from
    /// nothing being wrong.
    #[test]
    fn unjudged_admissions_counts_only_undated_ones() {
        const ISSUED_AT: u64 = 1_700_000_000;
        const A_YEAR: u64 = 365 * 24 * 60 * 60;

        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member_issued_at(
            &authority,
            2,
            mac(2),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::At(ISSUED_AT),
        );

        // A clocked receiver judges the window, so nothing is unjudged.
        let mut clocked = member_issued_at(
            &authority,
            3,
            mac(3),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::At(ISSUED_AT + 60),
        );
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(clocked.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert_eq!(
            clocked.unjudged_admissions(),
            0,
            "a node that judged the window admitted nothing undated"
        );

        // An unclocked one admits the same certificate without dating it.
        let mut board = member_issued_at(
            &authority,
            4,
            mac(4),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
            Clocked::Unknown,
        );
        assert_eq!(board.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert_eq!(board.unjudged_admissions(), 1);
    }

    /// Augmentation fails closed (rather than truncating) when the buffer has
    /// no room for the trailer.
    #[test]
    fn keepalive_augment_none_when_buffer_too_small() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut buf = [0u8; 4]; // header + far too little room for the trailer
        buf[0] = BatmanPacketType::Keepalive.as_u8();
        buf[1] = 5;
        assert!(a.augment_keepalive(&mut buf, 2).is_none());
    }

    /// Verifying a neighbor's OGM caches its raw certificate bytes (not just the
    /// derived `VerifiedCert`), retrievable by MAC alongside the cert's
    /// fingerprint — the store lazy cert distribution resolves fingerprints
    /// against.
    #[test]
    fn neighbor_cert_lookup_returns_cached_bytes() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let (cached_cert, cached_fp) = b.neighbor_cert(mac(2)).expect("cached after verify");
        assert_eq!(cached_cert.as_bytes(), a.cert.as_bytes());
        assert_eq!(cached_fp, a.cert.fingerprint());
    }

    /// An unknown MAC has no cached cert.
    #[test]
    fn neighbor_cert_lookup_none_for_unknown_mac() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let b = member(&authority, 3, mac(3), 1000);
        assert!(b.neighbor_cert(mac(2)).is_none());
    }

    /// A renewed cert for an already-known MAC (the same identity key, a fresh
    /// validity window) overwrites the stored bytes and fingerprint in place,
    /// rather than leaving the old cert cached alongside the new one.
    ///
    /// A renewal rather than a re-key, because a re-key is what the authority
    /// refuses to issue while the held certificate is live, and what
    /// `cache_neighbor` correspondingly refuses to cache — see
    /// `a_second_key_cannot_displace_a_live_member`.
    #[test]
    fn neighbor_cert_renewal_updates_stored_bytes_and_fingerprint() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut a1 = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a1.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        let (_, fp1) = b.neighbor_cert(mac(2)).expect("cached after first verify");

        // Same MAC and same key, a longer window — a renewal.
        let mut a2 = member(&authority, 2, mac(2), 5000);
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = a2.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let (cached_cert, fp2) = b.neighbor_cert(mac(2)).expect("still cached after renewal");
        assert_ne!(fp1, fp2, "renewal must change the fingerprint");
        assert_eq!(cached_cert.as_bytes(), a2.cert.as_bytes());
    }

    /// Once the neighbor table is at capacity, a newly verified neighbor evicts
    /// the crude first slot (matching `cache_neighbor`'s eviction policy) —
    /// its cached cert is gone too, not just its `VerifiedCert`.
    #[test]
    fn neighbor_cert_evicted_with_table_slot() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 100, mac(100), 1_000_000);

        // Fill the table to capacity with distinct originators.
        for n in 1..=MAX_NEIGHBOR_KEYS as u8 {
            let mut a = member(&authority, n, mac(n), 1_000_000);
            let (mut buf, len) = bare_ogm(mac(n), 1);
            let len = a.augment_ogm(&mut buf, len).unwrap();
            assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        }
        assert_eq!(b.neighbors().len(), MAX_NEIGHBOR_KEYS);
        assert!(
            b.neighbor_cert(mac(1)).is_some(),
            "first entry present pre-eviction"
        );

        // One more distinct originator: the crude policy overwrites slot 0.
        let mut over = member(&authority, 200, mac(200), 1_000_000);
        let (mut buf, len) = bare_ogm(mac(200), 1);
        let len = over.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        assert!(
            b.neighbor_cert(mac(1)).is_none(),
            "evicted neighbor's cert must be gone, not just its VerifiedCert"
        );
        assert!(b.neighbor_cert(mac(200)).is_some());
    }

    /// gap-4A: a second certificate for a **live** member's MAC, under a
    /// different identity key, must not displace the entry the member is
    /// using.
    ///
    /// The cached pairwise key is symmetric ECDH, so flipping it breaks the
    /// member's directed data plane in *both* directions — a total, sustained
    /// denial of one member's authenticated traffic from a single misissued
    /// certificate, which is what the red-team sweep measured at 0/6 delivery.
    /// The receiver is here made no more permissive than its own authority,
    /// which already refuses to issue a second key for a MAC whose certificate
    /// is still inside its window.
    #[test]
    fn a_second_key_cannot_displace_a_live_member() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut hq = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = hq.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        let pairwise_for = |b: &OgmAuth| {
            b.neighbors()
                .iter()
                .find(|n| n.cert.mac == mac(2))
                .map(|n| n.pairwise_key)
        };
        let held_key = pairwise_for(&b).expect("hq cached");

        // The residual this rule now covers: a `derive_mac` collision, since a
        // second *certified* key for hq's address cannot exist (design 09 §5 —
        // and `a_misissued_cert_for_a_live_member_never_reaches_the_cache`
        // below pins that outer refusal).
        let collision = colliding_neighbor(&authority, 9, mac(2), 1000, &b);
        assert_eq!(b.cache_neighbor(collision), Cached::RefusedLiveIdentity);

        let (cached, _) = b.neighbor_cert(mac(2)).expect("hq's entry survives");
        assert_eq!(
            cached.as_bytes(),
            hq.cert.as_bytes(),
            "the live member's certificate must not be replaced"
        );
        assert_eq!(
            pairwise_for(&b),
            Some(held_key),
            "nor the pairwise key derived from it"
        );
        assert_eq!(b.neighbors().len(), 1, "and no second entry for that MAC");
    }

    /// A misissued certificate raises `IdentityConflict` against the contested
    /// address, and is not merely dropped at `trace!`.
    ///
    /// The signal has to move with the refusal. Before the key↔address binding
    /// this condition reached `cache_neighbor`, was refused there, and raised
    /// this alarm; now `verify_cert` refuses it first, so without raising it
    /// here the most serious condition in the threat model — an authority that
    /// issued twice for one address, or an anchor no longer under sole control
    /// — would be *silent*, while the same attacker's directed frames raised
    /// `UnauthenticatedTraffic` against the victim.
    #[test]
    fn a_misissued_cert_raises_an_identity_conflict_alarm() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let eve_kp = Keypair::from_seed(&[9; 32]);
        let misissued =
            authority.issue_cert(mac(2), eve_kp.ed_pubkey(), eve_kp.x_pubkey(), 0, 1000);
        let mut eve = OgmAuth::new(eve_kp, misissued, authority.trust_anchor());
        eve.set_time(Duration::from_secs(100), Clocked::At(100));
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = eve.augment_ogm(&mut buf, len).unwrap();

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
        });

        let snapshot = board.snapshot();
        assert_eq!(snapshot.alarms.len(), 1, "the refusal must be reported");
        let raised = &snapshot.alarms[0];
        assert_eq!(raised.kind, wayfinder_alarm::AlarmKind::IdentityConflict);
        assert_eq!(raised.severity, wayfinder_alarm::Severity::Warning);
        assert_eq!(
            raised.subject,
            wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&mac(2).0)),
            "attributed to the contested address, not to the key that claimed it"
        );
    }

    /// A flood of the same misissuance is one alarm row with a count.
    ///
    /// The condition is reachable by arbitrary remote input at whatever rate an
    /// attacker sends, so an alarm system that grew a row per frame would
    /// become the flood it reports.
    #[test]
    fn a_flood_of_a_misissued_cert_is_one_alarm_row() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let eve_kp = Keypair::from_seed(&[9; 32]);
        let misissued =
            authority.issue_cert(mac(2), eve_kp.ed_pubkey(), eve_kp.x_pubkey(), 0, 1000);
        let mut eve = OgmAuth::new(eve_kp, misissued, authority.trust_anchor());
        eve.set_time(Duration::from_secs(100), Clocked::At(100));

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            for seqno in 100..110 {
                let (mut buf, len) = bare_ogm(mac(2), seqno);
                let len = eve.augment_ogm(&mut buf, len).unwrap();
                assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
            }
        });

        let snapshot = board.snapshot();
        assert_eq!(snapshot.alarms.len(), 1, "one row, however long the flood");
        assert_eq!(snapshot.alarms[0].count, 10, "the count carries the volume");
    }

    /// An ordinary verification failure must *not* raise the alarm — it is
    /// reserved for a misissuance, which is a statement about the authority.
    ///
    /// A forged or foreign certificate is something any outsider can produce at
    /// will; filing those as identity conflicts would make the alarm mean
    /// "somebody is transmitting nearby" and bury the one case it exists for.
    #[test]
    fn an_ordinary_bad_certificate_raises_no_identity_conflict() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let theirs = Authority::from_seed(&[9; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        // A foreign-mesh member: correctly derived address, wrong root.
        let mut foreign = member(&theirs, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = foreign.augment_ogm(&mut buf, len).unwrap();

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
        });
        assert!(
            board.snapshot().alarms.is_empty(),
            "a forged or foreign certificate is not an identity conflict"
        );
    }

    /// The outer defence, and the reason the rule above now guards only a hash
    /// collision: a certificate naming a live member's address under another
    /// key is refused at *verification*, so it never reaches the cache at all.
    ///
    /// This is gap 4's half of the pair (design 09 §5). §8.9's cache rule is
    /// what stood before it and is kept as defense in depth; this is what
    /// removed its precondition.
    #[test]
    fn a_misissued_cert_for_a_live_member_never_reaches_the_cache() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut hq = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = hq.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // A genuinely CA-signed certificate binding eve's key to hq's address.
        // The authority will still *mint* it — `issue_cert` is the primitive,
        // and nothing a verifier does can stop a misissuance being signed.
        let eve_kp = Keypair::from_seed(&[9; 32]);
        let misissued =
            authority.issue_cert(mac(2), eve_kp.ed_pubkey(), eve_kp.x_pubkey(), 0, 1000);
        let mut eve = OgmAuth::new(eve_kp, misissued, authority.trust_anchor());
        eve.set_time(Duration::from_secs(100), Clocked::At(100));
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = eve.augment_ogm(&mut buf, len).unwrap();

        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::Rejected,
            "a certificate naming an address its key does not derive must not verify"
        );
        let (cached, _) = b.neighbor_cert(mac(2)).expect("hq's entry survives");
        assert_eq!(cached.as_bytes(), hq.cert.as_bytes());
    }

    /// The point of the refusal, stated as the property it protects: the real
    /// member's genuinely-tagged directed frames keep verifying when a
    /// colliding key is refused. The pairwise key is symmetric, so a displaced
    /// entry would break send and receive at once.
    #[test]
    fn a_live_member_keeps_its_data_plane_under_a_second_key() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut hq = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = hq.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // hq learns b's keys too, so it can tag a frame at b.
        let (mut buf, len) = bare_ogm(mac(3), 7);
        let len = b.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(hq.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // A colliding key, refused: the pairwise key hq's traffic is tagged
        // with must survive it, in both directions (the key is symmetric, so a
        // displaced entry breaks send and receive at once).
        let collision = colliding_neighbor(&authority, 9, mac(2), 1000, &b);
        assert_eq!(b.cache_neighbor(collision), Cached::RefusedLiveIdentity);

        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        hq.tag_directed(mac(3), b"frame", &mut trailer)
            .expect("the real member can still tag");
        assert!(
            b.verify_directed(mac(2), b"frame", &trailer),
            "a frame the real member tagged must still verify"
        );
    }

    /// The refusal is keyed on the **identity** key, not the certificate: an
    /// agreement-key-only rotation is something the authority will sign for a
    /// live member (its lock compares `ed_pubkey` alone), so the receiver has
    /// to admit it or it would reject a certificate its own CA just issued.
    #[test]
    fn an_agreement_key_rotation_is_admitted_for_a_live_member() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut a1 = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a1.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // Same identity key, a fresh agreement key: signed by the seed-2
        // keypair, carrying the seed-9 keypair's `x_pubkey`.
        let kp = Keypair::from_seed(&[2; 32]);
        let rotated_x = Keypair::from_seed(&[9; 32]).x_pubkey();
        let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), rotated_x, 0, 1000);
        let mut a2 = OgmAuth::new(kp, cert, authority.trust_anchor());
        a2.set_time(Duration::from_secs(100), Clocked::At(100));

        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = a2.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let (cached, _) = b.neighbor_cert(mac(2)).expect("still cached");
        assert_eq!(
            cached.as_bytes(),
            a2.cert.as_bytes(),
            "an x-only rotation must replace the entry"
        );
    }

    /// Once the held certificate has lapsed, its MAC is free again: the entry
    /// is not live, so a colliding key caches normally. Without this the pin
    /// would outlive the certificate that justified it, and a departed member
    /// would hold its address against every later claimant forever.
    ///
    /// "A new key" here means a *colliding* one — since the key↔address binding
    /// two keys can only contend for one address by hashing to it (see
    /// `colliding_neighbor`). A genuine re-key is a different address.
    #[test]
    fn a_lapsed_members_mac_admits_a_new_key() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 100_000);

        let mut a1 = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a1.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // Past a1's `not_after`: the entry is gone, and a different key may
        // take the address. The pin must release, or a lapsed member would hold
        // its address against every later claimant forever.
        b.set_time(Duration::from_secs(2000), Clocked::At(2000));
        let a2 = colliding_neighbor(&authority, 9, mac(2), 100_000, &b);
        assert_eq!(b.cache_neighbor(a2), Cached::Stored);

        assert_eq!(
            b.neighbors()
                .iter()
                .find(|n| n.cert.mac == mac(2))
                .map(|n| n.cert.ed_pubkey),
            Some(Keypair::from_seed(&[9; 32]).ed_pubkey()),
            "a lapsed certificate releases the address it held"
        );
    }

    /// A revocation lifts the pin the same way: ingesting one calls
    /// `evict_neighbor`, so there is no held entry left for the rule to
    /// collide with and the address is free.
    ///
    /// Note this exercises the *pin's release*, not a flow an operator drives.
    /// Since the key↔address binding a real re-admission is same-key — a
    /// different key is a different address — so the colliding entry here
    /// stands in for the only contention that remains.
    #[test]
    fn a_revoked_members_mac_admits_a_new_key() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 100_000);

        let mut a1 = member(&authority, 2, mac(2), 100_000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a1.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        assert!(b.ingest_revocation(&authority.revoke(mac(2), 500, 100_000)));
        assert!(
            b.neighbor_cert(mac(2)).is_none(),
            "the revocation evicted the entry"
        );

        // Re-admission under a different key: the revocation evicted the entry,
        // so nothing is left for the pin to collide with and the address is
        // free. (A real re-admission is same-key — a different key is a
        // different address now — so this exercises the pin's release, not a
        // flow an operator drives.)
        b.set_time(Duration::from_secs(700), Clocked::At(700));
        let a2 = colliding_neighbor(&authority, 9, mac(2), 100_000, &b);
        assert_eq!(b.cache_neighbor(a2), Cached::Stored);

        assert_eq!(
            b.neighbors()
                .iter()
                .find(|n| n.cert.mac == mac(2))
                .map(|n| n.cert.ed_pubkey),
            Some(Keypair::from_seed(&[9; 32]).ed_pubkey()),
            "a revocation releases the address it evicted"
        );
    }

    /// A node with no clock cannot judge whether the entry it holds is still
    /// live, and `live_neighbor` calls everything live then — so mirroring that
    /// here would leave such a node pinning an address *forever* on an entry it
    /// cannot judge. It admits instead, matching the authority, which fails
    /// closed on a zero clock rather than locking an address on one.
    #[test]
    fn an_unclocked_node_admits_a_new_key() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        b.set_time(Duration::from_secs(0), Clocked::Unknown);

        let mut a1 = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a1.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let a2 = colliding_neighbor(&authority, 9, mac(2), 1000, &b);
        assert_eq!(b.cache_neighbor(a2), Cached::Stored);

        assert_eq!(
            b.neighbors()
                .iter()
                .find(|n| n.cert.mac == mac(2))
                .map(|n| n.cert.ed_pubkey),
            Some(Keypair::from_seed(&[9; 32]).ed_pubkey()),
            "an unclocked node cannot judge liveness, so it must not pin"
        );
    }

    /// The refusal is also *reported*. `derive_mac` yields 46 bits, so an
    /// accidental collision is negligible and two identity keys claiming one
    /// address means a misissuance or a compromised anchor — but silently
    /// dropping the second certificate would present to an operator as
    /// unexplained route flapping with nothing to grep for.
    ///
    /// Raised onto a scoped board rather than the process-global one, so
    /// `alarms.len() == 1` is an assertion about *this* raise rather than about
    /// whatever else has landed on the global board.
    #[test]
    fn a_second_key_for_a_live_member_raises_an_alarm() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut hq = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = hq.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let collision = colliding_neighbor(&authority, 9, mac(2), 1000, &b);

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            assert_eq!(b.cache_neighbor(collision), Cached::RefusedLiveIdentity);
        });

        let snapshot = board.snapshot();
        assert_eq!(snapshot.alarms.len(), 1);
        let raised = &snapshot.alarms[0];
        assert_eq!(raised.kind, wayfinder_alarm::AlarmKind::IdentityConflict);
        assert_eq!(raised.severity, wayfinder_alarm::Severity::Warning);
        assert_eq!(
            raised.subject,
            wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&mac(2).0)),
            "attributed to the contested address"
        );
    }

    /// A flooded losing certificate is one alarm row with a count, not one row
    /// per frame. Load-bearing rather than incidental: the refused certificate
    /// never enters `verify_ogm`'s `known` memo, so *every* copy reaches the
    /// refusal, and an alarm board that grew a row per copy would become the
    /// flood it exists to report.
    #[test]
    fn a_flood_of_a_second_key_is_one_alarm_row_with_a_count() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut hq = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = hq.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let collision = colliding_neighbor(&authority, 9, mac(2), 1000, &b);
        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            for _ in 0..10 {
                assert_eq!(b.cache_neighbor(collision), Cached::RefusedLiveIdentity);
            }
        });

        let snapshot = board.snapshot();
        assert_eq!(snapshot.alarms.len(), 1, "one row, however long the flood");
        assert_eq!(snapshot.alarms[0].count, 10, "the count carries the volume");
        assert!(
            snapshot.alarms[0].detail.starts_with("refused_key="),
            "the detail names the key that was turned away: {}",
            snapshot.alarms[0].detail
        );
    }

    /// The legitimate paths must stay *silent*. An alarm on every ordinary
    /// certificate renewal would train an operator to ignore the one row that
    /// means their authority issued twice for one address.
    #[test]
    fn a_renewal_and_an_agreement_key_rotation_raise_no_alarm() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut a1 = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a1.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            // A renewal: same identity key, longer window.
            let mut a2 = member(&authority, 2, mac(2), 5000);
            let (mut buf, len) = bare_ogm(mac(2), 8);
            let len = a2.augment_ogm(&mut buf, len).unwrap();
            assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

            // An agreement-key-only rotation: same identity key, fresh x key.
            let kp = Keypair::from_seed(&[2; 32]);
            let rotated_x = Keypair::from_seed(&[9; 32]).x_pubkey();
            let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), rotated_x, 0, 5000);
            let mut a3 = OgmAuth::new(kp, cert, authority.trust_anchor());
            a3.set_time(Duration::from_secs(100), Clocked::At(100));
            let (mut buf, len) = bare_ogm(mac(2), 9);
            let len = a3.augment_ogm(&mut buf, len).unwrap();
            assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        });

        assert!(
            board.snapshot().alarms.is_empty(),
            "an identity that never changed is not a conflict"
        );
    }

    /// A `CertReply` carrying a second identity for a live member's address is
    /// refused — and, critically, the outstanding request it failed to answer
    /// **survives**.
    ///
    /// The ordering inside `ingest_cert_reply` is what this pins. Clearing the
    /// in-flight entry before knowing whether the cache took the certificate
    /// would let whoever raced a reply in consume the fetch attempt for that
    /// MAC and report success doing it, deleting the retry backstop the
    /// function's contract promises.
    #[test]
    fn a_cert_reply_for_a_contested_address_keeps_the_request_outstanding() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut hq = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = hq.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let mut req = [0u8; 512];
        b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut req)
            .unwrap();

        let eve = member(&authority, 9, mac(2), 1000);
        assert!(
            !b.ingest_cert_reply(eve.cert.as_bytes()),
            "a reply for a contested address is not a cached cert"
        );
        let (cached, _) = b.neighbor_cert(mac(2)).expect("hq's entry survives");
        assert_eq!(cached.as_bytes(), hq.cert.as_bytes());

        // The request is still outstanding, so a genuine reply still lands —
        // which it could not do had the refused one consumed the entry.
        assert!(
            b.ingest_cert_reply(hq.cert.as_bytes()),
            "the refused reply must not have consumed the outstanding request"
        );
    }

    /// A `CertReq` presenting a second identity for a live member's address is
    /// refused *before* the rate limiter, so it cannot spend the real member's
    /// slot.
    ///
    /// `requester` is read off the presented certificate, so such a request
    /// arrives naming the member it is impersonating. Checking after the
    /// limiter would let an attacker keep that member's slot permanently hot
    /// and deny their genuine requests — the same inversion the
    /// proof-of-possession ordering above it exists to prevent, reached by a
    /// party who holds a real key and so passes that check cleanly.
    #[test]
    fn a_cert_request_for_a_contested_address_costs_the_member_nothing() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut responder = member(&authority, 1, mac(1), 1000);

        let mut hq = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = hq.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(responder.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let mut eve = member(&authority, 9, mac(2), 1000);
        let mut forged = [0u8; 512];
        let forged_len = eve
            .build_cert_request(mac(1), [0; 8], mac(9), &mut forged)
            .unwrap();
        assert_eq!(
            responder.verify_cert_request(&forged[..forged_len]),
            None,
            "a request under a second identity for a live address is refused"
        );

        // The real member's own request, immediately after and well inside the
        // rate-limit window, must still be answered.
        let mut genuine = [0u8; 512];
        let genuine_len = hq
            .build_cert_request(mac(1), [0; 8], mac(9), &mut genuine)
            .unwrap();
        assert_eq!(
            responder.verify_cert_request(&genuine[..genuine_len]),
            Some(mac(2)),
            "the refused request must not have consumed the member's slot"
        );
    }

    /// Build a "lazy" OGM: header + `CertFp` (not `Cert`) + `OgmSig`, signed
    /// exactly as `augment_ogm` would (over the full cert bytes) — the shape
    /// lazy cert distribution's requester side must resolve from its cache.
    fn augment_ogm_with_certfp(auth: &mut OgmAuth, buf: &mut [u8], len: usize) -> usize {
        let cert = auth.cert;
        let cert_bytes = cert.as_bytes();
        let mut orig = [0u8; 6];
        orig.copy_from_slice(&buf[ORIG_OFF..ORIG_OFF + 6]);
        let mut seqno = [0u8; 4];
        seqno.copy_from_slice(&buf[SEQNO_OFF..SEQNO_OFF + 4]);
        let signature = {
            let signed =
                HostAuth::signed_message(&orig, &seqno, cert_bytes, &mut auth.sign_scratch)
                    .unwrap();
            auth.keypair.sign(signed)
        };
        let fp = cert.fingerprint();
        let mut off = len;
        off = HostAuth::write_tvlv(buf, off, TvlvType::CertFp, &fp);
        off = HostAuth::write_tvlv(buf, off, TvlvType::OgmSig, &signature);
        let tvlv_len = (off - len) as u16;
        buf[TVLV_LEN_OFF..TVLV_LEN_OFF + 2].copy_from_slice(&tvlv_len.to_be_bytes());
        off
    }

    /// A fingerprint-only OGM from a never-seen originator cannot be verified
    /// (nothing cached to check the fingerprint against) — `verify_ogm` must
    /// ask for the cert rather than reject or (worse) accept unverified.
    #[test]
    fn certfp_ogm_from_unknown_originator_needs_cert() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = augment_ogm_with_certfp(&mut a, &mut buf, len);

        let expected_fp = a.cert.fingerprint();
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::NeedCert {
                orig: mac(2),
                fp: expected_fp
            }
        );
    }

    /// Once the cert is cached (e.g. via an ordinary legacy-format OGM), a
    /// later fingerprint-only OGM from the same originator verifies against
    /// the cached bytes with zero cert bytes on the wire.
    #[test]
    fn certfp_ogm_verifies_against_cached_cert() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        // Prime the cache with a full-cert OGM first.
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // A subsequent fingerprint-only OGM verifies from the cache.
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = augment_ogm_with_certfp(&mut a, &mut buf, len);
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
    }

    /// A rotated cert (new keys, same MAC) changes the fingerprint, so a
    /// fingerprint-only OGM after rotation is a cache miss (`NeedCert`) even
    /// though *a* cert for that MAC is still cached — a stale cert must not
    /// silently verify a rotated identity's signature.
    #[test]
    fn certfp_ogm_after_rotation_needs_cert() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut a1 = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a1.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        // Rotation: same MAC, freshly issued cert with different keys.
        let mut a2 = member(&authority, 9, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = augment_ogm_with_certfp(&mut a2, &mut buf, len);

        let expected_fp = a2.cert.fingerprint();
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::NeedCert {
                orig: mac(2),
                fp: expected_fp
            }
        );
    }

    /// A tampered signature on a fingerprint-only OGM is rejected even
    /// though the fingerprint matches a cached cert — the cache only selects
    /// which cert to check against, it is not itself a trust boundary.
    #[test]
    fn certfp_ogm_tampered_signature_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = augment_ogm_with_certfp(&mut a, &mut buf, len);
        buf[len - 1] ^= 0xff; // flip a signature byte
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
    }

    /// An expired cached cert still fails a fingerprint-matched OGM: the
    /// full anchor/expiry/revocation pipeline re-runs against the cached
    /// bytes on every OGM, not just at cache-population time.
    #[test]
    fn certfp_ogm_expired_cached_cert_is_dropped() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        b.set_time(Duration::from_secs(2000), Clocked::At(2000)); // past a's not_after = 1000
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = augment_ogm_with_certfp(&mut a, &mut buf, len);
        // The expired entry is evicted the moment the clock passes it, so the
        // fingerprint no longer resolves and the verdict is `NeedCert` rather
        // than `Rejected`. Either way this OGM is dropped, which is the
        // security property; the difference is that a fetch is now attempted,
        // which is what recovers the link if the peer has since renewed.
        assert_eq!(
            b.verify_ogm(&buf[..len]),
            OgmVerdict::NeedCert {
                orig: mac(2),
                fp: a.cert.fingerprint(),
            },
        );
        assert!(
            b.neighbor_cert(mac(2)).is_none(),
            "an expired cert must not remain usable"
        );
    }

    /// `build_cert_request` produces a self-authenticating body (the
    /// requester's own cert followed by a signature) that a verifier can
    /// check with nothing more than the requester's cert and the requested
    /// originator's MAC — the responder-side verification this sets up for.
    #[test]
    fn build_cert_request_produces_self_authenticating_body() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut buf = [0u8; 512];
        let len = b
            .build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
            .expect("first request must be sent");

        let cert_len = core::mem::size_of::<MembershipCert>();
        assert_eq!(len, cert_len + SIG_LEN);
        let (cert, sig_bytes) = buf[..len].split_at(cert_len);
        let (parsed_cert, _) = MembershipCert::ref_from_prefix(cert).unwrap();
        assert_eq!(
            parsed_cert.node_mac,
            mac(3).0,
            "carries the requester's own cert"
        );

        let mut msg = [0u8; CERT_REQ_SIG_DOMAIN.len() + 12];
        msg[..CERT_REQ_SIG_DOMAIN.len()].copy_from_slice(CERT_REQ_SIG_DOMAIN);
        msg[CERT_REQ_SIG_DOMAIN.len()..CERT_REQ_SIG_DOMAIN.len() + 6].copy_from_slice(&mac(2).0);
        msg[CERT_REQ_SIG_DOMAIN.len() + 6..].copy_from_slice(&mac(3).0);
        let mut sig = [0u8; SIG_LEN];
        sig.copy_from_slice(sig_bytes);
        assert!(verify_signature(&parsed_cert.ed_pubkey, &msg, &sig));
    }

    /// A second request for the same originator, before the retry backoff
    /// elapses, is suppressed (deduped) rather than re-sent — the
    /// requester-side half of keeping cert-fetch chatter bounded.
    #[test]
    fn build_cert_request_dedups_within_backoff() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut buf = [0u8; 512];
        assert!(
            b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
                .is_some()
        );
        assert!(
            b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
                .is_none(),
            "an immediate re-request for the same originator must be suppressed"
        );

        // Once the backoff interval elapses, a retry is allowed again.
        b.set_time(
            b.now + CERT_REQUEST_RETRY,
            Clocked::At(b.now_unix() + CERT_REQUEST_RETRY.as_secs()),
        );
        assert!(
            b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
                .is_some(),
            "a retry after the backoff window must be allowed"
        );
    }

    /// The retry budget is finite: once exhausted, further calls are
    /// suppressed for good rather than retrying forever.
    #[test]
    fn build_cert_request_retry_budget_is_finite() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut buf = [0u8; 512];

        for round in 0..MAX_CERT_REQUEST_ATTEMPTS {
            assert!(
                b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
                    .is_some()
            );
            // Skip the final advance: exhaustion must block a request made
            // in the *same* window the budget ran out, before any clock
            // advance has had a chance to reclaim the slot (see
            // `in_flight_table_reclaims_exhausted_entries` for that case).
            if round + 1 < MAX_CERT_REQUEST_ATTEMPTS {
                b.set_time(
                    b.now + CERT_REQUEST_RETRY,
                    Clocked::At(b.now_unix() + CERT_REQUEST_RETRY.as_secs()),
                );
            }
        }
        assert!(
            b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
                .is_none(),
            "retry budget exhausted"
        );
    }

    /// Requests for distinct originators are tracked independently.
    #[test]
    fn build_cert_request_tracks_distinct_originators_independently() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut buf = [0u8; 512];

        assert!(
            b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
                .is_some()
        );
        assert!(
            b.build_cert_request(mac(5), [0xBB; 8], mac(9), &mut buf)
                .is_some(),
            "a different originator must not be suppressed by the first's backoff"
        );
    }

    /// A valid `CertReply` answering an outstanding request is cached and
    /// clears the in-flight entry.
    #[test]
    fn ingest_cert_reply_caches_and_clears_in_flight() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut buf = [0u8; 512];
        b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
            .unwrap();

        let a = member(&authority, 2, mac(2), 1000);
        assert!(b.ingest_cert_reply(a.cert.as_bytes()));
        let (cached, fp) = b.neighbor_cert(mac(2)).expect("cached after reply");
        assert_eq!(cached.as_bytes(), a.cert.as_bytes());
        assert_eq!(fp, a.cert.fingerprint());

        // The in-flight entry is cleared: an unsolicited second reply for the
        // same MAC (no outstanding request now) is rejected.
        assert!(!b.ingest_cert_reply(a.cert.as_bytes()));
    }

    /// An unsolicited reply — no outstanding request for that MAC — is
    /// rejected, so a spoofed/unprompted `CertReply` cannot poison the cache.
    #[test]
    fn ingest_cert_reply_unsolicited_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let a = member(&authority, 2, mac(2), 1000);
        assert!(!b.ingest_cert_reply(a.cert.as_bytes()));
        assert!(b.neighbor_cert(mac(2)).is_none());
    }

    /// A reply body too short to contain a `MembershipCert` is rejected
    /// rather than panicking.
    #[test]
    fn ingest_cert_reply_malformed_body_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut buf = [0u8; 512];
        b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
            .unwrap();
        assert!(!b.ingest_cert_reply(&[0u8; 10]));
        assert!(b.neighbor_cert(mac(2)).is_none());
    }

    /// A reply carrying a cert that fails anchor verification (foreign mesh)
    /// is rejected even though a request is outstanding for that MAC.
    #[test]
    fn ingest_cert_reply_foreign_mesh_rejected() {
        let ours = Authority::from_seed(&[1; 32], 0xABCD);
        let theirs = Authority::from_seed(&[9; 32], 0xABCD);
        let mut b = member(&ours, 3, mac(3), 1000);
        let mut buf = [0u8; 512];
        b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
            .unwrap();

        let foreign = member(&theirs, 2, mac(2), 1000);
        assert!(!b.ingest_cert_reply(foreign.cert.as_bytes()));
        assert!(b.neighbor_cert(mac(2)).is_none());
    }

    /// A well-formed `CertReq` body (built with the real requester-side
    /// `build_cert_request`) verifies at the responder, yielding the
    /// requester's MAC and caching their cert — a free, verified exchange.
    #[test]
    fn verify_cert_request_accepts_valid_request_and_caches_requester() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000); // responder ("A")
        let mut requester = member(&authority, 3, mac(3), 1000);

        let mut buf = [0u8; 512];
        let len = requester
            .build_cert_request(mac(2), [0; 8], mac(9), &mut buf)
            .unwrap();

        assert_eq!(a.verify_cert_request(&buf[..len]), Some(mac(3)));
        let (cached, fp) = a.neighbor_cert(mac(3)).expect("requester cert cached");
        assert_eq!(cached.as_bytes(), requester.cert.as_bytes());
        assert_eq!(fp, requester.cert.fingerprint());
    }

    /// A body of the wrong length (not exactly cert+signature) is rejected.
    #[test]
    fn verify_cert_request_rejects_malformed_body() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        assert_eq!(a.verify_cert_request(&[0u8; 10]), None);
    }

    /// A tampered self-authentication signature is rejected even though the
    /// requester's cert itself is valid.
    #[test]
    fn verify_cert_request_rejects_tampered_signature() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut requester = member(&authority, 3, mac(3), 1000);
        let mut buf = [0u8; 512];
        let len = requester
            .build_cert_request(mac(2), [0; 8], mac(9), &mut buf)
            .unwrap();
        buf[len - 1] ^= 0xff;
        assert_eq!(a.verify_cert_request(&buf[..len]), None);
    }

    /// A requester from a foreign mesh (different trust anchor) is rejected.
    #[test]
    fn verify_cert_request_rejects_foreign_mesh() {
        let ours = Authority::from_seed(&[1; 32], 0xABCD);
        let theirs = Authority::from_seed(&[9; 32], 0xABCD);
        let mut a = member(&ours, 2, mac(2), 1000);
        let mut requester = member(&theirs, 3, mac(3), 1000);
        let mut buf = [0u8; 512];
        let len = requester
            .build_cert_request(mac(2), [0; 8], mac(9), &mut buf)
            .unwrap();
        assert_eq!(a.verify_cert_request(&buf[..len]), None);
    }

    /// A `CertReq` from a revoked requester is rejected even though its cert
    /// still passes anchor verification — a revoked member cannot use a
    /// still-valid cert to have the responder answer or cache it.
    #[test]
    fn verify_cert_request_rejects_revoked_requester() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut requester = member(&authority, 3, mac(3), 1000);
        let record = authority.revoke(mac(3), 50, 1000);
        assert!(a.ingest_revocation(&record));

        let mut buf = [0u8; 512];
        let len = requester
            .build_cert_request(mac(2), [0; 8], mac(9), &mut buf)
            .unwrap();
        assert_eq!(a.verify_cert_request(&buf[..len]), None);
        assert!(a.neighbor_cert(mac(3)).is_none());
    }

    /// Repeated requests from the same requester within the rate-limit
    /// window are dropped; once the window elapses, requests are accepted
    /// again — bounding the verification/airtime cost one member can impose.
    #[test]
    fn verify_cert_request_rate_limits_repeated_requests() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut requester = member(&authority, 3, mac(3), 1000);
        let mut buf = [0u8; 512];
        let len = requester
            .build_cert_request(mac(2), [0; 8], mac(9), &mut buf)
            .unwrap();

        assert_eq!(a.verify_cert_request(&buf[..len]), Some(mac(3)));
        assert_eq!(
            a.verify_cert_request(&buf[..len]),
            None,
            "an immediate repeat must be rate-limited"
        );

        a.set_time(
            a.now + CERT_REQ_RATE_LIMIT,
            Clocked::At(a.now_unix() + CERT_REQ_RATE_LIMIT.as_secs()),
        );
        assert_eq!(
            a.verify_cert_request(&buf[..len]),
            Some(mac(3)),
            "a request after the rate-limit window must be accepted"
        );
    }

    /// A forged request replaying a real member's public cert (certs are not
    /// secret) with a garbage signature must not consume that member's
    /// rate-limit slot — otherwise an attacker who never held the member's
    /// private key could keep it permanently "hot" and deny the member's own
    /// genuine, correctly-signed request. Proof-of-possession must be
    /// checked before the rate limiter is touched.
    #[test]
    fn verify_cert_request_forged_signature_does_not_consume_rate_limit_slot() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut requester = member(&authority, 3, mac(3), 1000);
        let mut buf = [0u8; 512];
        let len = requester
            .build_cert_request(mac(2), [0; 8], mac(9), &mut buf)
            .unwrap();

        // Attacker replays the requester's real (public, non-secret) cert
        // bytes but with a garbage signature — cannot prove possession.
        let mut forged = buf;
        forged[len - 1] ^= 0xff;
        assert_eq!(a.verify_cert_request(&forged[..len]), None);

        // The real requester's genuine, correctly-signed request — sent
        // immediately after, well within the rate-limit window — must still
        // succeed: the forged attempt above must not have consumed the slot.
        assert_eq!(
            a.verify_cert_request(&buf[..len]),
            Some(mac(3)),
            "a forged request must not deny the real requester's own request"
        );
    }

    /// The in-flight request table reclaims entries whose retry budget is
    /// exhausted, so a target that never answers (unreachable, or an
    /// attacker flooding fake fingerprint misses) cannot permanently pin
    /// slots and block fetching any other originator's cert.
    #[test]
    fn in_flight_table_reclaims_exhausted_entries() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        let mut buf = [0u8; 512];

        // Fill the table with originators that never answer, advancing all
        // of them in lockstep so every one reaches exhaustion in the same
        // round — without an intervening `set_time` (which prunes) letting
        // any of them get reclaimed mid-fill.
        for round in 0..MAX_CERT_REQUEST_ATTEMPTS {
            for n in 1..=MAX_IN_FLIGHT_CERT_REQUESTS as u8 {
                assert!(
                    b.build_cert_request(mac(n), [n; 8], mac(9), &mut buf)
                        .is_some()
                );
            }
            if round + 1 < MAX_CERT_REQUEST_ATTEMPTS {
                b.set_time(
                    b.now + CERT_REQUEST_RETRY,
                    Clocked::At(b.now_unix() + CERT_REQUEST_RETRY.as_secs()),
                );
            }
        }
        // The table is now full of exhausted entries: a new originator is
        // refused.
        assert!(
            b.build_cert_request(mac(200), [0; 8], mac(9), &mut buf)
                .is_none(),
            "table full of exhausted entries must refuse a new originator"
        );

        // Advancing the clock (any amount, since these entries never retry
        // again on their own) must reclaim the exhausted slots via the
        // periodic prune.
        b.set_time(
            b.now + Duration::from_secs(1),
            Clocked::At(b.now_unix() + 1),
        );
        assert!(
            b.build_cert_request(mac(200), [0; 8], mac(9), &mut buf)
                .is_some(),
            "a reclaimed slot must admit a new originator"
        );
    }

    /// Bug B (design 20 §2.2): reclaiming an exhausted in-flight slot is
    /// *elapsed*-time bookkeeping, so it must work on a node that has never
    /// had a wall clock — which is every bare-metal node.
    ///
    /// While the reclamation sat behind `prune_expired`'s `now_unix == 0`
    /// guard, the exact denial the `retain` exists to prevent was live on
    /// every board: `MAX_IN_FLIGHT_CERT_REQUESTS` targets that never answer
    /// pinned every slot permanently, blocking any further originator's cert
    /// fetch.
    #[test]
    fn in_flight_table_reclaims_exhausted_entries_without_a_clock() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[3; 32]);
        let cert = authority.issue_cert(mac(3), kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);
        let mut b = OgmAuth::new(kp, cert, authority.trust_anchor());
        // No wall clock, ever: the posture stays `Unknown`, as on a board.
        let mut mono = Duration::ZERO;
        b.set_time(mono, Clocked::Unknown);
        let mut buf = [0u8; 512];

        // Fill the table with originators that never answer, advancing them
        // in lockstep so every one exhausts its budget in the same round.
        for round in 0..MAX_CERT_REQUEST_ATTEMPTS {
            for n in 1..=MAX_IN_FLIGHT_CERT_REQUESTS as u8 {
                assert!(
                    b.build_cert_request(mac(n), [n; 8], mac(9), &mut buf)
                        .is_some(),
                    "an unclocked node must still be able to retry a cert fetch"
                );
            }
            if round + 1 < MAX_CERT_REQUEST_ATTEMPTS {
                mono += CERT_REQUEST_RETRY;
                b.set_time(mono, Clocked::Unknown);
            }
        }
        assert!(
            b.build_cert_request(mac(200), [0; 8], mac(9), &mut buf)
                .is_none(),
            "table full of exhausted entries must refuse a new originator"
        );

        mono += Duration::from_secs(1);
        b.set_time(mono, Clocked::Unknown);
        assert!(
            b.build_cert_request(mac(200), [0; 8], mac(9), &mut buf)
                .is_some(),
            "an unclocked node must still reclaim exhausted in-flight slots"
        );
    }

    /// The `CertReq` rate limit is a duration, so it is measured on the
    /// monotonic clock: a wall-clock step (an NTP correction, or the first
    /// real time reaching a node that booted without one) neither opens nor
    /// closes the window (design 20 §3(b)).
    #[test]
    fn cert_request_rate_limit_is_unaffected_by_a_wall_clock_step() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mono = Duration::from_secs(100);
        assert!(
            a.accept_cert_request_rate(mac(3)),
            "the first request from a requester is always accepted"
        );

        // A large wall-clock step with no elapsed time must not open the
        // window.
        a.set_time(mono, Clocked::At(100 + CERT_REQ_RATE_LIMIT.as_secs() * 10));
        assert!(
            !a.accept_cert_request_rate(mac(3)),
            "a wall-clock step must not open the rate-limit window"
        );

        // Real elapsed time does, even with the wall clock stepped backwards.
        a.set_time(mono + CERT_REQ_RATE_LIMIT, Clocked::Unknown);
        assert!(
            a.accept_cert_request_rate(mac(3)),
            "elapsed monotonic time must open the rate-limit window"
        );
    }

    /// A parked pending reply is visible via `has_pending_reply` until
    /// cleared.
    #[test]
    fn park_pending_reply_then_clear() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        assert!(!a.has_pending_reply(mac(3)));
        a.park_pending_reply(mac(3));
        assert!(a.has_pending_reply(mac(3)));
        a.clear_pending_reply(mac(3));
        assert!(!a.has_pending_reply(mac(3)));
    }

    /// A parked pending reply is evicted once its TTL elapses (garbage
    /// collected on the next clock advance, mirroring revocation GC).
    #[test]
    fn park_pending_reply_evicted_after_ttl() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        a.park_pending_reply(mac(3));
        assert!(a.has_pending_reply(mac(3)));
        a.set_time(
            a.now + PENDING_REPLY_TTL,
            Clocked::At(a.now_unix() + PENDING_REPLY_TTL.as_secs()),
        );
        assert!(
            !a.has_pending_reply(mac(3)),
            "a stale pending reply must be evicted after its TTL"
        );
    }

    /// Parking again for an already-parked requester refreshes its
    /// timestamp rather than adding a duplicate entry.
    #[test]
    fn park_pending_reply_refreshes_existing_entry() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        a.park_pending_reply(mac(3));
        a.set_time(
            a.now + PENDING_REPLY_TTL - Duration::from_secs(1),
            Clocked::At(a.now_unix() + PENDING_REPLY_TTL.as_secs() - 1),
        );
        a.park_pending_reply(mac(3)); // refresh before it would expire
        a.set_time(
            a.now + PENDING_REPLY_TTL - Duration::from_secs(1),
            Clocked::At(a.now_unix() + PENDING_REPLY_TTL.as_secs() - 1),
        );
        assert!(
            a.has_pending_reply(mac(3)),
            "the refreshed entry must not have expired yet"
        );
    }

    // ── Cert-distribution occupancy metrics (add-metric skill, Phase 6) ────

    /// The cert-store occupancy reports zero used against the neighbor-cache
    /// capacity before any neighbor cert has been cached.
    #[test]
    fn cert_store_occupancy_starts_empty() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let b = member(&authority, 3, mac(3), 1000);
        assert_eq!(b.cert_store_occupancy(), (0, MAX_NEIGHBOR_KEYS));
    }

    /// Caching a verified neighbor's cert (via a verified OGM) grows the
    /// cert-store occupancy by one.
    #[test]
    fn cert_store_occupancy_grows_with_cached_neighbor() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert_eq!(b.cert_store_occupancy(), (1, MAX_NEIGHBOR_KEYS));
    }

    /// The in-flight cert-request occupancy reports zero before any fetch is
    /// started.
    #[test]
    fn in_flight_cert_requests_occupancy_starts_empty() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let b = member(&authority, 3, mac(3), 1000);
        assert_eq!(
            b.in_flight_cert_requests_occupancy(),
            (0, MAX_IN_FLIGHT_CERT_REQUESTS)
        );
    }

    /// A successful `build_cert_request` grows the in-flight occupancy by one.
    #[test]
    fn in_flight_cert_requests_occupancy_grows_with_outstanding_fetch() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut buf = [0u8; 512];
        b.build_cert_request(mac(2), [0xAA; 8], mac(9), &mut buf)
            .expect("first request must be sent");
        assert_eq!(
            b.in_flight_cert_requests_occupancy(),
            (1, MAX_IN_FLIGHT_CERT_REQUESTS)
        );
    }

    /// The pending-reply (responder-side, parked) occupancy reports zero
    /// before any reply is parked.
    #[test]
    fn pending_cert_replies_occupancy_starts_empty() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let b = member(&authority, 3, mac(3), 1000);
        assert_eq!(b.pending_cert_replies_occupancy(), (0, MAX_PENDING_REPLIES));
    }

    /// Parking a reply grows the pending-reply occupancy by one.
    #[test]
    fn pending_cert_replies_occupancy_grows_with_parked_reply() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        a.park_pending_reply(mac(3));
        assert_eq!(a.pending_cert_replies_occupancy(), (1, MAX_PENDING_REPLIES));
    }

    // ── Capacity profiles ─────────────────────────────────────────────────

    /// A deliberately tiny profile for a constrained node: 8 neighbour keys,
    /// 4 revocations, 2 in-flight cert requests, 2 parked replies.
    type TinyAuth = OgmAuth<8, 4, 2, 2>;

    /// Today's host capacities, spelled out positionally.
    type HostAuth =
        OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>;

    /// Build a tiny-profile member, mirroring [`member`].
    fn tiny_member(authority: &Authority, seed: u8, m: Mac, valid_to: u64) -> TinyAuth {
        let kp = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), 0, valid_to);
        let mut auth = TinyAuth::with_capacities(kp, cert, authority.trust_anchor());
        auth.set_time(Duration::from_secs(100), Clocked::At(100));
        auth
    }

    /// The new parameters must default to today's values, so every existing
    /// `OgmAuth::new` call site keeps its current sizing.
    #[test]
    fn auth_defaults_preserve_todays_capacities() {
        assert_eq!(
            core::mem::size_of::<OgmAuth>(),
            core::mem::size_of::<HostAuth>()
        );
    }

    /// The point of the exercise: a small profile must actually reclaim RAM.
    /// `neighbors` alone is 64 x 272 bytes at host capacity.
    #[test]
    fn tiny_auth_profile_is_substantially_smaller() {
        let tiny = core::mem::size_of::<TinyAuth>();
        let host = core::mem::size_of::<HostAuth>();
        assert!(
            tiny * 4 < host,
            "tiny profile ({tiny} B) should be well under a quarter of host ({host} B)"
        );
    }

    /// Every occupancy metric must report *this* profile's capacity as its
    /// denominator, so an embedded node's cert-store gauge reads `n/8` rather
    /// than the host's `n/64`.
    #[test]
    fn auth_occupancy_denominators_follow_the_profile() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let b = tiny_member(&authority, 3, mac(3), 1000);

        assert_eq!(b.cert_store_occupancy(), (0, 8));
        assert_eq!(b.in_flight_cert_requests_occupancy(), (0, 2));
        assert_eq!(b.pending_cert_replies_occupancy(), (0, 2));
    }

    /// The neighbour cache evicts at the profile's bound, not the crate
    /// default of 64 — otherwise a tiny profile would overflow its own table.
    #[test]
    fn tiny_profile_neighbor_cache_evicts_at_its_own_bound() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = tiny_member(&authority, 100, mac(100), 1_000_000);

        for n in 1..=8u8 {
            let mut a = member(&authority, n, mac(n), 1_000_000);
            let (mut buf, len) = bare_ogm(mac(n), 1);
            let len = a.augment_ogm(&mut buf, len).unwrap();
            assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        }
        assert_eq!(
            b.neighbors().len(),
            8,
            "table saturates at the profile bound"
        );
        assert_eq!(b.cert_store_occupancy(), (8, 8));

        // A ninth distinct originator evicts rather than overflowing.
        let mut over = member(&authority, 200, mac(200), 1_000_000);
        let (mut buf, len) = bare_ogm(mac(200), 1);
        let len = over.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        assert_eq!(b.neighbors().len(), 8);
    }

    /// Capacity is a purely local memory decision: a host-profile node's OGM
    /// must still verify at a tiny-profile peer, and vice versa. If this ever
    /// fails, a profile has leaked into the wire format.
    #[test]
    fn profiles_do_not_change_the_wire_format() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut host = member(&authority, 2, mac(2), 1000);
        let mut tiny = tiny_member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = host.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(tiny.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let (mut buf, len) = bare_ogm(mac(3), 7);
        let len = tiny.augment_ogm(&mut buf, len).expect("augment");
        assert_eq!(host.verify_ogm(&buf[..len]), OgmVerdict::Verified);
    }

    // --- next-hop proof: challenge/response (gaps 1 + 2) -----------------
    //
    // See `docs/design/implemented/09-mesh-auth-gaps.md` §4. An OGM's signature
    // attests its *originator*; nothing attests the *forwarder*, so a next hop
    // is installed on the strength of possessing bytes anyone can copy. These
    // primitives are the proof that possession is not enough: the challenger
    // picks a fresh nonce, and only a node holding the pairwise key for the MAC
    // it claims can answer.

    /// The round trip a proven next hop rests on: `b` challenges `a`, `a`
    /// answers with the pairwise key both derived from each other's certs,
    /// and `b` accepts.
    #[test]
    fn a_challenge_response_round_trip_succeeds() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let nonce = b.issue_challenge(mac(2)).expect("a is a live neighbor");
        let response = a.answer_challenge(mac(3), &nonce).expect("b is live too");

        assert!(
            b.verify_challenge_response(mac(2), &response),
            "the holder of a's key answered b's own nonce"
        );
    }

    /// Tag `frame` for `dst` as `sender` would put it on the wire, returning
    /// the directed trailer. Panics if `sender` cannot tag — every caller here
    /// has already admitted `dst`.
    fn directed_trailer(
        sender: &mut OgmAuth,
        dst: Mac,
        frame: &[u8],
    ) -> [u8; DIRECTED_TRAILER_LEN] {
        let mut trailer = [0u8; DIRECTED_TRAILER_LEN];
        let len = sender
            .tag_directed(dst, frame, &mut trailer)
            .expect("dst is an admitted neighbour");
        assert_eq!(len, DIRECTED_TRAILER_LEN);
        trailer
    }

    /// A next-hop proof response as it appears on the wire: the sub-type byte
    /// the classifier reads, then the tag answering the nonce. Built here
    /// rather than passing the bare tag, because the sub-type is what earns
    /// the frame its counter exemption — a test that omits it is not
    /// exercising the path the router takes.
    fn proof_response_frame(tag: &[u8; TAG_LEN]) -> Vec<u8> {
        let mut frame = vec![BatmanPacketType::NextHopResponse.as_u8()];
        frame.extend_from_slice(tag);
        frame
    }

    /// Run `sender`'s directed send counter up, accepting each frame at
    /// `receiver`, so the receiver's replay high-water is where a long-running
    /// peer's would be rather than where a freshly converged fixture leaves it.
    fn run_up_counter(sender: &mut OgmAuth, sender_mac: Mac, receiver: &mut OgmAuth, dst: Mac) {
        for _ in 0..64 {
            let trailer = directed_trailer(sender, dst, b"traffic");
            assert!(receiver.verify_directed(sender_mac, b"traffic", &trailer));
        }
    }

    /// A peer that reboots keeps its identity but not its send counter, so its
    /// whole directed data plane lands behind the high-water a peer that stayed
    /// up still holds for it. The next-hop proof is what gets it out — and the
    /// proof frames are directed frames themselves, so before this the guard
    /// refused the very exchange that would have cleared it, leaving a member
    /// visible in the routing table (OGMs carry no pairwise tag) and permanently
    /// unroutable.
    #[test]
    fn a_rebooted_peer_regains_its_directed_data_plane_by_proving_itself() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        run_up_counter(&mut a, mac(2), &mut b, mac(3));

        // `a` reboots: same seed, same certificate, a send counter back at zero.
        let mut a = member(&authority, 2, mac(2), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let trailer = directed_trailer(&mut a, mac(3), b"morning");
        assert!(
            !b.verify_directed(mac(2), b"morning", &trailer),
            "the guard cannot tell a restart from a replay, and refuses on purpose"
        );

        // The proof exchange is the way out: its freshness is b's own nonce.
        let nonce = b.issue_challenge(mac(2)).expect("a is a live neighbour");
        let response = a.answer_challenge(mac(3), &nonce).expect("b is live too");
        let frame = proof_response_frame(&response);
        let trailer = directed_trailer(&mut a, mac(3), &frame);
        assert!(
            b.verify_directed_nonce_fresh(mac(2), &frame, &trailer),
            "a proof response behind the high-water is held for its nonce, not dropped"
        );
        assert!(
            b.verify_challenge_response(mac(2), &response),
            "the nonce b issued is answered under the pairwise key"
        );

        let trailer = directed_trailer(&mut a, mac(3), b"morning");
        assert!(
            b.verify_directed(mac(2), b"morning", &trailer),
            "proving liveness re-anchors the sequence, so ordinary traffic flows again"
        );
    }

    /// The exemption is scoped by the *sub-type*, and this method is `pub`, so
    /// it must refuse to apply that scope to anything else — whatever its
    /// caller believes. A `Unicast` handed to it takes the ordinary guard and
    /// its stale counter is refused, even with a challenge outstanding (which
    /// is the only other thing that gates the restart path).
    #[test]
    fn the_nonce_exemption_does_not_extend_to_a_non_proof_frame() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let unicast = [BatmanPacketType::Unicast.as_u8(), 0xff];
        let captured = directed_trailer(&mut a, mac(3), &unicast);
        run_up_counter(&mut a, mac(2), &mut b, mac(3));
        // Outstanding, so the restart gate is open and the sub-type is the only
        // thing left standing between this frame and the exemption.
        let _ = b.issue_challenge(mac(2)).expect("live neighbour");

        assert!(
            !b.verify_directed_nonce_fresh(mac(2), &unicast, &captured),
            "only a next-hop proof response may skip the replay counter"
        );
    }

    /// A restart claim is evidence, and evidence has to be authenticated. A
    /// forged or corrupted tag must neither create a claim nor disturb one
    /// already standing — otherwise an attacker with no pairwise key could name
    /// the counter the guard is rewound to.
    #[test]
    fn a_forged_tag_neither_creates_nor_disturbs_a_restart_claim() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        run_up_counter(&mut a, mac(2), &mut b, mac(3));

        let mut a = member(&authority, 2, mac(2), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        let nonce = b.issue_challenge(mac(2)).expect("live neighbour");
        let response = a.answer_challenge(mac(3), &nonce).expect("live neighbour");
        let frame = proof_response_frame(&response);

        let mut forged = directed_trailer(&mut a, mac(3), &frame);
        forged[DIRECTED_TRAILER_LEN - 1] ^= 0xFF;
        assert!(
            !b.verify_directed_nonce_fresh(mac(2), &frame, &forged),
            "a tag that does not verify proves nothing about a restart"
        );

        // The nonce answer inside is genuine, so the proof itself still
        // succeeds — `verify_challenge_response` judges the nonce, not the
        // frame that carried it. What must not follow is a re-anchor: the
        // forged frame raised no claim, so there is nothing to redeem.
        assert!(
            b.verify_challenge_response(mac(2), &response),
            "the nonce was answered under the pairwise key"
        );

        let trailer = directed_trailer(&mut a, mac(3), b"data");
        assert!(
            !b.verify_directed(mac(2), b"data", &trailer),
            "no authenticated frame ever named a restart, so the guard is \
             exactly where it was and the peer must answer properly to recover"
        );
    }

    /// A stale counter is only evidence of a restart while this node is
    /// actually mid-exchange with that peer. Outside one there is nothing the
    /// claim could ever be redeemed against, so recording it would just let any
    /// admitted member park a value in the single claim slot by replaying a
    /// captured response.
    #[test]
    fn a_stale_counter_response_with_no_challenge_outstanding_is_refused() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let nonce = b.issue_challenge(mac(2)).expect("live neighbour");
        let response = a.answer_challenge(mac(3), &nonce).expect("live neighbour");
        let frame = proof_response_frame(&response);
        let captured = directed_trailer(&mut a, mac(3), &frame);
        // Consume the outstanding challenge, then outrun the captured frame.
        assert!(b.verify_directed_nonce_fresh(mac(2), &frame, &captured));
        assert!(b.verify_challenge_response(mac(2), &response));
        run_up_counter(&mut a, mac(2), &mut b, mac(3));

        assert!(
            !b.verify_directed_nonce_fresh(mac(2), &frame, &captured),
            "nothing is outstanding, so a stale-counter response is just a replay"
        );
    }

    /// The recovery is deliberately **asymmetric** and it is easy to "tidy" the
    /// asymmetry away. `NextHopChallenge` keeps the full replay guard, so a
    /// rebooted node cannot challenge its way back in — the peer that stayed up
    /// has to challenge *it* first. This pins that direction: symmetrising the
    /// two sub-types would restore the replay-a-captured-challenge primitive
    /// and every other test here would stay green.
    #[test]
    fn a_rebooted_peer_cannot_challenge_its_way_out_only_answer() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        run_up_counter(&mut a, mac(2), &mut b, mac(3));

        let mut a = member(&authority, 2, mac(2), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let nonce = a.issue_challenge(mac(3)).expect("b is a live neighbour");
        let mut challenge = vec![BatmanPacketType::NextHopChallenge.as_u8()];
        challenge.extend_from_slice(&nonce);
        let trailer = directed_trailer(&mut a, mac(3), &challenge);
        assert!(
            !b.verify_directed(mac(2), &challenge, &trailer),
            "the reborn node's own challenge stays behind the replay guard"
        );

        // Recovery therefore has to start from `b`, and once it does the
        // reborn node's challenges get through on the re-anchored sequence.
        let nonce = b.issue_challenge(mac(2)).expect("live neighbour");
        let response = a.answer_challenge(mac(3), &nonce).expect("live neighbour");
        let frame = proof_response_frame(&response);
        let rsp_trailer = directed_trailer(&mut a, mac(3), &frame);
        assert!(b.verify_directed_nonce_fresh(mac(2), &frame, &rsp_trailer));
        assert!(b.verify_challenge_response(mac(2), &response));

        let trailer = directed_trailer(&mut a, mac(3), &challenge);
        assert!(
            b.verify_directed(mac(2), &challenge, &trailer),
            "after the re-anchor the reborn node can challenge in its turn"
        );
    }

    /// A claim is consumed by the next `verify_challenge_response` whatever that
    /// call decides, so a response that fails its nonce cannot leave one
    /// standing to be redeemed by a *later*, unrelated round — which would
    /// rewind the guard to a counter an attacker chose, long after the frame
    /// that named it.
    #[test]
    fn a_failed_nonce_leaves_no_claim_for_a_later_round_to_redeem() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        run_up_counter(&mut a, mac(2), &mut b, mac(3));

        // A reboot, and a response to a challenge that is outstanding — but
        // answered under the wrong nonce, so the proof fails. Its frame spends
        // the reborn peer's counter 1, which is what a leaked claim would
        // later rewind the guard to.
        let mut a = member(&authority, 2, mac(2), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        let _ = b.issue_challenge(mac(2)).expect("live neighbour");
        let wrong = a
            .answer_challenge(mac(3), &[0xAA; CHALLENGE_NONCE_LEN])
            .expect("live neighbour");
        let frame = proof_response_frame(&wrong);
        let trailer = directed_trailer(&mut a, mac(3), &frame);
        assert!(b.verify_directed_nonce_fresh(mac(2), &frame, &trailer));
        assert!(
            !b.verify_challenge_response(mac(2), &wrong),
            "the nonce does not match the outstanding challenge"
        );

        // Counter 2, tagged after the failed round and before the genuine one.
        // It is the probe: it sits above the counter the failed round named and
        // below the counter the genuine one will anchor to.
        let between = directed_trailer(&mut a, mac(3), b"between");

        // A genuine round now completes, on counter 3. It must anchor on its
        // *own* counter, not on the claim the failed round raised.
        let nonce = b.issue_challenge(mac(2)).expect("live neighbour");
        let response = a.answer_challenge(mac(3), &nonce).expect("live neighbour");
        let frame = proof_response_frame(&response);
        let trailer = directed_trailer(&mut a, mac(3), &frame);
        assert!(b.verify_directed_nonce_fresh(mac(2), &frame, &trailer));
        assert!(b.verify_challenge_response(mac(2), &response));

        assert!(
            !b.verify_directed(mac(2), b"between", &between),
            "the guard anchored to the proving frame's own counter; had the \
             failed round's claim been redeemed instead it would sit lower and \
             admit this"
        );
    }

    /// The re-anchor is not a periodic hole. A settled mesh re-proves every path
    /// neighbour about once per emission interval, so if a successful proof
    /// round reset the guard, every neighbour's replay window would reopen on a
    /// timer. An in-sequence proof response spends its counter like any other
    /// directed frame and leaves the high-water where it found it.
    #[test]
    fn a_steady_state_proof_round_does_not_reset_the_replay_guard() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        // A frame an attacker captures off the medium, then lets `a` outrun.
        let captured = directed_trailer(&mut a, mac(3), b"captured");
        run_up_counter(&mut a, mac(2), &mut b, mac(3));

        let nonce = b.issue_challenge(mac(2)).expect("live neighbour");
        let response = a.answer_challenge(mac(3), &nonce).expect("live neighbour");
        let frame = proof_response_frame(&response);
        let trailer = directed_trailer(&mut a, mac(3), &frame);
        assert!(b.verify_directed_nonce_fresh(mac(2), &frame, &trailer));
        assert!(b.verify_challenge_response(mac(2), &response));

        assert!(
            !b.verify_directed(mac(2), b"captured", &captured),
            "an ordinary proof round must leave the replay high-water alone"
        );
    }

    /// The nonce is what authorises the re-anchor, so a response that fails it
    /// must not move the high-water — otherwise tolerating the stale counter at
    /// the tag layer would hand back exactly the reset it exists to gate.
    #[test]
    fn a_proof_response_that_fails_its_nonce_does_not_re_anchor() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        run_up_counter(&mut a, mac(2), &mut b, mac(3));

        // One genuine round, which consumes b's outstanding challenge.
        let nonce = b.issue_challenge(mac(2)).expect("live neighbour");
        let spent = a.answer_challenge(mac(3), &nonce).expect("live neighbour");
        let frame = proof_response_frame(&spent);
        let trailer = directed_trailer(&mut a, mac(3), &frame);
        assert!(b.verify_directed_nonce_fresh(mac(2), &frame, &trailer));
        assert!(b.verify_challenge_response(mac(2), &spent));

        // `a` reboots, then answers the nonce that is already spent.
        let mut a = member(&authority, 2, mac(2), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        let stale = a.answer_challenge(mac(3), &nonce).expect("live neighbour");
        let frame = proof_response_frame(&stale);
        let trailer = directed_trailer(&mut a, mac(3), &frame);
        // Refused at the tag layer now, not merely unredeemed: with the spent
        // nonce there is no challenge outstanding, so a stale-counter response
        // is indistinguishable from a replay and raises no claim at all.
        assert!(
            !b.verify_directed_nonce_fresh(mac(2), &frame, &trailer),
            "a stale-counter response with nothing outstanding is just a replay"
        );
        assert!(
            !b.verify_challenge_response(mac(2), &stale),
            "nothing is outstanding: that nonce was already answered"
        );

        let trailer = directed_trailer(&mut a, mac(3), b"data");
        assert!(
            !b.verify_directed(mac(2), b"data", &trailer),
            "an unproven restart claim must leave the guard exactly where it was"
        );
    }

    /// The property the whole fix rests on. A captured response is worthless
    /// against the next challenge, because the nonce is fresh and the
    /// *challenger* chose it — unlike the OGM signature, which is a public
    /// authenticator over static content and so replays forever.
    #[test]
    fn a_captured_response_does_not_answer_a_fresh_challenge() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let nonce = b.issue_challenge(mac(2)).expect("live neighbor");
        let captured = a.answer_challenge(mac(3), &nonce).expect("live neighbor");
        assert!(b.verify_challenge_response(mac(2), &captured));

        // A later round: same parties, same keys, new nonce.
        let _ = b.issue_challenge(mac(2)).expect("live neighbor");
        assert!(
            !b.verify_challenge_response(mac(2), &captured),
            "a replayed response must not satisfy a fresh challenge"
        );
    }

    /// A response is only meaningful once. Accepting the same one twice would
    /// let an attacker who observed one exchange keep a route alive without
    /// the neighbor participating again.
    #[test]
    fn a_response_is_consumed_and_cannot_be_reused() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let nonce = b.issue_challenge(mac(2)).expect("live neighbor");
        let response = a.answer_challenge(mac(3), &nonce).expect("live neighbor");

        assert!(b.verify_challenge_response(mac(2), &response));
        assert!(
            !b.verify_challenge_response(mac(2), &response),
            "the outstanding challenge is consumed on the first acceptance"
        );
    }

    /// The pairwise key is what is actually being proven. A third member
    /// answering in `a`'s name holds a perfectly valid credential — and still
    /// cannot produce `a`'s tag, because the key is (a, b)-specific.
    #[test]
    fn another_member_cannot_answer_in_a_neighbors_name() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut c = member(&authority, 4, mac(4), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        admit_each_other(&mut c, mac(4), &mut b, mac(3));

        let nonce = b.issue_challenge(mac(2)).expect("a is a live neighbor");
        let forged = c.answer_challenge(mac(3), &nonce).expect("c is live too");

        assert!(
            !b.verify_challenge_response(mac(2), &forged),
            "c's tag must not pass as a's, however valid c's own credential"
        );
    }

    /// Answering a nonce the challenger never issued proves nothing.
    #[test]
    fn a_response_over_an_unissued_nonce_is_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let _ = b.issue_challenge(mac(2)).expect("live neighbor");
        let response = a
            .answer_challenge(mac(3), &[0xAA; CHALLENGE_NONCE_LEN])
            .expect("live neighbor");

        assert!(
            !b.verify_challenge_response(mac(2), &response),
            "the response must be over the challenger's own nonce"
        );
    }

    /// Nothing outstanding means nothing to accept — an unsolicited response
    /// must never promote a next hop.
    #[test]
    fn a_response_with_no_outstanding_challenge_is_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let response = a
            .answer_challenge(mac(3), &[0x11; CHALLENGE_NONCE_LEN])
            .expect("live neighbor");

        assert!(
            !b.verify_challenge_response(mac(2), &response),
            "b issued no challenge to a"
        );
    }

    /// A nonce must never repeat, or a response captured in an earlier round
    /// would answer a later one.
    #[test]
    fn successive_challenges_to_one_neighbor_never_repeat_a_nonce() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        let mut seen: heapless::Vec<[u8; CHALLENGE_NONCE_LEN], 16> = heapless::Vec::new();
        for _ in 0..16 {
            let nonce = b.issue_challenge(mac(2)).expect("live neighbor");
            assert!(!seen.contains(&nonce), "nonce repeated within one session");
            seen.push(nonce).expect("capacity");
        }
    }

    /// Two neighbors challenged in the same round get different nonces, so a
    /// response to one is not a response to the other.
    #[test]
    fn challenges_to_different_neighbors_differ() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut c = member(&authority, 4, mac(4), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        admit_each_other(&mut c, mac(4), &mut b, mac(3));

        let to_a = b.issue_challenge(mac(2)).expect("live neighbor");
        let to_c = b.issue_challenge(mac(4)).expect("live neighbor");
        assert_ne!(to_a, to_c);
    }

    /// The nonce is a PRF keyed by the challenger's *own* secret, not a
    /// counter anyone can follow: two nodes at the same point in their
    /// challenge sequence, challenging the same neighbor, must not produce the
    /// same nonce. Without this an attacker could pre-fetch a response for a
    /// nonce it knows is coming.
    #[test]
    fn two_challengers_derive_different_nonces_for_the_same_neighbor() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        let mut c = member(&authority, 4, mac(4), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        admit_each_other(&mut a, mac(2), &mut c, mac(4));

        let from_b = b.issue_challenge(mac(2)).expect("live neighbor");
        let from_c = c.issue_challenge(mac(2)).expect("live neighbor");
        assert_ne!(
            from_b, from_c,
            "the nonce must depend on the challenger's own key material"
        );
    }

    /// Fails closed for a peer we hold no verified key for — there is nobody
    /// to challenge, and no key to check an answer against.
    #[test]
    fn a_challenge_to_an_unverified_peer_fails_closed() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        assert!(
            b.issue_challenge(mac(2)).is_none(),
            "no verified neighbor, no challenge"
        );
        assert!(
            b.answer_challenge(mac(2), &[0x22; CHALLENGE_NONCE_LEN])
                .is_none(),
            "nor can we answer one from an unverified peer"
        );
    }

    /// A malformed (wrong-length) nonce is rejected explicitly rather than
    /// silently tagged as-is: `verify_challenge_response` already validates
    /// its `tag` argument the same way, so a challenge whose nonce was
    /// truncated or padded in transit gets the same treatment as a malformed
    /// response, not a silent pass-through.
    #[test]
    fn a_challenge_with_a_malformed_nonce_is_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));

        assert!(
            a.answer_challenge(mac(3), &[0xAA; CHALLENGE_NONCE_LEN - 1])
                .is_none(),
            "a short nonce must be rejected, not answered anyway"
        );
        assert!(
            a.answer_challenge(mac(3), &[0xAA; CHALLENGE_NONCE_LEN + 1])
                .is_none(),
            "an over-long nonce must be rejected, not answered anyway"
        );
    }

    /// Expiry is passive revocation (gap 3): a lapsed neighbor is not a
    /// challengeable one, on the same `live_neighbor` rule every other
    /// pairwise lookup goes through.
    #[test]
    fn a_challenge_to_an_expired_neighbor_fails_closed() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        admit_each_other(&mut a, mac(2), &mut b, mac(3));
        assert!(b.issue_challenge(mac(2)).is_some(), "live while valid");

        b.set_time(Duration::from_secs(2000), Clocked::At(2000));
        assert!(
            b.issue_challenge(mac(2)).is_none(),
            "an expired neighbor must not be challengeable"
        );
    }

    /// The in-progress table is bounded, and evicts the least-recently-issued
    /// rather than refusing new challenges: failing closed on a full table
    /// would let a churn of candidate next hops lock out proof of a
    /// legitimate one.
    ///
    /// Two details of the setup exist to keep this test honest at any
    /// [`MAX_IN_PROGRESS_PROOF`], including one raised to
    /// [`MAX_NEIGHBOR_KEYS`]. Both were silent breakages the last time the
    /// constant moved:
    ///
    /// - Each neighbor is challenged as soon as it is admitted, rather than
    ///   admitting all of them first. Once the two capacities are equal,
    ///   admitting one past the neighbor cache evicts the oldest cached
    ///   neighbor, and [`issue_challenge`](OgmAuth::issue_challenge) fails
    ///   closed on a neighbor it can no longer look up — so a challenge
    ///   deferred until after the last admission would never be issued at all.
    /// - Only the last peer is kept alive. An [`OgmAuth`] carries its whole
    ///   neighbor cache inline, so holding one per slot overflows a test
    ///   thread's stack well before the capacities meet.
    #[test]
    fn the_in_progress_table_evicts_least_recently_issued_when_full() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        // Fill the table, oldest first: one challenge per slot, each issued
        // while its neighbor is still cached.
        for i in 0..MAX_IN_PROGRESS_PROOF {
            let m = mac(10 + i as u8);
            let mut peer = member(&authority, 10 + i as u8, m, 1000);
            admit_each_other(&mut peer, m, &mut b, mac(3));
            assert!(b.issue_challenge(m).is_some());
        }

        // One more must be admitted, evicting the oldest outstanding challenge.
        let seed = 10 + MAX_IN_PROGRESS_PROOF as u8;
        let last = mac(seed);
        let mut last_peer = member(&authority, seed, last, 1000);
        admit_each_other(&mut last_peer, last, &mut b, mac(3));
        let nonce = b
            .issue_challenge(last)
            .expect("a new challenge must never be refused for want of room");

        let response = last_peer
            .answer_challenge(mac(3), &nonce)
            .expect("live neighbor");
        assert!(
            b.verify_challenge_response(last, &response),
            "the newest challenge is the one that survives"
        );
    }
}
