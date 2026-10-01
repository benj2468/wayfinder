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
//! # The map
//!
//! OGM authentication is where this module started and is no longer all it is:
//! it owns the node's whole **credential-control plane**, and builds those
//! frames itself rather than leaving the router to assemble them. One file per
//! exchange, each with its tests alongside:
//!
//! - `ogm.rs` — the OGM/keep-alive TVLV envelope, the only part that speaks
//!   `batman::wire`'s TVLV helpers.
//! - `pairwise.rs` — the neighbour key cache and the directed/fan-out data-plane
//!   authenticator, plus the replay counters both ride.
//! - `revocation.rs` — ingesting records, shunning their subjects, and the
//!   self-revocation held for the router to act on.
//! - `proof.rs` — next-hop challenge/response (design 09).
//! - `distribution.rs` — the `CertReq`/`CertReply` fetch (design 01).
//! - `renewal.rs` — the `RenewReq`/`RenewReply` exchange (design 24).
//! - `paths.rs` — the read-only view of routing state the three frame-building
//!   modules borrow to *address* what they build.
//!
//! The router lends a [`Paths`] view and is otherwise one delegation per verb.
//! **A new exchange belongs here, not in `CentralRouter`.**
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

/// Domain-separation prefix for a `RenewReq`'s self-authenticating signature,
/// over `authority_mac ‖ requester_mac ‖ nonce`.
///
/// Distinct from [`CERT_REQ_SIG_DOMAIN`] rather than sharing it, and the
/// separation is the same one the two exchanges need everywhere else: a
/// verified cert-request body means "I am a member, give me your cert" and a
/// verified renewal body means "I am this member, give me a new one for me". A
/// signature that satisfied both would let a captured `CertReq` be presented to
/// an authority as a renewal.
const RENEW_REQ_SIG_DOMAIN: &[u8] = b"wf-renewreq-sig-v1";

/// Domain-separation prefix for the PRF that draws a renewal request's nonce.
///
/// The same counter and the same key as the next-hop challenge nonce (design 24
/// §9.2 decides to reuse the source rather than add a second one), separated by
/// this domain so a nonce drawn for one purpose can never collide with one
/// drawn for the other.
const RENEW_NONCE_PRF_DOMAIN: &[u8] = b"wf-renew-nonce-v1";

/// Length of a renewal request's nonce: the PRF's output width.
pub const RENEWAL_NONCE_LEN: usize = TAG_LEN;

/// How long a renewal request stays outstanding before this node stops
/// treating a reply as answering it.
///
/// Two renewal poll intervals' worth. A reply travels a handful of mesh hops,
/// so anything that has not arrived within two whole poll cycles was not an
/// answer to this ask — and leaving the slot open past that would let a
/// certificate arriving arbitrarily later be accepted as though it had been
/// asked for.
///
/// Derived from [`RENEWAL_POLL_INTERVAL`] rather than spelled out, which it
/// could not be while that constant lived a layer up in the router.
///
/// Measured on the monotonic clock — see [`CERT_REQUEST_RETRY`].
const OUTSTANDING_RENEWAL_TTL: Duration = RENEWAL_POLL_INTERVAL.saturating_mul(2);

/// Minimum spacing between `RenewReq`s an authority will act on from the same
/// requester.
///
/// **Renewal's own budget, not [`CERT_REQ_RATE_LIMIT`]'s.** The two exchanges
/// mean different things and cost the authority different amounts, and a
/// limiter they shared would let a burst of lazy-distribution fetches deny a
/// member's genuine renewal — or the reverse.
///
/// Far longer than the cert-request limit because the traffic is: a certificate
/// is renewed a handful of times per lifetime, where a fingerprint miss can
/// recur whenever a peer rotates. A minute still leaves a board inside a
/// ~42-hour renewal window (at the 7-day lifetime `wayfinder-ca` issues) with
/// more retries than it can possibly need, while bounding what one member can
/// make an authority spend. Measured on the monotonic clock — see
/// [`CERT_REQUEST_RETRY`].
const RENEW_REQ_RATE_LIMIT: Duration = Duration::from_secs(60);

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

/// What a verified `RenewReq` body proves, and nothing more.
///
/// The **decision-free fact** design 24 §4.3 has the router surface to the
/// driver: an identity whose certificate chained to this mesh's anchor, which
/// is not revoked, and which proved possession of the key that certificate
/// names. Whether it is still a live holder — the re-issue rule — is the
/// authority's question, asked on the authority's own task, and nothing here
/// answers it.
///
/// The keys come from the *certificate*, never from anything the requester
/// could name independently: the authority re-issues for the identity it was
/// handed, so a field a requester could choose would be a field the authority
/// has to decide whether to trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRenewal {
    /// The requester's mesh address, as its certificate names it.
    pub mac: Mac,
    /// Its verified Ed25519 identity key — the key the re-issued certificate
    /// must name, and the one whose possession was just proved.
    pub ed_pubkey: [u8; 32],
    /// Its verified X25519 agreement key.
    pub x_pubkey: [u8; 32],
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

/// Constructor for the default capacities.
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
/// scale for RAM: the neighbour cache alone is 64 × 360 bytes at host
/// capacities. All four parameters default to the module constants of the same
/// name, so `OgmAuth::new` keeps exactly the sizing it had before they existed.
///
/// Capacity is a purely **local** memory decision — it never reaches the wire,
/// so a default-profile node and a tiny-profile node interoperate unchanged.
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
    /// Smoothed rate at which this node sends `CertReq` (lazy-cert-distribution
    /// fetches, as a requester with an unresolved fingerprint).
    ///
    /// Here rather than on the router because this is where the frame is built,
    /// and a counter that lives away from its own emission point is a counter
    /// that drifts. Still satisfies the root `CLAUDE.md`'s rule that metric
    /// state lives in the `no_std` core: `OgmAuth` *is* the core.
    ///
    /// **Carried across a re-auth**, unlike everything else in this struct —
    /// see [`adopt_control_rates`](Self::adopt_control_rates). What this counts
    /// is frames *this node* put on the wire, which a new certificate does not
    /// undo.
    cert_req_tx_rate: crate::RateEstimator,
    /// Smoothed rate at which this node sends `CertReply` (answering a
    /// `CertReq`, as the originator whose cert was asked for) — either
    /// immediately or via the opportunistic parked-reply flush.
    ///
    /// Carried across a re-auth, like
    /// [`cert_req_tx_rate`](Self::cert_req_tx_rate).
    cert_reply_tx_rate: crate::RateEstimator,
    /// The mesh address of the certificate authority this node renews against,
    /// or `None` when its credential was installed without one.
    ///
    /// A [`Mac`], not a socket address, and that is the whole of what design 24
    /// changes about renewal: a board has no IP stack to open a client
    /// connection with, but it is a routing member of the mesh and the
    /// authority is a mesh node too, so it already has the one thing renewal
    /// needs — a path. The host's `RenewalProviderData` still carries the
    /// address it dials; this is the same record's other half.
    ///
    /// Installed by the `SetAuth` that certified this node and replaced by
    /// every subsequent one, never read from configuration. A node moved
    /// between providers renews against the one it now belongs to, and one
    /// whose credential named no provider renews nowhere rather than reaching
    /// back to an authority it may have left.
    ///
    /// **Not a trust input.** A `RenewReply` is a certificate, and a
    /// certificate that does not verify against the held trust anchor is
    /// discarded whatever MAC it arrived from. This is a routing hint.
    renewal_authority: Option<Mac>,
    /// The monotonic instant this node last put a renewal request on the wire,
    /// or `None` when it has not asked or has already been answered.
    ///
    /// One slot: a node renews *itself*, so there is exactly one conversation
    /// to have, and a second ask replaces the first.
    ///
    /// **The instant, not the nonce.** Storing the nonce would suggest the
    /// reply is matched against it, and it is not: a `RenewReply` body is a
    /// bare certificate with no nonce echoed back, so there is nothing to
    /// compare. What this slot gates is whether *any* request is outstanding —
    /// which is the same rule `ingest_cert_reply` applies, and enough, because
    /// the reply must also chain to the trust anchor, name this node, and move
    /// both ends of the window forward.
    ///
    /// Keeping the instant buys the one thing a bare flag could not: the slot
    /// **expires**. Without that, a board partitioned from its authority stays
    /// "outstanding" for the rest of its boot after a single ask, and the rule
    /// degrades from "answers a request of mine" to "I have asked at least once
    /// since power-on". See [`OUTSTANDING_RENEWAL_TTL`].
    outstanding_renewal: Option<Duration>,
    /// Per-requester last-accepted-`RenewReq` monotonic instant (authority-side
    /// rate limit), keyed by requester MAC. Separate from
    /// [`cert_req_rate`](Self::cert_req_rate) so the two exchanges cannot
    /// exhaust each other's budget; see [`RENEW_REQ_RATE_LIMIT`].
    renew_req_rate: HVec<(Mac, Duration), MAX_NEIGHBOR_KEYS>,
    /// A renewed certificate installed here and not yet made durable by the
    /// shell.
    ///
    /// This state can change the credential the node runs under; it cannot
    /// write flash or a file. The split is the one
    /// `CentralRouter::pending_self_revocation` makes: the reaction the
    /// `no_std` core *can* perform happens immediately, and the rest is handed
    /// out through here for whoever owns the medium. A shell that never drains
    /// it leaves a board running under a certificate it loses at the next
    /// reset — the failure design 22 exists to prevent.
    pending_renewed_cert: Option<MembershipCert>,
    /// Renewal requests this node has put on the wire since boot.
    ///
    /// Counted here rather than in a driver, per the root `CLAUDE.md`: a board
    /// has no `wayfinder-driver`, so a driver-side counter would not exist on
    /// the hardware this is for. The *gap* between this and
    /// [`renewal_replies_accepted`](Self::renewal_replies_accepted) is the
    /// signal (design 24 §7) — asking and not being answered is the failure
    /// mode, and neither number alone shows it.
    renewal_requests_sent: u64,
    /// Re-issued certificates this node has accepted and installed.
    renewal_replies_accepted: u64,
    /// Monotonic instant the next renewal poll is due.
    ///
    /// Advanced by [`poll_renewal`](Self::poll_renewal) *whatever it decides*,
    /// including on the paths that emit nothing: a shell that sleeps on
    /// [`next_renewal_after`](Self::next_renewal_after) and then finds the
    /// deadline still due would spin. Starts at zero so a node's first poll
    /// happens on its first turn, matching the host renewer's "the first turn
    /// evaluates".
    ///
    /// Here rather than on the router, because the cadence is a property of
    /// the exchange and not of routing — the same reason
    /// [`outstanding_renewal`](Self::outstanding_renewal) and
    /// [`renew_req_rate`](Self::renew_req_rate) are here.
    next_renewal_poll: Duration,
    /// A verified `RenewReq` awaiting collection by the driver, which is the
    /// only layer that can reach the certificate authority (design 13 put it on
    /// its own task, off the router loop).
    ///
    /// **One slot, and a second verified request displaces it.** The right size
    /// because of what is on the other end: the driver drains this on the very
    /// next turn of its loop, so a request that finds the slot occupied is one
    /// that arrived inside a single iteration of a request that has not been
    /// picked up yet. Displacing costs that requester one round trip and its
    /// own retry is the backstop, where a queue would size a table for
    /// something nothing is asking for — and, on a board that will never be an
    /// authority, carry it forever unused. (Design 24 §9.1: copy the shape of
    /// the parked-reply machinery, do not reuse its table.)
    pending_renewal: Option<VerifiedRenewal>,
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
    /// `CentralRouter::handle_frame_with_metrics` → `verify_challenge_response` is
    /// one frame's
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

mod distribution;
mod ogm;
mod pairwise;
mod paths;
mod proof;
mod renewal;
mod revocation;

pub use paths::Paths;
pub use renewal::RENEWAL_POLL_INTERVAL;

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
            cert_req_tx_rate: crate::RateEstimator::default(),
            cert_reply_tx_rate: crate::RateEstimator::default(),
            renewal_authority: None,
            outstanding_renewal: None,
            renew_req_rate: HVec::new(),
            pending_renewed_cert: None,
            renewal_requests_sent: 0,
            renewal_replies_accepted: 0,
            next_renewal_poll: Duration::ZERO,
            pending_renewal: None,
            challenge_counter: 0,
            restart_candidate: None,
            in_progress: HVec::new(),
            ogm_crypto_ops: 0,
            unjudged_admissions: 0,
        }
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
        // And the outstanding renewal slot, on the same terms: it ages on
        // elapsed time and nothing else, so a board with no wall clock reclaims
        // it exactly as a host does.
        if self
            .outstanding_renewal
            .is_some_and(|asked| now.saturating_sub(asked) >= OUTSTANDING_RENEWAL_TTL)
        {
            self.outstanding_renewal = None;
        }
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
}

#[cfg(test)]
mod testutil;

#[cfg(test)]
mod tests {
    //! Tests for the struct itself: the capacity profiles, and the
    //! guarantee that choosing one never reaches the wire.

    use super::*;

    use super::testutil::*;
    use wayfinder_auth::Authority;

    // ── Capacity profiles ─────────────────────────────────────────────────

    /// A deliberately tiny profile for a constrained node: 8 neighbour keys,
    /// 4 revocations, 2 in-flight cert requests, 2 parked replies.
    type TinyAuth = OgmAuth<8, 4, 2, 2>;

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
            core::mem::size_of::<DefaultAuth>()
        );
    }

    /// The point of the exercise: a small profile must actually reclaim RAM.
    /// `neighbors` alone is 64 × 360 bytes at `default` capacity.
    #[test]
    fn tiny_auth_profile_is_substantially_smaller() {
        let tiny = core::mem::size_of::<TinyAuth>();
        let default_auth = core::mem::size_of::<DefaultAuth>();
        assert!(
            tiny * 4 < default_auth,
            "tiny profile ({tiny} B) should be well under a quarter of default ({default_auth} B)"
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

    /// Capacity is a purely local memory decision: a default-profile node's OGM
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
}
