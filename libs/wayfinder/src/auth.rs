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
//! only.  Data-plane batman frames — `BATADV_BCAST` (flooded ARP etc.),
//! `BATADV_UNICAST`, `BATADV_MCAST` — are **not** authenticated yet, so an
//! outsider can still inject/transit those (e.g. a broadcast flood) on an
//! auth-enabled mesh.  Segregation here is *control-plane* (a foreign node
//! cannot influence routing); full data-plane segregation arrives with the
//! pairwise tag.

use batman::wire::BatmanOgmPacket;
use batman::wire::BatmanTvlvHdr;
use batman::wire::TvlvType;
use batman::wire::find_tvlv;
use batman::wire::iter_tvlv;
use heapless::Vec as HVec;
use interfaces::frame::Mac;
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

/// Width, in seconds, of the coarse time bucket a keep-alive signs over.
/// Keep-alives carry no sequence number ([`batman::wire::BatmanKeepAlivePacket`]
/// is deliberately minimal), so this — together with
/// [`KEEPALIVE_TOLERANCE_BUCKETS`] — bounds how long a captured, genuinely
/// signed heartbeat can be replayed to fake a since-silenced neighbor's
/// liveness, without needing per-neighbor replay counters. Checked against the
/// same wall clock ([`OgmAuth::now_unix`]) cert-validity checks already rely
/// on, so this adds no new cross-node clock-sync assumption.
const KEEPALIVE_BUCKET_SECS: u64 = 30;

/// How many buckets into the past a keep-alive's signed bucket remains
/// acceptable (beyond the current one), absorbing clock skew and network
/// jitter near a bucket boundary. Total replay window:
/// `(KEEPALIVE_TOLERANCE_BUCKETS + 1) * KEEPALIVE_BUCKET_SECS`.
const KEEPALIVE_TOLERANCE_BUCKETS: u64 = 1;

/// Length of the trailer [`OgmAuth::augment_keepalive`] appends: an 8-byte
/// big-endian time bucket followed by the 64-byte signature.
const KEEPALIVE_TRAILER_LEN: usize = 8 + SIG_LEN;

/// Length of the directed-frame authentication trailer appended to unicast and
/// multicast frames when auth is enabled: an 8-byte big-endian replay counter
/// followed by the 16-byte pairwise tag.
pub const DIRECTED_TRAILER_LEN: usize = 8 + TAG_LEN;

/// Maximum number of revocation records held in the local revocation set.
pub(crate) const MAX_REVOKED: usize = 32;
/// Maximum number of verified neighbor key records cached.
pub(crate) const MAX_NEIGHBOR_KEYS: usize = 64;

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

/// Minimum spacing (seconds) between retransmissions of the same outstanding
/// `CertReq` — the requester-side retry backstop for a dropped request or
/// reply (design doc §3.5): a pending-query list at the responder is the
/// primary optimization, but a lost packet anywhere must not wedge the fetch
/// forever.
const CERT_REQUEST_RETRY_SECS: u64 = 5;

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
const PENDING_REPLY_TTL_SECS: u64 = 30;

/// Minimum spacing (seconds) between `CertReq`s this node will act on from
/// the same requester — bounds the verification/airtime cost a single
/// member (even a legitimate, self-authenticating one) can impose (design
/// doc §8).
const CERT_REQ_RATE_LIMIT_SECS: u64 = 2;

/// One verified requester whose `CertReply` is parked because this node had
/// no route back to them at request time.
#[derive(Debug, Clone, Copy)]
struct PendingReply {
    /// The requester to reply to once a route appears.
    requester: Mac,
    /// `now_unix` this entry was last (re)parked, for TTL eviction.
    parked_unix: u64,
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
    /// Earliest `now_unix` at which another retransmission is allowed.
    next_attempt_unix: u64,
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

/// One verified neighbor's keys, learned from its authenticated OGM cert.
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
    /// Current wall-clock time in unix seconds, refreshed by the driver; used
    /// for certificate validity-window checks.  Zero until first set, which (as
    /// the unix epoch) treats every not-yet-current cert as not-yet-valid, so
    /// the driver must set a real time before auth is meaningful.
    now_unix: u64,
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
    /// Per-neighbor outgoing replay counter for directed data-plane frames.
    send_counters: HVec<(Mac, u64), MAX_NEIGHBOR_KEYS>,
    /// Per-neighbor highest accepted incoming counter (monotonic replay guard).
    recv_counters: HVec<(Mac, u64), MAX_NEIGHBOR_KEYS>,
    /// Set whenever a *new* revocation is ingested, signalling the router to
    /// snap the engine's Trickle timers back to `i_min` so the carrying OGM (and
    /// thus the emergency purge) floods promptly instead of waiting out the
    /// backed-off emission interval.  Drained by
    /// [`take_trickle_reset_hint`](Self::take_trickle_reset_hint).
    trickle_reset_hint: bool,
    /// Outstanding lazy-cert-distribution fetches this node has requested but
    /// not yet resolved, keyed by originator MAC (one entry per originator).
    in_flight: HVec<InFlightCertRequest, MAX_IN_FLIGHT_CERT_REQUESTS>,
    /// Verified `CertReq` requesters this node (the responder) has no route
    /// to yet, parked for opportunistic flush once one appears.
    pending_replies: HVec<PendingReply, MAX_PENDING_REPLIES>,
    /// Per-requester last-accepted-`CertReq` instant (responder-side rate
    /// limit), keyed by requester MAC.
    cert_req_rate: HVec<(Mac, u64), MAX_NEIGHBOR_KEYS>,
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
            now_unix: 0,
            revocations: HVec::new(),
            neighbors: HVec::new(),
            sign_scratch: [0u8; SIGN_SCRATCH_LEN],
            send_counters: HVec::new(),
            recv_counters: HVec::new(),
            trickle_reset_hint: false,
            in_flight: HVec::new(),
            pending_replies: HVec::new(),
            cert_req_rate: HVec::new(),
        }
    }

    /// Take and clear the pending Trickle-reset hint: `true` if a new revocation
    /// was ingested since the last call, meaning the router should reset the
    /// engine's OGM timers so the purge re-floods at `i_min` without waiting for
    /// the backed-off emission interval.
    pub fn take_trickle_reset_hint(&mut self) -> bool {
        core::mem::take(&mut self.trickle_reset_hint)
    }

    /// Update the current wall-clock time (unix seconds) used for cert validity
    /// checks.  Called by the driver before serving traffic.  Also garbage-
    /// collects revocations whose `not_after` has passed: the cancelled cert has
    /// expired too, so passive expiry now covers the node and the record can be
    /// forgotten, freeing a slot in the bounded revocation set.
    pub fn set_time(&mut self, now_unix: u64) {
        self.now_unix = now_unix;
        self.prune_expired();
    }

    /// Drop revocations that have passed their `not_after`.  A no-op until the
    /// clock has been set (`now_unix == 0`), since expiry cannot be judged
    /// before a real time is known.
    fn prune_expired(&mut self) {
        if self.now_unix == 0 {
            return;
        }
        let now = self.now_unix;
        let mut i = 0;
        while i < self.revocations.len() {
            if self.revocations[i].record.not_after.get() <= now {
                self.revocations.swap_remove(i);
            } else {
                i += 1;
            }
        }
        self.pending_replies
            .retain(|p| now.saturating_sub(p.parked_unix) < PENDING_REPLY_TTL_SECS);
        // Reclaim in-flight requests whose retry budget is exhausted. Without
        // this, a target that never answers (unreachable, or an attacker
        // flooding NeedCert misses for fake originator MACs it never backs
        // with a real reply) permanently pins a slot: `build_cert_request`
        // returns `None` before incrementing `attempts` once exhausted, so
        // the entry would otherwise sit at `MAX_CERT_REQUEST_ATTEMPTS`
        // forever, and `MAX_IN_FLIGHT_CERT_REQUESTS` such dead entries would
        // permanently block fetching any further originator's cert.
        self.in_flight
            .retain(|r| r.attempts < MAX_CERT_REQUEST_ATTEMPTS);
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
        let mac = match self.anchor.verify_revocation(record) {
            Ok(m) => m,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping a revocation that failed verification");
                return false;
            }
        };
        // A revocation of *this* node is a no-op here: peers enforce it against
        // us, and storing/flooding our own death warrant would only waste a
        // flood slot and budget.
        if mac.0 == self.cert.node_mac {
            tracing::warn!("auth: received a revocation naming this node");
            return false;
        }
        // Ignore a revocation that has already expired on our clock — the
        // cancelled cert is gone too, so there is nothing left to enforce.
        if self.now_unix != 0 && record.not_after.get() <= self.now_unix {
            tracing::trace!("auth: dropping a revocation that has already expired");
            return false;
        }
        if self.revocations.iter().any(|r| r.record.node_mac == mac.0) {
            // Already known (MAC granularity): do not re-arm the flood budget, or
            // two nodes could keep re-flooding each other's records forever.  A
            // re-issued revocation for an already-revoked MAC therefore does not
            // re-propagate — acceptable, since the node is already being dropped.
            tracing::trace!("auth: dropping a revocation that is already known");
            return false;
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
            let now = self.now_unix;
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

    /// Whether `mac` is currently revoked: a known record whose enforcement
    /// window (`not_before ..= not_after`) contains this node's clock.  Outside
    /// the window — not yet effective, or expired (where the cancelled cert has
    /// also expired) — the node is not dropped on this basis.
    fn is_revoked(&self, mac: &[u8; 6]) -> bool {
        let now = self.now_unix;
        self.revocations.iter().any(|r| {
            &r.record.node_mac == mac
                && r.record.not_before.get() <= now
                && now < r.record.not_after.get()
        })
    }

    /// Drop any cached neighbor state for `mac` so a revoked node can no longer
    /// participate in the directed data plane: its pairwise key is forgotten
    /// (directed frames from it stop verifying, and we stop tagging to it) and
    /// its replay counters are reset.
    fn evict_neighbor(&mut self, mac: Mac) {
        tracing::trace!("auth: evicting neighbor: {:?}", mac);
        if let Some(i) = self.neighbors.iter().position(|n| n.cert.mac == mac) {
            self.neighbors.swap_remove(i);
        }
        if let Some(i) = self.send_counters.iter().position(|(m, _)| *m == mac) {
            self.send_counters.swap_remove(i);
        }
        if let Some(i) = self.recv_counters.iter().position(|(m, _)| *m == mac) {
            self.recv_counters.swap_remove(i);
        }
    }

    /// The MACs this node currently holds revocations for (for the security
    /// view / observability), regardless of whether their effective instant has
    /// been reached yet.
    pub fn revoked_macs(&self) -> impl Iterator<Item = Mac> + '_ {
        self.revocations.iter().map(|r| Mac(r.record.node_mac))
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
        self.neighbors
            .iter()
            .find(|n| n.cert.mac == mac)
            .map(|n| (n.raw_cert, n.raw_cert.fingerprint()))
    }

    /// This node's own membership certificate (for the security view: mesh id,
    /// bound MAC, and expiry).
    pub fn own_cert(&self) -> &MembershipCert {
        &self.cert
    }

    /// The wall-clock instant (unix seconds) the auth clock was last set to, for
    /// computing "expires in" in the security view.  Zero until first set.
    pub fn now_unix(&self) -> u64 {
        self.now_unix
    }

    /// The X25519 key of a verified neighbor, for pairwise data-plane keying.
    pub fn neighbor_x_pubkey(&self, mac: Mac) -> Option<[u8; 32]> {
        self.neighbors
            .iter()
            .find(|n| n.cert.mac == mac)
            .map(|n| n.cert.x_pubkey)
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
        let key = self
            .neighbors
            .iter()
            .find(|n| n.cert.mac == dst)
            .map(|n| n.pairwise_key)?;
        let src_mac = self.cert.node_mac;
        let counter = self.next_send_counter(dst)?;
        let tag = frame_tag(&key, counter, &src_mac, frame);
        trailer[..8].copy_from_slice(&counter.to_be_bytes());
        trailer[8..DIRECTED_TRAILER_LEN].copy_from_slice(&tag);
        Some(DIRECTED_TRAILER_LEN)
    }

    /// Verify a directed frame's `trailer` from neighbor `src`: check the
    /// pairwise tag over `frame` and that the counter is strictly newer than the
    /// last accepted from `src` (replay defense), updating it on success.
    /// Returns `false` (drop) if we have no key for `src`, the trailer is
    /// malformed, the tag is invalid, or the counter is a replay.
    pub fn verify_directed(&mut self, src: Mac, frame: &[u8], trailer: &[u8]) -> bool {
        if trailer.len() != DIRECTED_TRAILER_LEN {
            tracing::trace!("auth: dropping directed frame with malformed tag trailer");
            return false;
        }
        let Some(key) = self
            .neighbors
            .iter()
            .find(|n| n.cert.mac == src)
            .map(|n| n.pairwise_key)
        else {
            tracing::trace!("auth: dropping directed frame from an unverified neighbor");
            return false;
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
            return false;
        }
        if !self.accept_recv_counter(src, counter) {
            tracing::trace!("auth: dropping directed frame with a replayed/stale counter");
            return false;
        }
        true
    }

    /// Allocate the next outgoing directed-frame counter for `dst` (starting at
    /// 1).  Fails closed — returns `None` rather than reusing a counter — if the
    /// table is full ([`MAX_NEIGHBOR_KEYS`] neighbors) or the counter would wrap,
    /// since a `(key, counter)` reuse with the static pairwise key would make
    /// tags replayable.
    fn next_send_counter(&mut self, dst: Mac) -> Option<u64> {
        if let Some(e) = self.send_counters.iter_mut().find(|(m, _)| *m == dst) {
            e.1 = e.1.checked_add(1)?;
            return Some(e.1);
        }
        self.send_counters.push((dst, 1)).ok()?;
        Some(1)
    }

    /// Accept `counter` from `src` only if strictly newer than the last accepted
    /// (monotonic replay guard), recording it on success.  The first frame from
    /// a neighbor is accepted and recorded.
    fn accept_recv_counter(&mut self, src: Mac, counter: u64) -> bool {
        if let Some(e) = self.recv_counters.iter_mut().find(|(m, _)| *m == src) {
            if counter <= e.1 {
                return false;
            }
            e.1 = counter;
            return true;
        }
        self.recv_counters.push((src, counter)).is_ok()
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
        let verified = match self.anchor.verify_cert(cert, self.now_unix) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping OGM whose certificate failed verification");
                return OgmVerdict::Rejected;
            }
        };

        // The cert must be bound to the OGM's claimed originator, and not revoked.
        if verified.mac.0 != orig {
            tracing::trace!("auth: dropping OGM whose cert MAC does not match the originator");
            return OgmVerdict::Rejected;
        }
        if self.is_revoked(&orig) {
            tracing::trace!("auth: dropping OGM from a revoked originator");
            return OgmVerdict::Rejected;
        }

        let mut seqno = [0u8; 4];
        seqno.copy_from_slice(&payload[SEQNO_OFF..SEQNO_OFF + 4]);
        let ed_pubkey = verified.ed_pubkey;
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(sig_bytes);
        // The signature is computed over the full `cert_bytes`, so any
        // padding past the 156-byte cert (which `ref_from_prefix` ignores)
        // changes the signed message and fails below — the cert length is
        // implicitly pinned by the signature.  On the lazy path `cert_bytes`
        // is always exactly 156 bytes (a `MembershipCert::as_bytes()`), so
        // this only bites the legacy wire path, unchanged from before.
        let signature_ok =
            match Self::signed_message(&orig, &seqno, cert_bytes, &mut self.sign_scratch) {
                Some(signed) => verify_signature(&ed_pubkey, signed, &signature),
                None => {
                    tracing::trace!("auth: dropping OGM, signed-message buffer too small");
                    return OgmVerdict::Rejected;
                }
            };
        if !signature_ok {
            tracing::trace!("auth: dropping OGM with an invalid signature");
            return OgmVerdict::Rejected;
        }

        let pairwise_key = self.keypair.pairwise_key(&verified.x_pubkey);
        self.cache_neighbor(NeighborKeys {
            cert: verified,
            pairwise_key,
            raw_cert: *cert,
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
    /// this node's MAC, and the coarse time bucket ([`KEEPALIVE_BUCKET_SECS`]).
    /// Mirrors [`signed_message`](Self::signed_message)'s shape but with its
    /// own domain separator and no cert — the receiver checks the signature
    /// against its neighbor cache instead of a cert carried on the wire (see
    /// [`verify_keepalive`](Self::verify_keepalive)). Returns the filled
    /// prefix of `out`.
    fn keepalive_signed_message<'a>(
        src: &[u8; 6],
        bucket: &[u8; 8],
        out: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let total = KEEPALIVE_SIG_DOMAIN.len() + src.len() + bucket.len();
        let buf = out.get_mut(..total)?;
        let (a, rest) = buf.split_at_mut(KEEPALIVE_SIG_DOMAIN.len());
        a.copy_from_slice(KEEPALIVE_SIG_DOMAIN);
        let (b, c) = rest.split_at_mut(src.len());
        b.copy_from_slice(src);
        c.copy_from_slice(bucket);
        Some(&out[..total])
    }

    /// Append a signed liveness trailer to a keep-alive heartbeat the engine
    /// has just built in `buf[..len]`: an 8-byte coarse time bucket and a
    /// 64-byte Ed25519 signature over it and this node's own MAC. Unlike
    /// [`augment_ogm`](Self::augment_ogm), no cert or fingerprint is attached
    /// — a keep-alive is only ever exchanged with a neighbor whose OGM (and
    /// thus cert) this node has already verified and cached, and
    /// [`verify_keepalive`](Self::verify_keepalive) checks against that cache
    /// rather than identity carried on the wire, so resending it on every
    /// heartbeat would be pure overhead. Returns `None` if `buf` lacks room
    /// for the trailer.
    pub fn augment_keepalive(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        let src = self.cert.node_mac;
        let bucket = (self.now_unix / KEEPALIVE_BUCKET_SECS).to_be_bytes();
        let signature = {
            let signed = Self::keepalive_signed_message(&src, &bucket, &mut self.sign_scratch)?;
            self.keypair.sign(signed)
        };
        let new_len = len.checked_add(KEEPALIVE_TRAILER_LEN)?;
        if new_len > buf.len() {
            return None;
        }
        buf[len..len + 8].copy_from_slice(&bucket);
        buf[len + 8..new_len].copy_from_slice(&signature);
        Some(new_len)
    }

    /// Verify an incoming keep-alive's [`augment_keepalive`] trailer, claimed
    /// to be from `src`. Checks, in order: the signed time bucket is within
    /// [`KEEPALIVE_TOLERANCE_BUCKETS`] of now (bounding replay of a captured,
    /// genuinely-signed heartbeat); `src`'s cert is cached (from a
    /// previously-verified OGM — a neighbor never OGM-verified fails closed,
    /// the same as an unresolvable OGM fingerprint) and has not expired on
    /// this node's clock; `src` is not revoked; and the signature itself.
    /// Returns `true` only if every check passes.
    pub fn verify_keepalive(&mut self, src: Mac, payload: &[u8]) -> bool {
        let Some(trailer_start) = payload.len().checked_sub(KEEPALIVE_TRAILER_LEN) else {
            tracing::trace!("auth: dropping keep-alive shorter than its auth trailer");
            return false;
        };
        let trailer = &payload[trailer_start..];
        let mut bucket_bytes = [0u8; 8];
        bucket_bytes.copy_from_slice(&trailer[..8]);
        let bucket = u64::from_be_bytes(bucket_bytes);
        let now_bucket = self.now_unix / KEEPALIVE_BUCKET_SECS;
        if bucket > now_bucket || now_bucket - bucket > KEEPALIVE_TOLERANCE_BUCKETS {
            tracing::trace!("auth: dropping keep-alive with an out-of-window time bucket");
            return false;
        }
        let Some(neighbor) = self.neighbors.iter().find(|n| n.cert.mac == src).copied() else {
            tracing::trace!("auth: dropping keep-alive from an unverified neighbor");
            return false;
        };
        if self.now_unix > neighbor.cert.not_after {
            tracing::trace!("auth: dropping keep-alive whose cached cert has expired");
            return false;
        }
        if self.is_revoked(&src.0) {
            tracing::trace!("auth: dropping keep-alive from a revoked neighbor");
            return false;
        }
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&trailer[8..KEEPALIVE_TRAILER_LEN]);
        let signed_ok =
            match Self::keepalive_signed_message(&src.0, &bucket_bytes, &mut self.sign_scratch) {
                Some(signed) => verify_signature(&neighbor.cert.ed_pubkey, signed, &signature),
                None => false,
            };
        if !signed_ok {
            tracing::trace!("auth: dropping keep-alive with an invalid signature");
        }
        signed_ok
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
                existing.next_attempt_unix = 0;
            }
            if self.now_unix < existing.next_attempt_unix {
                return None; // still within backoff
            }
            if existing.attempts >= MAX_CERT_REQUEST_ATTEMPTS {
                tracing::debug!(?orig, "auth: cert-request retry budget exhausted");
                return None;
            }
            existing.attempts += 1;
            existing.next_attempt_unix = self.now_unix.saturating_add(CERT_REQUEST_RETRY_SECS);
            existing.first_hop = first_hop;
        } else {
            let entry = InFlightCertRequest {
                orig,
                fp,
                first_hop,
                attempts: 1,
                next_attempt_unix: self.now_unix.saturating_add(CERT_REQUEST_RETRY_SECS),
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
        let verified = match self.anchor.verify_cert(cert, self.now_unix) {
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
        self.in_flight.swap_remove(pos);

        let pairwise_key = self.keypair.pairwise_key(&verified.x_pubkey);
        self.cache_neighbor(NeighborKeys {
            cert: verified,
            pairwise_key,
            raw_cert: *cert,
        });
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
    /// from the same MAC ([`CERT_REQ_RATE_LIMIT_SECS`], §8), and caches the
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
        let verified = match self.anchor.verify_cert(cert, self.now_unix) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping cert request whose requester cert failed verification");
                return None;
            }
        };
        let requester = verified.mac;

        if self.is_revoked(&requester.0) {
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

        if !self.accept_cert_request_rate(requester) {
            tracing::trace!(?requester, "auth: rate-limiting repeated cert request");
            return None;
        }

        let pairwise_key = self.keypair.pairwise_key(&verified.x_pubkey);
        self.cache_neighbor(NeighborKeys {
            cert: verified,
            pairwise_key,
            raw_cert: *cert,
        });
        Some(requester)
    }

    /// Accept a `CertReq` from `requester` only if at least
    /// [`CERT_REQ_RATE_LIMIT_SECS`] has passed since the last one accepted
    /// from them, recording the acceptance on success. The first request
    /// from a requester is always accepted.
    fn accept_cert_request_rate(&mut self, requester: Mac) -> bool {
        if let Some(entry) = self.cert_req_rate.iter_mut().find(|(m, _)| *m == requester) {
            if self.now_unix.saturating_sub(entry.1) < CERT_REQ_RATE_LIMIT_SECS {
                return false;
            }
            entry.1 = self.now_unix;
            return true;
        }
        if self.cert_req_rate.push((requester, self.now_unix)).is_err() {
            // Table full: overwrite the first entry rather than refusing a
            // legitimate new requester outright (bounded, simple eviction —
            // mirrors `cache_neighbor`'s policy).
            tracing::debug!("auth: cert-request rate-limit table full; evicting an entry");
            if let Some(first) = self.cert_req_rate.first_mut() {
                *first = (requester, self.now_unix);
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
    /// ([`PENDING_REPLY_TTL_SECS`], garbage-collected by
    /// [`set_time`](Self::set_time)); the requester's own retry
    /// ([`build_cert_request`](Self::build_cert_request) backoff) is the
    /// backstop if this node is never flushed or the entry is evicted.
    pub fn park_pending_reply(&mut self, requester: Mac) {
        if let Some(entry) = self
            .pending_replies
            .iter_mut()
            .find(|p| p.requester == requester)
        {
            entry.parked_unix = self.now_unix;
            return;
        }
        let entry = PendingReply {
            requester,
            parked_unix: self.now_unix,
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

    /// Insert or refresh a verified neighbor's keys.
    fn cache_neighbor(&mut self, keys: NeighborKeys) {
        if let Some(slot) = self
            .neighbors
            .iter_mut()
            .find(|n| n.cert.mac == keys.cert.mac)
        {
            *slot = keys;
        } else if self.neighbors.push(keys).is_err() {
            // Table full: overwrite the first entry rather than dropping the
            // freshly verified neighbor (bounded, simple eviction).
            if let Some(first) = self.neighbors.first_mut() {
                *first = keys;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use batman::wire::BATADV_IV_OGM;
    use batman::wire::BATADV_KEEPALIVE;
    use batman::wire::BatmanKeepAlivePacket;
    use batman::wire::BatmanOgmPacket;
    use wayfinder_auth::Authority;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Build a bare OGM (header only, no TVLV) for `orig` into a fresh buffer,
    /// returning `(buf, len)` with generous trailing capacity for augmentation.
    fn bare_ogm(orig: Mac, seqno: u32) -> ([u8; 512], usize) {
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
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
            packet_type: BATADV_KEEPALIVE,
            version: 5,
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
        auth.set_time(100);
        auth
    }

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
        b.set_time(2000); // past a's not_after = 1000
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
        let record = authority.revoke(mac(2), 0, 1000);
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
        b.set_time(500);
        let (mut buf, len) = bare_ogm(mac(2), 8);
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
        let forged = attacker.revoke(mac(2), 0, 1000);
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
        let record = authority.revoke(mac(2), 0, 1000);
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

        let record = authority.revoke(mac(9), 0, 1000);
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
        let record = authority.revoke(mac(9), 0, 1000);
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
        let record = authority.revoke(mac(3), 0, 1000);
        assert!(a.ingest_revocation(&record));
        assert!(a.tag_directed(mac(3), b"f", &mut trailer).is_none());
    }

    /// A revocation naming *this* node is a no-op: it is neither stored nor
    /// re-flooded (peers enforce it against us; we don't carry our own).
    #[test]
    fn self_revocation_is_a_noop() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let record = authority.revoke(mac(2), 0, 1000); // a's own MAC
        assert!(!a.ingest_revocation(&record));
        assert_eq!(a.revoked_macs().count(), 0);
    }

    /// A node whose clock is unset (`now_unix == 0`) does not enforce a
    /// revocation whose `not_before` is in the future, even though the record is
    /// stored — timing is honoured rather than failing open.
    #[test]
    fn unset_clock_does_not_enforce_future_revocation() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[3; 32]);
        let cert = authority.issue_cert(mac(3), kp.ed_pubkey(), kp.x_pubkey(), 0, 1_000_000);
        // Note: no set_time, so now_unix == 0.
        let mut b = OgmAuth::new(kp, cert, authority.trust_anchor());

        let record = authority.revoke(mac(2), 500, 1000); // effective at 500
        assert!(b.ingest_revocation(&record));
        // now_unix is 0, which is below not_before (500), so mac(2) is not yet
        // revoked: the check is a window, not "stored ⇒ dropped".
        assert!(!b.is_revoked(&mac(2).0));
    }

    /// Once a revocation's `not_after` passes, `set_time` garbage-collects it,
    /// freeing the slot — the bound on how long a record is retained.
    #[test]
    fn expired_revocation_is_garbage_collected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1_000_000); // now_unix = 100
        let record = authority.revoke(mac(2), 0, 1000);
        assert!(b.ingest_revocation(&record));
        assert_eq!(b.revoked_macs().count(), 1);
        // Advance past not_after: the record is pruned on the clock update.
        b.set_time(1001);
        assert_eq!(b.revoked_macs().count(), 0);
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

        let record = authority.revoke(mac(2), 0, 1000);
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
        b.set_time(2000);
        let record = authority.revoke(mac(2), 0, 1000); // not_after 1000 < now 2000
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
        let record = authority.revoke(mac(9), 0, 1000);
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
        let record = authority.revoke(mac(2), 0, 1000);
        assert!(b.ingest_revocation(&record));

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();
        assert!(!b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A keep-alive is rejected once the sender's cached cert has expired on
    /// the verifier's clock, even though the signed time bucket is still
    /// within the replay-tolerance window — cert expiry and bucket freshness
    /// are independent checks.
    #[test]
    fn keepalive_with_expired_cached_cert_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 131); // cert expires shortly after signing
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive(); // a signs at now_unix = 100
        let len = a.augment_keepalive(&mut buf, len).unwrap();

        b.set_time(140); // one bucket later (within tolerance), past a's not_after = 131
        assert!(!b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A keep-alive signed one bucket in the past is still accepted — the
    /// tolerance window absorbs normal clock skew and network jitter near a
    /// bucket boundary.
    #[test]
    fn keepalive_bucket_within_tolerance_accepted() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1_000_000);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive(); // a signs at now_unix = 100
        let len = a.augment_keepalive(&mut buf, len).unwrap();

        b.set_time(100 + KEEPALIVE_BUCKET_SECS);
        assert!(b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A keep-alive signed further in the past than the tolerance window is
    /// rejected — this bounds how long a captured, genuinely-signed heartbeat
    /// can be replayed to fake a since-silenced neighbor's liveness.
    #[test]
    fn keepalive_bucket_beyond_tolerance_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1_000_000);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();

        b.set_time(100 + KEEPALIVE_BUCKET_SECS * 2);
        assert!(!b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// A keep-alive claiming a time bucket newer than the verifier's own
    /// clock is rejected rather than accepted early.
    #[test]
    fn keepalive_future_bucket_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1_000_000);
        let mut b = member(&authority, 3, mac(3), 1_000_000);
        mutual_verify(&mut a, mac(2), &mut b, mac(3));

        a.set_time(1000); // a's clock is far ahead of b's
        let (mut buf, len) = bare_keepalive();
        let len = a.augment_keepalive(&mut buf, len).unwrap();
        // b is still at now_unix = 100
        assert!(!b.verify_keepalive(mac(2), &buf[..len]));
    }

    /// Augmentation fails closed (rather than truncating) when the buffer has
    /// no room for the trailer.
    #[test]
    fn keepalive_augment_none_when_buffer_too_small() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut buf = [0u8; 4]; // header + far too little room for the trailer
        buf[0] = BATADV_KEEPALIVE;
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

    /// A rotated cert for an already-known MAC (same node, new keys) overwrites
    /// the stored bytes and fingerprint in place, rather than leaving the old
    /// cert cached alongside the new one.
    #[test]
    fn neighbor_cert_rotation_updates_stored_bytes_and_fingerprint() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);

        let mut a1 = member(&authority, 2, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a1.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
        let (_, fp1) = b.neighbor_cert(mac(2)).expect("cached after first verify");

        // Same MAC, freshly issued cert with different keys — a rotation.
        let mut a2 = member(&authority, 9, mac(2), 1000);
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = a2.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        let (cached_cert, fp2) = b
            .neighbor_cert(mac(2))
            .expect("still cached after rotation");
        assert_ne!(fp1, fp2, "rotation must change the fingerprint");
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
    fn certfp_ogm_expired_cached_cert_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);

        b.set_time(2000); // past a's not_after = 1000
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = augment_ogm_with_certfp(&mut a, &mut buf, len);
        assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Rejected);
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
        b.set_time(b.now_unix + CERT_REQUEST_RETRY_SECS);
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
                b.set_time(b.now_unix + CERT_REQUEST_RETRY_SECS);
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
        let record = authority.revoke(mac(3), 0, 1000);
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

        a.set_time(a.now_unix + CERT_REQ_RATE_LIMIT_SECS);
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
                b.set_time(b.now_unix + CERT_REQUEST_RETRY_SECS);
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
        b.set_time(b.now_unix + 1);
        assert!(
            b.build_cert_request(mac(200), [0; 8], mac(9), &mut buf)
                .is_some(),
            "a reclaimed slot must admit a new originator"
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
        a.set_time(a.now_unix + PENDING_REPLY_TTL_SECS);
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
        a.set_time(a.now_unix + PENDING_REPLY_TTL_SECS - 1);
        a.park_pending_reply(mac(3)); // refresh before it would expire
        a.set_time(a.now_unix + PENDING_REPLY_TTL_SECS - 1);
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
        auth.set_time(100);
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
}
