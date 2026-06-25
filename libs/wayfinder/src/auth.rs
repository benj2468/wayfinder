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

use batman::wire::{BatmanOgmPacket, BatmanTvlvHdr, TvlvType, find_tvlv, iter_tvlv};
use heapless::Vec as HVec;
use interfaces::frame::Mac;
use wayfinder_auth::{
    Keypair, MembershipCert, RevocationRecord, TAG_LEN, TrustAnchor, frame_tag, verify_frame_tag,
    verify_signature,
};
use zerocopy::{FromBytes, IntoBytes};

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

/// Length of the directed-frame authentication trailer appended to unicast and
/// multicast frames when auth is enabled: an 8-byte big-endian replay counter
/// followed by the 16-byte pairwise tag.
pub const DIRECTED_TRAILER_LEN: usize = 8 + TAG_LEN;

/// Maximum number of revocation records held in the local revocation set.
const MAX_REVOKED: usize = 32;
/// Maximum number of verified neighbor key records cached.
const MAX_NEIGHBOR_KEYS: usize = 64;

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
    /// The neighbor's node MAC.
    pub mac: Mac,
    /// Its Ed25519 identity key (verifies its OGM signatures).
    pub ed_pubkey: [u8; 32],
    /// Its X25519 key (derives the pairwise data-plane key).
    pub x_pubkey: [u8; 32],
    /// The symmetric pairwise key shared with this neighbor, derived once (from
    /// our secret and its `x_pubkey`) when the neighbor is cached, and reused to
    /// tag/verify directed data-plane frames.
    pub pairwise_key: [u8; 32],
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

/// Per-node OGM authentication state, held by the router when auth is enabled.
pub struct OgmAuth {
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
}

impl OgmAuth {
    /// Build auth state from this node's keypair, its membership cert, and the
    /// mesh trust anchor.
    pub fn new(keypair: Keypair, cert: MembershipCert, anchor: TrustAnchor) -> Self {
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
            return false;
        }
        if self.revocations.iter().any(|r| r.record.node_mac == mac.0) {
            // Already known (MAC granularity): do not re-arm the flood budget, or
            // two nodes could keep re-flooding each other's records forever.  A
            // re-issued revocation for an already-revoked MAC therefore does not
            // re-propagate — acceptable, since the node is already being dropped.
            return false;
        }
        let known = KnownRevocation {
            record: *record,
            floods_left: REVOKE_FLOOD_BUDGET,
        };
        if self.revocations.push(known).is_err() {
            // Set full.  Prefer evicting an already-expired entry (passive expiry
            // covers it); otherwise overwrite the most-quiescent live entry
            // (lowest remaining flood budget).  The `min_by_key` orders expired
            // (`not_after <= now` → `false`) before live, then by budget.  With
            // `MAX_REVOKED` *simultaneously live* revocations this still drops a
            // live one — a hard bound worth surfacing rather than hiding.
            let now = self.now_unix;
            tracing::warn!("auth: revocation set full; evicting an entry to admit a new purge");
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
        if let Some(i) = self.neighbors.iter().position(|n| n.mac == mac) {
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

    /// The X25519 key of a verified neighbor, for pairwise data-plane keying.
    pub fn neighbor_x_pubkey(&self, mac: Mac) -> Option<[u8; 32]> {
        self.neighbors
            .iter()
            .find(|n| n.mac == mac)
            .map(|n| n.x_pubkey)
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
            .find(|n| n.mac == dst)
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
            .find(|n| n.mac == src)
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
    /// per-hop fields (ttl, tq, prev_sender) are deliberately excluded so the
    /// signature survives forwarding.  Returns the filled prefix of `out`.
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
    pub fn augment_ogm(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        if len < OGM_HDR {
            return None;
        }
        // Copy of our cert so its bytes don't hold a borrow of `self` while the
        // reused `sign_scratch` field is borrowed below (MembershipCert is Copy).
        let cert = self.cert;
        let cert_bytes = cert.as_bytes();

        // Sign over the immutable identity (orig + seqno, as on the wire) + cert.
        let mut orig = [0u8; 6];
        orig.copy_from_slice(&buf[ORIG_OFF..ORIG_OFF + 6]);
        let mut seqno = [0u8; 4];
        seqno.copy_from_slice(&buf[SEQNO_OFF..SEQNO_OFF + 4]);
        let signature = {
            let signed = Self::signed_message(&orig, &seqno, cert_bytes, &mut self.sign_scratch)?;
            self.keypair.sign(signed)
        };

        let cert_record = TVLV_HDR + cert_bytes.len();
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
        off = Self::write_tvlv(buf, off, TvlvType::Cert, cert_bytes);
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

    /// Verify an incoming OGM's authentication, caching the originator's keys on
    /// success.  Returns `true` only if the OGM carries a cert that chains to
    /// our trust anchor (correct mesh, valid window, not revoked) and a
    /// signature that verifies against that cert's key over the OGM's immutable
    /// identity.  A `false` return means the OGM must be dropped.
    pub fn verify_ogm(&mut self, payload: &[u8]) -> bool {
        if payload.len() < OGM_HDR {
            tracing::trace!("auth: dropping OGM shorter than its header");
            return false;
        }
        let tail = &payload[OGM_HDR..];
        let (Some(cert_bytes), Some(sig_bytes)) = (
            find_tvlv(tail, TvlvType::Cert),
            find_tvlv(tail, TvlvType::OgmSig),
        ) else {
            // Unauthenticated OGM under an auth-enabled mesh (e.g. another mesh).
            tracing::trace!("auth: dropping OGM missing cert or signature TVLV");
            return false;
        };
        if sig_bytes.len() != SIG_LEN {
            tracing::trace!("auth: dropping OGM with malformed signature TVLV length");
            return false;
        }
        let Ok((cert, _)) = MembershipCert::ref_from_prefix(cert_bytes) else {
            tracing::trace!("auth: dropping OGM with malformed membership certificate");
            return false;
        };
        let verified = match self.anchor.verify_cert(cert, self.now_unix) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping OGM whose certificate failed verification");
                return false;
            }
        };

        // The cert must be bound to the OGM's claimed originator, and not revoked.
        let mut orig = [0u8; 6];
        orig.copy_from_slice(&payload[ORIG_OFF..ORIG_OFF + 6]);
        if verified.mac.0 != orig {
            tracing::trace!("auth: dropping OGM whose cert MAC does not match the originator");
            return false;
        }
        if self.is_revoked(&orig) {
            tracing::trace!("auth: dropping OGM from a revoked originator");
            return false;
        }

        let mut seqno = [0u8; 4];
        seqno.copy_from_slice(&payload[SEQNO_OFF..SEQNO_OFF + 4]);
        let ed_pubkey = verified.ed_pubkey;
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(sig_bytes);
        // The signature is computed over the full `cert_bytes` from the TVLV, so
        // any padding past the 156-byte cert (which `ref_from_prefix` ignores)
        // changes the signed message and fails below — the cert length is
        // implicitly pinned by the signature.
        let signature_ok =
            match Self::signed_message(&orig, &seqno, cert_bytes, &mut self.sign_scratch) {
                Some(signed) => verify_signature(&ed_pubkey, signed, &signature),
                None => {
                    tracing::trace!("auth: dropping OGM, signed-message buffer too small");
                    return false;
                }
            };
        if !signature_ok {
            tracing::trace!("auth: dropping OGM with an invalid signature");
            return false;
        }

        let pairwise_key = self.keypair.pairwise_key(&verified.x_pubkey);
        self.cache_neighbor(NeighborKeys {
            mac: Mac(orig),
            ed_pubkey,
            x_pubkey: verified.x_pubkey,
            pairwise_key,
        });

        // Fold in any revocation records this OGM carries — each independently
        // signed by the mesh root — so an emergency purge floods alongside
        // normal OGM traffic.  Done only after the carrying OGM verified, so
        // an outsider cannot drive this path, and last so a revocation of the
        // *originator itself* (carried in a forwarded copy) still records.
        self.ingest_revocations_from_tail(tail);
        true
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
        if let Some(slot) = self.neighbors.iter_mut().find(|n| n.mac == keys.mac) {
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
    use batman::wire::{BATADV_IV_OGM, BatmanOgmPacket};
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
            prev_sender: orig,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        let mut buf = [0u8; 512];
        buf[..OGM_HDR].copy_from_slice(ogm.as_bytes());
        (buf, OGM_HDR)
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

        assert!(b.verify_ogm(&buf[..len]));
        assert_eq!(b.neighbors().len(), 1);
        assert_eq!(b.neighbor_x_pubkey(mac(2)), Some(a.cert.x_pubkey));
    }

    /// An unauthenticated OGM (no cert/sig TVLVs) is rejected when auth is on.
    #[test]
    fn unauthenticated_ogm_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let (buf, len) = bare_ogm(mac(2), 7);
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(b.verify_ogm(&buf[..len]));
        // Once the clock reaches the effective instant, the node is dropped.
        b.set_time(500);
        let (mut buf, len) = bare_ogm(mac(2), 8);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(b.verify_ogm(&buf[..len]));
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
        assert!(b.verify_ogm(&buf[..len]));
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
        len = OgmAuth::write_tvlv(&mut buf, len, batman::wire::TvlvType::Mcast, &[1, 2, 3, 4]);
        let mcast_record = TVLV_HDR + 4;
        buf[TVLV_LEN_OFF..TVLV_LEN_OFF + 2].copy_from_slice(&(mcast_record as u16).to_be_bytes());

        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert!(b.verify_ogm(&buf[..len]));
        // The mcast TVLV is still findable after the appended records.
        assert_eq!(
            find_tvlv(&buf[OGM_HDR..len], batman::wire::TvlvType::Mcast),
            Some(&[1, 2, 3, 4][..])
        );
    }

    /// Exchange OGMs both ways so `a` and `b` each cache the other's verified
    /// pairwise key (a precondition for tagging/verifying directed frames).
    fn mutual_verify(a: &mut OgmAuth, a_mac: Mac, b: &mut OgmAuth, b_mac: Mac) {
        let (mut buf, len) = bare_ogm(a_mac, 1);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert!(b.verify_ogm(&buf[..len]));
        let (mut buf, len) = bare_ogm(b_mac, 1);
        let len = b.augment_ogm(&mut buf, len).unwrap();
        assert!(a.verify_ogm(&buf[..len]));
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
}
