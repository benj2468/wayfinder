//! The neighbour key cache and the pairwise data-plane authenticator:
//! directed-frame tags, fan-out signatures, and the replay counters both ride.

use super::*;

impl<
    const MAX_NEIGHBOR_KEYS: usize,
    const MAX_REVOKED: usize,
    const MAX_IN_FLIGHT_CERT_REQUESTS: usize,
    const MAX_PENDING_REPLIES: usize,
> OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>
{
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

    /// Drop any cached neighbor state for `mac` so a revoked node can no longer
    /// participate in the directed data plane: its pairwise key is forgotten
    /// (directed frames from it stop verifying, and we stop tagging to it) and
    /// its replay counters are reset.
    pub(super) fn evict_neighbor(&mut self, mac: Mac) {
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
    pub(super) fn next_send_counter(&mut self) -> Option<u64> {
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
    pub(super) fn accept_recv_counter(&mut self, src: Mac, counter: u64) -> CounterVerdict {
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
    pub(super) fn live_neighbor(&self, mac: Mac) -> Option<&NeighborKeys> {
        self.neighbors
            .iter()
            .find(|n| n.cert.mac == mac && !self.wall.proves_past(n.cert.not_after))
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
    pub(super) fn anchor_recv_counter(&mut self, src: Mac, counter: u64) -> bool {
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
    pub(super) fn evict_expired_neighbors(&mut self) {
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
    ///   not carry, and at 64 × 360 bytes that is a real budget on exactly the
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
    pub(super) fn cache_neighbor(&mut self, keys: NeighborKeys) -> Cached {
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
    pub(super) fn identity_conflict(&self, mac: Mac, ed_pubkey: &[u8; 32]) -> bool {
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
    pub(super) fn report_identity_conflict(mac: Mac, refused: &[u8; 32]) {
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
    //! Tests for the neighbour key cache and the pairwise data plane.

    use super::*;

    use super::super::testutil::*;
    use wayfinder_auth::Authority;

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
}
