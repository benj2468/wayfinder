//! Revocation: ingesting records, shunning their subjects, and the
//! self-revocation this node holds for the router to act on.

use super::*;

impl<
    const MAX_NEIGHBOR_KEYS: usize,
    const MAX_REVOKED: usize,
    const MAX_IN_FLIGHT_CERT_REQUESTS: usize,
    const MAX_PENDING_REPLIES: usize,
> OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>
{
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
    pub(super) fn is_revoked(&self, cert: &VerifiedCert) -> bool {
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

    /// Parse and ingest every [`TvlvType::Revoke`] record in an OGM `tail`.
    /// Each is independently verified by
    /// [`ingest_revocation`](Self::ingest_revocation) against the trust anchor,
    /// so a malformed or forged record is simply ignored.
    pub(super) fn ingest_revocations_from_tail(&mut self, tail: &[u8]) {
        // `tail` is part of the caller's payload, disjoint from `self`, so the
        // borrow held by the iterator coexists with ingesting into `self`.
        for value in iter_tvlv(tail, TvlvType::Revoke) {
            if let Ok((rec, _)) = RevocationRecord::ref_from_prefix(value) {
                self.ingest_revocation(rec);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for revocation ingest, enforcement and self-revocation.

    use super::*;

    use super::super::testutil::*;
    use wayfinder_auth::Authority;

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
}
