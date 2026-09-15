//! Lazy certificate distribution (design 01): the `CertReq`/`CertReply`
//! exchange that resolves a fingerprint this node cannot match.
//!
//! Both frames are built here, headers included. Every route this module asks
//! `paths` for is asked **proof-agnostically**
//! ([`Paths::next_hop_unproven_ok`]), and that is the one thing to keep if this
//! code moves again: proving a neighbour needs its pairwise key, which needs
//! its certificate, which is what this exchange fetches. Gating it on proof
//! deadlocks bootstrap.

use super::*;
use crate::BATMAN_VERSION;
use crate::ETH_P_BATMAN;
use crate::LinkFrameData;
use batman::wire::BatmanCertReplyPacket;
use batman::wire::BatmanCertReqPacket;
use interfaces::frame::LinkFrameDataMut;
use tracing::debug;
use tracing::trace;

impl<
    const MAX_NEIGHBOR_KEYS: usize,
    const MAX_REVOKED: usize,
    const MAX_IN_FLIGHT_CERT_REQUESTS: usize,
    const MAX_PENDING_REPLIES: usize,
> OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>
{
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
    pub(super) fn accept_cert_request_rate(&mut self, requester: Mac) -> bool {
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

    /// Build the `CertReq` that resolves a fingerprint this node cannot match,
    /// or `None` when the request cannot be built or will not fit `tx_buf`.
    ///
    /// `first_hop` is the OGM's link source, not a routed next hop, and that is
    /// deliberate: [`verify_ogm`](Self::verify_ogm) gates before the engine
    /// sees the OGM, so nothing has installed a route to `orig` yet — but
    /// whoever relayed or originated the OGM demonstrably has one.
    pub fn build_cert_req_frame<'tx>(
        &mut self,
        now: Duration,
        orig: Mac,
        fp: [u8; 8],
        first_hop: Mac,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx>> {
        let hdr_len = core::mem::size_of::<BatmanCertReqPacket>();
        let body = tx_buf.get_mut(hdr_len..)?;
        let body_len = self.build_cert_request(orig, fp, first_hop, body)?;

        let hdr = BatmanCertReqPacket {
            packet_type: BatmanPacketType::CertReq.as_u8(),
            version: BATMAN_VERSION,
            ttl: 50,
            dest: orig,
        };
        tx_buf[..hdr_len].copy_from_slice(hdr.as_bytes());
        self.cert_req_tx_rate.observe(now, 0);
        Some(LinkFrameData {
            dst: first_hop,
            protocol: ETH_P_BATMAN,
            payload: &tx_buf[..hdr_len + body_len],
        })
    }

    /// Handle a `CertReq` body that has reached the node it names, writing the
    /// answer into `reply` and returning its next hop and length.
    ///
    /// Terminates here: this node is the originator whose cert was requested
    /// (the terminal-only responder — an intermediate holder answering early is
    /// a deferred optimization). Verifies the requester's self-authenticating
    /// body, then either answers immediately (a route exists) or parks the
    /// request for [`flush_pending_cert_reply`](Self::flush_pending_cert_reply)
    /// to pick up once one appears.
    ///
    /// Returns the next hop and written length rather than a borrowed
    /// [`LinkFrameData`], because that borrow cannot outlive this function's
    /// own `&mut` parameter; the caller, which owns `reply` directly, builds
    /// the frame.
    pub fn answer_cert_request(
        &mut self,
        now: Duration,
        paths: &impl Paths,
        body: &[u8],
        reply: &mut LinkFrameDataMut<'_>,
    ) -> Option<(Mac, usize)> {
        let requester = self.verify_cert_request(body)?;

        let hdr_len = core::mem::size_of::<BatmanCertReplyPacket>();
        let cert_bytes = self.cert.as_bytes();
        let total = hdr_len + cert_bytes.len();

        match paths.next_hop_unproven_ok(now, requester) {
            Some(next) if total <= reply.payload.len() => {
                let reply_hdr = BatmanCertReplyPacket {
                    packet_type: BatmanPacketType::CertReply.as_u8(),
                    version: BATMAN_VERSION,
                    ttl: 50,
                    dest: requester,
                };
                reply.payload[..hdr_len].copy_from_slice(reply_hdr.as_bytes());
                reply.payload[hdr_len..total].copy_from_slice(cert_bytes);
                self.cert_reply_tx_rate.observe(now, 0);
                return Some((next, total));
            }
            Some(_) => {
                // A route exists, but the reply doesn't fit the transmit
                // buffer — a local MTU misconfiguration (own cert + header is a
                // fixed ~165 bytes), not "no route yet". Parking it wouldn't
                // help (the opportunistic flush hits the same buffer), but the
                // requester's own retry is a harmless no-op backstop either
                // way, so park it anyway rather than add a second silent-drop
                // path.
                debug!(
                    total,
                    buf_len = reply.payload.len(),
                    "auth: cert reply does not fit the transmit buffer"
                );
            }
            None => {
                trace!(?requester, "auth: no route to cert requester yet");
            }
        }
        // Park it for the opportunistic flush once verifying one of the
        // requester's OGMs confirms a route back.
        self.park_pending_reply(requester);
        None
    }

    /// After an OGM that itself needed no re-flood, opportunistically flush a
    /// parked pending `CertReply` for that OGM's originator (`orig`), now that
    /// verifying it (re)confirms a route back to them (design 01 §3.3/§5.4).
    ///
    /// Builds the reply — this node's own cert, since a pending reply is only
    /// ever parked for *this* node's own cert request (the terminal-only
    /// responder; see [`verify_cert_request`](Self::verify_cert_request)) —
    /// into `reply`'s scratch buffer, and clears the pending entry only on full
    /// success (route resolved and the buffer had room), so a failed attempt
    /// leaves the entry parked for the next opportunity.
    ///
    /// Returns the next hop and the written length; the caller builds the final
    /// borrowed [`LinkFrameData`], for the reason
    /// [`answer_cert_request`](Self::answer_cert_request) gives.
    pub fn flush_pending_cert_reply(
        &mut self,
        now: Duration,
        paths: &impl Paths,
        orig: Mac,
        reply: &mut LinkFrameDataMut<'_>,
    ) -> Option<(Mac, usize)> {
        if !self.has_pending_reply(orig) {
            return None;
        }
        // Proof-agnostic: see the `answer_cert_request` reply path above.
        let next = paths.next_hop_unproven_ok(now, orig)?;
        let cert_bytes = self.cert.as_bytes();
        let hdr_len = core::mem::size_of::<BatmanCertReplyPacket>();
        let total = hdr_len + cert_bytes.len();
        if total > reply.payload.len() {
            return None;
        }
        let hdr = BatmanCertReplyPacket {
            packet_type: BatmanPacketType::CertReply.as_u8(),
            version: BATMAN_VERSION,
            ttl: 50,
            dest: orig,
        };
        reply.payload[..hdr_len].copy_from_slice(hdr.as_bytes());
        reply.payload[hdr_len..total].copy_from_slice(cert_bytes);
        reply.dst = next;
        reply.protocol = ETH_P_BATMAN;
        self.cert_reply_tx_rate.observe(now, 0);
        self.clear_pending_reply(orig);
        Some((next, total))
    }

    /// Smoothed frames/sec at which this node sends `CertReq` — lazy-cert
    /// fetches it originated as a requester with an unresolved fingerprint.
    pub fn cert_req_tx_rate(&self, now: Duration) -> f64 {
        self.cert_req_tx_rate.rate(now).1
    }

    /// Smoothed frames/sec at which this node sends `CertReply` — answers it
    /// gave as the originator whose cert was asked for, immediately or via the
    /// opportunistic parked-reply flush.
    pub fn cert_reply_tx_rate(&self, now: Duration) -> f64 {
        self.cert_reply_tx_rate.rate(now).1
    }

    /// Adopt `prev`'s cert-control send rates, so they survive a credential
    /// change.
    ///
    /// These two gauges moved from `CentralRouter` into this struct so each
    /// `observe` sits beside the frame it counts — but `set_auth` replaces this
    /// struct wholesale, which would zero them on every re-enrollment and every
    /// renewal a host node completes over its socket. That is a lie in the one
    /// direction a gauge must not lie: `cert_req_tx_rate` exists to show
    /// cert-cache churn, and a mesh that is churning would read as idle for a
    /// full decay window each time a certificate is installed.
    ///
    /// The distinction to keep if more state is added here: everything else
    /// `set_auth` discards is *scoped to the credential* and is genuinely stale
    /// under a new one. A count of frames this node put on the wire is not — it
    /// is node observability that happens to live here.
    pub(crate) fn adopt_control_rates(&mut self, prev: &Self) {
        self.cert_req_tx_rate = prev.cert_req_tx_rate;
        self.cert_reply_tx_rate = prev.cert_reply_tx_rate;
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the lazy certificate-distribution exchange.

    use super::*;

    use super::super::testutil::*;
    use wayfinder_auth::Authority;

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

    /// A [`Paths`] view answering with `via` when it knows the destination.
    ///
    /// `None` for `via` is "no route at all". Cert distribution asks only
    /// [`Paths::next_hop_unproven_ok`], so both methods answer the same here —
    /// the *proven*-vs-unproven distinction is pinned on the renewal side, in
    /// `auth/renewal.rs`, which is the module that must not confuse them.
    struct Route {
        me: Mac,
        to: Mac,
        via: Option<Mac>,
    }

    impl Paths for Route {
        fn self_ident(&self) -> Mac {
            self.me
        }
        fn next_hop(&self, _now: Duration, dest: Mac) -> Option<Mac> {
            (dest == self.to).then_some(self.via).flatten()
        }
        fn next_hop_unproven_ok(&self, now: Duration, dest: Mac) -> Option<Mac> {
            self.next_hop(now, dest)
        }
    }

    /// A flush that finds no route leaves the entry **parked**.
    ///
    /// [`flush_pending_cert_reply`](OgmAuth::flush_pending_cert_reply) promises
    /// to clear the entry "only on full success", and until now only the
    /// success path was covered — making the no-route path clear it too passed
    /// the whole suite. The cost of that regression is a requester whose
    /// certificate is dropped on the one attempt the responder makes, with the
    /// parked entry (the thing that exists to retry it) deleted on the way out.
    ///
    /// Reachable without a router at all, which is what the [`Paths`] seam is
    /// for.
    #[test]
    fn a_flush_with_no_route_back_leaves_the_reply_parked() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut responder = member(&authority, 2, mac(2), 1000);
        responder.park_pending_reply(mac(3));

        let mut buf = [0u8; 512];
        let mut reply: LinkFrameDataMut<'_> = buf.as_mut_slice().into();
        assert!(
            responder
                .flush_pending_cert_reply(
                    Duration::ZERO,
                    &Route {
                        me: mac(2),
                        to: mac(3),
                        via: None,
                    },
                    mac(3),
                    &mut reply,
                )
                .is_none(),
            "no route back, so nothing is emitted"
        );
        assert_eq!(
            responder.pending_cert_replies_occupancy().0,
            1,
            "and the entry stays parked for the next opportunity"
        );
    }

    /// The same, when a route exists but the transmit buffer cannot hold the
    /// reply — the other half of "only on full success".
    #[test]
    fn a_flush_that_does_not_fit_the_buffer_leaves_the_reply_parked() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut responder = member(&authority, 2, mac(2), 1000);
        responder.park_pending_reply(mac(3));

        // A header plus a ~156-byte certificate does not fit in 32 bytes.
        let mut buf = [0u8; 32];
        let mut reply: LinkFrameDataMut<'_> = buf.as_mut_slice().into();
        let paths = Route {
            me: mac(2),
            to: mac(3),
            via: Some(mac(4)),
        };
        assert!(
            responder
                .flush_pending_cert_reply(Duration::ZERO, &paths, mac(3), &mut reply)
                .is_none()
        );
        assert_eq!(responder.pending_cert_replies_occupancy().0, 1);
    }
}
