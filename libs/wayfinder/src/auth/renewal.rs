//! Membership renewal over the mesh (design 24): the `RenewReq`/`RenewReply`
//! exchange a node with no IP stack renews itself through.
//!
//! Both halves of the exchange are built here, headers included, rather than
//! in the router. The router's part is to lend a [`Paths`] view so a frame can
//! be addressed, and to carry a verified request out to the certificate
//! authority — which lives on its own task since design 13 and which the
//! `no_std` core must never learn to reach.

use super::*;
use crate::BATMAN_VERSION;
use crate::ETH_P_BATMAN;
use crate::LinkFrameData;
use batman::wire::BatmanRenewReplyPacket;
use batman::wire::BatmanRenewReqPacket;
use tracing::trace;
use tracing::warn;

/// How often a node evaluates whether its membership certificate needs
/// renewing over the mesh.
///
/// Fifteen minutes, matching the host renewer's `RENEWAL_CHECK_INTERVAL` and
/// for the same reason: the question is answered from state already in memory,
/// but it is asked from a path that also runs per frame, so it is paced rather
/// than evaluated continuously. It is also this node's retry cadence when a
/// renewal goes unanswered, which is what sets the floor.
///
/// **No backoff**, deliberately (design 24 §9.4). At the seven-day lifetime
/// `wayfinder-ca` issues, the renewal window is about 42 hours, so a fixed
/// quarter-hour cadence gives a partitioned board roughly 170 attempts to find
/// a path back — and each attempt is one small frame against a window measured
/// in days. Backoff would trade that margin for an airtime saving nothing has
/// asked for, on a node that spends more on a single OGM round.
pub const RENEWAL_POLL_INTERVAL: Duration = Duration::from_secs(15 * 60);

impl<
    const MAX_NEIGHBOR_KEYS: usize,
    const MAX_REVOKED: usize,
    const MAX_IN_FLIGHT_CERT_REQUESTS: usize,
    const MAX_PENDING_REPLIES: usize,
> OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>
{
    /// Record the authority this node renews against by its **pinned public
    /// key**, or clear it.
    ///
    /// The key, not the address it implies. Since design 09 §5 a node's mesh
    /// address is the address its identity key derives, so the two are one
    /// fact — and taking the derived value would put `derive_mac` at every call
    /// site, which is the gap `NodeRecord` closes by persisting the key. One
    /// derivation, here, and an address no key derives becomes unrepresentable.
    ///
    /// Written by the `SetAuth` that installs a credential, alongside the
    /// credential itself — see [`renewal_authority`](Self::renewal_authority)
    /// for why it is never read from configuration.
    pub fn set_renewal_authority(&mut self, provider_key: Option<&[u8; 32]>) {
        self.renewal_authority = provider_key.map(wayfinder_auth::derive_mac);
    }

    /// The mesh address of the authority this node renews against.
    pub fn renewal_authority(&self) -> Option<Mac> {
        self.renewal_authority
    }

    /// Renewal requests this node has put on the wire since boot.
    pub fn renewal_requests_sent(&self) -> u64 {
        self.renewal_requests_sent
    }

    /// Re-issued certificates this node has accepted and installed since boot.
    ///
    /// The gap from [`renewal_requests_sent`](Self::renewal_requests_sent) is
    /// the signal an operator reads: asking and not being answered is the
    /// failure this whole path exists to make visible.
    pub fn renewal_replies_accepted(&self) -> u64 {
        self.renewal_replies_accepted
    }

    /// Whether this node should be asking for a fresh certificate now.
    ///
    /// **Deliberately not `MembershipCert::due_renewal`**, and the difference is
    /// design 24 §4.5. `due_renewal` is `!expired(now) && now >= renew_from()`,
    /// and a board holds [`Clocked::AtLeast`] — a monotone lower bound, which
    /// can prove an instant is past and can *never* prove one is still ahead.
    /// So the second half of that conjunction is provable to a board and the
    /// first half never is, and a node that insisted on evaluating both would
    /// simply never renew.
    ///
    /// What it does instead: ask whenever it can prove `renew_from` is past,
    /// and let the authority be the judge of expiry. A board whose floor has
    /// drifted far behind reality may therefore spend one round trip on a
    /// request the authority refuses as lapsed — against the alternative, which
    /// is a wrong local decision made silently. That is design 20 §5.1's
    /// "enforcement is distributed" applied to one more case.
    ///
    /// A node with no clock at all ([`Clocked::Unknown`]) proves neither half
    /// and asks nothing: there is no evidence it is in the window, and on a
    /// duty-cycle-limited radio a guess is not the same trade as a proof.
    ///
    /// Says nothing about *whether it can* — that is
    /// [`build_renewal_request`](Self::build_renewal_request)'s answer, which
    /// is `None` for a node with no recorded authority.
    pub fn renewal_due(&self) -> bool {
        self.wall.proves_past(self.cert.renew_from())
    }

    /// Write a `RenewReq` body into `buf` and record the request as
    /// outstanding, returning its length.
    ///
    /// The body is `cert ‖ nonce ‖ sig(domain ‖ authority ‖ self ‖ nonce)` —
    /// the certificate this node is currently running under, and a proof it
    /// holds the key that certificate names. **No CSR is transmitted.** The
    /// authority re-issues from the identity it just verified; anything else a
    /// board could put in a request would be a field the authority must then
    /// decide whether to trust, and there is nothing it needs (design 24 §4.2).
    ///
    /// The authority's address is bound into the signed message so a request
    /// captured on one provider's mesh cannot be presented to another — within
    /// one mesh the trust anchor would not tell them apart.
    ///
    /// `None` when this node records no renewal authority (it has nowhere to
    /// ask), when the nonce counter is exhausted, or when `buf` is too small.
    ///
    /// A second call replaces what is outstanding. That does **not** make a
    /// reply to the superseded request refusable — the reply carries no nonce,
    /// so the two are indistinguishable — it only restarts the window in which
    /// any reply is accepted at all. See
    /// [`outstanding_renewal`](Self::outstanding_renewal).
    pub fn build_renewal_request(&mut self, buf: &mut [u8]) -> Option<usize> {
        let ca = self.renewal_authority?;

        // The same counter and PRF key the next-hop challenge draws from,
        // separated by domain (design 24 §9.2). Its known weakness on a board —
        // it restarts at every reboot — costs renewal nothing: a repeated nonce
        // is at worst a re-issue of a certificate to its rightful holder (§5.3),
        // and the reply is matched against this node's own outstanding slot
        // rather than against the nonce's uniqueness.
        let seq = self.challenge_counter.checked_add(1)?;
        self.challenge_counter = seq;
        let nonce = frame_tag(&self.nonce_prf_key(), seq, RENEW_NONCE_PRF_DOMAIN, &ca.0);

        let signature = self.keypair.sign(&Self::renewal_signed_message(
            &ca.0,
            &self.cert.node_mac,
            &nonce,
        ));

        let cert_bytes = self.cert.as_bytes();
        let total = cert_bytes.len() + RENEWAL_NONCE_LEN + signature.len();
        let out = buf.get_mut(..total)?;
        let (cert_out, rest) = out.split_at_mut(cert_bytes.len());
        cert_out.copy_from_slice(cert_bytes);
        let (nonce_out, sig_out) = rest.split_at_mut(RENEWAL_NONCE_LEN);
        nonce_out.copy_from_slice(&nonce);
        sig_out.copy_from_slice(&signature);

        self.outstanding_renewal = Some(self.now);
        self.renewal_requests_sent = self.renewal_requests_sent.saturating_add(1);
        Some(total)
    }

    /// The message a renewal request's signature is computed over: the domain,
    /// the authority being asked, the requester, and the nonce.
    fn renewal_signed_message(
        authority: &[u8; 6],
        requester: &[u8; 6],
        nonce: &[u8; RENEWAL_NONCE_LEN],
    ) -> [u8; RENEW_REQ_SIG_DOMAIN.len() + 12 + RENEWAL_NONCE_LEN] {
        let mut msg = [0u8; RENEW_REQ_SIG_DOMAIN.len() + 12 + RENEWAL_NONCE_LEN];
        let (domain, rest) = msg.split_at_mut(RENEW_REQ_SIG_DOMAIN.len());
        domain.copy_from_slice(RENEW_REQ_SIG_DOMAIN);
        let (a, rest) = rest.split_at_mut(6);
        a.copy_from_slice(authority);
        let (r, n) = rest.split_at_mut(6);
        r.copy_from_slice(requester);
        n.copy_from_slice(nonce);
        msg
    }

    /// Verify an incoming `RenewReq` body delivered locally to this node — i.e.
    /// this node is the authority it was routed to.
    ///
    /// Everything decidable from `no_std` auth state and nothing else: the
    /// requester's certificate against the trust anchor, revocation, proof of
    /// possession of the key that certificate names, the identity lock, and the
    /// rate limit. **No policy runs here.** Whether this node is a certificate
    /// authority at all, and whether the holder still matches, is the
    /// authority's question — asked on its own task (design 13), off the
    /// router loop. What comes out of here is a *decision-free fact*: this is
    /// who asked, and this is the identity they proved (design 24 §4.3).
    ///
    /// The ordering is
    /// [`verify_cert_request`](Self::verify_cert_request)'s, for the same
    /// reasons, and it is the security property rather than a nicety — the
    /// cheapest refusals come first, and proof of possession is spent before
    /// the rate limiter so replaying a member's public certificate with a
    /// garbage signature cannot keep that member's slot hot and deny their
    /// genuine renewals (design 24 §6).
    ///
    /// Returns `None` (dropped, `trace!`-logged) on any failure; the caller
    /// must not forward anything to the authority in that case.
    pub fn verify_renewal_request(&mut self, body: &[u8]) -> Option<VerifiedRenewal> {
        let cert_len = core::mem::size_of::<MembershipCert>();
        if body.len() != cert_len + RENEWAL_NONCE_LEN + SIG_LEN {
            tracing::trace!("auth: dropping malformed renewal request body");
            return None;
        }
        let (cert_bytes, rest) = body.split_at(cert_len);
        let (nonce_bytes, sig_bytes) = rest.split_at(RENEWAL_NONCE_LEN);
        let Ok((cert, _)) = MembershipCert::ref_from_prefix(cert_bytes) else {
            tracing::trace!("auth: dropping renewal request with a malformed requester cert");
            return None;
        };
        let verified = match self.anchor.verify_cert(cert, self.wall) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping renewal request whose requester cert failed verification");
                return None;
            }
        };
        let requester = verified.mac;

        if self.is_revoked(&verified) {
            tracing::trace!("auth: dropping renewal request from a revoked requester");
            return None;
        }

        let mut nonce = [0u8; RENEWAL_NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);
        let msg = Self::renewal_signed_message(&self.cert.node_mac, &requester.0, &nonce);
        let mut sig = [0u8; SIG_LEN];
        sig.copy_from_slice(sig_bytes);
        if !verify_signature(&verified.ed_pubkey, &msg, &sig) {
            tracing::trace!(
                "auth: dropping renewal request with an invalid self-authentication signature"
            );
            return None;
        }

        if self.identity_conflict(requester, &verified.ed_pubkey) {
            Self::report_identity_conflict(requester, &verified.ed_pubkey);
            return None;
        }

        if !self.accept_renewal_request_rate(requester) {
            tracing::trace!(?requester, "auth: rate-limiting repeated renewal request");
            return None;
        }

        Some(VerifiedRenewal {
            mac: requester,
            ed_pubkey: verified.ed_pubkey,
            x_pubkey: verified.x_pubkey,
        })
    }

    /// Accept a `RenewReq` from `requester` only if at least
    /// [`RENEW_REQ_RATE_LIMIT`] has passed since the last one accepted from
    /// them, recording the acceptance on success.
    ///
    /// A copy of [`accept_cert_request_rate`](Self::accept_cert_request_rate)
    /// over a *separate* table rather than a shared one, deliberately: see
    /// [`RENEW_REQ_RATE_LIMIT`].
    fn accept_renewal_request_rate(&mut self, requester: Mac) -> bool {
        if let Some(entry) = self
            .renew_req_rate
            .iter_mut()
            .find(|(m, _)| *m == requester)
        {
            if self.now.saturating_sub(entry.1) < RENEW_REQ_RATE_LIMIT {
                return false;
            }
            entry.1 = self.now;
            return true;
        }
        if self.renew_req_rate.push((requester, self.now)).is_err() {
            // Table full: overwrite the first entry rather than refusing a
            // legitimate new requester outright — the same bounded, simple
            // eviction `cert_req_rate` and `cache_neighbor` use.
            tracing::debug!("auth: renewal-request rate-limit table full; evicting an entry");
            if let Some(first) = self.renew_req_rate.first_mut() {
                *first = (requester, self.now);
            }
        }
        true
    }

    /// Ingest a `RenewReply` body (a raw [`MembershipCert`]) delivered locally
    /// to this node, installing it as the credential this node runs under and
    /// returning it for the shell to persist.
    ///
    /// Four rules, each refusing a substitution a relay could otherwise make —
    /// the frame carries no end-to-end integrity of its own, so any node on the
    /// path can replace the body. It must **chain to the held trust anchor**
    /// (which is what makes the authority's MAC a routing hint and not a trust
    /// input), **name this node** under the key this node holds, **answer an
    /// outstanding request**, and **move both ends of the window forward**.
    /// The last two are design 24 §5.3 and §11.2.1; see
    /// [`outstanding_renewal`](Self::outstanding_renewal) for what the third
    /// does and does not promise.
    ///
    /// Returns whether the certificate was installed. A `false` return means
    /// the reply was dropped, the node keeps running under what it already
    /// holds, and the next renewal poll is the retry.
    ///
    /// On success the certificate is also held for
    /// [`take_renewed_cert`](Self::take_renewed_cert), which is how it reaches
    /// the shell that can make it durable.
    pub fn ingest_renew_reply(&mut self, body: &[u8]) -> bool {
        let Ok((cert, _)) = MembershipCert::ref_from_prefix(body) else {
            tracing::trace!("auth: dropping malformed renewal reply");
            return false;
        };
        // Checked before the anchor, because it is the cheaper refusal and
        // because an unsolicited reply is the one an attacker sends.
        // Occupied *and* still fresh. An expired slot is not an outstanding
        // request: see `outstanding_renewal` for why a slot that never expired
        // would degrade this rule to "this node has asked at least once since
        // power-on" on exactly the board most likely to be partitioned.
        let outstanding = self
            .outstanding_renewal
            .is_some_and(|asked| self.now.saturating_sub(asked) < OUTSTANDING_RENEWAL_TTL);
        if !outstanding {
            tracing::trace!("auth: dropping renewal reply that answers no outstanding request");
            return false;
        }
        let verified = match self.anchor.verify_cert(cert, self.wall) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping renewal reply that failed verification");
                return false;
            }
        };
        if verified.mac.0 != self.cert.node_mac || verified.ed_pubkey != self.cert.ed_pubkey {
            tracing::trace!(
                mac = ?verified.mac,
                "auth: dropping renewal reply that certifies another identity"
            );
            return false;
        }
        // **Both ends of the window, not just the far one.**
        //
        // `not_after` alone is the obvious rule and it is not enough. A
        // `RenewReply` is relayed hop by hop with no end-to-end integrity of
        // its own, so a node on the path can substitute the body — and while
        // the anchor check above stops it inventing a certificate and the
        // identity check stops it presenting somebody else's, neither stops it
        // replaying a *genuine, root-signed certificate this very board used to
        // hold*. Certificates are public; they ride every OGM.
        //
        // Such a replay normally fails here, because each re-issue runs longer
        // than the last. It stops failing the moment an operator *shortens*
        // this device's approved lifetime, which is a thing an operator does —
        // and it is the one case where being wrong matters most, since a
        // certificate's lifetime is the only revocation bound that reaches a
        // member which is offline when the revocation floods. Accepting the old
        // copy would undo the reduction silently.
        //
        // `not_before` settles it. The authority stamps it at the instant of
        // issue (`CertAuthority::sign`), so a genuine re-issue never moves it
        // backwards and a replayed older certificate always does. Equality is
        // admitted, so two issues inside one second are not refused for it.
        if cert.not_after.get() <= self.cert.not_after.get()
            || cert.not_before.get() < self.cert.not_before.get()
        {
            tracing::trace!(
                "auth: dropping renewal reply that would move the credential backwards"
            );
            return false;
        }

        let installed = *cert;
        self.cert = installed;
        self.outstanding_renewal = None;
        self.pending_renewed_cert = Some(installed);
        self.renewal_replies_accepted = self.renewal_replies_accepted.saturating_add(1);
        tracing::info!(
            not_after = installed.not_after.get(),
            "auth: installed a renewed membership certificate"
        );
        true
    }

    /// Take the renewed certificate awaiting a durable write, if any.
    ///
    /// Taken once: a shell that persisted the same install twice would spend a
    /// flash erase for nothing, and on a board that budget is what design 22
    /// §4.5 sizes.
    pub fn take_renewed_cert(&mut self) -> Option<MembershipCert> {
        self.pending_renewed_cert.take()
    }

    /// Handle a `RenewReq` body that has reached the node it names.
    ///
    /// Terminates here: this node is the authority the request was routed to.
    /// Verify everything decidable from `no_std` auth state — anchor,
    /// revocation, proof of possession, the rate limit — and hold the identity
    /// it proved for the driver to collect with
    /// [`take_renewal_request`](Self::take_renewal_request).
    ///
    /// The answer is deliberately **not** built here, and that asymmetry with
    /// [`answer_cert_request`](Self::answer_cert_request) is the whole of what
    /// design 13 forces: the router loop does not own a `CertAuthority` and
    /// must not learn to. This surfaces a decision-free fact and lets the
    /// authority's own task apply the holder match.
    pub fn handle_renew_req(&mut self, body: &[u8]) {
        let Some(verified) = self.verify_renewal_request(body) else {
            return;
        };
        // Displaces rather than queues; see the field's doc for why one slot is
        // the right size here.
        if self.pending_renewal.is_some() {
            trace!(
                requester = ?verified.mac,
                "auth: displacing a renewal request the driver has not collected"
            );
        }
        self.pending_renewal = Some(verified);
    }

    /// Take the verified renewal request this node is holding for its driver,
    /// if any.
    ///
    /// The seam design 24 §4.3 opens: this module proved who asked, the
    /// certificate authority decides whether to re-issue, and they are on
    /// different executors since design 13. Taken rather than borrowed, so the
    /// driver owns the round trip from here and a second call cannot start it
    /// twice.
    pub fn take_renewal_request(&mut self) -> Option<VerifiedRenewal> {
        self.pending_renewal.take()
    }

    /// Emit this node's due `RenewReq` into `tx_buf`, if one is due and there
    /// is a path to the authority to put it on.
    ///
    /// **At most one request per call, and the deadline advances whatever this
    /// decides** — including on every path that returns `None`. A shell that
    /// sleeps on [`next_renewal_after`](Self::next_renewal_after) and then
    /// found the deadline still due would spin, which is the same trap
    /// `CentralRouter::poll_ping` documents for a probe session.
    ///
    /// Returns `None` when there is nothing to do (not yet due, no recorded
    /// authority, not inside the renewal window this node can
    /// prove) and when there is something to do but no way to do it (no live
    /// route to the authority). The second case is **quiet by design**: a board
    /// partitioned from its authority is the ordinary condition on a mesh
    /// (design 24 §5.4), and it retries on the next poll. What makes it visible
    /// when it stops being ordinary is the gap between
    /// [`renewal_requests_sent`](Self::renewal_requests_sent) and
    /// [`renewal_replies_accepted`](Self::renewal_replies_accepted), plus the
    /// shell's alarm.
    ///
    /// `dst` in the returned frame is the **next hop**, not the authority: the
    /// packet is routed hop-by-hop toward `dest` in its header, exactly like a
    /// unicast. `paths` is asked with [`Paths::next_hop`] and not
    /// [`Paths::next_hop_unproven_ok`] — renewal requires a pairwise tag like
    /// any other directed frame, so a hop this node has not proven is a hop it
    /// could not authenticate to anyway.
    pub fn poll_renewal<'tx>(
        &mut self,
        now: Duration,
        paths: &impl Paths,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx>> {
        if now < self.next_renewal_poll {
            return None;
        }
        self.next_renewal_poll = now.saturating_add(RENEWAL_POLL_INTERVAL);

        let ca = self.renewal_authority();
        let subject = Subject::Node(NodeId::new(&paths.self_ident().0));

        // The operator-facing half (design 24 §7), decided *before* the
        // route and the authority are consulted so that the two ways a node
        // fails to renew — nowhere to ask, and nobody answering — both reach an
        // operator. Raised on every poll: `alarm!` coalesces on
        // `(kind, subject)`, so a board asking every quarter hour for two days
        // produces one row with a count rather than two hundred rows, which is
        // the shape a condition that persists and retries needs.
        if self.renewal_due() {
            // The distinguishing clause comes **first**, because an alarm's
            // detail is truncated at `DETAIL_CAP` (64 bytes) and a row whose
            // two variants differ only past that boundary renders identically —
            // which defeats the whole reason for raising this on a node that
            // cannot act on it.
            if ca.is_some() {
                alarm!(
                    Severity::Warning,
                    AlarmKind::CertExpiring,
                    subject,
                    "renewing over the mesh: certificate is in its last quarter"
                );
            } else {
                alarm!(
                    Severity::Warning,
                    AlarmKind::CertExpiring,
                    subject,
                    "no renewal authority recorded: certificate nearly expired"
                );
            }
        } else {
            // Retired here rather than where a reply lands, so the one place
            // that decides the condition holds is the one that decides it has
            // lifted — which covers every way a node leaves the window, not
            // only the renewal this path drove.
            wayfinder_alarm::clear(AlarmKind::CertExpiring, &subject);
            return None;
        }

        let ca = ca?;
        let Some(next) = paths.next_hop(now, ca) else {
            // `trace!` and not `warn!`: see the doc above. This is reachable
            // every fifteen minutes on a partitioned board, and a `warn!` there
            // would evict the bounded log ring a probe-less node depends on.
            trace!(?ca, "renewal: no live route to the authority yet");
            return None;
        };

        let hdr_len = core::mem::size_of::<BatmanRenewReqPacket>();
        // Traced, unlike the no-route case above, and the difference is whether
        // the condition is transient. No route is ordinary on a mesh and clears
        // itself; these do not. A transmit buffer too small for a certificate,
        // or a nonce counter that has run out, is permanent — the next poll
        // takes the identical path forever, `renewal_requests_sent` never
        // moves, and the alarm would go on saying this node is renewing.
        //
        // `warn!` rather than `trace!` because this is node-local: not
        // reachable by remote input, so the bounded-log-ring flood rule that
        // keeps the receive path quiet does not apply.
        let Some(body) = tx_buf.get_mut(hdr_len..) else {
            warn!(
                buf_len = tx_buf.len(),
                hdr_len, "renewal: transmit buffer cannot hold a request header"
            );
            return None;
        };
        let Some(body_len) = self.build_renewal_request(body) else {
            warn!("renewal: could not build a request; this node cannot renew itself");
            return None;
        };

        let hdr = BatmanRenewReqPacket {
            packet_type: BatmanPacketType::RenewReq.as_u8(),
            version: BATMAN_VERSION,
            ttl: 50,
            dest: ca,
        };
        tx_buf[..hdr_len].copy_from_slice(hdr.as_bytes());
        trace!(?ca, ?next, "renewal: requesting a fresh certificate");
        Some(LinkFrameData {
            dst: next,
            protocol: ETH_P_BATMAN,
            payload: &tx_buf[..hdr_len + body_len],
        })
    }

    /// Time from `now` until this node next evaluates whether to renew, or
    /// `None` when it has no authority recorded to renew against.
    ///
    /// A shell that sleeps must fold this into the same `min` as
    /// `CentralRouter::next_broadcast_after` and its siblings.
    ///
    /// `None` for a node with nowhere to ask — the certificate-authority
    /// posture, a node enrolled offline, an unauthenticated mesh — so nothing
    /// is ever woken for a question it cannot answer. Deliberately **not**
    /// `None` merely because the certificate is not yet due: whether it is due
    /// turns on a wall clock this loop is what advances, so a deadline
    /// suppressed on that basis would be a deadline that never comes back.
    pub fn next_renewal_after(&self, now: Duration) -> Option<Duration> {
        self.renewal_authority()?;
        Some(self.next_renewal_poll.saturating_sub(now))
    }

    /// Build the `RenewReply` carrying `cert` back to `requester`, addressed to
    /// the next hop toward them.
    ///
    /// The authority's half of the exchange, called by the driver once the
    /// certificate authority has re-issued. `None` when there is no live route
    /// back — nothing is parked, because the requester's own retry is already
    /// the backstop and a reply held here would be a certificate aging in a
    /// buffer — or when `tx_buf` is too small for the header and a certificate.
    pub fn send_renew_reply<'tx>(
        &mut self,
        now: Duration,
        paths: &impl Paths,
        requester: Mac,
        cert: &MembershipCert,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx>> {
        let next = paths.next_hop(now, requester)?;
        let hdr_len = core::mem::size_of::<BatmanRenewReplyPacket>();
        let cert_bytes = cert.as_bytes();
        let total = hdr_len + cert_bytes.len();
        let out = tx_buf.get_mut(..total)?;

        let hdr = BatmanRenewReplyPacket {
            packet_type: BatmanPacketType::RenewReply.as_u8(),
            version: BATMAN_VERSION,
            ttl: 50,
            dest: requester,
        };
        out[..hdr_len].copy_from_slice(hdr.as_bytes());
        out[hdr_len..].copy_from_slice(cert_bytes);
        trace!(
            ?requester,
            ?next,
            "renewal: answering with a fresh certificate"
        );
        Some(LinkFrameData {
            dst: next,
            protocol: ETH_P_BATMAN,
            payload: &tx_buf[..total],
        })
    }
}

#[cfg(test)]
mod tests {
    //! Tests for membership renewal over the mesh.

    use super::*;

    use super::super::testutil::*;
    use wayfinder_auth::Authority;

    // ── certificate renewal over the mesh (design 24) ─────────────────────────

    /// A board in its renewal window, the authority it renews against recorded
    /// by the enrollment that certified it.
    ///
    /// `valid_to` is picked so the default renewal fraction puts `now` inside
    /// the last quarter — the state the whole exchange is only ever reached
    /// from.
    fn renewing_board(authority: &Authority, seed: u8, ca_seed: u8, valid_to: u64) -> OgmAuth {
        let mut board = member(authority, seed, mac(seed), valid_to);
        board.set_renewal_authority(Some(&Keypair::from_seed(&[ca_seed; 32]).ed_pubkey()));
        board
    }

    /// The round trip, at the level the router hands it to: a board writes a
    /// request body, the authority's own auth state verifies it, and what comes
    /// back out is the identity to re-certify — address and both public keys,
    /// taken from the certificate rather than from anything the requester could
    /// name independently.
    #[test]
    fn a_renewal_request_round_trips_from_a_board_to_the_authority() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let ca_mac = mac(3);
        let mut board = renewing_board(&authority, 1, 3, 1000);
        let mut ca = member(&authority, 3, ca_mac, 1000);

        let mut buf = [0u8; 512];
        let len = board
            .build_renewal_request(&mut buf)
            .expect("a board with a recorded authority can always ask");

        let verified = ca
            .verify_renewal_request(&buf[..len])
            .expect("a live holder's request verifies");
        assert_eq!(verified.mac, mac(1));
        assert_eq!(
            verified.ed_pubkey,
            Keypair::from_seed(&[1; 32]).ed_pubkey(),
            "the identity to re-certify comes from the presented certificate"
        );
        assert_eq!(verified.x_pubkey, Keypair::from_seed(&[1; 32]).x_pubkey());
        assert_eq!(board.renewal_requests_sent(), 1);
    }

    /// A board with no recorded authority asks nobody. It is the same rule the
    /// host renewer keeps (`renew.rs`, "where the provider comes from"): a node
    /// whose credential was installed without a provider has nowhere to ask,
    /// and reaching back to an authority a previous credential came from is the
    /// one thing worse than waiting for an operator.
    #[test]
    fn a_board_with_no_recorded_authority_builds_no_request() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let mut board = member(&authority, 1, mac(1), 1000);
        let mut buf = [0u8; 512];
        assert_eq!(board.build_renewal_request(&mut buf), None);
        assert_eq!(board.renewal_requests_sent(), 0);
    }

    /// The verifier refuses, in order, everything `verify_cert_request` refuses:
    /// a malformed body, a certificate that does not chain to this mesh's
    /// anchor, and a body whose signature does not prove possession of the key
    /// the certificate names.
    ///
    /// The *order* is the security property, not a nicety: proof of possession
    /// must be spent before the rate limiter, or an attacker replaying a real
    /// member's certificate — which is public, it rides every OGM — with a
    /// garbage signature could keep that member's rate-limit slot permanently
    /// hot and deny their genuine renewals.
    #[test]
    fn a_renewal_request_verifies_like_a_cert_request() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let other_mesh = Authority::from_seed(&[9; 32], 43);
        let ca_mac = mac(3);
        let mut ca = member(&authority, 3, ca_mac, 1000);

        assert_eq!(ca.verify_renewal_request(&[]), None, "empty body");
        assert_eq!(ca.verify_renewal_request(&[0xff; 32]), None, "short body");

        // A well-formed request from another mesh's member: the signature is
        // genuine, the certificate is not ours.
        let mut stranger = renewing_board(&other_mesh, 5, 3, 1000);
        let mut buf = [0u8; 512];
        let len = stranger.build_renewal_request(&mut buf).unwrap();
        assert_eq!(
            ca.verify_renewal_request(&buf[..len]),
            None,
            "a certificate that does not chain to this anchor is refused"
        );

        // Our own member's certificate, replayed with the signature corrupted:
        // anyone can do this, since a certificate is a public document.
        let mut board = renewing_board(&authority, 1, 3, 1000);
        let len = board.build_renewal_request(&mut buf).unwrap();
        buf[len - 1] ^= 0xff;
        assert_eq!(
            ca.verify_renewal_request(&buf[..len]),
            None,
            "a body that does not prove possession of the named key is refused"
        );

        // **And the refusal cost the named member nothing.** This is the
        // assertion the ordering exists for, and without it the whole property
        // is untested: moving `accept_renewal_request_rate` above the signature
        // check would pass every other line here. The limiter is 60s against a
        // 15-minute retry, so a spent slot denies the real board its renewal
        // for the rest of the interval — and its alternative is an operator
        // with a serial cable.
        let len = board.build_renewal_request(&mut buf).unwrap();
        assert!(
            ca.verify_renewal_request(&buf[..len]).is_some(),
            "a forged signature must not consume the impersonated member's rate-limit slot"
        );
    }

    /// Revocation bites before the authority is ever reached: a revoked
    /// member's renewal is refused at the first hop that knows about it
    /// (design 24 §6), not only at the CA.
    #[test]
    fn a_renewal_request_from_a_revoked_holder_is_refused() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let ca_mac = mac(3);
        let mut board = renewing_board(&authority, 1, 3, 1000);
        let mut ca = member(&authority, 3, ca_mac, 1000);
        // `not_before` of 50 rather than 0: a zero instant is refused as a record
        // that could never cancel anything, and the member fixture stands at 100.
        assert!(ca.ingest_revocation(&authority.revoke(mac(1), 50, 10_000)));

        let mut buf = [0u8; 512];
        let len = board.build_renewal_request(&mut buf).unwrap();
        assert_eq!(ca.verify_renewal_request(&buf[..len]), None);
    }

    /// Repeated requests from one requester are rate-limited, and on a limiter
    /// of renewal's own rather than the one `CertReq` spends.
    ///
    /// Two exchanges that mean different things — "I am a member, give me your
    /// cert" and "I am this member, give me a new one for me" — must not be
    /// able to exhaust each other's budget (design 24 §4.2).
    #[test]
    fn renewal_requests_are_rate_limited_on_their_own_budget() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let ca_mac = mac(3);
        let mut board = renewing_board(&authority, 1, 3, 1000);
        let mut ca = member(&authority, 3, ca_mac, 1000);

        let mut buf = [0u8; 512];
        let len = board.build_renewal_request(&mut buf).unwrap();
        assert!(ca.verify_renewal_request(&buf[..len]).is_some());
        let len = board.build_renewal_request(&mut buf).unwrap();
        assert_eq!(
            ca.verify_renewal_request(&buf[..len]),
            None,
            "a second request inside the limit is refused"
        );

        // A cert request from the same node still gets its own first slot.
        let mut req_buf = [0u8; 512];
        let req_len = board
            .build_cert_request(ca_mac, [0; 8], ca_mac, &mut req_buf)
            .unwrap();
        assert!(
            ca.verify_cert_request(&req_buf[..req_len]).is_some(),
            "the cert-request budget is untouched by renewal traffic"
        );

        ca.set_time(
            Duration::from_secs(100) + RENEW_REQ_RATE_LIMIT,
            Clocked::At(200),
        );
        let len = board.build_renewal_request(&mut buf).unwrap();
        assert!(
            ca.verify_renewal_request(&buf[..len]).is_some(),
            "and the limit does lift"
        );
    }

    /// A reply this node did not ask for is dropped, however well it verifies
    /// (design 24 §5.3). Without this rule any member could hand a board a
    /// certificate of the authority's choosing at a moment of the attacker's.
    #[test]
    fn a_renew_reply_that_answers_no_outstanding_request_is_dropped() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        let mut board = renewing_board(&authority, 1, 3, 1000);

        let fresh = authority.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 5000);
        assert!(
            !board.ingest_renew_reply(fresh.as_bytes()),
            "nothing was outstanding"
        );
        assert!(board.take_renewed_cert().is_none());
        assert_eq!(board.renewal_replies_accepted(), 0);
        assert_eq!(
            board.own_cert().not_after.get(),
            1000,
            "and the credential in use is untouched"
        );
    }

    /// The ordinary success: a board that asked, and is answered, runs under
    /// the re-issued certificate from that moment — and the accepted reply is
    /// handed back for the shell to persist.
    #[test]
    fn a_renew_reply_answering_an_outstanding_request_is_installed() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        let mut board = renewing_board(&authority, 1, 3, 1000);

        let mut buf = [0u8; 512];
        board.build_renewal_request(&mut buf).unwrap();

        let fresh = authority.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 5000);
        assert!(
            board.ingest_renew_reply(fresh.as_bytes()),
            "a fresh certificate for this holder, answering its own request"
        );
        assert_eq!(board.own_cert().not_after.get(), 5000);
        assert_eq!(board.renewal_replies_accepted(), 1);
        assert_eq!(
            board
                .take_renewed_cert()
                .expect("held for the shell to make durable")
                .not_after
                .get(),
            5000
        );
        assert!(
            board.take_renewed_cert().is_none(),
            "taken once, so a shell cannot spend a second erase saying the same thing"
        );

        // The request is no longer outstanding: one answer per ask.
        assert!(!board.ingest_renew_reply(fresh.as_bytes()));
    }

    /// A reply naming somebody else is not this node's renewal, whoever signed
    /// it — including a certificate the relay legitimately holds, its own. A
    /// certificate is useful only to the holder of the key it names, and
    /// installing another member's would leave this node signing OGMs its peers
    /// refuse.
    #[test]
    fn a_renew_reply_naming_another_node_is_dropped() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let other = Keypair::from_seed(&[2; 32]);
        let mut board = renewing_board(&authority, 1, 3, 1000);

        let mut buf = [0u8; 512];
        board.build_renewal_request(&mut buf).unwrap();

        let theirs = authority.issue_cert(
            other.derived_mac(),
            other.ed_pubkey(),
            other.x_pubkey(),
            0,
            5000,
        );
        assert!(!board.ingest_renew_reply(theirs.as_bytes()));
        assert_eq!(board.own_cert().not_after.get(), 1000);
    }

    /// A reply must never move the credential *backwards* — design 22 §4.6's
    /// clock-rollback prohibition reaching the credential beside the
    /// checkpoint. A replayed older certificate would otherwise shorten a
    /// board's remaining life, and on a board the shortening is durable.
    #[test]
    fn a_renew_reply_must_not_roll_the_credential_backwards() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        let mut board = renewing_board(&authority, 1, 3, 1000);

        let mut buf = [0u8; 512];
        board.build_renewal_request(&mut buf).unwrap();

        let older = authority.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 900);
        assert!(!board.ingest_renew_reply(older.as_bytes()));
        assert_eq!(board.own_cert().not_after.get(), 1000);
    }

    /// **The posture case** (design 24 §4.5). A board holds a monotone lower
    /// bound on the time: it can prove an instant is past and can *never* prove
    /// one is still ahead. So half of `due_renewal` — "not yet expired" — is
    /// unprovable to it, and it does not try to evaluate that half.
    ///
    /// It asks whenever it can prove `renew_from` is past and lets the
    /// authority judge expiry. The cost of being wrong is one round trip and an
    /// operator-visible refusal, against a wrong local decision made silently.
    #[test]
    fn a_board_attempts_renewal_on_a_proven_floor_without_proving_non_expiry() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        // A window of [0, 1000], so `renew_from` is 750.
        let cert = authority.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 1000);
        let mut board = OgmAuth::new(kp, cert, authority.trust_anchor());
        board.set_renewal_authority(Some(&Keypair::from_seed(&[3; 32]).ed_pubkey()));

        board.set_time(Duration::from_secs(10), Clocked::AtLeast(700));
        assert!(
            !board.renewal_due(),
            "a floor short of `renew_from` proves nothing yet"
        );

        board.set_time(Duration::from_secs(20), Clocked::AtLeast(800));
        assert!(
            !Clocked::AtLeast(800).proves_before(1000),
            "the premise: a floor can never prove the certificate is still live"
        );
        assert!(
            board.renewal_due(),
            "and the board asks anyway, on the half it *can* prove"
        );

        // A node with no clock at all proves neither half and asks nothing:
        // there is no evidence it is in the window, and spending a radio's
        // airtime on a guess is not the same trade as spending a round trip on
        // a proof.
        board.set_time(Duration::from_secs(30), Clocked::Unknown);
        assert!(!board.renewal_due());
    }

    // ── what a hostile relay can and cannot do to a renewal ───────────────────

    /// A board mid-renewal, holding a certificate valid `[0, 1000]`.
    fn board_awaiting_reply(authority: &Authority) -> OgmAuth {
        let mut board = renewing_board(authority, 1, 3, 1000);
        let mut buf = [0u8; 512];
        board.build_renewal_request(&mut buf).unwrap();
        board
    }

    /// **The root signature is the whole gate**, and nothing a relay can build
    /// without the root key gets past it.
    ///
    /// A `RenewReply` is relayed hop by hop with no end-to-end integrity of its
    /// own, so any node on the path can replace the body outright. What stops
    /// that mattering is that the board judges the *content* against the same
    /// trust anchor every peer judges it against — so a board can never end up
    /// holding something its peers would reject as a forgery, because it would
    /// not install a forgery in the first place.
    ///
    /// The strongest forgery available is a different root under the same mesh
    /// id, which is what this uses.
    #[test]
    fn a_renew_reply_signed_by_a_foreign_root_is_refused() {
        let real = Authority::from_seed(&[7; 32], 42);
        let evil = Authority::from_seed(&[66; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        let mut board = board_awaiting_reply(&real);

        let forged = evil.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 9_000_000);
        assert!(!board.ingest_renew_reply(forged.as_bytes()));
        assert_eq!(board.own_cert().not_after.get(), 1000);
    }

    /// **A genuine, root-signed certificate for this very board, replayed.**
    ///
    /// The one case the other checks do not cover, and the reason this node
    /// compares `not_before` as well as `not_after`. Certificates are public —
    /// they ride every OGM — so an adjacent member can keep a copy of one this
    /// board used to hold. "Moves the credential forward" alone does not refuse
    /// it: if an operator has since *shortened* this device's approved lifetime
    /// (per-approval TTL is a thing an operator sets), the old certificate
    /// outlives the current one and passes a `not_after` test.
    ///
    /// Installing it would undo the operator's reduction — silently, and on
    /// precisely the node whose exposure they were trying to limit, since a
    /// certificate's lifetime is the only revocation bound that reaches a
    /// member which is offline when the revocation floods.
    ///
    /// `not_before` is what settles it: the authority stamps it at the instant
    /// of issue, so a real re-issue never moves it backwards and a replayed
    /// older certificate always does.
    #[test]
    fn a_renew_reply_replaying_an_older_certificate_for_this_board_is_refused() {
        let real = Authority::from_seed(&[7; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        // The board currently holds `[500, 1000]` — an operator has shortened
        // it since the certificate below was issued.
        let current = real.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 500, 1000);
        let mut board = OgmAuth::new(Keypair::from_seed(&[1; 32]), current, real.trust_anchor());
        board.set_time(Duration::from_secs(100), Clocked::At(900));
        board.set_renewal_authority(Some(&Keypair::from_seed(&[3; 32]).ed_pubkey()));
        let mut buf = [0u8; 512];
        board.build_renewal_request(&mut buf).unwrap();

        // Issued long ago, for a year: it outlives what the board holds now.
        let stale = real.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 31_536_000);
        assert!(
            stale.not_after.get() > 1000,
            "the fixture only means something if the replay would otherwise pass \
             the move-forward test"
        );
        assert!(
            !board.ingest_renew_reply(stale.as_bytes()),
            "a certificate whose window opened before the one in use is a replay, \
             however long it runs for"
        );
        assert_eq!(board.own_cert().not_after.get(), 1000);
    }

    /// The legitimate re-issue the rule above must not catch: a fresh window,
    /// opening at the instant the authority signed it.
    #[test]
    fn a_renew_reply_opening_a_later_window_is_still_accepted() {
        let real = Authority::from_seed(&[7; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        let current = real.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 500, 1000);
        let mut board = OgmAuth::new(Keypair::from_seed(&[1; 32]), current, real.trust_anchor());
        board.set_time(Duration::from_secs(100), Clocked::At(900));
        board.set_renewal_authority(Some(&Keypair::from_seed(&[3; 32]).ed_pubkey()));
        let mut buf = [0u8; 512];
        board.build_renewal_request(&mut buf).unwrap();

        let fresh = real.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 900, 1900);
        assert!(board.ingest_renew_reply(fresh.as_bytes()));
        assert_eq!(board.own_cert().not_after.get(), 1900);
    }

    /// **Equality on `not_before` is admitted**, and this pins it because the
    /// natural "tighten it" edit is to make the comparison match the `<=` used
    /// on `not_after` one line above.
    ///
    /// Two issues inside the same second share a `not_before` — the authority
    /// stamps it from a whole-second clock — so refusing equality would refuse
    /// a legitimate re-issue. The board would then retry every fifteen minutes
    /// forever while its two counters diverged, which is the failure the
    /// counters exist to report and would here be self-inflicted.
    #[test]
    fn a_renew_reply_reissued_within_the_same_second_is_accepted() {
        let real = Authority::from_seed(&[7; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        let current = real.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 500, 1000);
        let mut board = OgmAuth::new(Keypair::from_seed(&[1; 32]), current, real.trust_anchor());
        board.set_time(Duration::from_secs(100), Clocked::At(900));
        board.set_renewal_authority(Some(&[0x0B; 32]));
        let mut buf = [0u8; 512];
        board.build_renewal_request(&mut buf).unwrap();

        // Same `not_before`, later `not_after`.
        let same_second = real.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 500, 5000);
        assert!(board.ingest_renew_reply(same_second.as_bytes()));
        assert_eq!(board.own_cert().not_after.get(), 5000);
    }

    /// An outstanding request **expires**. Without that, a board partitioned
    /// from its authority stays "outstanding" for the rest of its boot after a
    /// single ask, and the rule that a reply must answer a request of this
    /// node's own degrades to "this node has asked at least once since
    /// power-on" — on exactly the board most likely to be partitioned.
    #[test]
    fn a_renew_reply_arriving_long_after_the_ask_is_dropped() {
        let real = Authority::from_seed(&[7; 32], 42);
        let kp = Keypair::from_seed(&[1; 32]);
        let mut board = board_awaiting_reply(&real);

        // Well past the window in which a reply could be answering that ask.
        board.set_time(
            Duration::from_secs(100) + OUTSTANDING_RENEWAL_TTL,
            Clocked::At(200),
        );

        let fresh = real.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 5000);
        assert!(
            !board.ingest_renew_reply(fresh.as_bytes()),
            "the slot aged out, so nothing is outstanding for this to answer"
        );
        assert_eq!(board.own_cert().not_after.get(), 1000);
    }

    /// A [`Paths`] view with one route, standing in for the routing engine.
    ///
    /// The point of the seam: renewal needs exactly three facts to address a
    /// frame, so its emission path can be exercised without a `CentralRouter`,
    /// a `BatmanEngine` or a converged mesh behind it.
    struct OneRoute {
        me: Mac,
        to: Mac,
        via: Mac,
    }

    impl Paths for OneRoute {
        fn self_ident(&self) -> Mac {
            self.me
        }
        fn next_hop(&self, _now: Duration, dest: Mac) -> Option<Mac> {
            (dest == self.to).then_some(self.via)
        }
        fn next_hop_unproven_ok(&self, now: Duration, dest: Mac) -> Option<Mac> {
            self.next_hop(now, dest)
        }
    }

    /// A [`Paths`] view whose only path runs through a hop that has **not**
    /// proven itself: `next_hop_unproven_ok` answers, `next_hop` does not.
    ///
    /// The distinction [`OneRoute`] cannot express, and the one the two
    /// renewal tests below exist to pin.
    struct OnlyUnproven {
        me: Mac,
        to: Mac,
        via: Mac,
    }

    impl Paths for OnlyUnproven {
        fn self_ident(&self) -> Mac {
            self.me
        }
        fn next_hop(&self, _now: Duration, _dest: Mac) -> Option<Mac> {
            None
        }
        fn next_hop_unproven_ok(&self, _now: Duration, dest: Mac) -> Option<Mac> {
            (dest == self.to).then_some(self.via)
        }
    }

    /// A renewal request is **not** sent over an unproven next hop.
    ///
    /// The one property separating renewal from the cert-distribution exchange
    /// it is otherwise cut from, and nothing else pins it: swapping
    /// [`poll_renewal`](OgmAuth::poll_renewal)'s [`Paths::next_hop`] for
    /// [`Paths::next_hop_unproven_ok`] passes every other test in the
    /// workspace, because they all prove the peer first and a *proven* hop
    /// satisfies both.
    ///
    /// What the regression would cost is worse than a dropped frame.
    /// `build_renewal_request` bumps
    /// [`renewal_requests_sent`](OgmAuth::renewal_requests_sent) before the
    /// frame reaches the driver's pairwise-tag stage, so a board would report
    /// itself renewing, raise no alarm, and never renew.
    #[test]
    fn a_renewal_request_is_not_sent_over_an_unproven_hop() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let mut board = renewing_board(&authority, 1, 3, 1000);
        board.set_time(Duration::ZERO, Clocked::At(800));
        let paths = OnlyUnproven {
            me: mac(1),
            to: mac(3),
            via: mac(2),
        };

        let mut tx = [0u8; 512];
        assert!(
            board
                .poll_renewal(Duration::ZERO, &paths, &mut tx)
                .is_none(),
            "the only path is via an unproven hop, so there is no path"
        );
        assert_eq!(
            board.renewal_requests_sent(),
            0,
            "and nothing counted a request that never left"
        );
    }

    /// Nor is the authority's answer, for the same reason.
    #[test]
    fn a_renewal_reply_is_not_sent_over_an_unproven_hop() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let mut ca = member(&authority, 3, mac(3), 1000);
        let kp = Keypair::from_seed(&[1; 32]);
        let reissued = authority.issue_cert(mac(1), kp.ed_pubkey(), kp.x_pubkey(), 0, 2000);
        let paths = OnlyUnproven {
            me: mac(3),
            to: mac(1),
            via: mac(2),
        };

        let mut tx = [0u8; 512];
        assert!(
            ca.send_renew_reply(Duration::ZERO, &paths, mac(1), &reissued, &mut tx)
                .is_none(),
            "a reissued certificate must not be handed to an unproven relay"
        );
    }

    /// The poll is paced by the auth module itself, not by whoever calls it.
    ///
    /// A second call at the same instant emits nothing, and the deadline is
    /// `RENEWAL_POLL_INTERVAL` out — which is what stops a shell that sleeps on
    /// [`next_renewal_after`](OgmAuth::next_renewal_after) from waking to a
    /// deadline it can never discharge, and what stops one that polls per frame
    /// from putting a request on a duty-cycled radio every frame.
    #[test]
    fn the_renewal_poll_is_paced_by_the_auth_module() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let mut board = renewing_board(&authority, 1, 3, 1000);
        // `member` certifies from 0 to `valid_to`, so 800 is inside the last
        // quarter: the only window a request is ever built from.
        board.set_time(Duration::ZERO, Clocked::At(800));
        let paths = OneRoute {
            me: mac(1),
            to: mac(3),
            via: mac(2),
        };

        let mut tx = [0u8; 512];
        let frame = board
            .poll_renewal(Duration::ZERO, &paths, &mut tx)
            .expect("due, with a route to the authority");
        assert_eq!(frame.dst, mac(2), "addressed to the next hop, not the CA");
        assert_eq!(frame.payload[0], BatmanPacketType::RenewReq.as_u8());
        assert_eq!(board.renewal_requests_sent(), 1);

        let mut tx = [0u8; 512];
        assert!(
            board
                .poll_renewal(Duration::ZERO, &paths, &mut tx)
                .is_none(),
            "one request per interval, however often the shell polls"
        );
        assert_eq!(
            board.next_renewal_after(Duration::ZERO),
            Some(RENEWAL_POLL_INTERVAL),
            "and the deadline moved, so a sleeping shell does not spin"
        );
    }

    /// No route to the authority still advances the deadline.
    ///
    /// The partitioned board, which is the ordinary condition on a mesh: it
    /// must retry on the *next* interval rather than on the next frame, and
    /// `renewal_requests_sent` must not move for an attempt that never left.
    #[test]
    fn a_board_with_no_route_to_its_authority_still_paces_itself() {
        let authority = Authority::from_seed(&[7; 32], 42);
        let mut board = renewing_board(&authority, 1, 3, 1000);
        board.set_time(Duration::ZERO, Clocked::At(800));
        // Knows a route to somebody, just not to the authority.
        let paths = OneRoute {
            me: mac(1),
            to: mac(9),
            via: mac(2),
        };

        let mut tx = [0u8; 512];
        assert!(
            board
                .poll_renewal(Duration::ZERO, &paths, &mut tx)
                .is_none()
        );
        assert_eq!(board.renewal_requests_sent(), 0);
        assert_eq!(
            board.next_renewal_after(Duration::ZERO),
            Some(RENEWAL_POLL_INTERVAL)
        );
    }
}
