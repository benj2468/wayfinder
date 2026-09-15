//! Next-hop proof (design 09): the challenge/response that shows a
//! candidate next hop holds the key its certificate names.
//!
//! Both frames are built here; the **scheduling** is not, and that split is
//! deliberate. Which neighbour is due a challenge, and the backoff that keeps a
//! failing candidate from starving the rest, live in the routing engine's
//! per-neighbour proof table — `BatmanEngine::challenge_candidates` /
//! `note_challenged` / `note_proven`. This module holds the keys and knows
//! nothing about who is a candidate; the engine holds the schedule and knows
//! nothing about keys. `CentralRouter::poll_challenge` is the one place the two
//! meet, and its whole routing content is two calls — pick a candidate, record
//! that it was asked — with the frame itself built here.
//!
//! Unlike every other exchange in this module these frames are **link-local**:
//! they take no [`Paths`](super::Paths) view at all, because a challenge goes
//! to the neighbour being challenged and its answer goes straight back out the
//! interface the challenge arrived on. Resolving either through routing state
//! would be the bug, not the feature.

use super::*;
use crate::BATMAN_VERSION;
use crate::ETH_P_BATMAN;
use crate::LinkFrameData;
use batman::wire::BatmanNextHopChallengePacket;
use batman::wire::BatmanNextHopResponsePacket;
use tracing::trace;

impl<
    const MAX_NEIGHBOR_KEYS: usize,
    const MAX_REVOKED: usize,
    const MAX_IN_FLIGHT_CERT_REQUESTS: usize,
    const MAX_PENDING_REPLIES: usize,
> OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>
{
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
    pub(super) fn nonce_prf_key(&self) -> [u8; 32] {
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

    /// Build the `NextHopChallenge` frame for `target` into `tx_buf`.
    ///
    /// `None` when there is no cached key for `target` — the ordinary state of
    /// an unproven relay, and exactly the attacker case this feature defends
    /// against — or when `tx_buf` cannot hold the header and nonce. A caller
    /// that has already marked the candidate challenged must treat both as
    /// "attempted"; see `CentralRouter::poll_challenge` for why.
    pub fn build_challenge_frame<'tx>(
        &mut self,
        target: Mac,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx>> {
        let nonce = self.issue_challenge(target)?;
        let hdr_len = core::mem::size_of::<BatmanNextHopChallengePacket>();
        let total = hdr_len + nonce.len();
        if tx_buf.len() < total {
            trace!("drop: tx buffer too small for challenge");
            return None;
        }
        let hdr = BatmanNextHopChallengePacket {
            packet_type: BatmanPacketType::NextHopChallenge.as_u8(),
            version: BATMAN_VERSION,
        };
        tx_buf[..hdr_len].copy_from_slice(hdr.as_bytes());
        tx_buf[hdr_len..total].copy_from_slice(&nonce);
        Some(LinkFrameData {
            dst: target,
            protocol: ETH_P_BATMAN,
            payload: &tx_buf[..total],
        })
    }

    /// Answer a `NextHopChallenge` from `src`, writing the `NextHopResponse`
    /// into `tx_buf`.
    ///
    /// `body` is the challenge's nonce (the payload past its header). `None`
    /// when the challenger is unverified — answering is refused inside
    /// [`answer_challenge`](Self::answer_challenge), since there is no pairwise
    /// key and a reply would cost work while telling the asker nothing — or
    /// when `tx_buf` cannot hold the response.
    ///
    /// The returned frame is addressed to `src` and must be pinned to the
    /// interface the challenge arrived on; see this module's header.
    pub fn answer_challenge_frame<'tx>(
        &self,
        src: Mac,
        body: &[u8],
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx>> {
        let Some(tag) = self.answer_challenge(src, body) else {
            trace!(?src, "drop: challenge from an unverified peer");
            return None;
        };
        let rsp_len = core::mem::size_of::<BatmanNextHopResponsePacket>();
        let total = rsp_len + tag.len();
        if tx_buf.len() < total {
            trace!("drop: tx buffer too small for challenge response");
            return None;
        }
        let hdr = BatmanNextHopResponsePacket {
            packet_type: BatmanPacketType::NextHopResponse.as_u8(),
            version: BATMAN_VERSION,
        };
        tx_buf[..rsp_len].copy_from_slice(hdr.as_bytes());
        tx_buf[rsp_len..total].copy_from_slice(&tag);
        Some(LinkFrameData {
            dst: src,
            protocol: ETH_P_BATMAN,
            payload: &tx_buf[..total],
        })
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the next-hop proof challenge/response.

    use super::*;

    use super::super::testutil::*;
    use batman::wire::BatmanPacketType;
    use wayfinder_auth::Authority;

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
