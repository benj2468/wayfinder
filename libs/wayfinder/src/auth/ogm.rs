//! The OGM/keep-alive TVLV envelope: the certificate and signature records
//! this node attaches to its own emissions, and the verification an incoming
//! one is gated on.

use super::*;

impl<
    const MAX_NEIGHBOR_KEYS: usize,
    const MAX_REVOKED: usize,
    const MAX_IN_FLIGHT_CERT_REQUESTS: usize,
    const MAX_PENDING_REPLIES: usize,
> OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>
{
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
    pub(super) fn signed_message<'a>(
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
    pub(super) fn write_tvlv(
        buf: &mut [u8],
        off: usize,
        tvlv_type: TvlvType,
        value: &[u8],
    ) -> usize {
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
        // Since issue #18 (design 09 §5) landed, a certificate cannot name an
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
    pub(super) fn keepalive_signed_message<'a>(
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

    /// Verify an incoming keep-alive's
    /// [`augment_keepalive`](Self::augment_keepalive) trailer, claimed
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
}

#[cfg(test)]
mod tests {
    //! Tests for the OGM/keep-alive TVLV envelope.

    use super::*;

    use super::super::testutil::*;
    use batman::wire::BatmanPacketType;
    use wayfinder_auth::Authority;

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

    /// Augmentation preserves an existing TVLV tail (e.g. mcast) and the
    /// signature still verifies — cert/sig are appended, not overwriting.
    #[test]
    fn augment_preserves_existing_tvlv_tail() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        // Hand-build an OGM with a small pre-existing TVLV record in the tail.
        let (mut buf, mut len) = bare_ogm(mac(2), 7);
        len = DefaultAuth::write_tvlv(&mut buf, len, batman::wire::TvlvType::Mcast, &[1, 2, 3, 4]);
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
                DefaultAuth::signed_message(&orig, &seqno, cert_bytes, &mut auth.sign_scratch)
                    .unwrap();
            auth.keypair.sign(signed)
        };
        let fp = cert.fingerprint();
        let mut off = len;
        off = DefaultAuth::write_tvlv(buf, off, TvlvType::CertFp, &fp);
        off = DefaultAuth::write_tvlv(buf, off, TvlvType::OgmSig, &signature);
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
}
