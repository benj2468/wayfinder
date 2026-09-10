//! The signed revocation record used for active (emergency) purge of a node,
//! complementing the passive purge provided by short-lived cert expiry.

use interfaces::frame::Mac;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Unaligned;
use zerocopy::byteorder::network_endian::U32;
use zerocopy::byteorder::network_endian::U64;

use crate::clock::Clocked;
use crate::error::AuthError;
use crate::key::verify_signature;

/// Version byte for [`RevocationRecord`]; the only version accepted.
///
/// Bumped 1 → 2 when `not_before` gained its second meaning (the issuance
/// cut-off, see the field's docs).  The layout is byte-identical across the
/// two, so the version is the *only* thing separating them — and the two
/// readings fail in opposite directions (a v1 record read as v2 cancels
/// nothing; a v2 record read as v1 cancels a legitimate re-admission), which
/// is why there is no compatibility shim and a v1 record is simply refused.
pub const REVOKE_VERSION: u8 = 2;

/// A mesh root's signed statement that a node's credentials *as of a given
/// instant* are no longer valid, flooded across the mesh for immediate removal.
///
/// Nodes store the record and drop frames from any certificate for `node_mac`
/// issued at or before its [`not_before`](Self::not_before); one issued after is
/// a re-admission and survives.  It is deliberately **not** keyed on the MAC
/// alone — a node whose MAC it cannot readily change would otherwise be
/// excluded until `not_after` with no recovery.
/// Passive cert expiry then makes the removal permanent without further
/// traffic.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct RevocationRecord {
    /// Layout/version marker; must equal [`REVOKE_VERSION`].
    pub version: u8,
    /// Reserved flag bits; sent as 0.
    pub flags: u8,
    /// The mesh this revocation applies to.  Network byte order.
    pub mesh_id: U32,
    /// The node MAC being revoked.
    pub node_mac: [u8; 6],
    /// Unix-seconds instant the revocation takes effect, **and** the line
    /// dividing cancelled certificates from surviving ones: a certificate for
    /// [`node_mac`](Self::node_mac) is cancelled by this record only if its
    /// own `not_before` is at or before this instant.
    ///
    /// So a certificate issued *after* the revocation — a re-admission, which
    /// by definition the authority signed knowing it had revoked — is
    /// unaffected, and a re-approved node rejoins under its own MAC instead of
    /// waiting out [`not_after`](Self::not_after).  That matters most where a
    /// node's MAC is not the operator's to pick: it is the address its identity
    /// key derives (design 09 §5), so re-admitting a node under a *different*
    /// address means rotating its identity, and without this a revoked node
    /// would have no way back short of that.
    ///
    /// (This used to say an nRF board's MAC was FICR-derived and could not
    /// change at all. Design 22 made a board seed-derived like every other
    /// node, so the example is gone; the argument is unchanged and now applies
    /// uniformly.)
    ///
    /// The tie (a certificate issued in the same second) resolves toward
    /// *revoked*: this is a security control, and an authority re-admitting a
    /// node can trivially stamp the new certificate a second later, whereas
    /// the other reading would leave a same-second hole.
    ///
    /// **Must be non-zero.**  Zero would cancel no certificate at all while
    /// still verifying and flooding, so
    /// [`verify_revocation`](crate::cert::TrustAnchor::verify_revocation)
    /// refuses it as [`AuthError::NoRevocationInstant`].  Network byte order.
    pub not_before: U64,
    /// Unix-seconds instant the revocation expires and may be forgotten.  Set by
    /// the issuer to (at least) the revoked certificate's own `not_after`, so a
    /// node need only enforce the revocation until the cert it cancels would
    /// have expired anyway — after which passive expiry takes over.  This bounds
    /// how long a record must be retained, letting nodes garbage-collect it and
    /// keeping the local revocation set from filling permanently.  Network byte
    /// order.
    pub not_after: U64,
    /// Ed25519 signature by the mesh root over the preceding fields.
    pub signature: [u8; 64],
}

impl RevocationRecord {
    /// On-wire / on-disk size of a revocation record. Like
    /// [`MembershipCert::SERIALIZED_LEN`](crate::MembershipCert::SERIALIZED_LEN)
    /// this is `size_of::<Self>()`, named so callers that persist one do not
    /// recompute it.
    pub const SERIALIZED_LEN: usize = core::mem::size_of::<Self>();

    /// Parse an owned record from its raw
    /// [`as_bytes`](zerocopy::IntoBytes::as_bytes) form — a blob read back
    /// from a settings store, say — ignoring any trailing bytes.  `None` if
    /// `bytes` is shorter than the fixed layout.
    ///
    /// Mirrors [`MembershipCert::from_bytes`](crate::cert::MembershipCert::from_bytes),
    /// and exists for the same reason: a caller holding bytes should not have
    /// to depend on `zerocopy` to turn them into a record.  Parsing is not
    /// verification — the result still has to go through
    /// [`TrustAnchor::verify_revocation`](crate::cert::TrustAnchor::verify_revocation).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<RevocationRecord> {
        RevocationRecord::read_from_prefix(bytes)
            .ok()
            .map(|(r, _)| r)
    }

    /// The byte range the signature covers: every field except the trailing
    /// signature.
    pub fn signed_body(&self) -> &[u8] {
        let body_len = Self::SERIALIZED_LEN - 64;
        &self.as_bytes()[..body_len]
    }

    /// Whether this record cancels `cert` as of `now_unix`.
    ///
    /// Three questions at once, which is the point of having one function
    /// rather than the condition spelled out at each call site: the record
    /// must name the certificate's MAC, its enforcement window
    /// (`not_before .. not_after`, half-open) must contain `now_unix`, and the
    /// certificate must have been issued at or before the revocation instant.
    ///
    /// That last clause is what makes a revocation cancel *credentials* rather
    /// than a MAC forever — see [`not_before`](Self::not_before) for why, and
    /// for why the tie resolves toward cancelled.
    ///
    /// The caller must already have verified this record against the trust
    /// anchor; this is the enforcement question, not the authenticity one.
    #[must_use]
    pub fn cancels(&self, cert: &crate::cert::VerifiedCert, now_unix: u64) -> bool {
        self.cancels_cert_for(&cert.mac.0, cert.not_before, now_unix)
    }

    /// [`cancels`](Self::cancels) against a certificate's MAC and issuance
    /// instant directly, for the one caller that has neither a
    /// [`VerifiedCert`](crate::cert::VerifiedCert) nor a reason to make one:
    /// a node asking whether a record cancels **its own** certificate, which
    /// it already holds and has no need to re-verify against its own anchor.
    ///
    /// Kept as the primitive both entry points call so the condition is
    /// written once — two copies of it are two things to keep in step.
    #[must_use]
    pub fn cancels_cert_for(
        &self,
        node_mac: &[u8; 6],
        cert_not_before: u64,
        now_unix: u64,
    ) -> bool {
        self.names_cert(node_mac, cert_not_before)
            && self.not_before.get() <= now_unix
            && now_unix < self.not_after.get()
    }

    /// The **clock-free** half of [`cancels`](Self::cancels): does this record
    /// name this certificate at all — same MAC, and issued at or before the
    /// revocation instant?
    ///
    /// Split out because it is the half that answers "is this credential the
    /// one being cancelled", and it compares two CA-signed instants with no
    /// wall clock involved. The other half — whether the record is *in force
    /// right now* — is the only part that needs a clock, and is what
    /// [`cancels_under`](Self::cancels_under) varies by posture.
    ///
    /// This is what keeps "a node with no clock enforces its records" from
    /// meaning "this address is banned forever": a certificate issued after
    /// the revocation instant is a deliberate re-admission and is not named
    /// here, whatever the reader's clock says.
    #[must_use]
    pub fn names_cert(&self, node_mac: &[u8; 6], cert_not_before: u64) -> bool {
        &self.node_mac == node_mac && cert_not_before <= self.not_before.get()
    }

    /// Whether this record cancels `cert` under the reader's clock posture.
    ///
    /// [`cancels`](Self::cancels) asks the same question of a node that knows
    /// the time. This one is what a node that does not must ask, and the
    /// difference is confined to the enforcement window:
    ///
    /// | posture | enforcement window |
    /// |---|---|
    /// | [`Clocked::At`] | `not_before <= now < not_after`, as before |
    /// | [`Clocked::AtLeast`] / [`Clocked::Unknown`] | in force unless *provably* expired |
    ///
    /// **A held record is treated as in force when the window cannot be
    /// judged**, and that direction is deliberate. The alternative is what the
    /// bare `now_unix` produced: no real record has `not_before <= 0`, so a
    /// node with no clock silently enforced *nothing* — it would ingest a
    /// revocation, evict the named neighbour once (which looks like it
    /// worked), and re-admit them on their very next OGM. Design 20 §5.1 rests
    /// on the opposite: "an all-board segment keeps active revocation and
    /// loses passive."
    ///
    /// Erring toward enforcement is also the safe direction here in a way it
    /// is not for a certificate window. Refusing a peer costs one route;
    /// honouring a revoked one is the harm revocation exists to prevent. And
    /// the cost is bounded by [`names_cert`](Self::names_cert): the only node
    /// an over-long enforcement window can refuse is one still presenting the
    /// certificate the record was aimed at.
    #[must_use]
    pub fn cancels_under(&self, cert: &crate::cert::VerifiedCert, now: Clocked) -> bool {
        if !self.names_cert(&cert.mac.0, cert.not_before) {
            return false;
        }
        match now {
            Clocked::At(t) => self.not_before.get() <= t && t < self.not_after.get(),
            // Cannot place the window. Enforce unless the posture can *prove*
            // the record is spent — which a floor can, whenever it has already
            // reached `not_after`.
            Clocked::AtLeast(_) | Clocked::Unknown => !now.proves_reached(self.not_after.get()),
        }
    }
}

impl crate::cert::TrustAnchor {
    /// Verify a flooded `record` against this anchor as of `now_unix`,
    /// returning the revoked MAC on success.  Checks the version, that it is
    /// for this mesh, that it carries a revocation instant at all, the root
    /// signature — so an attacker cannot forge revocations to evict honest
    /// nodes — and that the record has not already expired.
    ///
    /// Note what this does *not* answer: whether the record cancels a
    /// particular certificate.  That needs the certificate, and is decided
    /// where the revocation set is consulted (`OgmAuth::is_revoked` in
    /// `wayfinder`), against `not_before` as the issuance cut-off.
    ///
    /// # What "as of `now_unix`" does and does not cover
    ///
    /// A record past its `not_after` is [`AuthError::Expired`]: the certificate
    /// it cancels has expired too, so there is nothing left to enforce and
    /// storing it would only occupy a slot in a bounded set. This check lives
    /// here rather than at each call site because this is the function a new
    /// caller reaches for, and a name like `verify_` should not leave the most
    /// consequential half of validity to whatever the caller remembers.
    ///
    /// A record whose `not_before` has *not* arrived is deliberately still
    /// `Ok`. It is a valid statement about the future, and a node that receives
    /// one should store it and enforce it when the time comes; whether a stored
    /// revocation is in force *now* is a separate question, answered where the
    /// revocation set is consulted ([`OgmAuth::is_revoked`] in `wayfinder`).
    ///
    /// A `now_unix` of zero — a node whose clock has never been set, which is
    /// the normal state of a freshly booted board — expires nothing, since no
    /// real record has a `not_after` at or below it. That falls out of the
    /// comparison rather than needing a special case, and a revocation is
    /// exactly the message such a node most needs to act on.
    ///
    /// [`OgmAuth::is_revoked`]: https://docs.rs/wayfinder
    pub fn verify_revocation(
        &self,
        record: &RevocationRecord,
        now_unix: u64,
    ) -> Result<Mac, AuthError> {
        if record.version != REVOKE_VERSION {
            return Err(AuthError::BadVersion);
        }
        if record.mesh_id.get() != self.mesh_id {
            return Err(AuthError::WrongMesh);
        }
        // Structural, so it sits with the version/mesh checks rather than with
        // the dated ones below: a zero instant is not a record that has gone
        // stale, it is a record that could never cancel anything.
        if record.not_before.get() == 0 {
            return Err(AuthError::NoRevocationInstant);
        }
        if !verify_signature(&self.root_pubkey, record.signed_body(), &record.signature) {
            return Err(AuthError::BadSignature);
        }
        // Copy out of the packed struct before comparing (no refs into packed).
        let not_after = record.not_after.get();
        if not_after <= now_unix {
            return Err(AuthError::Expired);
        }
        Ok(Mac(record.node_mac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Authority;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A revocation issued by an authority verifies against its anchor and names
    /// the revoked MAC.
    #[test]
    fn issued_revocation_verifies() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let record = authority.revoke(mac(7), 500, 1000);
        assert_eq!(
            authority.trust_anchor().verify_revocation(&record, 0),
            Ok(mac(7))
        );
    }

    /// A revocation that has already expired is refused by the anchor itself,
    /// rather than by whatever the caller remembers to check afterwards.
    ///
    /// The cancelled certificate has expired too, so there is nothing left to
    /// enforce — and the function a new caller reaches for should be the one
    /// that says so.
    #[test]
    fn an_expired_revocation_is_refused() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let record = authority.revoke(mac(7), 500, 1000);

        assert_eq!(
            authority.trust_anchor().verify_revocation(&record, 1000),
            Err(AuthError::Expired),
            "not_after is the instant it stops applying, not the last instant it does"
        );
        assert_eq!(
            authority.trust_anchor().verify_revocation(&record, 999),
            Ok(mac(7))
        );
    }

    /// A revocation with no instant (`not_before == 0`) is refused as
    /// malformed rather than accepted as a record that cancels nothing.
    ///
    /// Under v1 semantics zero meant "effective immediately"; under v2 the
    /// field is also the issuance cut-off, so a zero would verify, be stored,
    /// flood the mesh, and cancel no certificate at all — a security control
    /// that silently no-ops.  Refusing it here is what makes a v1-shaped
    /// record impossible to mistake for a v2 one.
    #[test]
    fn a_revocation_with_no_instant_is_refused() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let record = authority.revoke(mac(7), 0, 1000);
        assert_eq!(
            authority.trust_anchor().verify_revocation(&record, 100),
            Err(AuthError::NoRevocationInstant)
        );
    }

    /// A revocation dated to take effect later still verifies.
    ///
    /// Deliberately asymmetric with expiry, and the asymmetry is the point: a
    /// record whose `not_before` has not arrived is one a node should *store*
    /// and enforce when it does, so refusing it here would discard a valid
    /// statement about the future. Whether it is in force *now* is a separate
    /// question, answered where the revocation set is consulted.
    #[test]
    fn a_revocation_not_yet_in_force_still_verifies() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let record = authority.revoke(mac(7), 500, 1000);

        assert_eq!(
            authority.trust_anchor().verify_revocation(&record, 100),
            Ok(mac(7))
        );
    }

    /// A node whose clock has never been set treats every revocation as
    /// unexpired, rather than discarding all of them.
    ///
    /// An embedded node boots with no time source, and a revocation is the one
    /// message it most needs to act on. Zero falls out of the comparison
    /// correctly — nothing is `not_after <= 0` — so this needs no special case,
    /// only a test to keep one from being introduced.
    #[test]
    fn an_unset_clock_expires_nothing() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let record = authority.revoke(mac(7), 500, 1000);

        assert_eq!(
            authority.trust_anchor().verify_revocation(&record, 0),
            Ok(mac(7))
        );
    }

    /// A forged revocation (wrong signing key) is rejected, so an attacker
    /// cannot evict honest members.
    #[test]
    fn forged_revocation_rejected() {
        let real = Authority::from_seed(&[1u8; 32], 0xABCD);
        let attacker = Authority::from_seed(&[8u8; 32], 0xABCD);
        let record = attacker.revoke(mac(7), 500, 1000);
        assert_eq!(
            real.trust_anchor().verify_revocation(&record, 0),
            Err(AuthError::BadSignature)
        );
    }

    /// Tampering with the expiry (covered by the signed body) is rejected.
    #[test]
    fn tampered_not_after_rejected() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let mut record = authority.revoke(mac(7), 500, 1000);
        record.not_after = U64::new(9_999);
        assert_eq!(
            authority.trust_anchor().verify_revocation(&record, 0),
            Err(AuthError::BadSignature)
        );
    }

    /// A revocation for another mesh is rejected.
    #[test]
    fn wrong_mesh_revocation_rejected() {
        let authority = Authority::from_seed(&[1u8; 32], 0x1111);
        let record = authority.revoke(mac(7), 500, 1000);
        let mut anchor = authority.trust_anchor();
        anchor.mesh_id = 0x2222;
        assert_eq!(
            anchor.verify_revocation(&record, 0),
            Err(AuthError::WrongMesh)
        );
    }
}
