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

use crate::error::AuthError;
use crate::key::verify_signature;

/// Version byte for [`RevocationRecord`]; the only version accepted.
pub const REVOKE_VERSION: u8 = 1;

/// A mesh root's signed statement that a node MAC is no longer a member, flooded
/// across the mesh for immediate removal.  Nodes add the MAC to their local
/// revocation set and drop its frames; passive cert expiry then makes the
/// removal permanent without further traffic.
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
    /// Unix-seconds instant the revocation takes effect.  Network byte order.
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
    /// The byte range the signature covers: every field except the trailing
    /// signature.
    pub fn signed_body(&self) -> &[u8] {
        let body_len = core::mem::size_of::<RevocationRecord>() - 64;
        &self.as_bytes()[..body_len]
    }
}

impl crate::cert::TrustAnchor {
    /// Verify a flooded `record` against this anchor as of `now_unix`,
    /// returning the revoked MAC on success.  Checks the version, that it is
    /// for this mesh, the root signature — so an attacker cannot forge
    /// revocations to evict honest nodes — and that the record has not already
    /// expired.
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
