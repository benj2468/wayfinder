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
    /// Verify a flooded `record` against this anchor, returning the revoked MAC
    /// on success.  Checks the version, that it is for this mesh, and the root
    /// signature — so an attacker cannot forge revocations to evict honest
    /// nodes.
    pub fn verify_revocation(&self, record: &RevocationRecord) -> Result<Mac, AuthError> {
        if record.version != REVOKE_VERSION {
            return Err(AuthError::BadVersion);
        }
        if record.mesh_id.get() != self.mesh_id {
            return Err(AuthError::WrongMesh);
        }
        if !verify_signature(&self.root_pubkey, record.signed_body(), &record.signature) {
            return Err(AuthError::BadSignature);
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
            authority.trust_anchor().verify_revocation(&record),
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
            real.trust_anchor().verify_revocation(&record),
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
            authority.trust_anchor().verify_revocation(&record),
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
        assert_eq!(anchor.verify_revocation(&record), Err(AuthError::WrongMesh));
    }
}
