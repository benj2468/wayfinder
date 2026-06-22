//! The mesh certificate authority — the signing role run by the enrollment
//! portal.  Host-only (`std`): it holds the mesh root key, issues member
//! certificates, and signs revocations.  Embedded nodes never link this module;
//! they only *verify* against a [`TrustAnchor`].

use interfaces::frame::Mac;
use zerocopy::byteorder::network_endian::{U32, U64};

use crate::cert::{CERT_VERSION, MembershipCert, TrustAnchor};
use crate::key::Keypair;
use crate::revoke::{REVOKE_VERSION, RevocationRecord};

/// A mesh's certificate authority: custody of the root key plus the mesh id it
/// is the root of.  Created from a persisted root seed at portal startup.
pub struct Authority {
    root: Keypair,
    mesh_id: u32,
}

impl Authority {
    /// Build an authority from an existing root keypair and its mesh id.
    pub fn new(root: Keypair, mesh_id: u32) -> Self {
        Self { root, mesh_id }
    }

    /// Build an authority by deriving the root keypair from a 32-byte seed.
    /// Persisting the seed (securely) persists the entire mesh root of trust.
    pub fn from_seed(seed: &[u8; 32], mesh_id: u32) -> Self {
        Self::new(Keypair::from_seed(seed), mesh_id)
    }

    /// The mesh id this authority is the root of.
    pub fn mesh_id(&self) -> u32 {
        self.mesh_id
    }

    /// The public trust anchor for this mesh, distributed to every member so it
    /// can verify certs and revocations.
    pub fn trust_anchor(&self) -> TrustAnchor {
        TrustAnchor {
            mesh_id: self.mesh_id,
            root_pubkey: self.root.ed_pubkey(),
        }
    }

    /// Issue a membership certificate binding `mac` to the given Ed25519 and
    /// X25519 public keys, valid over `[not_before, not_after]` (unix seconds).
    /// Keep the window short — expiry is the passive revocation mechanism.
    pub fn issue_cert(
        &self,
        mac: Mac,
        ed_pubkey: [u8; 32],
        x_pubkey: [u8; 32],
        not_before: u64,
        not_after: u64,
    ) -> MembershipCert {
        let mut cert = MembershipCert {
            version: CERT_VERSION,
            flags: 0,
            mesh_id: U32::new(self.mesh_id),
            node_mac: mac.0,
            ed_pubkey,
            x_pubkey,
            not_before: U64::new(not_before),
            not_after: U64::new(not_after),
            signature: [0u8; 64],
        };
        // The signed body is every field except the trailing signature, which
        // is currently zeroed; sign it then stamp the signature in.
        let signature = self.root.sign(cert.signed_body());
        cert.signature = signature;
        cert
    }

    /// Sign a revocation for `mac`, effective at `not_before` (unix seconds),
    /// for flooding across the mesh as an emergency purge.
    pub fn revoke(&self, mac: Mac, not_before: u64) -> RevocationRecord {
        let mut record = RevocationRecord {
            version: REVOKE_VERSION,
            flags: 0,
            mesh_id: U32::new(self.mesh_id),
            node_mac: mac.0,
            not_before: U64::new(not_before),
            signature: [0u8; 64],
        };
        let signature = self.root.sign(record.signed_body());
        record.signature = signature;
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// The anchor exposes the mesh id and the root's public key.
    #[test]
    fn trust_anchor_matches_root() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();
        assert_eq!(anchor.mesh_id, 0xABCD);
        assert_eq!(
            anchor.root_pubkey,
            Keypair::from_seed(&[1u8; 32]).ed_pubkey()
        );
    }

    /// Two authorities with different seeds produce different anchors even on
    /// the same mesh id — distinct roots of trust.
    #[test]
    fn distinct_roots_distinct_anchors() {
        let a = Authority::from_seed(&[1u8; 32], 0xABCD);
        let b = Authority::from_seed(&[2u8; 32], 0xABCD);
        assert_ne!(a.trust_anchor().root_pubkey, b.trust_anchor().root_pubkey);
        // And a's cert does not verify under b's anchor.
        let node = Keypair::from_seed(&[3u8; 32]);
        let cert = a.issue_cert(mac(1), node.ed_pubkey(), node.x_pubkey(), 0, 100);
        assert!(b.trust_anchor().verify_cert(&cert, 50).is_err());
    }
}
