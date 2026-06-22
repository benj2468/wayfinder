//! The membership certificate and the per-mesh trust anchor that verifies it.

use interfaces::frame::Mac;
use zerocopy::byteorder::network_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::error::AuthError;
use crate::key::verify_signature;

/// Version byte stamped on every [`MembershipCert`] this build produces and the
/// only version it accepts.  Bump when the signed layout changes.
pub const CERT_VERSION: u8 = 1;

/// A membership certificate: the mesh root's signed attestation that an Ed25519
/// identity key (and its companion X25519 agreement key) belongs to a particular
/// node MAC on a particular mesh, valid for a bounded window.
///
/// Laid out as a fixed `#[repr(C, packed)]` record so it travels verbatim in an
/// OGM TVLV and parses zero-copy on the receiver.  The trailing
/// [`signature`](Self::signature) covers every preceding field (see
/// [`Self::signed_body`]); a verifier recomputes that range and checks it
/// against the [`TrustAnchor`].
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct MembershipCert {
    /// Layout/version marker; must equal [`CERT_VERSION`].
    pub version: u8,
    /// Reserved flag bits; sent as 0.
    pub flags: u8,
    /// The mesh this cert grants membership to (must match the verifier's
    /// trust anchor).  Network byte order.
    pub mesh_id: U32,
    /// The node MAC this cert binds the keys to.
    pub node_mac: [u8; 6],
    /// The node's Ed25519 identity public key (verifies its OGM signatures).
    pub ed_pubkey: [u8; 32],
    /// The node's X25519 public key (for pairwise key agreement with neighbors).
    pub x_pubkey: [u8; 32],
    /// Unix-seconds instant before which the cert is not yet valid.  Network
    /// byte order.
    pub not_before: U64,
    /// Unix-seconds instant after which the cert has expired.  Short-lived certs
    /// are the passive revocation mechanism.  Network byte order.
    pub not_after: U64,
    /// Ed25519 signature by the mesh root over [`Self::signed_body`].
    pub signature: [u8; 64],
}

impl MembershipCert {
    /// The byte range the signature covers: every field except the trailing
    /// 64-byte signature itself.  Both the issuer (when signing) and the
    /// verifier compute the signature over exactly these bytes.
    pub fn signed_body(&self) -> &[u8] {
        let body_len = core::mem::size_of::<MembershipCert>() - 64;
        &self.as_bytes()[..body_len]
    }
}

/// The root of trust for one mesh: its identifier and the root public key that
/// signs every member's certificate.  A node ships with the anchor of the mesh
/// it belongs to and accepts only certificates that verify against it — which is
/// exactly what segregates one mesh from another sharing the same medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The mesh this anchor is the root of.
    pub mesh_id: u32,
    /// The mesh root's Ed25519 public key.
    pub root_pubkey: [u8; 32],
}

/// The trusted facts extracted from a certificate once it has verified: used by
/// the router to attribute OGM signatures and derive pairwise data-plane keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedCert {
    /// The node MAC the cert is bound to.
    pub mac: Mac,
    /// The node's verified Ed25519 identity key.
    pub ed_pubkey: [u8; 32],
    /// The node's verified X25519 agreement key.
    pub x_pubkey: [u8; 32],
    /// When the cert expires (unix seconds), so the router can age it out.
    pub not_after: u64,
}

impl TrustAnchor {
    /// Verify `cert` against this anchor as of `now_unix` (unix seconds).
    ///
    /// Checks, in order: the version byte, that the cert is for *this* mesh, the
    /// root signature, and the validity window.  Returns the trusted facts on
    /// success, or the first failing [`AuthError`].  Fail-closed: any error
    /// means the cert (and the frame carrying it) must be rejected.
    pub fn verify_cert(
        &self,
        cert: &MembershipCert,
        now_unix: u64,
    ) -> Result<VerifiedCert, AuthError> {
        if cert.version != CERT_VERSION {
            return Err(AuthError::BadVersion);
        }
        if cert.mesh_id.get() != self.mesh_id {
            return Err(AuthError::WrongMesh);
        }
        if !verify_signature(&self.root_pubkey, cert.signed_body(), &cert.signature) {
            return Err(AuthError::BadSignature);
        }
        // Copy out of the packed struct before comparing (no refs into packed).
        let not_before = cert.not_before.get();
        let not_after = cert.not_after.get();
        if now_unix < not_before {
            return Err(AuthError::NotYetValid);
        }
        if now_unix > not_after {
            return Err(AuthError::Expired);
        }
        Ok(VerifiedCert {
            mac: Mac(cert.node_mac),
            ed_pubkey: cert.ed_pubkey,
            x_pubkey: cert.x_pubkey,
            not_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Authority;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A cert issued by an authority verifies against that authority's anchor
    /// within its validity window, and yields the bound keys.
    #[test]
    fn issued_cert_verifies() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(mac(5), node.ed_pubkey(), node.x_pubkey(), 100, 200);

        let verified = authority.trust_anchor().verify_cert(&cert, 150).unwrap();
        assert_eq!(verified.mac, mac(5));
        assert_eq!(verified.ed_pubkey, node.ed_pubkey());
        assert_eq!(verified.x_pubkey, node.x_pubkey());
        assert_eq!(verified.not_after, 200);
    }

    /// A cert from another mesh's authority fails on the trust-anchor signature
    /// (different root key) — this is the segregation property.
    #[test]
    fn foreign_authority_cert_rejected() {
        let ours = Authority::from_seed(&[1u8; 32], 0xABCD);
        let theirs = Authority::from_seed(&[9u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = theirs.issue_cert(mac(5), node.ed_pubkey(), node.x_pubkey(), 100, 200);
        assert_eq!(
            ours.trust_anchor().verify_cert(&cert, 150),
            Err(AuthError::BadSignature)
        );
    }

    /// A cert for a different mesh id is rejected before the signature check.
    #[test]
    fn wrong_mesh_rejected() {
        let authority = Authority::from_seed(&[1u8; 32], 0x1111);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(mac(5), node.ed_pubkey(), node.x_pubkey(), 100, 200);
        let mut anchor = authority.trust_anchor();
        anchor.mesh_id = 0x2222;
        assert_eq!(anchor.verify_cert(&cert, 150), Err(AuthError::WrongMesh));
    }

    /// The validity window is enforced at both ends.
    #[test]
    fn expiry_window_enforced() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(mac(5), node.ed_pubkey(), node.x_pubkey(), 100, 200);
        let anchor = authority.trust_anchor();
        assert_eq!(anchor.verify_cert(&cert, 99), Err(AuthError::NotYetValid));
        assert_eq!(anchor.verify_cert(&cert, 201), Err(AuthError::Expired));
        assert!(anchor.verify_cert(&cert, 100).is_ok());
        assert!(anchor.verify_cert(&cert, 200).is_ok());
    }

    /// Tampering with any signed field invalidates the signature.
    #[test]
    fn tampered_cert_rejected() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let mut cert = authority.issue_cert(mac(5), node.ed_pubkey(), node.x_pubkey(), 100, 200);
        // Flip the bound MAC; the signature no longer covers these bytes.
        cert.node_mac = mac(6).0;
        assert_eq!(
            authority.trust_anchor().verify_cert(&cert, 150),
            Err(AuthError::BadSignature)
        );
    }

    /// A cert parses zero-copy from its own bytes unchanged (wire round-trip).
    #[test]
    fn cert_roundtrips_through_bytes() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(mac(5), node.ed_pubkey(), node.x_pubkey(), 100, 200);
        let bytes = cert.as_bytes().to_vec();
        let (parsed, _) = MembershipCert::ref_from_prefix(&bytes).unwrap();
        assert!(authority.trust_anchor().verify_cert(parsed, 150).is_ok());
    }

    use crate::key::Keypair;
}
