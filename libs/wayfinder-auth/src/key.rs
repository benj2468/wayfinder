//! Node key material: an Ed25519 identity keypair plus the X25519 key used for
//! pairwise key agreement, both derived deterministically from one 32-byte seed.

use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

/// Domain-separation label folded into the seed when deriving the X25519 secret,
/// so the agreement key is independent of the Ed25519 signing key even though
/// both come from the same seed.
const X25519_DERIVE_LABEL: &[u8] = b"wayfinder-x25519-v1";

/// A node's long-term key material.
///
/// Holds the Ed25519 signing key (its cryptographic identity, bound to a MAC by
/// a [`MembershipCert`](crate::MembershipCert)) and a matching X25519 secret for
/// deriving pairwise data-plane keys with neighbors.  Both are derived from a
/// single 32-byte seed via [`Keypair::from_seed`], so persisting a node's
/// identity is just persisting that seed.
pub struct Keypair {
    signing: SigningKey,
    x_secret: StaticSecret,
}

impl Keypair {
    /// Derive a keypair deterministically from a 32-byte seed.  The same seed
    /// always yields the same identity, so a node persists its identity by
    /// persisting the seed.  The X25519 secret is derived from a domain-separated
    /// hash of the seed so it is independent of the Ed25519 key.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);

        let mut h = Blake2s256::new();
        h.update(X25519_DERIVE_LABEL);
        h.update(seed);
        let x_seed: [u8; 32] = h.finalize().into();

        Self {
            signing,
            x_secret: StaticSecret::from(x_seed),
        }
    }

    /// Generate a fresh random keypair from OS entropy.  Host-only (the portal
    /// and `wayfinder-tap` enrollment); embedded nodes load a persisted seed.
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS RNG unavailable");
        Self::from_seed(&seed)
    }

    /// This node's Ed25519 public key — the value bound to its MAC by a
    /// membership cert and used to verify its OGM signatures.
    pub fn ed_pubkey(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// This node's X25519 public key — carried in its cert so neighbors can
    /// derive the shared pairwise key with [`Keypair::pairwise_key`].
    pub fn x_pubkey(&self) -> [u8; 32] {
        PublicKey::from(&self.x_secret).to_bytes()
    }

    /// Sign `msg` (e.g. an OGM's immutable header) with the Ed25519 identity key.
    /// Verify with [`verify_signature`] against [`Keypair::ed_pubkey`].
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Derive the symmetric pairwise key shared with the neighbor whose X25519
    /// public key is `peer_x_pubkey` (read from that neighbor's verified cert).
    /// Both ends compute the same key from their own secret and the other's
    /// public key — no handshake.  The raw Diffie-Hellman output is hashed
    /// (with domain separation) into the returned key, which feeds
    /// [`frame_tag`](crate::frame_tag).
    pub fn pairwise_key(&self, peer_x_pubkey: &[u8; 32]) -> [u8; 32] {
        let shared = self
            .x_secret
            .diffie_hellman(&PublicKey::from(*peer_x_pubkey));
        let mut h = Blake2s256::new();
        h.update(b"wayfinder-pairwise-v1");
        h.update(shared.as_bytes());
        h.finalize().into()
    }
}

/// Verify an Ed25519 `signature` over `msg` against `ed_pubkey`.  Returns
/// `false` for a malformed public key or a signature that does not verify;
/// `true` only on a valid signature.  Used to check OGM origin signatures and
/// (via the trust anchor) certificate signatures.
pub fn verify_signature(ed_pubkey: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(ed_pubkey) else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(signature))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seed deterministically yields the same keys every time.
    #[test]
    fn from_seed_is_deterministic() {
        let a = Keypair::from_seed(&[7u8; 32]);
        let b = Keypair::from_seed(&[7u8; 32]);
        assert_eq!(a.ed_pubkey(), b.ed_pubkey());
        assert_eq!(a.x_pubkey(), b.x_pubkey());
    }

    /// Distinct seeds yield distinct identities.
    #[test]
    fn different_seeds_differ() {
        let a = Keypair::from_seed(&[1u8; 32]);
        let b = Keypair::from_seed(&[2u8; 32]);
        assert_ne!(a.ed_pubkey(), b.ed_pubkey());
    }

    /// A signature from a key verifies under that key's public half, and a
    /// tampered message does not.
    #[test]
    fn sign_then_verify_roundtrips() {
        let kp = Keypair::from_seed(&[42u8; 32]);
        let msg = b"originator message header";
        let sig = kp.sign(msg);
        assert!(verify_signature(&kp.ed_pubkey(), msg, &sig));
        assert!(!verify_signature(
            &kp.ed_pubkey(),
            b"different bytes!!",
            &sig
        ));
    }

    /// A signature does not verify under a different node's public key.
    #[test]
    fn signature_rejected_for_wrong_key() {
        let signer = Keypair::from_seed(&[3u8; 32]);
        let other = Keypair::from_seed(&[4u8; 32]);
        let sig = signer.sign(b"hello");
        assert!(!verify_signature(&other.ed_pubkey(), b"hello", &sig));
    }

    /// Both ends of a pair derive the identical pairwise key from their own
    /// secret and the peer's public X25519 key (the no-handshake property).
    #[test]
    fn pairwise_key_agreement_is_symmetric() {
        let a = Keypair::from_seed(&[10u8; 32]);
        let b = Keypair::from_seed(&[20u8; 32]);
        let ka = a.pairwise_key(&b.x_pubkey());
        let kb = b.pairwise_key(&a.x_pubkey());
        assert_eq!(ka, kb);
    }

    /// A third party derives a different key — it cannot reconstruct the pair's
    /// shared secret without one of their private keys.
    #[test]
    fn pairwise_key_differs_for_third_party() {
        let a = Keypair::from_seed(&[10u8; 32]);
        let b = Keypair::from_seed(&[20u8; 32]);
        let eve = Keypair::from_seed(&[99u8; 32]);
        let ab = a.pairwise_key(&b.x_pubkey());
        let eve_b = eve.pairwise_key(&b.x_pubkey());
        assert_ne!(ab, eve_b);
    }
}
