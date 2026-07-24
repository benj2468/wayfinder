//! Shared bridge between the mesh Ed25519 identity and rustls **raw public
//! keys** (RFC 7250), used by both ends of the management API's TLS transport.
//!
//! The management TLS handshake carries a bare Ed25519 key rather than an X.509
//! chain: each side presents its own identity key, and the peer's key is
//! surfaced for an app-layer authorization decision. Two bridges are needed
//! because the mesh identity is an
//! [`ed25519-dalek`](https://docs.rs/ed25519-dalek) seed while the TLS stack is
//! `ring`-backed — the same Ed25519 keys, different libraries:
//!
//! * [`certified_key_from_seed`] turns a 32-byte seed into a rustls
//!   [`CertifiedKey`] to *present* in the handshake.
//! * [`raw_ed25519_from_spki`] recovers a peer's raw 32-byte key from the SPKI
//!   DER rustls hands back in `peer_certificates()`.
//!
//! Both the `wayfinder-server` (which presents the node's key and reads the
//! connecting client's) and `wayfinder-client` (which presents the operator's
//! key and pins the node's) crates depend on this crate rather than on each
//! other, so the bridge logic — and its wire-format edge cases — lives in
//! exactly one place.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::sync::Arc;

use rustls::DigitallySignedStruct;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{WebPkiSupportedAlgorithms, ring, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer,
};
use rustls::sign::CertifiedKey;

/// Fixed DER prefix of a PKCS#8 v1 Ed25519 private key, immediately followed by
/// the 32-byte seed.  `ring` loads Ed25519 via `from_pkcs8_maybe_unchecked`,
/// which accepts this seed-only v1 form (no embedded public key), so our
/// `ed25519-dalek` seed serialises directly.
const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Fixed DER prefix of an Ed25519 `SubjectPublicKeyInfo`, immediately followed by
/// the 32-byte public key.  This is what rustls presents for a raw public key and
/// returns in `peer_certificates()`.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Build a rustls raw-public-key [`CertifiedKey`] from a 32-byte Ed25519 seed —
/// the caller's own identity seed — for presenting in the RFC 7250 handshake.
/// The resulting key's presented "certificate" is the Ed25519 SPKI, so a peer
/// sees exactly the identity public key.
pub fn certified_key_from_seed(seed: &[u8; 32]) -> Result<Arc<CertifiedKey>, rustls::Error> {
    let mut pkcs8 = Vec::with_capacity(ED25519_PKCS8_V1_PREFIX.len() + 32);
    pkcs8.extend_from_slice(&ED25519_PKCS8_V1_PREFIX);
    pkcs8.extend_from_slice(seed);

    let signing_key = ring::default_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)))?;

    // The presented "certificate" for a raw public key is the SPKI DER.
    let spki = signing_key
        .public_key()
        .ok_or_else(|| rustls::Error::General("signing key exposes no public key".into()))?;
    let cert = vec![CertificateDer::from(spki.as_ref().to_vec())];

    Ok(Arc::new(CertifiedKey::new(cert, signing_key)))
}

/// Recover the raw 32-byte Ed25519 public key from a `SubjectPublicKeyInfo` DER
/// (the form rustls hands back for a raw-public-key peer), or `None` if `spki` is
/// not a well-formed Ed25519 SPKI.
pub fn raw_ed25519_from_spki(spki: &[u8]) -> Option<[u8; 32]> {
    let key = spki.strip_prefix(&ED25519_SPKI_PREFIX[..])?;
    key.try_into().ok()
}

/// Verify the TLS 1.3 `CertificateVerify` signature made over a raw public key.
///
/// Shared by both the client- and server-side certificate verifiers: for a raw
/// public key the peer's "certificate" bytes *are* the SPKI, so this hands them
/// to rustls's raw-key signature check against the crypto provider's supported
/// algorithms.
pub fn verify_raw_key_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    algs: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
    verify_tls13_signature_with_raw_key(message, &spki, dss, algs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder_auth::Keypair;

    /// A `CertifiedKey` built from a seed presents the Ed25519 SPKI for that
    /// seed, and the raw key recovered from that SPKI equals the public key
    /// `ed25519-dalek` derives from the *same* seed.  This is the interop
    /// guarantee that makes RPK sound here: the key TLS (ring) authenticates is
    /// byte-for-byte the identity the membership cert (dalek) binds.
    #[test]
    fn certified_key_roundtrips_to_the_dalek_ed25519_pubkey() {
        let seed = [7u8; 32];
        let ck = certified_key_from_seed(&seed).expect("valid seed builds a key");

        // The presented "certificate" is the raw-public-key SPKI DER.
        let spki = ck.cert[0].as_ref();
        let raw = raw_ed25519_from_spki(spki).expect("presented SPKI is Ed25519");

        assert_eq!(raw, Keypair::from_seed(&seed).ed_pubkey());
    }

    /// Non-Ed25519 or malformed SPKI input is rejected rather than mis-parsed.
    #[test]
    fn raw_ed25519_from_spki_rejects_non_ed25519() {
        assert!(raw_ed25519_from_spki(&[]).is_none());
        assert!(raw_ed25519_from_spki(&[0u8; 44]).is_none(), "wrong prefix");
        // Right prefix but truncated key.
        let mut short = ED25519_SPKI_PREFIX.to_vec();
        short.extend_from_slice(&[0u8; 31]);
        assert!(raw_ed25519_from_spki(&short).is_none());
    }
}
