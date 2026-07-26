//! Deterministic derivation of a node's mesh MAC address from its Ed25519
//! identity key, so the address a node routes under is stable across restarts
//! without depending on whatever the OS assigns a freshly-created TAP device.

use blake2::Blake2s256;
use blake2::Digest;
use interfaces::frame::Mac;

/// Domain-separation label folded into the pubkey when deriving the MAC, so
/// this hash use can never collide with another `Blake2s256` use over the same
/// pubkey bytes elsewhere in the crate (e.g. [`crate::key::Keypair::pairwise_key`]).
const MAC_DERIVE_LABEL: &[u8] = b"wayfinder-mac-v1";

/// Deterministically derive a node's mesh MAC address from its Ed25519 public
/// key, so the address is stable across restarts (unlike a MAC an OS assigns
/// a freshly-created TAP device) and self-consistent with the identity a
/// [`MembershipCert`](crate::MembershipCert) binds it to.
///
/// Takes the first 6 bytes of a domain-separated `Blake2s256` digest of the
/// pubkey, then forces the first octet's low two bits per standard MAC
/// addressing convention: the locally-administered bit (`0x02`) is set,
/// marking this as a software-assigned (non-vendor) address, and the
/// multicast/group bit (`0x01`) is cleared, so the result is always usable as
/// a unicast interface address.
pub fn derive_mac(ed_pubkey: &[u8; 32]) -> Mac {
    let mut h = Blake2s256::new();
    h.update(MAC_DERIVE_LABEL);
    h.update(ed_pubkey);
    let digest = h.finalize();

    let mut bytes = [0u8; 6];
    bytes.copy_from_slice(&digest[..6]);
    force_locally_administered_unicast(&mut bytes);

    Mac(bytes)
}

/// Force `bytes` into a valid locally-administered unicast MAC by setting the
/// locally-administered bit (`0x02`) and clearing the multicast/group bit
/// (`0x01`) on the first octet — the same convention [`derive_mac`] applies.
/// Exposed so a node with no persisted identity to derive from (mesh auth not
/// configured) can apply the same convention to a freshly-generated random
/// fallback MAC, keeping every MAC this crate ever hands out valid and
/// consistent.
pub fn force_locally_administered_unicast(bytes: &mut [u8; 6]) {
    bytes[0] = (bytes[0] & 0xFE) | 0x02;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Keypair;

    /// The same public key always derives the same MAC.
    #[test]
    fn derive_mac_is_deterministic() {
        let kp = Keypair::from_seed(&[7u8; 32]);
        let a = derive_mac(&kp.ed_pubkey());
        let b = derive_mac(&kp.ed_pubkey());
        assert_eq!(a, b);
    }

    /// The derived MAC always has the locally-administered bit (0x02) set on
    /// its first octet, per the standard MAC addressing convention for
    /// software-assigned (non-vendor) addresses.
    #[test]
    fn derive_mac_sets_locally_administered_bit() {
        let kp = Keypair::from_seed(&[1u8; 32]);
        let mac = derive_mac(&kp.ed_pubkey());
        assert_eq!(mac.0[0] & 0x02, 0x02);
    }

    /// The derived MAC always has the multicast/group bit (0x01) cleared on its
    /// first octet — it must be usable as a unicast interface address.
    #[test]
    fn derive_mac_clears_multicast_bit() {
        let kp = Keypair::from_seed(&[1u8; 32]);
        let mac = derive_mac(&kp.ed_pubkey());
        assert_eq!(mac.0[0] & 0x01, 0x00);
    }

    /// Distinct identity keys derive distinct MACs.
    #[test]
    fn derive_mac_differs_for_distinct_keys() {
        let a = Keypair::from_seed(&[1u8; 32]);
        let b = Keypair::from_seed(&[2u8; 32]);
        assert_ne!(derive_mac(&a.ed_pubkey()), derive_mac(&b.ed_pubkey()));
    }

    /// `Keypair::derived_mac` agrees with the free function it wraps.
    #[test]
    fn keypair_derived_mac_matches_free_fn() {
        let kp = Keypair::from_seed(&[42u8; 32]);
        assert_eq!(kp.derived_mac(), derive_mac(&kp.ed_pubkey()));
    }
}
