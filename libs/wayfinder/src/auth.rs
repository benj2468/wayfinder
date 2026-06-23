//! Opt-in OGM authentication, the control-plane half of mesh segregation.
//!
//! When a mesh enables authentication, every OGM carries two extra TVLV records
//! in its tail: the originator's membership certificate ([`WF_TVLV_CERT`]) and
//! an Ed25519 signature over the OGM's immutable identity fields
//! ([`WF_TVLV_OGM_SIG`]).  A receiver verifies the cert against its mesh trust
//! anchor and the signature against the cert's key, dropping anything that fails
//! — so an outsider (or a node from another mesh) cannot inject or forge OGMs,
//! and its topology never enters the routing table.
//!
//! This lives in the router (not the `batman` engine) so the engine stays free
//! of any crypto dependency: [`OgmAuth::augment_ogm`] post-processes the OGM the
//! engine builds, and [`OgmAuth::verify_ogm`] gates an incoming OGM *before* it
//! reaches the engine.  Because the engine preserves unknown TVLVs verbatim when
//! it re-floods, the cert/sig records propagate unchanged with no engine change.
//!
//! Only the *originator's* signature is checked here (one-to-many control
//! plane).  Directed data-plane frames are authenticated separately by a
//! pairwise tag keyed off the neighbor keys this module caches.
//!
//! **Scope (read before trusting this boundary):** this authenticates *OGMs*
//! only.  Data-plane batman frames — `BATADV_BCAST` (flooded ARP etc.),
//! `BATADV_UNICAST`, `BATADV_MCAST` — are **not** authenticated yet, so an
//! outsider can still inject/transit those (e.g. a broadcast flood) on an
//! auth-enabled mesh.  Segregation here is *control-plane* (a foreign node
//! cannot influence routing); full data-plane segregation arrives with the
//! pairwise tag.

use batman::wire::{BatmanOgmPacket, BatmanTvlvHdr, WF_TVLV_CERT, WF_TVLV_OGM_SIG, find_tvlv};
use heapless::Vec as HVec;
use interfaces::frame::Mac;
use wayfinder_auth::{Keypair, MembershipCert, TrustAnchor, verify_signature};
use zerocopy::{FromBytes, IntoBytes};

/// Fixed size of the BATMAN OGM header preceding the TVLV tail.
const OGM_HDR: usize = core::mem::size_of::<BatmanOgmPacket>();
/// Size of a TVLV record header.
const TVLV_HDR: usize = core::mem::size_of::<BatmanTvlvHdr>();
/// Byte offset of the OGM `seqno` field (after type/version/ttl/flags).
const SEQNO_OFF: usize = 4;
/// Byte offset of the OGM `orig` MAC field (after seqno).
const ORIG_OFF: usize = 8;
/// Byte offset of the OGM `tvlv_len` field (last two header bytes).
const TVLV_LEN_OFF: usize = OGM_HDR - 2;
/// Length of an Ed25519 signature.
const SIG_LEN: usize = 64;

/// Domain-separation prefix bound into the OGM signature so a signature can
/// never be confused with one over any other message type.
const SIG_DOMAIN: &[u8] = b"wf-ogm-sig-v1";

/// Maximum number of revoked MACs held in the local revocation set.
const MAX_REVOKED: usize = 32;
/// Maximum number of verified neighbor key records cached.
const MAX_NEIGHBOR_KEYS: usize = 64;

/// Size of the reused scratch buffer for assembling the OGM signed message
/// (domain prefix + orig + seqno + certificate).  Generous over the ~180-byte
/// maximum so the buffer can be a fixed field rather than re-created per call.
const SIGN_SCRATCH_LEN: usize = 256;

/// Compile-time guarantee that the scratch buffer fits the largest signed
/// message, so a future certificate-layout growth is caught here rather than
/// silently rejecting every OGM at runtime (`signed_message` fails closed).
const _: () =
    assert!(SIGN_SCRATCH_LEN >= SIG_DOMAIN.len() + 6 + 4 + core::mem::size_of::<MembershipCert>());

/// One verified neighbor's keys, learned from its authenticated OGM cert.
#[derive(Debug, Clone, Copy)]
pub struct NeighborKeys {
    /// The neighbor's node MAC.
    pub mac: Mac,
    /// Its Ed25519 identity key (verifies its OGM signatures).
    pub ed_pubkey: [u8; 32],
    /// Its X25519 key (derives the pairwise data-plane key).
    pub x_pubkey: [u8; 32],
}

/// Per-node OGM authentication state, held by the router when auth is enabled.
pub struct OgmAuth {
    /// This node's key material, for signing its own OGMs.
    keypair: Keypair,
    /// This node's membership certificate, attached to its OGMs.
    cert: MembershipCert,
    /// The mesh trust anchor, against which incoming certs are verified.
    anchor: TrustAnchor,
    /// Current wall-clock time in unix seconds, refreshed by the driver; used
    /// for certificate validity-window checks.  Zero until first set, which (as
    /// the unix epoch) treats every not-yet-current cert as not-yet-valid, so
    /// the driver must set a real time before auth is meaningful.
    now_unix: u64,
    /// MACs revoked by a flooded revocation record; their OGMs are dropped even
    /// while their cert has not yet expired.
    revoked: HVec<Mac, MAX_REVOKED>,
    /// Keys of neighbors whose OGMs have verified, for pairwise-key derivation
    /// and security observability.
    neighbors: HVec<NeighborKeys, MAX_NEIGHBOR_KEYS>,
    /// Reused scratch buffer for assembling the OGM signed message, so signing
    /// and verifying do not stack-allocate it on every call.
    sign_scratch: [u8; SIGN_SCRATCH_LEN],
}

impl OgmAuth {
    /// Build auth state from this node's keypair, its membership cert, and the
    /// mesh trust anchor.
    pub fn new(keypair: Keypair, cert: MembershipCert, anchor: TrustAnchor) -> Self {
        Self {
            keypair,
            cert,
            anchor,
            now_unix: 0,
            revoked: HVec::new(),
            neighbors: HVec::new(),
            sign_scratch: [0u8; SIGN_SCRATCH_LEN],
        }
    }

    /// Update the current wall-clock time (unix seconds) used for cert validity
    /// checks.  Called by the driver before serving traffic.
    pub fn set_time(&mut self, now_unix: u64) {
        self.now_unix = now_unix;
    }

    /// Record a revoked MAC so its OGMs are dropped immediately, not only once
    /// its cert expires.  No-op if already present or the set is full.
    pub fn revoke(&mut self, mac: Mac) {
        if !self.revoked.contains(&mac) {
            let _ = self.revoked.push(mac);
        }
    }

    /// This node's own trust anchor (for the security view / observability).
    pub fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }

    /// The keys of neighbors whose OGMs have verified.
    pub fn neighbors(&self) -> &[NeighborKeys] {
        &self.neighbors
    }

    /// The X25519 key of a verified neighbor, for pairwise data-plane keying.
    pub fn neighbor_x_pubkey(&self, mac: Mac) -> Option<[u8; 32]> {
        self.neighbors
            .iter()
            .find(|n| n.mac == mac)
            .map(|n| n.x_pubkey)
    }

    /// Build the canonical signed message for an OGM: a domain prefix followed
    /// by the immutable identity bytes (originator MAC and sequence number, as
    /// they appear on the wire) and the originator's certificate.  Mutable
    /// per-hop fields (ttl, tq, prev_sender) are deliberately excluded so the
    /// signature survives forwarding.  Returns the filled prefix of `out`.
    ///
    /// Excluding the mutable `tq` is only *safe* because the engine clamps an
    /// advertised TQ by the locally-measured link quality to the sender (the
    /// `local_quality` argument to `BatmanEngine::handle_rx`): a member replaying
    /// a victim's signed OGM with an inflated TQ still can't advertise a path
    /// better than its real link.  Keep that clamp if this exclusion stays.
    fn signed_message<'a>(
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
    pub fn augment_ogm(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        if len < OGM_HDR {
            return None;
        }
        // Copy of our cert so its bytes don't hold a borrow of `self` while the
        // reused `sign_scratch` field is borrowed below (MembershipCert is Copy).
        let cert = self.cert;
        let cert_bytes = cert.as_bytes();

        // Sign over the immutable identity (orig + seqno, as on the wire) + cert.
        let mut orig = [0u8; 6];
        orig.copy_from_slice(&buf[ORIG_OFF..ORIG_OFF + 6]);
        let mut seqno = [0u8; 4];
        seqno.copy_from_slice(&buf[SEQNO_OFF..SEQNO_OFF + 4]);
        let signature = {
            let signed = Self::signed_message(&orig, &seqno, cert_bytes, &mut self.sign_scratch)?;
            self.keypair.sign(signed)
        };

        let cert_record = TVLV_HDR + cert_bytes.len();
        let sig_record = TVLV_HDR + SIG_LEN;
        let added = cert_record + sig_record;
        let new_len = len.checked_add(added)?;
        if new_len > buf.len() {
            return None;
        }
        // Reject (rather than wrap) if the additions would overflow the u16
        // `tvlv_len` field — checked up front, before writing anything.
        let old_tvlv_len = u16::from_be_bytes([buf[TVLV_LEN_OFF], buf[TVLV_LEN_OFF + 1]]);
        let updated_tvlv_len = u16::try_from(added)
            .ok()
            .and_then(|a| old_tvlv_len.checked_add(a))?;

        let mut off = len;
        off = Self::write_tvlv(buf, off, WF_TVLV_CERT, cert_bytes);
        off = Self::write_tvlv(buf, off, WF_TVLV_OGM_SIG, &signature);

        // Grow the header's tvlv_len to cover the two new records.
        buf[TVLV_LEN_OFF..TVLV_LEN_OFF + 2].copy_from_slice(&updated_tvlv_len.to_be_bytes());

        Some(off)
    }

    /// Write one TVLV record (header + value) at `off`, returning the next
    /// offset.  The caller must have ensured the buffer has room.
    fn write_tvlv(buf: &mut [u8], off: usize, tvlv_type: u8, value: &[u8]) -> usize {
        debug_assert!(
            value.len() <= u16::MAX as usize,
            "TVLV value exceeds u16 length"
        );
        let hdr = BatmanTvlvHdr {
            tvlv_type,
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        buf[off..off + TVLV_HDR].copy_from_slice(hdr.as_bytes());
        let vstart = off + TVLV_HDR;
        buf[vstart..vstart + value.len()].copy_from_slice(value);
        vstart + value.len()
    }

    /// Verify an incoming OGM's authentication, caching the originator's keys on
    /// success.  Returns `true` only if the OGM carries a cert that chains to
    /// our trust anchor (correct mesh, valid window, not revoked) and a
    /// signature that verifies against that cert's key over the OGM's immutable
    /// identity.  A `false` return means the OGM must be dropped.
    pub fn verify_ogm(&mut self, payload: &[u8]) -> bool {
        if payload.len() < OGM_HDR {
            tracing::trace!("auth: dropping OGM shorter than its header");
            return false;
        }
        let tail = &payload[OGM_HDR..];
        let (Some(cert_bytes), Some(sig_bytes)) = (
            find_tvlv(tail, WF_TVLV_CERT),
            find_tvlv(tail, WF_TVLV_OGM_SIG),
        ) else {
            // Unauthenticated OGM under an auth-enabled mesh (e.g. another mesh).
            tracing::trace!("auth: dropping OGM missing cert or signature TVLV");
            return false;
        };
        if sig_bytes.len() != SIG_LEN {
            tracing::trace!("auth: dropping OGM with malformed signature TVLV length");
            return false;
        }
        let Ok((cert, _)) = MembershipCert::ref_from_prefix(cert_bytes) else {
            tracing::trace!("auth: dropping OGM with malformed membership certificate");
            return false;
        };
        let verified = match self.anchor.verify_cert(cert, self.now_unix) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(error = ?e, "auth: dropping OGM whose certificate failed verification");
                return false;
            }
        };

        // The cert must be bound to the OGM's claimed originator, and not revoked.
        let mut orig = [0u8; 6];
        orig.copy_from_slice(&payload[ORIG_OFF..ORIG_OFF + 6]);
        if verified.mac.0 != orig {
            tracing::trace!("auth: dropping OGM whose cert MAC does not match the originator");
            return false;
        }
        if self.revoked.iter().any(|m| m.0 == orig) {
            tracing::trace!("auth: dropping OGM from a revoked originator");
            return false;
        }

        let mut seqno = [0u8; 4];
        seqno.copy_from_slice(&payload[SEQNO_OFF..SEQNO_OFF + 4]);
        let ed_pubkey = verified.ed_pubkey;
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(sig_bytes);
        // The signature is computed over the full `cert_bytes` from the TVLV, so
        // any padding past the 156-byte cert (which `ref_from_prefix` ignores)
        // changes the signed message and fails below — the cert length is
        // implicitly pinned by the signature.
        let signature_ok =
            match Self::signed_message(&orig, &seqno, cert_bytes, &mut self.sign_scratch) {
                Some(signed) => verify_signature(&ed_pubkey, signed, &signature),
                None => {
                    tracing::trace!("auth: dropping OGM, signed-message buffer too small");
                    return false;
                }
            };
        if !signature_ok {
            tracing::trace!("auth: dropping OGM with an invalid signature");
            return false;
        }

        self.cache_neighbor(NeighborKeys {
            mac: Mac(orig),
            ed_pubkey,
            x_pubkey: verified.x_pubkey,
        });
        true
    }

    /// Insert or refresh a verified neighbor's keys.
    fn cache_neighbor(&mut self, keys: NeighborKeys) {
        if let Some(slot) = self.neighbors.iter_mut().find(|n| n.mac == keys.mac) {
            *slot = keys;
        } else if self.neighbors.push(keys).is_err() {
            // Table full: overwrite the first entry rather than dropping the
            // freshly verified neighbor (bounded, simple eviction).
            if let Some(first) = self.neighbors.first_mut() {
                *first = keys;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use batman::wire::{BATADV_IV_OGM, BatmanOgmPacket};
    use wayfinder_auth::Authority;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Build a bare OGM (header only, no TVLV) for `orig` into a fresh buffer,
    /// returning `(buf, len)` with generous trailing capacity for augmentation.
    fn bare_ogm(orig: Mac, seqno: u32) -> ([u8; 512], usize) {
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            prev_sender: orig,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        let mut buf = [0u8; 512];
        buf[..OGM_HDR].copy_from_slice(ogm.as_bytes());
        (buf, OGM_HDR)
    }

    /// An authority and a member node's auth state, sharing the same anchor.
    fn member(authority: &Authority, seed: u8, m: Mac, valid_to: u64) -> OgmAuth {
        let kp = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), 0, valid_to);
        let mut auth = OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(100);
        auth
    }

    /// A node augments its OGM; a peer on the same mesh accepts it and learns
    /// the originator's keys.
    #[test]
    fn signed_ogm_verifies_for_same_mesh() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);

        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).expect("augment");

        assert!(b.verify_ogm(&buf[..len]));
        assert_eq!(b.neighbors().len(), 1);
        assert_eq!(b.neighbor_x_pubkey(mac(2)), Some(a.cert.x_pubkey));
    }

    /// An unauthenticated OGM (no cert/sig TVLVs) is rejected when auth is on.
    #[test]
    fn unauthenticated_ogm_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = member(&authority, 3, mac(3), 1000);
        let (buf, len) = bare_ogm(mac(2), 7);
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(!b.verify_ogm(&buf[..len]));
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
        assert!(!b.verify_ogm(&buf[..len]));
    }

    /// An expired cert (now past not_after) is rejected.
    #[test]
    fn expired_cert_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        b.set_time(2000); // past a's not_after = 1000
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert!(!b.verify_ogm(&buf[..len]));
    }

    /// A revoked originator is dropped even with a still-valid signature/cert.
    #[test]
    fn revoked_originator_rejected() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = member(&authority, 2, mac(2), 1000);
        let mut b = member(&authority, 3, mac(3), 1000);
        b.revoke(mac(2));
        let (mut buf, len) = bare_ogm(mac(2), 7);
        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert!(!b.verify_ogm(&buf[..len]));
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
        len = OgmAuth::write_tvlv(
            &mut buf,
            len,
            batman::wire::BATADV_TVLV_MCAST,
            &[1, 2, 3, 4],
        );
        let mcast_record = TVLV_HDR + 4;
        buf[TVLV_LEN_OFF..TVLV_LEN_OFF + 2].copy_from_slice(&(mcast_record as u16).to_be_bytes());

        let len = a.augment_ogm(&mut buf, len).unwrap();
        assert!(b.verify_ogm(&buf[..len]));
        // The mcast TVLV is still findable after the appended records.
        assert_eq!(
            find_tvlv(&buf[OGM_HDR..len], batman::wire::BATADV_TVLV_MCAST),
            Some(&[1, 2, 3, 4][..])
        );
    }
}
