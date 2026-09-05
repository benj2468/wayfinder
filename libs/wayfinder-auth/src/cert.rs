//! The membership certificate and the per-mesh trust anchor that verifies it.

use blake2::Blake2s256;
use blake2::Digest;
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
use crate::mac::derive_mac;

/// Version byte stamped on every [`MembershipCert`] this build produces and the
/// only version it accepts.  Bump when the signed layout changes.
pub const CERT_VERSION: u8 = 1;

/// [`MembershipCert::flags`] bit granting the **management-administration
/// capability**: the holder may invoke privileged management-API operations
/// (`SetAuth`, `SetConfig`, `RevokeNode`, CSR approve/deny), not merely
/// participate in routing.  It is part of the signed body, so only the mesh root
/// can grant it and tampering breaks the signature — meaning the management
/// layer may trust it only after [`TrustAnchor::verify_cert`] succeeds (see
/// [`VerifiedCert::admin`]).
pub const CERT_FLAG_ADMIN: u8 = 0x01;

/// [`MembershipCert::flags`] bit marking the holder as a **person, not a
/// device**: a short-lived session certificate minted by the certificate
/// authority in exchange for user credentials, rather than a membership
/// certificate issued to a node that routes.
///
/// It grants nothing on its own — capability is [`CERT_FLAG_ADMIN`] or
/// [`CERT_FLAG_VIEWER`], and this bit is orthogonal to both. What it buys is
/// that `ListCerts` and the security tab can tell an operator's credential
/// apart from a node's, which is otherwise unanswerable: both are certificates
/// bound to a MAC, and a user's MAC is derived from a session key that exists
/// only for the length of a shift.
///
/// Part of the signed body, so it is decided by the issuer and cannot be
/// claimed. That is also why it exists *before* the first user certificate is
/// issued rather than after: retrofitting a signed flag means re-issuing every
/// certificate that predates it.
pub const CERT_FLAG_USER: u8 = 0x02;

/// [`MembershipCert::flags`] bit granting the **read-only management
/// capability**: the holder may invoke the management API's queries (routing
/// table, link quality, metrics, logs) but none of its mutations and none of
/// its secrets.
///
/// Deliberately a bit of its own rather than "a verified certificate that is
/// not an admin". Every device on the mesh already holds a verified non-admin
/// certificate, so a tier granted by *absence* would hand every node read
/// access to every other node's management API in one release, with nothing in
/// any configuration changing to say so. Earned by a bit, the tier is granted
/// deliberately or not at all.
///
/// [`CERT_FLAG_ADMIN`] subsumes it: an admin certificate need not also carry
/// this bit to read.
pub const CERT_FLAG_VIEWER: u8 = 0x04;

/// [`MembershipCert::flags`] bit marking the holder as an **enrolled mesh
/// device**: a node that routes, as distinct from a person's session
/// ([`CERT_FLAG_USER`]) and from a management capability
/// ([`CERT_FLAG_ADMIN`]/[`CERT_FLAG_VIEWER`]).
///
/// Deliberately a signed bit rather than "a verified certificate carrying none
/// of the other bits". Inferring device-ness from absence makes every
/// unrecognised or malformed capability combination silently become a device,
/// and it makes the meaning of a certificate depend on which bits the *reader*
/// happens to know about — so a cert issued by a newer CA would change tier
/// under an older verifier. Issued explicitly, the classification is the
/// issuer's decision and travels inside the signature.
///
/// It grants no management capability. What it earns is the management API's
/// member tier, which is exactly one request wide — see
/// `wayfinder_server::MgmtAccess::GrantedMember`.
pub const CERT_FLAG_MEMBER: u8 = 0x08;

/// Domain-separation label folded into the fingerprint hash, so it can never
/// collide with another `Blake2s256` use over the same or overlapping bytes
/// elsewhere in the crate (e.g. [`crate::key::Keypair::pairwise_key`]).
const CERT_FINGERPRINT_LABEL: &[u8] = b"wayfinder-certfp-v1";

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
    /// Capability bits, part of the signed body: [`CERT_FLAG_ADMIN`] (full
    /// management), [`CERT_FLAG_VIEWER`] (read-only management),
    /// [`CERT_FLAG_USER`] (the holder is a person's session, not a device) and
    /// [`CERT_FLAG_MEMBER`] (the holder is an enrolled device that routes).
    /// The remaining bits are reserved and sent as 0.
    ///
    /// Unknown bits are masked off on verification, never rejected, so a cert
    /// issued by a newer CA still verifies against an older node's firmware.
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
    /// Parse an owned certificate from its raw [`as_bytes`](zerocopy::IntoBytes::as_bytes)
    /// form (e.g. a file the portal issued), ignoring any trailing bytes.
    /// Returns `None` if `bytes` is shorter than the fixed certificate layout.
    pub fn from_bytes(bytes: &[u8]) -> Option<MembershipCert> {
        MembershipCert::read_from_prefix(bytes).ok().map(|(c, _)| c)
    }

    /// The byte range the signature covers: every field except the trailing
    /// 64-byte signature itself.  Both the issuer (when signing) and the
    /// verifier compute the signature over exactly these bytes.
    pub fn signed_body(&self) -> &[u8] {
        let body_len = core::mem::size_of::<MembershipCert>() - 64;
        &self.as_bytes()[..body_len]
    }

    /// An 8-byte fingerprint over the whole certificate (`Blake2s256`,
    /// domain-separated, truncated), for lazy cert distribution: an OGM
    /// carries this instead of the full cert, and a receiver holding a cert
    /// with a matching fingerprint can verify the OGM against its cached copy
    /// with zero cert bytes on the wire. It changes on any field change,
    /// including key rotation, so a fingerprint mismatch signals "fetch the
    /// new cert." It is not a trust boundary — a fetched cert is always
    /// re-verified against the [`TrustAnchor`] — only collision-resistance
    /// among legitimate certs is required, which 8 bytes of `Blake2s256` is
    /// ample for.
    pub fn fingerprint(&self) -> [u8; 8] {
        let mut h = Blake2s256::new();
        h.update(CERT_FINGERPRINT_LABEL);
        h.update(self.as_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&digest[..8]);
        fp
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
    /// When the cert becomes valid (unix seconds) — its issuance instant.
    ///
    /// Carried through verification because it is what a revocation is judged
    /// against: a `RevocationRecord` cancels this certificate only if this
    /// instant is at or before the record's own `not_before`.  Without it here
    /// every revocation check would have to re-parse the raw certificate.
    pub not_before: u64,
    /// When the cert expires (unix seconds), so the router can age it out.
    pub not_after: u64,
    /// Whether the cert carries the management-administration capability
    /// ([`CERT_FLAG_ADMIN`]).  The only production constructor of a
    /// [`VerifiedCert`] is [`TrustAnchor::verify_cert`], so in normal use this
    /// bit reflects a flag that was signed by the mesh root — not an attacker's
    /// raw, unverified cert.  (The struct's fields are public, so tests may
    /// build one directly; the guarantee is the construction convention, not a
    /// type-level seal.)
    pub admin: bool,
    /// Whether the cert carries the read-only management capability
    /// ([`CERT_FLAG_VIEWER`]).  Same trust story as [`admin`](Self::admin).
    /// An [`admin`](Self::admin) cert may read without also setting this;
    /// callers deciding "may this read?" should accept either.
    pub viewer: bool,
    /// Whether the cert marks a person's session rather than a device
    /// ([`CERT_FLAG_USER`]).  Carries no capability of its own — it is what
    /// lets an operator's credential be told apart from a node's in
    /// `ListCerts` and the security tab.
    pub user: bool,
    /// Whether the cert marks an enrolled mesh device ([`CERT_FLAG_MEMBER`]).
    /// Same trust story as [`admin`](Self::admin).  Mutually exclusive with
    /// [`user`](Self::user) in everything the CA issues, and false on a
    /// certificate predating the bit — which is why nothing infers it from the
    /// absence of the others.
    pub member: bool,
}

/// Whether `mac` is an address **reserved** by ethernet addressing, and so one
/// no node may hold a membership certificate for: any multicast address (the
/// group bit, `0x01`, set on the first octet — which also covers broadcast,
/// `ff:ff:ff:ff:ff:ff`), or the all-zeros null address.
///
/// This is the verifying counterpart to
/// [`force_locally_administered_unicast`](crate::mac::force_locally_administered_unicast),
/// which stamps the same convention on every address this crate hands out. It
/// is deliberately *narrower* than that convention: it does not require the
/// locally-administered bit. Only addresses that mean "not one node" are
/// refused; whether an address follows this crate's derivation convention is a
/// separate question, answered by the key↔address binding in `verify_cert`
/// rather than folded in here. Keeping the two apart is what lets each error
/// name its own mistake.
fn is_reserved_mac(mac: [u8; 6]) -> bool {
    mac[0] & 0x01 != 0 || mac == [0u8; 6]
}

impl TrustAnchor {
    /// On-disk / on-wire size of a serialized trust anchor: a 4-byte big-endian
    /// mesh id followed by the 32-byte root public key.
    pub const SERIALIZED_LEN: usize = 4 + 32;

    /// Serialize to its fixed 36-byte form (`mesh_id` big-endian, then the root
    /// public key) for distribution to nodes as a file.
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_LEN] {
        let mut out = [0u8; Self::SERIALIZED_LEN];
        out[..4].copy_from_slice(&self.mesh_id.to_be_bytes());
        out[4..].copy_from_slice(&self.root_pubkey);
        out
    }

    /// Parse a trust anchor from its [`to_bytes`](Self::to_bytes) form, or
    /// `None` if `bytes` is too short.
    pub fn from_bytes(bytes: &[u8]) -> Option<TrustAnchor> {
        if bytes.len() < Self::SERIALIZED_LEN {
            return None;
        }
        let mut mesh_id = [0u8; 4];
        mesh_id.copy_from_slice(&bytes[..4]);
        let mut root_pubkey = [0u8; 32];
        root_pubkey.copy_from_slice(&bytes[4..Self::SERIALIZED_LEN]);
        Some(TrustAnchor {
            mesh_id: u32::from_be_bytes(mesh_id),
            root_pubkey,
        })
    }

    /// Verify `cert` against this anchor as of `now_unix` (unix seconds).
    ///
    /// Checks, in order: the version byte, that the cert is for *this* mesh, the
    /// root signature, that the subject MAC is one a node can actually route
    /// under (not broadcast, not multicast, not the null address), that the
    /// subject MAC is the address its `ed_pubkey` derives, and the validity
    /// window.  Returns the trusted facts on success, or the first failing
    /// [`AuthError`].
    /// Fail-closed: any error means the cert (and the frame carrying it) must
    /// be rejected.
    ///
    /// The order of the last three is deliberate and tested. Both address
    /// checks sit *after* the signature, so a forgery is reported as one rather
    /// than as a misissuance; and the reserved-address check sits before the
    /// derivation check, because every reserved subject fails both — a derived
    /// address is never reserved — and "the CA bound a broadcast address" names
    /// the mistake where "the MAC does not match the key" describes a symptom
    /// of it.
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
        // Deliberately *after* the signature check: this rejects a cert the
        // mesh root genuinely signed, so it is a misissuance and not a forgery,
        // and the error should say so.  Nothing this verifier does can prevent
        // the misissuance; refusing to admit its subject is what bounds it.
        // Taken by value, like the window fields below — no refs into packed.
        if is_reserved_mac(cert.node_mac) {
            return Err(AuthError::ReservedAddress);
        }
        // The key↔address binding, and the reason a *compromised* authority
        // still cannot mint an impersonation credential: producing a cert for
        // an address some other key derives would need a `derive_mac` preimage,
        // which signing does not provide.  Ordered after `is_reserved_mac`
        // because a reserved subject fails both and the reserved diagnosis is
        // the one that names the mistake.
        if derive_mac(&cert.ed_pubkey) != Mac(cert.node_mac) {
            return Err(AuthError::MacKeyMismatch);
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
            not_before,
            not_after,
            admin: cert.flags & CERT_FLAG_ADMIN != 0,
            viewer: cert.flags & CERT_FLAG_VIEWER != 0,
            user: cert.flags & CERT_FLAG_USER != 0,
            member: cert.flags & CERT_FLAG_MEMBER != 0,
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

    /// A trust anchor round-trips through its serialized file form.
    #[test]
    fn trust_anchor_roundtrips_through_bytes() {
        let anchor = Authority::from_seed(&[1u8; 32], 0xABCD).trust_anchor();
        let bytes = anchor.to_bytes();
        assert_eq!(bytes.len(), TrustAnchor::SERIALIZED_LEN);
        assert_eq!(TrustAnchor::from_bytes(&bytes), Some(anchor));
        // Too-short input is rejected rather than panicking.
        assert_eq!(TrustAnchor::from_bytes(&bytes[..10]), None);
    }

    /// A device's membership certificate carries the *member* capability as a
    /// signed bit — not as the absence of every other bit.  This is what the
    /// management API's member tier is granted on: an enrolled node proving
    /// possession of the key the CA certified, and nothing more.  A cert with
    /// no bits at all is a cert with no capability, which must stay
    /// distinguishable from a device's.
    #[test]
    fn issued_member_cert_carries_the_member_capability() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );

        let verified = authority.trust_anchor().verify_cert(&cert, 150).unwrap();
        assert!(verified.member, "an enrolled device is a member");
        assert!(!verified.admin);
        assert!(!verified.viewer);
        assert!(!verified.user);
    }

    /// A person's session certificate is *not* a member: it is a credential for
    /// an operator, not a device that routes, so it must not earn the member
    /// tier (and so cannot mint a VPN credential for a device identity it does
    /// not have).
    #[test]
    fn issued_user_cert_is_not_a_member() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let session = Keypair::from_seed(&[3u8; 32]);

        for admin in [true, false] {
            let cert = authority.issue_user_cert(
                session.derived_mac(),
                session.ed_pubkey(),
                session.x_pubkey(),
                100,
                200,
                admin,
            );
            let verified = authority.trust_anchor().verify_cert(&cert, 150).unwrap();
            assert!(!verified.member, "a user session is not a device");
            assert!(verified.user);
            assert_eq!(verified.admin, admin);
            assert_eq!(verified.viewer, !admin);
        }
    }

    /// A certificate predating the member bit (`flags == 0`) still verifies —
    /// unknown/absent capability bits are masked, never rejected — and simply
    /// carries no capability.  This is what keeps the new bit from being a flag
    /// day for already-issued certs and already-flashed verifiers.
    #[test]
    fn cert_without_the_member_bit_verifies_without_capability() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        // Signed with no flags at all, standing in for a cert issued before the
        // member bit existed.
        let legacy = authority.issue_with_flags(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
            0,
        );

        let verified = authority.trust_anchor().verify_cert(&legacy, 150).unwrap();
        assert!(!verified.member);
        assert!(!verified.admin);
        assert!(!verified.viewer);
        assert!(!verified.user);
    }

    /// A cert issued by an authority verifies against that authority's anchor
    /// within its validity window, and yields the bound keys.
    #[test]
    fn issued_cert_verifies() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );

        let verified = authority.trust_anchor().verify_cert(&cert, 150).unwrap();
        assert_eq!(verified.mac, node.derived_mac());
        assert_eq!(verified.ed_pubkey, node.ed_pubkey());
        assert_eq!(verified.x_pubkey, node.x_pubkey());
        assert_eq!(verified.not_after, 200);
    }

    /// The admin capability is a signed flag in the cert, surfaced *only*
    /// through verification: a plain member verifies as non-admin, while a cert
    /// the CA issued with the admin capability verifies as admin.  The
    /// management API authorizes privileged operations off this verified bit,
    /// never a raw (unverified, hence attacker-controllable) cert — which is why
    /// it lands on `VerifiedCert`, produced only on the `verify_cert` success
    /// path.
    #[test]
    fn admin_capability_travels_through_verification() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let anchor = authority.trust_anchor();

        // A plain membership cert carries no admin capability.
        let member = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
        assert!(
            !anchor.verify_cert(&member, 150).unwrap().admin,
            "a plain membership cert must not be an admin"
        );

        // A cert the CA issued with the admin capability verifies as admin.
        let admin = authority.issue_user_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
            true,
        );
        assert!(
            anchor.verify_cert(&admin, 150).unwrap().admin,
            "an admin-issued cert must carry the admin capability once verified"
        );
    }

    /// A cert from another mesh's authority fails on the trust-anchor signature
    /// (different root key) — this is the segregation property.
    #[test]
    fn foreign_authority_cert_rejected() {
        let ours = Authority::from_seed(&[1u8; 32], 0xABCD);
        let theirs = Authority::from_seed(&[9u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = theirs.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
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
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
        let mut anchor = authority.trust_anchor();
        anchor.mesh_id = 0x2222;
        assert_eq!(anchor.verify_cert(&cert, 150), Err(AuthError::WrongMesh));
    }

    /// The validity window is enforced at both ends.
    #[test]
    fn expiry_window_enforced() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
        let anchor = authority.trust_anchor();
        assert_eq!(anchor.verify_cert(&cert, 99), Err(AuthError::NotYetValid));
        assert_eq!(anchor.verify_cert(&cert, 201), Err(AuthError::Expired));
        assert!(anchor.verify_cert(&cert, 100).is_ok());
        assert!(anchor.verify_cert(&cert, 200).is_ok());
    }

    /// **A verifier with no clock refuses every certificate a real authority
    /// issues.**
    ///
    /// Not a corner case. `CertAuthority` stamps `not_before` from its own
    /// clock and refuses to issue at all without one, so every genuine
    /// certificate carries a real Unix timestamp — and the window check above
    /// has no zero-clock bypass, so `0 < not_before` is `NotYetValid`.
    ///
    /// Pinned because nothing else did: every other fixture in this workspace
    /// issues with `not_before = 0` (see the test below), which is why a
    /// bare-metal node — permanently at `now_unix == 0`, since no board calls
    /// `OgmAuth::set_time` — being unable to admit *anyone* went unnoticed.
    ///
    /// This characterises today's behaviour rather than asserting a fix. The
    /// "Auth on Embedded" epic owns choosing what an unclocked node should do
    /// instead, and this is the test that has to change when it does.
    #[test]
    fn an_unclocked_verifier_refuses_a_certificate_from_a_real_authority() {
        const ISSUED_AT: u64 = 1_700_000_000;
        const A_YEAR: u64 = 365 * 24 * 60 * 60;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            ISSUED_AT,
            ISSUED_AT + A_YEAR,
        );
        let anchor = authority.trust_anchor();

        assert_eq!(
            anchor.verify_cert(&cert, 0),
            Err(AuthError::NotYetValid),
            "an unclocked verifier refuses a certificate that is valid right now"
        );

        // The control: the certificate is fine and the anchor is fine. The
        // clock is the whole difference.
        assert!(
            anchor.verify_cert(&cert, ISSUED_AT + 1).is_ok(),
            "the same certificate verifies the moment the verifier knows the time"
        );
    }

    /// The contrast that explains the blind spot: a certificate issued with
    /// `not_before = 0` verifies happily on an unclocked verifier, because zero
    /// is not below zero.
    ///
    /// That is the shape every test fixture in this workspace uses, and no
    /// authority ever produces it — `CertAuthority` refuses to issue without a
    /// clock. So the fixtures agreed with each other and with nothing that
    /// ships.
    #[test]
    fn a_zero_not_before_is_what_hid_the_unclocked_gap() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            0,
            200,
        );

        assert!(
            authority.trust_anchor().verify_cert(&cert, 0).is_ok(),
            "the fixture shape verifies at time zero, which a real one does not"
        );
    }

    /// Tampering with any signed field invalidates the signature.
    #[test]
    fn tampered_cert_rejected() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let mut cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
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
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
        let bytes = cert.as_bytes().to_vec();
        let (parsed, _) = MembershipCert::ref_from_prefix(&bytes).unwrap();
        assert!(authority.trust_anchor().verify_cert(parsed, 150).is_ok());
    }

    /// The fingerprint is deterministic: hashing the same cert bytes twice
    /// yields the same 8-byte tag.
    #[test]
    fn fingerprint_is_deterministic() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
        assert_eq!(cert.fingerprint(), cert.fingerprint());
    }

    /// Any change to the cert (e.g. a rotated key, here simulated by flipping
    /// the bound MAC) changes the fingerprint, so a fingerprint mismatch on an
    /// OGM correctly signals "the cert changed, re-fetch it."
    #[test]
    fn fingerprint_changes_when_cert_changes() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let cert_a = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
        let mut cert_b = cert_a;
        cert_b.node_mac = mac(6).0;
        assert_ne!(cert_a.fingerprint(), cert_b.fingerprint());
    }

    /// Two distinct, independently-issued certs do not collide.
    #[test]
    fn fingerprint_differs_across_distinct_certs() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node_a = Keypair::from_seed(&[2u8; 32]);
        let node_b = Keypair::from_seed(&[3u8; 32]);
        let cert_a = authority.issue_cert(
            node_a.derived_mac(),
            node_a.ed_pubkey(),
            node_a.x_pubkey(),
            100,
            200,
        );
        let cert_b = authority.issue_cert(
            node_b.derived_mac(),
            node_b.ed_pubkey(),
            node_b.x_pubkey(),
            100,
            200,
        );
        assert_ne!(cert_a.fingerprint(), cert_b.fingerprint());
    }

    /// A cert binding a member at a **reserved** address is rejected however
    /// genuinely the mesh root signed it.  Nothing routes at broadcast, at a
    /// multicast (group-bit) address or at the null address, so a certificate
    /// naming one is a misissuance rather than a member — and admitting it
    /// would let a directed frame purporting to originate from "every node",
    /// or from no node at all, pass `verify_directed` at the receiver.
    #[test]
    fn reserved_node_mac_rejected() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let anchor = authority.trust_anchor();

        for reserved in [
            Mac([0xFF; 6]),                // broadcast
            Mac([0x01, 0, 0, 0, 0, 1]),    // the group bit alone
            Mac([0x33, 0x33, 0, 0, 0, 1]), // an IPv6 multicast address
            Mac([0x00; 6]),                // the null address
        ] {
            let cert = authority.issue_cert(reserved, node.ed_pubkey(), node.x_pubkey(), 100, 200);
            assert_eq!(
                anchor.verify_cert(&cert, 150),
                Err(AuthError::ReservedAddress),
                "reserved address {reserved:?} must not verify",
            );
        }
    }

    /// The reserved-address check is narrow: it must not reject the address a
    /// node actually routes under, which since the key↔address binding landed
    /// is the derived one and only that.
    ///
    /// Narrowness is now pinned on [`is_reserved_mac`] directly
    /// (`reserved_check_admits_a_globally_administered_address`) rather than
    /// through `verify_cert`, because `verify_cert` no longer admits *any*
    /// address a key does not derive — there is no globally-administered MAC
    /// left to feed it.
    #[test]
    fn ordinary_unicast_node_mac_still_verifies() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();

        for seed in [2u8, 9, 200] {
            let node = Keypair::from_seed(&[seed; 32]);
            let cert = authority.issue_cert(
                node.derived_mac(),
                node.ed_pubkey(),
                node.x_pubkey(),
                100,
                200,
            );
            assert!(
                anchor.verify_cert(&cert, 150).is_ok(),
                "a derived address from seed {seed} must verify",
            );
        }
    }

    /// `is_reserved_mac` stays narrower than the convention `derive_mac`
    /// stamps: it refuses only addresses meaning "not one node", never a
    /// globally-administered address a node's hardware came with.
    ///
    /// Tested on the predicate rather than through `verify_cert` — see
    /// `ordinary_unicast_node_mac_still_verifies` for why that route is closed.
    #[test]
    fn reserved_check_admits_a_globally_administered_address() {
        // Locally-administered bit clear, group bit clear: not this crate's
        // convention, but a real unicast address all the same.
        assert!(!is_reserved_mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert!(!is_reserved_mac([0x02, 0, 0, 0, 0, 1]));
        assert!(is_reserved_mac([0xFF; 6]));
        assert!(is_reserved_mac([0x01, 0, 0, 0, 0, 1]));
        assert!(is_reserved_mac([0u8; 6]));
    }

    /// A certificate's `node_mac` must be the address its `ed_pubkey` derives.
    ///
    /// This is the half of gap 4 that holds even against a *compromised*
    /// authority: minting a credential that binds an attacker's key to a
    /// victim's address would need a `derive_mac` preimage, which a signing key
    /// does not provide. Every node enforces it for itself, so the key↔address
    /// binding stops being a policy no node can audit.
    #[test]
    fn node_mac_must_derive_from_its_ed_pubkey() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let victim = Keypair::from_seed(&[2u8; 32]);
        let attacker = Keypair::from_seed(&[3u8; 32]);
        let anchor = authority.trust_anchor();

        // Genuinely CA-signed, and binding the attacker's key to the victim's
        // address: exactly the misissuance `submit_csr` used to accept.
        let impersonation = authority.issue_cert(
            victim.derived_mac(),
            attacker.ed_pubkey(),
            attacker.x_pubkey(),
            100,
            200,
        );
        assert_eq!(
            anchor.verify_cert(&impersonation, 150),
            Err(AuthError::MacKeyMismatch),
            "a cert naming another key's address must not verify",
        );

        // An invented address belonging to nobody is refused by the same rule.
        let invented =
            authority.issue_cert(mac(5), attacker.ed_pubkey(), attacker.x_pubkey(), 100, 200);
        assert_eq!(
            anchor.verify_cert(&invented, 150),
            Err(AuthError::MacKeyMismatch),
            "a cert naming an address no key derives must not verify",
        );
    }

    /// The agreement key is deliberately *not* part of the binding: only
    /// `ed_pubkey` derives the address, so a certificate that rotates x25519
    /// material alone still verifies.
    ///
    /// This matches the authority's own live-member identity lock (§8.9),
    /// which compares `ed_pubkey` alone for the same reason — a wider rule here
    /// would reject a certificate this mesh's authority had just issued.
    #[test]
    fn x_pubkey_is_not_part_of_the_mac_binding() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let rekeyed_agreement = Keypair::from_seed(&[3u8; 32]);
        let anchor = authority.trust_anchor();

        let cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            rekeyed_agreement.x_pubkey(),
            100,
            200,
        );
        assert!(anchor.verify_cert(&cert, 150).is_ok());
    }

    /// A reserved address is reported as reserved, not as a key mismatch.
    ///
    /// Both faults hold at once — `derive_mac` can never produce a reserved
    /// address, so every reserved subject also mismatches — and the order is
    /// load-bearing for the operator reading the error: "the CA bound a
    /// broadcast address" names the mistake, where "the MAC does not match the
    /// key" describes a symptom of it.
    #[test]
    fn reserved_address_outranks_the_mac_key_mismatch() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let anchor = authority.trust_anchor();

        let cert =
            authority.issue_cert(Mac([0xFF; 6]), node.ed_pubkey(), node.x_pubkey(), 100, 200);
        assert_eq!(
            anchor.verify_cert(&cert, 150),
            Err(AuthError::ReservedAddress),
        );
    }

    /// A forgery is reported as a bad signature, not as a key mismatch: the
    /// binding check sits after the signature check so an unsigned cert is
    /// never described as a misissuance.
    #[test]
    fn bad_signature_outranks_the_mac_key_mismatch() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let node = Keypair::from_seed(&[2u8; 32]);
        let anchor = authority.trust_anchor();

        let mut cert = authority.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            100,
            200,
        );
        // Repoint the subject at an address the key does not derive, which also
        // invalidates the signature over the body.
        cert.node_mac = mac(6).0;
        assert_eq!(anchor.verify_cert(&cert, 150), Err(AuthError::BadSignature));
    }

    use crate::key::Keypair;
}
