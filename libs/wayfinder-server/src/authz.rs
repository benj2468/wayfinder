//! Management-API authorization policy.
//!
//! Authentication (proving *who* a client is) happens at the transport: the
//! client proves possession of an Ed25519 identity over the rustls channel and
//! its [`MembershipCert`](wayfinder::wayfinder_auth::MembershipCert) is verified
//! against the installed trust anchor, yielding a
//! [`VerifiedCert`](wayfinder::wayfinder_auth::VerifiedCert).  This module is the
//! *authorization* step layered on top: given those verified facts, decide
//! whether the client may invoke privileged operations.
//!
//! Kept as a pure decision over verified inputs (no transport, no crypto) so the
//! policy — "a verified, non-revoked admin may manage" — is unit-testable on its
//! own and shared by every transport.

use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::AuthError;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder::wayfinder_auth::VerifiedCert;

/// The overall management access decision for a client that has completed the
/// TLS handshake, proving possession of `handshake_key` (its raw Ed25519 public
/// key, RFC 7250).  Produced by [`decide_access`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtAccess {
    /// Granted via the enrolled path: a verified, non-revoked admin cert bound to
    /// the handshake key.
    GrantedAdmin,
    /// Granted via the bootstrap path: the node is un-enrolled and the client
    /// proved possession of the node's own key.
    GrantedBootstrap,
    /// Refused, with the reason.
    Denied(MgmtDenied),
}

/// Why a management client was refused ([`MgmtAccess::Denied`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtDenied {
    /// Bootstrap path: the node is un-enrolled and the handshake key is not this
    /// node's own key.
    NotOwnKey,
    /// Enrolled path: no membership cert was presented after the handshake.
    MissingCert,
    /// Enrolled path: the presented cert failed verification against the trust
    /// anchor (carries the underlying [`AuthError`]).
    CertInvalid(AuthError),
    /// Enrolled path: the cert verified but its key is not the TLS-authenticated
    /// handshake key, so it was not bound to this session (e.g. a cert replayed
    /// by someone who does not hold its private key).
    KeyMismatch,
    /// Enrolled path: the verified cert lacks the admin capability.
    NotAdmin,
    /// Enrolled path: the verified admin's node has been revoked.
    Revoked,
}

/// Decide whether a client that completed the TLS handshake with `handshake_key`
/// may invoke privileged management operations.
///
/// The node runs in one of two modes, selected by `anchor`:
///
/// * **Un-enrolled** (`anchor` is `None`): only the bootstrap path applies —
///   access is granted iff `handshake_key` equals the node's `own_key`. This is
///   how a fresh node accepts its first `SetAuth` before it has any trust anchor
///   to verify a membership cert against.
/// * **Enrolled** (`anchor` is `Some`): self-key bootstrap is refused
///   (fail-closed); the client must present a `cert` that verifies against the
///   anchor as of `now_unix`, whose key matches `handshake_key` (binding the cert
///   to this session), and that carries the admin capability for a node
///   `is_revoked` reports as active.
pub fn decide_access(
    handshake_key: &[u8; 32],
    cert: Option<&MembershipCert>,
    anchor: Option<&TrustAnchor>,
    own_key: &[u8; 32],
    now_unix: u64,
    is_revoked: impl FnOnce(Mac) -> bool,
) -> MgmtAccess {
    let Some(anchor) = anchor else {
        // Un-enrolled: bootstrap path only.
        return if handshake_key == own_key {
            MgmtAccess::GrantedBootstrap
        } else {
            MgmtAccess::Denied(MgmtDenied::NotOwnKey)
        };
    };

    // Enrolled: a membership admin cert bound to the handshake key is required.
    let Some(cert) = cert else {
        return MgmtAccess::Denied(MgmtDenied::MissingCert);
    };
    let verified = match anchor.verify_cert(cert, now_unix) {
        Ok(v) => v,
        Err(e) => return MgmtAccess::Denied(MgmtDenied::CertInvalid(e)),
    };
    // Bind the cert to this TLS session: it must be the key the handshake proved
    // possession of, else it's a cert the client doesn't actually hold.
    if &verified.ed_pubkey != handshake_key {
        return MgmtAccess::Denied(MgmtDenied::KeyMismatch);
    }
    match authorize_admin(&verified, is_revoked) {
        None => MgmtAccess::GrantedAdmin,
        Some(reason) => MgmtAccess::Denied(reason),
    }
}

/// Decide whether an authenticated client bearing `cert` may invoke privileged
/// management operations: `None` grants access, `Some(reason)` refuses it.
///
/// `cert` must already have been verified against the trust anchor (it is a
/// [`VerifiedCert`], produced only on the verification success path), so its
/// [`admin`](VerifiedCert::admin) bit is trustworthy.  `is_revoked` reports
/// whether a given node MAC has an active revocation — supplied as a predicate so
/// the policy stays decoupled from where revocation state lives (the router's
/// `OgmAuth`).
///
/// Revocation is checked first: it dominates the admin capability, so a revoked
/// admin is refused ([`MgmtDenied::Revoked`]) rather than allowed.
pub fn authorize_admin(
    cert: &VerifiedCert,
    is_revoked: impl FnOnce(Mac) -> bool,
) -> Option<MgmtDenied> {
    if is_revoked(cert.mac) {
        Some(MgmtDenied::Revoked)
    } else if !cert.admin {
        Some(MgmtDenied::NotAdmin)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder::interfaces::frame::Mac;
    use wayfinder::wayfinder_auth::Authority;
    use wayfinder::wayfinder_auth::Keypair;
    use wayfinder::wayfinder_auth::VerifiedCert;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Build a verified cert for `mac`, with or without the admin capability;
    /// the key/expiry fields are irrelevant to the authorization decision.
    fn verified(m: Mac, admin: bool) -> VerifiedCert {
        VerifiedCert {
            mac: m,
            ed_pubkey: [0u8; 32],
            x_pubkey: [0u8; 32],
            not_after: 0,
            admin,
        }
    }

    /// The management authorization rule: a client may invoke privileged ops iff
    /// its verified cert carries the admin capability *and* its node has not been
    /// revoked.  Revocation dominates the admin bit — a revoked admin is still
    /// refused.
    #[test]
    fn admin_authorization_requires_admin_and_not_revoked() {
        // Verified admin, not revoked → allowed (no denial reason).
        assert_eq!(authorize_admin(&verified(mac(1), true), |_| false), None);

        // Verified but lacking the admin capability → refused.
        assert_eq!(
            authorize_admin(&verified(mac(1), false), |_| false),
            Some(MgmtDenied::NotAdmin)
        );

        // Verified admin whose node has been revoked → refused despite the admin
        // bit; revocation is the dominant, mesh-wide fact.
        assert_eq!(
            authorize_admin(&verified(mac(1), true), |m| m == mac(1)),
            Some(MgmtDenied::Revoked)
        );
    }

    /// While the node is un-enrolled (no trust anchor), the only credential that
    /// grants access is proof of possession of the node's *own* key — the
    /// bootstrap path. Any other key is refused.
    #[test]
    fn bootstrap_grants_only_the_nodes_own_key() {
        let own = Keypair::from_seed(&[7u8; 32]);
        let other = Keypair::from_seed(&[8u8; 32]);

        assert_eq!(
            decide_access(&own.ed_pubkey(), None, None, &own.ed_pubkey(), 100, |_| {
                false
            }),
            MgmtAccess::GrantedBootstrap
        );
        assert_eq!(
            decide_access(
                &other.ed_pubkey(),
                None,
                None,
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::NotOwnKey)
        );
    }

    /// Once enrolled, access requires a membership cert that (a) verifies against
    /// the trust anchor, (b) is bound to the TLS-authenticated handshake key, and
    /// (c) carries the admin capability for a non-revoked node. Each failure mode
    /// names its own reason.
    #[test]
    fn enrolled_requires_admin_cert_bound_to_handshake_key() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();
        let own = Keypair::from_seed(&[7u8; 32]);

        let admin_kp = Keypair::from_seed(&[2u8; 32]);
        let admin_cert =
            authority.issue_admin_cert(mac(5), admin_kp.ed_pubkey(), admin_kp.x_pubkey(), 0, 200);

        // Verified admin cert whose key matches the handshake key → granted.
        assert_eq!(
            decide_access(
                &admin_kp.ed_pubkey(),
                Some(&admin_cert),
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::GrantedAdmin
        );

        // No cert presented on an enrolled node → refused.
        assert_eq!(
            decide_access(
                &admin_kp.ed_pubkey(),
                None,
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::MissingCert)
        );

        // Valid admin cert, but the handshake key isn't the cert's key: the cert
        // wasn't bound to this session (someone replayed a cert they don't own).
        assert_eq!(
            decide_access(
                &own.ed_pubkey(),
                Some(&admin_cert),
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::KeyMismatch)
        );

        // A plain (non-admin) member cert, properly bound → refused as non-admin.
        let member_kp = Keypair::from_seed(&[3u8; 32]);
        let member_cert =
            authority.issue_cert(mac(6), member_kp.ed_pubkey(), member_kp.x_pubkey(), 0, 200);
        assert_eq!(
            decide_access(
                &member_kp.ed_pubkey(),
                Some(&member_cert),
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::NotAdmin)
        );

        // Admin cert, bound, but the node is revoked → refused.
        assert_eq!(
            decide_access(
                &admin_kp.ed_pubkey(),
                Some(&admin_cert),
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |m| m == mac(5)
            ),
            MgmtAccess::Denied(MgmtDenied::Revoked)
        );

        // Cert that fails verification (here: expired at now=999) surfaces the
        // underlying AuthError.
        assert_eq!(
            decide_access(
                &admin_kp.ed_pubkey(),
                Some(&admin_cert),
                Some(&anchor),
                &own.ed_pubkey(),
                999,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::CertInvalid(
                wayfinder::wayfinder_auth::AuthError::Expired
            ))
        );
    }

    /// Security-critical: once enrolled, self-key bootstrap no longer grants
    /// access. Presenting the node's own key with no admin cert is refused
    /// (fail-closed), so a leaked device key cannot manage a provisioned node.
    #[test]
    fn self_key_bootstrap_refused_once_enrolled() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();
        let own = Keypair::from_seed(&[7u8; 32]);

        assert_eq!(
            decide_access(
                &own.ed_pubkey(),
                None,
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::MissingCert)
        );
    }
}
