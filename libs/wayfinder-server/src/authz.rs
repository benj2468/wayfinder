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
//!
//! # Enrollment is the one thing a stranger may do
//!
//! A node asking to join a mesh has, by definition, no membership cert yet — so
//! a policy that admitted only admins would close the door it needs to knock on:
//! the enrolling node could never open the connection that carries its CSR, and
//! online enrollment would be impossible against any provider that is itself an
//! enrolled member (which every real one is).
//!
//! So a client that presents no cert is admitted, and [`permits`] then confines
//! it to the enrollment requests. Admission control has not moved — it is where
//! it always was, in the provider's enrollment policy: the shared token, and the
//! operator approving the request. What this grants is the ability to *ask*.

use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::AuthError;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder::wayfinder_auth::VerifiedCert;
use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;

/// The overall management access decision for a client that has completed the
/// TLS handshake, proving possession of `handshake_key` (its raw Ed25519 public
/// key, RFC 7250).  Produced by [`decide_access`]; what each grant may then
/// *invoke* is [`permits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtAccess {
    /// Granted via the enrolled path: a verified, non-revoked admin cert bound to
    /// the handshake key.
    GrantedAdmin,
    /// Granted via the self-key path: the client proved possession of the node's
    /// *own* identity key.
    GrantedSelfKey,
    /// Granted for enrollment only: the client presented no membership cert, so
    /// it is a stranger — admitted solely to submit a CSR and read the mesh
    /// trust anchor (see [`permits`]).
    GrantedEnrollment,
    /// Refused, with the reason.
    Denied(MgmtDenied),
}

/// Why a management client was refused ([`MgmtAccess::Denied`]).
///
/// Every variant is a *failed claim to be an admin* — a client that presented a
/// cert which did not hold up. Presenting no cert at all is not a denial: it is
/// [`MgmtAccess::GrantedEnrollment`], which can do nothing but enroll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtDenied {
    /// The presented cert failed verification against the trust anchor (carries
    /// the underlying [`AuthError`]).
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

/// Decide what a client that completed the TLS handshake with `handshake_key`
/// may do, in three tiers:
///
/// * **Self-key** ([`MgmtAccess::GrantedSelfKey`]): `handshake_key` is the
///   node's `own_key`, so the client holds the node's identity seed. Full
///   management access, whether or not the node is enrolled. Whoever holds that
///   seed *is* this node on the mesh — it signs the node's OGMs and terminates
///   the node's own TLS — so withholding management from it would protect
///   nothing while breaking the one credential a node's local operator is
///   guaranteed to have. This is also what carries a dashboard across the
///   moment of enrollment, when the node acquires an anchor it previously
///   lacked.
/// * **Admin** ([`MgmtAccess::GrantedAdmin`]): the node is enrolled and the
///   client presented a `cert` that verifies against the `anchor` as of
///   `now_unix`, whose key matches `handshake_key` (binding the cert to this
///   session), carrying the admin capability for a node `is_revoked` reports as
///   active. Full management access. A cert that fails any of those checks is
///   [`MgmtAccess::Denied`] — a failed claim, not a fallback to a lesser tier.
/// * **Enrollment** ([`MgmtAccess::GrantedEnrollment`]): no cert was presented
///   at all, so the client is a stranger and may only enroll — see [`permits`]
///   and this module's header for why that door is open.
pub fn decide_access(
    handshake_key: &[u8; 32],
    cert: Option<&MembershipCert>,
    anchor: Option<&TrustAnchor>,
    own_key: &[u8; 32],
    now_unix: u64,
    is_revoked: impl FnOnce(Mac) -> bool,
) -> MgmtAccess {
    if handshake_key == own_key {
        return MgmtAccess::GrantedSelfKey;
    }
    // No anchor means nothing to verify a cert against, so no client can prove
    // admin here; enrollment is all that is left (and is exactly what a fresh
    // provider being stood up needs to answer).
    let Some(anchor) = anchor else {
        return MgmtAccess::GrantedEnrollment;
    };
    // A stranger with no cert: enrollment only.
    let Some(cert) = cert else {
        return MgmtAccess::GrantedEnrollment;
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

/// Whether a connection holding `access` may invoke `request`.
///
/// Both full grants may invoke everything, so this is really the definition of
/// what [`MgmtAccess::GrantedEnrollment`] means: the two requests a node that
/// wants to join has to make, and nothing else.
///
/// * `SubmitCsr` — ask the provider to certify this node's keys. Whether it is
///   granted, parked for approval or refused is the provider's enrollment
///   policy to decide, not this function's.
/// * `GetTrustAnchor` — read the mesh's public trust anchor. Public by
///   construction: every OGM on the mesh is verified against it, so it is not a
///   secret being handed out.
///
/// Everything else — every read of routing state, every setting, every
/// provider action including approving a CSR — needs a full grant. A
/// `SubmitCsr` names its own subject, so an enrollment connection cannot reach
/// past the request it came to make.
///
/// Note what this deliberately does *not* require: that the submitted CSR's key
/// be the connection's handshake key. A client may submit a CSR for keys it
/// does not hold — but the certificate that comes back is bound to those keys,
/// so it is useless to anyone but their holder. All such a client achieves is
/// an entry in the provider's pending queue, which is what the enrollment token
/// and operator approval are there to filter.
pub fn permits(access: MgmtAccess, request: &ReqKind) -> bool {
    match access {
        MgmtAccess::GrantedAdmin | MgmtAccess::GrantedSelfKey => true,
        MgmtAccess::GrantedEnrollment => {
            matches!(request, ReqKind::SubmitCsr(_) | ReqKind::GetTrustAnchor(_))
        }
        MgmtAccess::Denied(_) => false,
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

    /// Proof of possession of the node's own key grants full management — and
    /// keeps doing so after the node enrolls. A dashboard reaching an
    /// un-enrolled node has no other credential it *can* hold, so a self-key
    /// grant that lapsed the instant enrollment succeeded would lock out the
    /// operator at exactly the moment they enrolled the node.
    #[test]
    fn the_nodes_own_key_grants_management_enrolled_or_not() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();
        let own = Keypair::from_seed(&[7u8; 32]);

        assert_eq!(
            decide_access(&own.ed_pubkey(), None, None, &own.ed_pubkey(), 100, |_| {
                false
            }),
            MgmtAccess::GrantedSelfKey
        );
        assert_eq!(
            decide_access(
                &own.ed_pubkey(),
                None,
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::GrantedSelfKey,
            "installing a trust anchor must not revoke the node's own key"
        );
    }

    /// A stranger presenting no cert is admitted for enrollment rather than
    /// refused: without this an un-enrolled node could never submit the CSR
    /// that would enroll it, since a provider worth enrolling with is itself an
    /// enrolled member. It holds whether or not this node has an anchor of its
    /// own — a provider being stood up has to answer the first CSR too.
    #[test]
    fn a_stranger_with_no_cert_is_admitted_for_enrollment() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();
        let own = Keypair::from_seed(&[7u8; 32]);
        let stranger = Keypair::from_seed(&[8u8; 32]);

        assert_eq!(
            decide_access(
                &stranger.ed_pubkey(),
                None,
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::GrantedEnrollment
        );
        assert_eq!(
            decide_access(
                &stranger.ed_pubkey(),
                None,
                None,
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::GrantedEnrollment
        );
    }

    /// The enrollment grant is only worth having because of what it cannot do:
    /// it submits a CSR and reads the trust anchor, and every other request —
    /// including the provider action that would approve its own CSR — is
    /// refused. The two full grants may invoke anything.
    #[test]
    fn an_enrollment_connection_may_only_enroll() {
        use wayfinder_protos::wayfinder::v1alpha::ApproveCsrRequest;
        use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusRequest;
        use wayfinder_protos::wayfinder::v1alpha::GetTrustAnchorRequest;
        use wayfinder_protos::wayfinder::v1alpha::SetAuthRequest;
        use wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest;

        let csr = ReqKind::SubmitCsr(SubmitCsrRequest::default());
        let trust_anchor = ReqKind::GetTrustAnchor(GetTrustAnchorRequest {});
        let approve = ReqKind::ApproveCsr(ApproveCsrRequest::default());
        let security = ReqKind::GetSecurityStatus(GetSecurityStatusRequest {});
        let set_auth = ReqKind::SetAuth(SetAuthRequest::default());

        assert!(permits(MgmtAccess::GrantedEnrollment, &csr));
        assert!(permits(MgmtAccess::GrantedEnrollment, &trust_anchor));
        assert!(!permits(MgmtAccess::GrantedEnrollment, &approve));
        assert!(!permits(MgmtAccess::GrantedEnrollment, &security));
        assert!(!permits(MgmtAccess::GrantedEnrollment, &set_auth));

        for full in [MgmtAccess::GrantedAdmin, MgmtAccess::GrantedSelfKey] {
            assert!(permits(full, &csr));
            assert!(permits(full, &approve));
            assert!(permits(full, &set_auth));
        }
        assert!(!permits(
            MgmtAccess::Denied(MgmtDenied::NotAdmin),
            &trust_anchor
        ));
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

        // Valid admin cert, but the handshake key isn't the cert's key: the cert
        // wasn't bound to this session (someone replayed a cert they don't own).
        // A denial, not a demotion to the enrollment tier: presenting a cert is
        // a claim, and a claim that fails is refused outright.
        let replayer = Keypair::from_seed(&[4u8; 32]);
        assert_eq!(
            decide_access(
                &replayer.ed_pubkey(),
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

    /// The boundary that survives the self-key grant: a key that is neither the
    /// node's own nor bound to an admin cert manages nothing, whatever it
    /// presents. (An earlier rule also refused the node's *own* key once
    /// enrolled; see [`decide_access`] for why that was reversed.)
    #[test]
    fn a_key_that_is_neither_own_nor_admin_manages_nothing() {
        use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusRequest;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();
        let own = Keypair::from_seed(&[7u8; 32]);
        let stranger = Keypair::from_seed(&[8u8; 32]);
        let member_cert =
            authority.issue_cert(mac(6), stranger.ed_pubkey(), stranger.x_pubkey(), 0, 200);

        // With a member cert: denied outright.
        assert_eq!(
            decide_access(
                &stranger.ed_pubkey(),
                Some(&member_cert),
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::NotAdmin)
        );
        // With no cert: admitted, but unable to invoke anything but enrollment.
        assert!(!permits(
            decide_access(
                &stranger.ed_pubkey(),
                None,
                Some(&anchor),
                &own.ed_pubkey(),
                100,
                |_| false
            ),
            &ReqKind::GetSecurityStatus(GetSecurityStatusRequest {})
        ));
    }
}
