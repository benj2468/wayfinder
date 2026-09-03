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

use wayfinder::wayfinder_auth::AuthError;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder::wayfinder_auth::VerifiedCert;

#[cfg(feature = "std")]
use wayfinder_protos::rpc::AccessTier;
#[cfg(feature = "std")]
use wayfinder_protos::rpc::access_tiers;
#[cfg(feature = "std")]
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
    /// Granted read-only: a verified, non-revoked cert bound to the handshake
    /// key carrying [`CERT_FLAG_VIEWER`](wayfinder::wayfinder_auth::CERT_FLAG_VIEWER)
    /// but not the admin capability. What it may invoke is [`permits`]: the
    /// queries, and nothing that mutates or discloses a secret.
    GrantedViewer,
    /// Granted via the self-key path: the client proved possession of the node's
    /// *own* identity key.
    ///
    /// The widest tier: [`permits`] admits every request without exception,
    /// including `GetVpnEnrollment` — which the admin tier is refused. That is
    /// not this tier being *more* privileged so much as it being the only full
    /// grant that is a device: it is the node, so the credential minted for it
    /// is the node's own.
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
/// Every variant is a *failed claim to a management capability* — a client that
/// presented a cert which did not hold up. Presenting no cert at all is not a
/// denial: it is [`MgmtAccess::GrantedEnrollment`], which can do nothing but
/// enroll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtDenied {
    /// The presented cert failed verification against the trust anchor (carries
    /// the underlying [`AuthError`]).
    CertInvalid(AuthError),
    /// Enrolled path: the cert verified but its key is not the TLS-authenticated
    /// handshake key, so it was not bound to this session (e.g. a cert replayed
    /// by someone who does not hold its private key).
    KeyMismatch,
    /// Enrolled path: the verified cert carries no *management* capability —
    /// neither [`CERT_FLAG_ADMIN`](wayfinder::wayfinder_auth::CERT_FLAG_ADMIN)
    /// nor [`CERT_FLAG_VIEWER`](wayfinder::wayfinder_auth::CERT_FLAG_VIEWER).
    ///
    /// This is where an ordinary *device* certificate lands, and where it
    /// belongs: a node routes over the mesh, it does not manage the node it
    /// connects to. Design 18 retired the one tier that sat between here and
    /// the viewer tier — a device-scoped grant that existed solely to hand out
    /// a VPN credential — so the rule is once again the simple one: management
    /// access takes a signed management bit, and everything else is denied.
    ///
    /// A certificate whose bits this build does not recognise also lands here,
    /// since unknown flags are masked off rather than guessed at.
    NoCapability,
    /// Enrolled path: the verified admin's node has been revoked.
    Revoked,
}

/// Decide what a client that completed the TLS handshake with `handshake_key`
/// may do, in three tiers:
///
/// * **Self-key** ([`MgmtAccess::GrantedSelfKey`]): `handshake_key` is the
///   node's `own_key`, so the client holds the node's identity seed. `own_key`
///   is an `Option` because a node with no identity seed configured has no such
///   key at all, and this tier is then simply unavailable — rather than resting
///   on a sentinel value being unreachable, which for the all-zero key it was
///   not: that is a valid Ed25519 encoding of a low-order point, and the TLS
///   `CertificateVerify` proving possession here is checked by `ring`, not by
///   dalek's `verify_strict`. Full
///   management access, whether or not the node is enrolled. Whoever holds that
///   seed *is* this node on the mesh — it signs the node's OGMs and terminates
///   the node's own TLS — so withholding management from it would protect
///   nothing while breaking the one credential a node's local operator is
///   guaranteed to have. This is also what carries a dashboard across the
///   moment of enrollment, when the node acquires an anchor it previously
///   lacked. `own_key` is not a value this function caches or freezes: the
///   caller (the TLS accept loop) reads it fresh from the router loop on every
///   connection, so a seed the node has since rotated away from — via
///   `SetAuth` installing a different one — stops earning this grant on the
///   very next connection, not only after a restart. It is also the one full
///   grant that is a *device* rather than a person, so it is the one admitted
///   to `GetVpnEnrollment` — see [`permits`].
/// * **Admin** ([`MgmtAccess::GrantedAdmin`]): the node is enrolled and the
///   client presented a `cert` that verifies against the `anchor` as of
///   `now_unix`, whose key matches `handshake_key` (binding the cert to this
///   session), carrying the admin capability for a node `is_revoked` reports as
///   active. Full management access. A cert that fails any of those checks is
///   [`MgmtAccess::Denied`] — a failed claim, not a fallback to a lesser tier.
/// * **Viewer** ([`MgmtAccess::GrantedViewer`]): as the admin tier, but the
///   verified cert carries
///   [`CERT_FLAG_VIEWER`](wayfinder::wayfinder_auth::CERT_FLAG_VIEWER) instead
///   of the admin capability. Read-only management access — see [`permits`].
///   Note what this is *not*: it is not "a verified cert that is not an admin".
///   Every device on the mesh holds a verified non-admin cert, so granting the
///   tier by absence would be granting it to the whole mesh; it takes a signed
///   bit, and a cert with neither bit is [`MgmtDenied::NoCapability`].
/// * **Enrollment** ([`MgmtAccess::GrantedEnrollment`]): no cert was presented
///   at all, so the client is a stranger and may only enroll — see [`permits`]
///   and this module's header for why that door is open.
pub fn decide_access(
    handshake_key: &[u8; 32],
    cert: Option<&MembershipCert>,
    anchor: Option<&TrustAnchor>,
    own_key: Option<&[u8; 32]>,
    now_unix: u64,
    is_revoked: impl FnOnce(&VerifiedCert) -> bool,
) -> MgmtAccess {
    if own_key == Some(handshake_key) {
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
    match authorize_capability(&verified, is_revoked) {
        Ok(access) => access,
        Err(reason) => MgmtAccess::Denied(reason),
    }
}

/// Whether a connection holding `access` may invoke `request`.
///
/// Two halves, and the split is the point. *Which tiers a request admits* is
/// declared per-request in `wayfinder-protos`'s `rpc_table!`, next to that
/// request's owner and audit class. *Which tier a connection earned* is
/// [`decide_access`], here. This function is only the join between them, so
/// there is no list to fall out of step with the proto: a request kind added
/// without an `access` list does not compile, where the tier lists this
/// replaced were `matches!` arms with an implicit catch-all — a new kind
/// silently became permitted for admin and self-key and refused for viewer and
/// enrollment. `SetUserRole`, `SetUserEnabled` and `SetUserPassword` all
/// reached the proto that way.
///
/// The policy those declarations encode is unchanged, and three parts of it are
/// worth reading in one place even though each is now stated at its own entry:
///
/// * **`GetVpnEnrollment` is the one request the admin tier may not invoke.**
///   It is not a management capability being exercised — it mints a tunnel
///   credential bound to *the calling device's own identity*. An operator's
///   session certificate is fully privileged and is not a device, so for it the
///   request has no meaning rather than being a privilege it lacks. The node's
///   own seed *is* a device identity — the node's — which is why
///   [`MgmtAccess::GrantedSelfKey`] is admitted and the certificate authority
///   can join the tunnel it coordinates through the same RPC every other node
///   uses. What makes that safe is where the MAC comes from: the router, not
///   the connection.
///
/// * **The enrollment tier is a closed allowlist** — `SubmitCsr`,
///   `GetTrustAnchor`, `AuthenticateUser` and the two invitation-redemption
///   requests. A caller holding nothing this mesh has signed has to be able to
///   make those, whether it is a node joining or a person redeeming an
///   invitation, and admission control for them has not moved: the enrollment
///   token and the operator's approval for a CSR, the password, the second
///   factor and the per-account lockout for a login, and the 256-bit
///   single-use invitation for a redemption. What is deliberately *not*
///   admitted beside them is the rest of the account store — an enrollment
///   connection can redeem an invitation it already holds and cannot mint one,
///   list one, or revoke one.
///
/// * **The viewer tier is earned by a signed bit, never by the absence of
///   another.** Every device on the mesh holds a verified non-admin
///   certificate, so a tier granted by absence would be a tier the whole mesh
///   already had, silently widening every time a capability was added. Design
///   18 removed the tier that tested this rule hardest — a device-scoped grant
///   exactly one request wide, existing only to mint a VPN credential — and
///   the rule is what remains: a new tier needs a new bit, never a new gap.
///
/// SECURITY ALERT: this function and the `access` lists it reads hold
/// security-critical access-control logic. Changing either requires careful
/// consideration.
#[cfg(feature = "std")]
pub fn permits(access: MgmtAccess, request: &ReqKind) -> bool {
    // A denial is not a tier: it names no row in the table, and must not be
    // mapped onto one.
    let tier = match access {
        MgmtAccess::GrantedAdmin => AccessTier::Admin,
        MgmtAccess::GrantedSelfKey => AccessTier::SelfKey,
        MgmtAccess::GrantedViewer => AccessTier::Viewer,
        MgmtAccess::GrantedEnrollment => AccessTier::Enrollment,
        MgmtAccess::Denied(_) => return false,
    };
    access_tiers(request).contains(&tier)
}

/// Which management tier an authenticated client bearing `cert` earns:
/// [`MgmtAccess::GrantedAdmin`], [`MgmtAccess::GrantedViewer`], or an
/// `Err(reason)` refusing it.
///
/// `cert` must already have been verified against the trust anchor (it is a
/// [`VerifiedCert`], produced only on the verification success path), so its
/// [`admin`](VerifiedCert::admin) and [`viewer`](VerifiedCert::viewer) bits are
/// trustworthy.  `is_revoked` reports whether an active revocation cancels
/// *this certificate* — supplied as a predicate so the policy stays decoupled
/// from where revocation state lives (the router's `OgmAuth`).
///
/// It takes the whole certificate, not its MAC, because a revocation cancels
/// the credentials that existed when it was signed: a certificate issued after
/// the revocation instant is a re-admission and must not be refused here. See
/// [`RevocationRecord::cancels`](wayfinder_auth::RevocationRecord::cancels).
///
/// Revocation is checked first: it dominates every capability, so a revoked
/// admin is refused ([`MgmtDenied::Revoked`]) rather than allowed. The
/// remaining bits are then ordered widest-first — admin, viewer, member — so a
/// cert carrying several is reported at the widest tier it earns. That
/// direction matters in one specific way: the member tier is the only one whose
/// single request the wider tiers may *not* invoke, so resolving a multi-bit
/// cert downward instead would let an issuer narrow an operator's grant by
/// setting an extra bit.
///
/// SECURITY ALERT: this function holds security-critical access-control
/// logic. Changing it requires careful consideration.
pub fn authorize_capability(
    cert: &VerifiedCert,
    is_revoked: impl FnOnce(&VerifiedCert) -> bool,
) -> Result<MgmtAccess, MgmtDenied> {
    if is_revoked(cert) {
        Err(MgmtDenied::Revoked)
    } else if cert.admin {
        Ok(MgmtAccess::GrantedAdmin)
    } else if cert.viewer {
        Ok(MgmtAccess::GrantedViewer)
    } else {
        Err(MgmtDenied::NoCapability)
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
            not_before: 0,
            not_after: 0,
            admin,
            viewer: false,
            user: false,
            member: false,
        }
    }

    /// A verified cert carrying the read-only capability and nothing else.
    fn verified_viewer(m: Mac) -> VerifiedCert {
        VerifiedCert {
            viewer: true,
            ..verified(m, false)
        }
    }

    /// The management authorization rule: a client may invoke privileged ops iff
    /// its verified cert carries the admin capability *and* its node has not been
    /// revoked.  Revocation dominates the admin bit — a revoked admin is still
    /// refused.
    #[test]
    fn admin_authorization_requires_admin_and_not_revoked() {
        // Verified admin, not revoked → the full grant.
        assert_eq!(
            authorize_capability(&verified(mac(1), true), |_| false),
            Ok(MgmtAccess::GrantedAdmin)
        );

        // Verified but carrying no management capability at all → refused.
        // This is where an ordinary device certificate lands, and it must stay
        // there: every node on the mesh holds one.
        assert_eq!(
            authorize_capability(&verified(mac(1), false), |_| false),
            Err(MgmtDenied::NoCapability)
        );

        // Verified admin whose node has been revoked → refused despite the admin
        // bit; revocation is the dominant, mesh-wide fact.
        assert_eq!(
            authorize_capability(&verified(mac(1), true), |c: &VerifiedCert| c.mac == mac(1)),
            Err(MgmtDenied::Revoked)
        );
    }

    /// The viewer capability is earned by its own signed bit, is dominated by
    /// revocation like every other capability, and is *subsumed* by the admin
    /// bit — a cert carrying both is an admin, so an admin never has to be
    /// flagged as a viewer as well in order to read.
    #[test]
    fn the_viewer_capability_is_its_own_bit_and_the_admin_bit_subsumes_it() {
        assert_eq!(
            authorize_capability(&verified_viewer(mac(1)), |_| false),
            Ok(MgmtAccess::GrantedViewer)
        );
        assert_eq!(
            authorize_capability(&verified_viewer(mac(1)), |c: &VerifiedCert| c.mac == mac(1)),
            Err(MgmtDenied::Revoked),
            "revocation dominates the viewer capability too"
        );
        assert_eq!(
            authorize_capability(
                &VerifiedCert {
                    viewer: true,
                    ..verified(mac(1), true)
                },
                |_| false
            ),
            Ok(MgmtAccess::GrantedAdmin),
            "admin dominates viewer: both bits is an admin, not a viewer"
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
            decide_access(
                &own.ed_pubkey(),
                None,
                None,
                Some(&own.ed_pubkey()),
                100,
                |_| { false }
            ),
            MgmtAccess::GrantedSelfKey
        );
        assert_eq!(
            decide_access(
                &own.ed_pubkey(),
                None,
                Some(&anchor),
                Some(&own.ed_pubkey()),
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
    /// A node with no identity seed configured has no own key, and nothing may
    /// claim one.
    ///
    /// The sentinel this replaces was an all-zero key, defended as unreachable
    /// by any real handshake key. All-zeros is in fact a valid Ed25519 encoding
    /// — a low-order point — and the `CertificateVerify` that proves possession
    /// here is checked by `ring`, not by dalek's `verify_strict`, which is the
    /// function that rejects low-order keys. Making the absence a `None` costs
    /// an `Option` and closes the question rather than arguing it.
    #[test]
    fn a_node_with_no_identity_key_grants_no_self_key_tier() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();

        assert_eq!(
            decide_access(&[0u8; 32], None, None, None, 100, |_| false),
            MgmtAccess::GrantedEnrollment,
            "an all-zero handshake key against a seedless node is a stranger, not the node"
        );
        assert_eq!(
            decide_access(&[0u8; 32], None, Some(&anchor), None, 100, |_| false),
            MgmtAccess::GrantedEnrollment,
            "and an installed anchor does not change that"
        );
        assert_eq!(
            decide_access(&[9u8; 32], None, None, None, 100, |_| false),
            MgmtAccess::GrantedEnrollment,
            "nor does any other key stand in for an absent one"
        );
    }

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
                Some(&own.ed_pubkey()),
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
                Some(&own.ed_pubkey()),
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
            MgmtAccess::Denied(MgmtDenied::NoCapability),
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
        let admin_cert = authority.issue_user_cert(
            mac(5),
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
            true,
        );

        // Verified admin cert whose key matches the handshake key → granted.
        assert_eq!(
            decide_access(
                &admin_kp.ed_pubkey(),
                Some(&admin_cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
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
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::KeyMismatch)
        );

        // A plain (non-admin) device cert, properly bound → the member tier,
        // which is not management: it earns one request (its own VPN
        // credential) and none of the privileged ones. Asserted both ways here
        // rather than on the tier name alone, since the property that matters
        // is what the tier can *do*.
        let member_kp = Keypair::from_seed(&[3u8; 32]);
        let member_cert =
            authority.issue_cert(mac(6), member_kp.ed_pubkey(), member_kp.x_pubkey(), 0, 200);
        let decision = decide_access(
            &member_kp.ed_pubkey(),
            Some(&member_cert),
            Some(&anchor),
            Some(&own.ed_pubkey()),
            100,
            |_| false,
        );
        // A device certificate carries no management capability, so it is
        // denied outright — the tier that used to sit here existed only to
        // mint a VPN credential and went with it (design 18).
        assert_eq!(decision, MgmtAccess::Denied(MgmtDenied::NoCapability));
        assert!(!permits(
            decision,
            &ReqKind::SetAuth(wayfinder_protos::wayfinder::v1alpha::SetAuthRequest::default())
        ));
        assert!(!permits(
            decision,
            &ReqKind::ApproveCsr(
                wayfinder_protos::wayfinder::v1alpha::ApproveCsrRequest::default()
            )
        ));

        // Admin cert, bound, but the node is revoked → refused.
        assert_eq!(
            decide_access(
                &admin_kp.ed_pubkey(),
                Some(&admin_cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |c: &VerifiedCert| c.mac == mac(5)
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
                Some(&own.ed_pubkey()),
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

        // With a device's member cert: admitted to the member tier, which
        // manages nothing — the security-status read this test names is
        // refused, as is every other management request.
        assert!(!permits(
            decide_access(
                &stranger.ed_pubkey(),
                Some(&member_cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            &ReqKind::GetSecurityStatus(GetSecurityStatusRequest {})
        ));
        // With no cert: admitted, but unable to invoke anything but enrollment.
        assert!(!permits(
            decide_access(
                &stranger.ed_pubkey(),
                None,
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            &ReqKind::GetSecurityStatus(GetSecurityStatusRequest {})
        ));
    }

    use wayfinder_protos::rpc::AccessTier;
    use wayfinder_protos::rpc::Audited;
    use wayfinder_protos::rpc::RateLimit;
    use wayfinder_protos::rpc::access_tiers;
    use wayfinder_protos::rpc::audited;
    /// One value per request variant, so the sweeps below cover the whole
    /// request surface rather than a hand-picked sample of it.
    ///
    /// Re-exported from `wayfinder-protos`'s declaration table (behind its
    /// `test-support` feature) rather than listed here. It used to be a
    /// test-only macro in this file that expanded to both the list and an
    /// exhaustive match whose only job was to fail to compile when the list
    /// fell behind the proto — a check this module needed because `permits`
    /// classified requests with `matches!` arms that had an implicit
    /// catch-all, so nothing else forced a decision on a new kind.
    ///
    /// `rpc_table!` forces it at the declaration now: a request with no
    /// `access` list does not compile, and this list is generated from the same
    /// table, so it cannot fall behind what it is sweeping.
    use wayfinder_protos::rpc::every_request_kind;
    use wayfinder_protos::rpc::rate_limit;
    use wayfinder_protos::rpc::request_kind_name;

    /// The classifications the design calls one-of-a-kind really are, counted
    /// over the whole surface rather than spot-checked on the named instance.
    ///
    /// This replaced a test in `rpc.rs` whose name promised "exactly one" and
    /// whose body asserted only that the one it named was classified correctly
    /// — so a *second* disclosure, or a second request refusing admin, would
    /// have passed it. Both properties are load-bearing:
    ///
    /// * A disclosure is a secret leaving the node. The audit log is the only
    ///   record of who learned the enrollment token and when, and a second
    ///   request that hands out a secret without being classified `Disclosure`
    ///   would leave no trace at all.
    /// * `GetVpnEnrollment` is the one request an *admin* is refused, because
    ///   it mints a credential for a device identity an operator's session
    ///   certificate does not have. A second such request would mean the "two
    ///   full grants may invoke everything except one" rule stated throughout
    ///   this crate's docs had quietly stopped being true.
    #[test]
    fn the_singular_classifications_are_singular() {
        let all = every_request_kind();

        let disclosures: Vec<_> = all
            .iter()
            .filter(|k| audited(k) == Audited::Disclosure)
            .map(request_kind_name)
            .collect();
        assert_eq!(
            disclosures,
            ["RevealEnrollmentToken"],
            "the set of requests classified as a secret disclosure changed"
        );

        // Empty, and that is the point. There used to be exactly one request
        // an admin was refused — `GetVpnEnrollment`, refused for not naming a
        // *device* rather than for want of privilege — and it went with the
        // VPN control plane in design 18. An admin grant is now unqualified.
        //
        // Asserted rather than deleted: "no exceptions" is a property worth
        // holding, and a future request that carves one out should have to say
        // so here, where the reasoning is, instead of appearing quietly in a
        // table.
        let admin_refused: Vec<_> = all
            .iter()
            .filter(|k| !access_tiers(k).contains(&AccessTier::Admin))
            .map(request_kind_name)
            .collect();
        assert_eq!(
            admin_refused,
            Vec::<&str>::new(),
            "the admin tier gained a request it may not invoke"
        );
    }

    /// Every request reachable on the enrollment tier that *costs* something
    /// spends a bucket, and every bucket holds only the requests it was sized
    /// for.
    ///
    /// `access` and `limit` are declared independently in `rpc_table!`, and
    /// nothing else cross-checks them: mutation testing showed
    /// `GetTrustAnchor` could be moved to `RateLimit::Login` with the whole
    /// suite still green. That is not cosmetic — an anonymous node polling for
    /// the trust anchor would then drain the login budget for its source
    /// address, locking out sign-ins from behind the same NAT, which is
    /// precisely the cross-flow starvation the separate buckets exist to
    /// prevent (see `RateLimit`'s doc).
    ///
    /// So the buckets are pinned per kind, not merely spot-checked.
    #[test]
    fn every_request_spends_the_bucket_its_flow_was_sized_for() {
        for request in every_request_kind() {
            let expected = match &request {
                ReqKind::SubmitCsr(_) => RateLimit::SubmitCsr,
                ReqKind::AuthenticateUser(_) => RateLimit::Login,
                // Both halves of one redemption, one bucket: bounding either
                // alone bounds nothing.
                ReqKind::BeginUserRegistration(_) | ReqKind::CompleteUserRegistration(_) => {
                    RateLimit::Registration
                }
                _ => RateLimit::Unmetered,
            };
            assert_eq!(
                rate_limit(&request),
                expected,
                "rate-limit bucket for {request:?}"
            );
        }
    }

    /// Nothing an anonymous caller can reach is free unless it is a pure read.
    ///
    /// The invariant behind the table above, asserted separately so that adding
    /// an expensive request to the enrollment tier and forgetting to meter it
    /// fails here rather than in production. `GetTrustAnchor` is the one
    /// deliberate exception: it hands back a public value every OGM on the mesh
    /// is already verified against, and it is what a joining node must read
    /// before it can verify anything at all.
    #[test]
    fn an_unmetered_enrollment_request_is_a_read_or_the_trust_anchor() {
        for request in every_request_kind() {
            if !permits(MgmtAccess::GrantedEnrollment, &request) {
                continue;
            }
            if matches!(rate_limit(&request), RateLimit::Unmetered) {
                assert!(
                    matches!(request, ReqKind::GetTrustAnchor(_)),
                    "{request:?} is reachable with no credential and spends no bucket"
                );
            }
        }
    }

    /// The enrollment tier is a *closed* allowlist over the whole request
    /// surface: exactly `SubmitCsr`, `GetTrustAnchor`, `AuthenticateUser`,
    /// `BeginUserRegistration` and `CompleteUserRegistration`, and every other
    /// kind refused — including the ones that would otherwise be the prize
    /// (`ApproveCsr` on its own request, `SetAuth`, `SetConfig`, `GetLogs`).
    ///
    /// What makes this a sweep of the *whole* surface rather than a hand-picked
    /// sample is that `every_request_kind()` is generated from the same
    /// `rpc_table!` entries being swept: it cannot fall behind the proto,
    /// because a variant missing from the table does not compile.
    #[test]
    fn permits_confines_the_enrollment_tier_to_a_closed_allowlist() {
        let all = every_request_kind();

        for request in &all {
            // Notably not on the list: `RevealEnrollmentToken`. A node asking
            // to join has to be *given* the token; a node that could ask the
            // provider for it would make the token no barrier at all.
            let expected = matches!(
                request,
                ReqKind::SubmitCsr(_)
                    | ReqKind::GetTrustAnchor(_)
                    | ReqKind::AuthenticateUser(_)
                    // Redeeming an invite: somebody who does not have an
                    // account yet holds no credential, so a tier that required
                    // one would close the door they need to knock on. What
                    // confines them is the token — 256 bits, single-use,
                    // expiring, and minted by an admin who chose the name and
                    // the role.
                    //
                    // Note what is *not* admitted beside them: an enrollment
                    // connection can redeem an invite it holds and can do
                    // nothing else to the account store. It cannot mint one,
                    // list one, or revoke one.
                    | ReqKind::BeginUserRegistration(_)
                    | ReqKind::CompleteUserRegistration(_)
            );
            assert_eq!(
                permits(MgmtAccess::GrantedEnrollment, request),
                expected,
                "enrollment tier verdict for {request:?}"
            );
            // The admin tier may invoke anything *except* `GetVpnEnrollment`
            // — the one request it means nothing for, since its response is
            // scoped to a device identity an operator's session certificate
            // is not. Asserted over the same closed set so the two cannot
            // drift.
            // No exceptions remain: design 18 retired the one request an
            // admin could be refused, which was refused for not naming a
            // device rather than for want of privilege.
            assert!(
                permits(MgmtAccess::GrantedAdmin, request),
                "admin tier verdict for {request:?}"
            );
            // The self-key tier is the one grant with no exception at all: it
            // is the node itself, so `GetVpnEnrollment` has an identity to
            // mint for — its own.
            assert!(
                permits(MgmtAccess::GrantedSelfKey, request),
                "self-key tier verdict for {request:?}"
            );
            assert!(
                !permits(MgmtAccess::Denied(MgmtDenied::NoCapability), request),
                "a denied connection was permitted {request:?}"
            );
        }
    }

    /// The viewer tier is a closed allowlist over the same whole request
    /// surface: every query, and not one mutation or disclosure.
    ///
    /// Written as an explicit *refusal* list rather than as "everything that
    /// isn't a `Get`", so that a request named like a read but shaped like
    /// something else has to be classified deliberately. `RevealEnrollmentToken`
    /// is the one that makes the point: a read by shape, the mesh's admission
    /// credential by content.
    #[test]
    fn permits_confines_the_viewer_tier_to_the_queries() {
        let all = every_request_kind();

        for request in &all {
            let refused = matches!(
                request,
                ReqKind::SetAuth(_)
                    | ReqKind::SetConfig(_)
                    | ReqKind::SetLogLevel(_)
                    // Starting a ping is not the read its status is. It puts
                    // frames on the air at a cadence the caller chooses, and
                    // takes the node's one session slot away from whoever held
                    // it — a read-only grant that could do either would be
                    // read-only in name. `PingStatus` beside it is a genuine
                    // query and stays open to a viewer: "can this node reach
                    // that one" is the question the tier exists to answer.
                    | ReqKind::Ping(_)
                    | ReqKind::CancelPing(_)
                    | ReqKind::SubmitCsr(_)
                    | ReqKind::RevokeNode(_)
                    | ReqKind::ApproveCsr(_)
                    | ReqKind::DenyCsr(_)
                    | ReqKind::RevealEnrollmentToken(_)
                    | ReqKind::Authenticate(_)
                    // A viewer holds a certificate already; logging in again on
                    // the same connection has no defined meaning, and letting
                    // it through would put a credential-minting request behind
                    // a read-only grant.
                    | ReqKind::AuthenticateUser(_)
                    | ReqKind::CreateUser(_)
                    // Removing an account is administering who may administer
                    // the mesh, which is the furthest thing there is from a
                    // read-only tier's business.
                    | ReqKind::RemoveUser(_)
                    // A read by shape, and refused anyway: the account roster
                    // is who may administer the mesh, which is an
                    // administrator's business. A viewer reads the *network*.
                    // Widening this later is one line; narrowing it after
                    // somebody has relied on it is not.
                    | ReqKind::ListUsers(_)
                    // Deciding that an account will exist, with a role, is the
                    // same administration `CreateUser` beside it is — taken one
                    // step earlier in time. And revoking one is how an admin
                    // responds to a token they believe has leaked.
                    | ReqKind::CreateUserInvite(_)
                    | ReqKind::RevokeUserInvite(_)
                    // A read by shape, refused for the reason `ListUsers` above
                    // is: who is being given administrative access is an
                    // administrator's business. A viewer reads the *network*.
                    | ReqKind::ListUserInvites(_)
                    // A viewer holds a certificate already. Redeeming an invite
                    // on that connection has no defined meaning, and would put
                    // an account-creating request behind a read-only grant.
                    | ReqKind::BeginUserRegistration(_)
                    | ReqKind::CompleteUserRegistration(_)
                    // Ending the sessions somebody currently holds is the same
                    // administration `RemoveUser` above is, minus the deletion.
                    | ReqKind::RevokeUserSessions(_)
                    // Deciding who may administer the mesh, whether an account
                    // may sign in at all, and what its credential is. The three
                    // are the account lifecycle between `CreateUser` and
                    // `RemoveUser`, and belong to the same tier those do — a
                    // read-only grant that could promote its own holder would
                    // not be read-only for longer than one request.
                    | ReqKind::SetUserRole(_)
                    | ReqKind::SetUserEnabled(_)
                    | ReqKind::SetUserPassword(_)
                    // A read of public material, and refused all the same —
                    // because nothing needs it. `--cert-from` fetches a node's
                    // certificate over a connection that proves the node's own
                    // seed, which is `GrantedSelfKey` before any certificate is
                    // examined, so no caller in this workspace reaches this
                    // request as a viewer. Granting it anyway would be widening
                    // a `SECURITY ALERT` allowlist for a consumer that does not
                    // exist, and the rule this file already applies to
                    // `ListUsers` above applies here: widening later is one
                    // line, narrowing after somebody has relied on it is not.
                    //
                    // Nothing is being protected by the refusal, to be clear.
                    // A viewer already reads every *field* of the certificate
                    // from `GetSecurityStatus` (mesh id, own MAC, both public
                    // keys, expiry) and `ListCerts` beside it; what this adds
                    // is the root's signature over those fields, which is
                    // verification material rather than a secret. Grant it the
                    // day something needs it.
                    | ReqKind::GetOwnCert(_)
            );
            assert_eq!(
                permits(MgmtAccess::GrantedViewer, request),
                !refused,
                "viewer tier verdict for {request:?}"
            );
        }
    }

    /// A viewer certificate is admitted as a viewer through the whole
    /// `decide_access` path — verified against the anchor, bound to the
    /// handshake key — while the *same* certificate stripped of its capability
    /// bit is refused rather than demoted to a lesser grant.
    #[test]
    fn a_viewer_certificate_is_admitted_as_a_viewer_and_a_bare_one_is_not() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();
        let own = Keypair::from_seed(&[7u8; 32]);
        let operator = Keypair::from_seed(&[8u8; 32]);

        let viewer_cert = authority.issue_user_cert(
            mac(5),
            operator.ed_pubkey(),
            operator.x_pubkey(),
            0,
            200,
            false,
        );
        assert_eq!(
            decide_access(
                &operator.ed_pubkey(),
                Some(&viewer_cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            MgmtAccess::GrantedViewer
        );

        // An ordinary device certificate — what every node on the mesh holds —
        // earns no *read* access. This is the property that makes the viewer
        // tier safe: it is granted by a bit, never by the absence of one. The
        // device lands on the member tier instead, which reads nothing.
        let device_cert =
            authority.issue_cert(mac(6), operator.ed_pubkey(), operator.x_pubkey(), 0, 200);
        let decision = decide_access(
            &operator.ed_pubkey(),
            Some(&device_cert),
            Some(&anchor),
            Some(&own.ed_pubkey()),
            100,
            |_| false,
        );
        assert_eq!(decision, MgmtAccess::Denied(MgmtDenied::NoCapability));
        assert!(!permits(
            decision,
            &ReqKind::GetRoutingTable(
                wayfinder_protos::wayfinder::v1alpha::GetRoutingTableRequest {}
            )
        ));
    }

    /// The anchor-absent column of the authorization matrix.
    ///
    /// A node with no trust anchor has nothing to verify a certificate
    /// *against*, so presenting one tells it nothing: expired, foreign,
    /// admin-flagged or bound to another key, every row lands on the same
    /// enrollment tier a client with no cert at all gets. That is not the
    /// "a failed claim is denied" rule being bypassed — no check ran to fail.
    /// The property that matters, and the one asserted here, is that on an
    /// anchorless node a certificate can never buy *more* access than
    /// presenting nothing.
    #[test]
    fn without_an_anchor_no_certificate_grants_more_than_enrollment() {
        let own = Keypair::from_seed(&[7u8; 32]);
        let stranger = Keypair::from_seed(&[8u8; 32]);
        let foreign = Authority::from_seed(&[1u8; 32], 0xABCD);

        // An admin cert bound to the presenting key — the strongest thing a
        // client could offer — and one already expired at `now`.
        let admin_cert = foreign.issue_user_cert(
            mac(5),
            stranger.ed_pubkey(),
            stranger.x_pubkey(),
            0,
            200,
            true,
        );
        // A plain member cert, and one issued to somebody else's key entirely.
        let member_cert =
            foreign.issue_cert(mac(6), stranger.ed_pubkey(), stranger.x_pubkey(), 0, 200);
        let other = Keypair::from_seed(&[9u8; 32]);
        let other_cert =
            foreign.issue_user_cert(mac(7), other.ed_pubkey(), other.x_pubkey(), 0, 200, true);

        for (label, cert, now) in [
            ("no cert", None, 100),
            ("admin cert", Some(&admin_cert), 100),
            ("expired admin cert", Some(&admin_cert), 999),
            ("member cert", Some(&member_cert), 100),
            ("cert for another key", Some(&other_cert), 100),
        ] {
            assert_eq!(
                decide_access(
                    &stranger.ed_pubkey(),
                    cert,
                    None,
                    Some(&own.ed_pubkey()),
                    now,
                    |_| false
                ),
                MgmtAccess::GrantedEnrollment,
                "anchorless node, {label}"
            );
        }

        // And the node's own key still outranks all of it.
        assert_eq!(
            decide_access(
                &own.ed_pubkey(),
                Some(&admin_cert),
                None,
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            MgmtAccess::GrantedSelfKey
        );
    }

    /// A certificate signed by a root that is not this mesh's is refused, in
    /// both shapes it can take: a foreign mesh id (caught by the id check) and
    /// a foreign root reusing *our* mesh id (caught only by the signature).
    ///
    /// The second is the one worth having a test for — a mesh id is a public,
    /// guessable label, so an attacker standing up their own authority would
    /// naturally reuse it, and the signature is then the only thing between
    /// their admin cert and this node's management API.
    #[test]
    fn a_certificate_from_a_foreign_root_is_denied() {
        let ours = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = ours.trust_anchor();
        let own = Keypair::from_seed(&[7u8; 32]);
        let attacker = Keypair::from_seed(&[2u8; 32]);

        // A different root, a different mesh: rejected on the mesh id.
        let other_mesh = Authority::from_seed(&[42u8; 32], 0xBEEF);
        let cert = other_mesh.issue_user_cert(
            mac(5),
            attacker.ed_pubkey(),
            attacker.x_pubkey(),
            0,
            200,
            true,
        );
        assert_eq!(
            decide_access(
                &attacker.ed_pubkey(),
                Some(&cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::CertInvalid(AuthError::WrongMesh))
        );

        // A different root claiming *our* mesh id: only the signature separates
        // this from a genuine admin cert.
        let impostor = Authority::from_seed(&[42u8; 32], 0xABCD);
        let cert = impostor.issue_user_cert(
            mac(5),
            attacker.ed_pubkey(),
            attacker.x_pubkey(),
            0,
            200,
            true,
        );
        assert_eq!(
            decide_access(
                &attacker.ed_pubkey(),
                Some(&cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::CertInvalid(AuthError::BadSignature))
        );
    }

    /// `member` and `user` are documented as mutually exclusive in everything
    /// the CA issues, but that is an issuer convention, not something the wire
    /// format or this function's callers can rely on unchecked. A cert
    /// carrying both must never earn the member tier: the tier mints a
    /// device-scoped VPN credential, and `user` marks a person's session, not
    /// a device.
    #[test]
    fn the_member_bit_does_not_grant_a_session_certificate() {
        assert_eq!(
            authorize_capability(
                &VerifiedCert {
                    member: true,
                    user: true,
                    ..verified(mac(1), false)
                },
                |_| false
            ),
            Err(MgmtDenied::NoCapability),
            "member+user must not earn the device-scoped member tier"
        );
    }

    /// Admin and viewer dominate the member bit. A certificate carrying both a
    /// management capability and the member bit is reported at its management
    /// tier, so an operator's grant is never quietly narrowed to the one-request
    /// member tier by an issuer setting an extra bit.
    #[test]
    fn a_management_capability_dominates_the_member_bit() {
        assert_eq!(
            authorize_capability(
                &VerifiedCert {
                    member: true,
                    ..verified(mac(1), true)
                },
                |_| false
            ),
            Ok(MgmtAccess::GrantedAdmin)
        );
        assert_eq!(
            authorize_capability(
                &VerifiedCert {
                    member: true,
                    ..verified_viewer(mac(1))
                },
                |_| false
            ),
            Ok(MgmtAccess::GrantedViewer)
        );
    }
}
