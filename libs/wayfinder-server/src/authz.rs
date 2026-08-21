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
    /// Enrolled path: the verified cert carries no management capability at
    /// all — neither
    /// [`CERT_FLAG_ADMIN`](wayfinder::wayfinder_auth::CERT_FLAG_ADMIN) nor
    /// [`CERT_FLAG_VIEWER`](wayfinder::wayfinder_auth::CERT_FLAG_VIEWER).
    ///
    /// This is where an ordinary *device* certificate lands, which is the
    /// point: every node on the mesh holds one, so a tier granted by the
    /// absence of the admin bit would be a tier every node already had.
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
///   very next connection, not only after a restart.
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
    is_revoked: impl FnOnce(Mac) -> bool,
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
/// Both full grants may invoke everything, so this is really the definition of
/// the two confined tiers: what [`MgmtAccess::GrantedEnrollment`] means — the
/// two requests a node that wants to join has to make, and nothing else — and
/// what [`MgmtAccess::GrantedViewer`] means, below.
///
/// * `SubmitCsr` — ask the provider to certify this node's keys. Whether it is
///   granted, parked for approval or refused is the provider's enrollment
///   policy to decide, not this function's.
/// * `GetTrustAnchor` — read the mesh's public trust anchor. Public by
///   construction: every OGM on the mesh is verified against it, so it is not a
///   secret being handed out.
/// * `AuthenticateUser` — exchange a username, password and TOTP code for a
///   short-lived management certificate. On this tier for the same reason
///   `SubmitCsr` is: someone who has not logged in yet holds no credential, so
///   a tier that required one would close the door they need to knock on.
///   Admission control has not moved here either — it is the password, the
///   second factor, the per-account lockout, and the account having been
///   created by an admin in the first place.
///
/// Everything else — every read of routing state, every setting, every
/// provider action including approving a CSR — needs a full grant.
///
/// **What actually confines an enrollment connection is this *request set***
/// (exactly `SubmitCsr` and `GetTrustAnchor`) — not anything about a
/// `SubmitCsr`'s *contents*. `node_mac`, `ed_pubkey` and `x_pubkey` are
/// entirely client-supplied and bound to nothing about this connection: the
/// handshake key is never checked against them, so a client can submit a CSR
/// naming a MAC and keys it does not hold. That reach-past is deliberate, not
/// an oversight — it is what lets one node enroll another on its behalf,
/// which nothing else in this design offers a substitute for — but it is
/// real, and it is what lets an anonymous client park a CSR under a real
/// node's MAC and block that node's genuine enrollment (a scenario
/// `authority.rs`'s held-CSR docs describe, though not by this name). Two
/// things bound how much that reach can cost, without closing it:
/// `authority.rs`'s `MAX_HELD_CSRS` caps how large the held-CSR store may
/// grow no matter how many sources contribute to it, and
/// `PreAuthLimits` in `transport.rs` caps how fast any *one* source may
/// contribute. Neither stops a single submission from squatting a MAC; both
/// stop it from being repeated without bound. The certificate that comes
/// back is bound to the keys named in the CSR, so it is useless to anyone
/// but their holder — all a squatting client achieves is one entry in the
/// provider's pending queue, up to the cap, which the enrollment token and
/// operator approval are there to filter.
///
/// # The viewer tier
///
/// [`MgmtAccess::GrantedViewer`] is the queries and nothing else: every
/// `Get*`/`List*`/`ResolveRoute` request, and none of the mutations
/// (`SetAuth`, `SetConfig`, `SetLogLevel`, `RevokeNode`, `ApproveCsr`,
/// `DenyCsr`, `SubmitCsr`) or disclosures (`RevealEnrollmentToken`).
///
/// Two of those exclusions are worth stating rather than leaving to the reader.
/// `RevealEnrollmentToken` is a *read* by shape and a secret by content — the
/// credential that admits nodes to the mesh — and it is the one request whose
/// disclosure the design already treats as a discrete, logged, admin-gated act;
/// a read-only tier that could perform it would undo that. `SetLogLevel` reads
/// like a debugging convenience, but it changes what every sink on the node
/// emits, which is node-wide state and is exactly the sort of thing a viewer
/// exists not to touch. `Authenticate` is excluded because the connection has
/// already authenticated: a second one on the same connection has no defined
/// meaning and must not silently re-tier it.
///
/// SECURITY ALERT: this function holds security-critical access-control
/// logic. Changing it requires careful consideration.
#[cfg(feature = "std")]
pub fn permits(access: MgmtAccess, request: &ReqKind) -> bool {
    match access {
        MgmtAccess::GrantedAdmin | MgmtAccess::GrantedSelfKey => true,
        MgmtAccess::GrantedViewer => matches!(
            request,
            ReqKind::GetNodeInfo(_)
                | ReqKind::GetRoutingTable(_)
                | ReqKind::GetLinkQualityTable(_)
                | ReqKind::ResolveRoute(_)
                | ReqKind::GetOgmSchedule(_)
                | ReqKind::GetThroughput(_)
                | ReqKind::GetMetrics(_)
                | ReqKind::GetTrustAnchor(_)
                | ReqKind::GetSecurityStatus(_)
                | ReqKind::ListCerts(_)
                | ReqKind::ListPendingCsrs(_)
                | ReqKind::GetKeepaliveTable(_)
                | ReqKind::GetLinkFeaturesTable(_)
                | ReqKind::GetLogs(_)
        ),
        MgmtAccess::GrantedEnrollment => matches!(
            request,
            ReqKind::SubmitCsr(_) | ReqKind::GetTrustAnchor(_) | ReqKind::AuthenticateUser(_)
        ),
        MgmtAccess::Denied(_) => false,
    }
}

/// Which management tier an authenticated client bearing `cert` earns:
/// [`MgmtAccess::GrantedAdmin`], [`MgmtAccess::GrantedViewer`], or an
/// `Err(reason)` refusing it.
///
/// `cert` must already have been verified against the trust anchor (it is a
/// [`VerifiedCert`], produced only on the verification success path), so its
/// [`admin`](VerifiedCert::admin) and [`viewer`](VerifiedCert::viewer) bits are
/// trustworthy.  `is_revoked` reports whether a given node MAC has an active
/// revocation — supplied as a predicate so the policy stays decoupled from
/// where revocation state lives (the router's `OgmAuth`).
///
/// Revocation is checked first: it dominates every capability, so a revoked
/// admin is refused ([`MgmtDenied::Revoked`]) rather than allowed. The admin
/// bit then dominates the viewer bit — a cert carrying both is an admin, not a
/// viewer, so an admin need not also be flagged as a viewer in order to read.
///
/// SECURITY ALERT: this function holds security-critical access-control
/// logic. Changing it requires careful consideration.
pub fn authorize_capability(
    cert: &VerifiedCert,
    is_revoked: impl FnOnce(Mac) -> bool,
) -> Result<MgmtAccess, MgmtDenied> {
    if is_revoked(cert.mac) {
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
            not_after: 0,
            admin,
            viewer: false,
            user: false,
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
            authorize_capability(&verified(mac(1), true), |m| m == mac(1)),
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
            authorize_capability(&verified_viewer(mac(1)), |m| m == mac(1)),
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

        // A plain (non-admin) member cert, properly bound → refused as non-admin.
        let member_kp = Keypair::from_seed(&[3u8; 32]);
        let member_cert =
            authority.issue_cert(mac(6), member_kp.ed_pubkey(), member_kp.x_pubkey(), 0, 200);
        assert_eq!(
            decide_access(
                &member_kp.ed_pubkey(),
                Some(&member_cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::NoCapability)
        );

        // Admin cert, bound, but the node is revoked → refused.
        assert_eq!(
            decide_access(
                &admin_kp.ed_pubkey(),
                Some(&admin_cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
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

        // With a member cert: denied outright.
        assert_eq!(
            decide_access(
                &stranger.ed_pubkey(),
                Some(&member_cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::NoCapability)
        );
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

    /// Every management request kind this build knows, one value each, so a
    /// policy test can sweep the whole surface rather than the handful someone
    /// remembered.
    ///
    /// Deliberately hand-written rather than derived: prost generates no
    /// variant iterator, and the point of the list is that adding a proto
    /// request forces a decision *here* about what the enrollment tier may do
    /// with it. `permits` fails closed on its own (it is a positive
    /// allowlist), so the risk this guards is the opposite one — a privileged
    /// kind being quietly moved *into* the allowlist, which nothing else would
    /// make a reviewer look at.
    fn every_request_kind() -> Vec<ReqKind> {
        use wayfinder_protos::wayfinder::v1alpha::*;
        vec![
            ReqKind::GetNodeInfo(GetNodeInfoRequest {}),
            ReqKind::GetRoutingTable(GetRoutingTableRequest {}),
            ReqKind::GetLinkQualityTable(GetLinkQualityTableRequest {}),
            ReqKind::ResolveRoute(ResolveRouteRequest::default()),
            ReqKind::GetOgmSchedule(GetOgmScheduleRequest {}),
            ReqKind::GetThroughput(GetThroughputRequest {}),
            ReqKind::GetMetrics(GetMetricsRequest {}),
            ReqKind::SetAuth(SetAuthRequest::default()),
            ReqKind::GetTrustAnchor(GetTrustAnchorRequest {}),
            ReqKind::SubmitCsr(SubmitCsrRequest::default()),
            ReqKind::RevokeNode(RevokeNodeRequest::default()),
            ReqKind::GetSecurityStatus(GetSecurityStatusRequest {}),
            ReqKind::ListCerts(ListCertsRequest {}),
            ReqKind::ListPendingCsrs(ListPendingCsrsRequest {}),
            ReqKind::ApproveCsr(ApproveCsrRequest::default()),
            ReqKind::DenyCsr(DenyCsrRequest::default()),
            ReqKind::SetConfig(SetConfigRequest::default()),
            ReqKind::GetKeepaliveTable(GetKeepAliveTableRequest {}),
            ReqKind::Authenticate(AuthenticateRequest::default()),
            ReqKind::GetLinkFeaturesTable(GetLinkFeaturesTableRequest {}),
            ReqKind::GetLogs(GetLogsRequest::default()),
            ReqKind::SetLogLevel(SetLogLevelRequest::default()),
            ReqKind::RevealEnrollmentToken(RevealEnrollmentTokenRequest {}),
            ReqKind::AuthenticateUser(AuthenticateUserRequest::default()),
            ReqKind::ListUsers(ListUsersRequest {}),
            ReqKind::CreateUser(CreateUserRequest::default()),
            ReqKind::RemoveUser(RemoveUserRequest::default()),
        ]
    }

    /// The enrollment tier is a *closed* allowlist over the whole request
    /// surface: exactly `SubmitCsr`, `GetTrustAnchor` and `AuthenticateUser`,
    /// and every one of the other twenty-four kinds refused — including the ones that would otherwise be
    /// the prize (`ApproveCsr` on its own request, `SetAuth`, `SetConfig`,
    /// `GetLogs`).
    ///
    /// The count assertion is the load-bearing half. Without it a request kind
    /// added to the proto and forgotten here would pass by omission, and the
    /// sweep would silently stop covering the surface it claims to.
    #[test]
    fn permits_confines_the_enrollment_tier_to_a_closed_allowlist() {
        let all = every_request_kind();
        assert_eq!(
            all.len(),
            27,
            "every_request_kind must list every variant of the request oneof; \
             add the new one (and decide what the enrollment tier may do with it)"
        );

        for request in &all {
            // Notably not on the list: `RevealEnrollmentToken`. A node asking
            // to join has to be *given* the token; a node that could ask the
            // provider for it would make the token no barrier at all.
            let expected = matches!(
                request,
                ReqKind::SubmitCsr(_) | ReqKind::GetTrustAnchor(_) | ReqKind::AuthenticateUser(_)
            );
            assert_eq!(
                permits(MgmtAccess::GrantedEnrollment, request),
                expected,
                "enrollment tier verdict for {request:?}"
            );
            // Both full grants may invoke anything, and every denial nothing —
            // asserted over the same closed set so neither can drift.
            for full in [MgmtAccess::GrantedAdmin, MgmtAccess::GrantedSelfKey] {
                assert!(permits(full, request), "full grant refused {request:?}");
            }
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
        assert_eq!(
            all.len(),
            27,
            "every_request_kind must list every variant of the request oneof; \
             add the new one (and decide what the viewer tier may do with it)"
        );

        for request in &all {
            let refused = matches!(
                request,
                ReqKind::SetAuth(_)
                    | ReqKind::SetConfig(_)
                    | ReqKind::SetLogLevel(_)
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
        // earns nothing. This is the property that makes the tier safe to add:
        // it is granted by a bit, never by the absence of one.
        let device_cert =
            authority.issue_cert(mac(6), operator.ed_pubkey(), operator.x_pubkey(), 0, 200);
        assert_eq!(
            decide_access(
                &operator.ed_pubkey(),
                Some(&device_cert),
                Some(&anchor),
                Some(&own.ed_pubkey()),
                100,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::NoCapability)
        );
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
}
