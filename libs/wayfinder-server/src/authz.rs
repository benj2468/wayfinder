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
    /// Granted to an enrolled device: a verified, non-revoked certificate
    /// carrying
    /// [`CERT_FLAG_MEMBER`](wayfinder::wayfinder_auth::CERT_FLAG_MEMBER) and
    /// bound to the handshake key, but no management capability.
    ///
    /// Every node on the mesh holds such a certificate, so this tier is
    /// deliberately the narrowest in the enum: [`permits`] confines it to
    /// `GetVpnEnrollment` and nothing else. Anything admitted here is admitted
    /// to the whole mesh at once. (It is not the *only* tier admitted to that
    /// request — [`MgmtAccess::GrantedSelfKey`] is too — but it is the only
    /// one for which the request is the whole of what the tier can do.)
    ///
    /// It is earned by a *signed bit*, never by the absence of the others — see
    /// [`CERT_FLAG_MEMBER`](wayfinder::wayfinder_auth::CERT_FLAG_MEMBER). A
    /// certificate carrying no capability at all remains
    /// [`MgmtDenied::NoCapability`], which is also where every certificate
    /// issued before that bit existed still lands.
    GrantedMember,
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
    /// Enrolled path: the verified cert carries no capability bit at all —
    /// none of
    /// [`CERT_FLAG_ADMIN`](wayfinder::wayfinder_auth::CERT_FLAG_ADMIN),
    /// [`CERT_FLAG_VIEWER`](wayfinder::wayfinder_auth::CERT_FLAG_VIEWER) or
    /// [`CERT_FLAG_MEMBER`](wayfinder::wayfinder_auth::CERT_FLAG_MEMBER).
    ///
    /// Two things land here. A certificate issued before `CERT_FLAG_MEMBER`
    /// existed, which is why adding that bit was not a flag day: such a
    /// certificate keeps the access it always had (none) until it is reissued.
    /// And a certificate whose bits this build does not recognise, since
    /// unknown flags are masked off rather than guessed at.
    ///
    /// What no longer lands here is an ordinary *device* certificate: it
    /// carries `CERT_FLAG_MEMBER` and earns [`MgmtAccess::GrantedMember`],
    /// which is one request wide. That tier is granted by the bit being
    /// present, never by the management bits being absent — a tier granted by
    /// absence would be a tier every node on the mesh already had, and would
    /// silently widen every time a capability was added.
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
/// * **Member** ([`MgmtAccess::GrantedMember`]): as the admin tier, but the
///   verified cert carries
///   [`CERT_FLAG_MEMBER`](wayfinder::wayfinder_auth::CERT_FLAG_MEMBER) and no
///   management capability — an enrolled device proving possession of the key
///   this mesh's CA certified. One request wide; see [`permits`].
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
/// [`MgmtAccess::GrantedSelfKey`] may invoke everything and
/// [`MgmtAccess::GrantedAdmin`] everything but one request, so this is really
/// the definition of the three confined tiers: what
/// [`MgmtAccess::GrantedEnrollment`] means — the requests a caller holding
/// nothing this mesh has signed has to make, whether it is a node joining or a
/// person redeeming an invitation, and nothing else — what [`MgmtAccess::GrantedViewer`]
/// means, below, and what [`MgmtAccess::GrantedMember`] means, which is the one
/// request the admin tier is excluded from.
///
/// # The one request the admin tier may not invoke
///
/// `GetVpnEnrollment` is gated on the request, ahead of the tier match. It is
/// not a management capability being exercised — it mints a tunnel credential
/// bound to *the calling device's own identity*. An operator's session
/// certificate is fully privileged and is not a device identity, so for it the
/// request has no meaning rather than being a privilege it lacks.
///
/// The node's own seed *is* a device identity — the node's — which is why
/// [`MgmtAccess::GrantedSelfKey`] is admitted here and the certificate
/// authority can join the tunnel it coordinates through the same RPC every
/// other node uses. What makes that safe is where the MAC comes from: the
/// router, not the connection. See the comment at the top of the function
/// body.
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
/// * `BeginUserRegistration` / `CompleteUserRegistration` — redeem a one-time
///   invitation into the account it was minted for. On this tier for the
///   sharpest version of the same reason: somebody who does not have an account
///   *yet* holds no credential of any kind, and this is the request that gives
///   them one. Admission control is the token — 256 bits, single-use, expiring,
///   and minted by an admin who chose both the name and the role it will
///   create. Note what is deliberately *not* admitted beside them: an
///   enrollment connection can redeem an invitation it already holds and can do
///   nothing else to the account store — it cannot mint one, list one, or
///   revoke one.
///
/// Everything else — every read of routing state, every setting, every
/// provider action including approving a CSR — needs a full grant.
///
/// **What actually confines an enrollment connection is this *request set***
/// (the five above) — not anything about a
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
/// `Get*`/`List*`/`ResolveRoute` request except `ListUsers`, and none of the
/// mutations
/// (`SetAuth`, `SetConfig`, `SetLogLevel`, `RevokeNode`, `ApproveCsr`,
/// `DenyCsr`, `SubmitCsr`, `RevokeVpnPeer`) or disclosures
/// (`RevealEnrollmentToken`, `GetVpnEnrollment`).
///
/// `ListVpnPeers` is a query and is *not* on the viewer's list, unlike the
/// `List*` requests beside it. It is answered by calling out to the
/// coordination server, so admitting it on a read-only tier would let a viewer
/// drive outbound requests from the CA at whatever rate it polls.
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
    // Decided by the request before the tier, and the only request that is.
    // `GetVpnEnrollment` does not grant its caller a capability — it mints a
    // credential *for the caller's device identity*. So the question here is
    // not how privileged a tier is but whether it names a node the
    // coordination server can register.
    //
    // Two tiers do. The member tier is an enrolled device presenting the
    // certificate this mesh's CA issued it, and the transport takes the MAC
    // from that verified certificate. The self-key tier is the node itself —
    // whoever holds its seed signs its OGMs and terminates its TLS — and the
    // transport takes the MAC from the router (`AuthSnapshot::own_mac`),
    // never from the connection, because a certificate presented on a
    // self-key connection is never verified.
    //
    // The admin tier does not: an operator's session certificate is a person,
    // not a device, so for it the request has no meaning rather than being a
    // privilege it lacks.
    //
    // This is also what makes the design's two gates genuinely independent: a
    // party holding the shared enrollment token can have *a* certificate issued
    // for keys it names, but reaching this request additionally requires
    // proving possession of a key that names a node — the certified one, or
    // the node's own seed.
    if matches!(request, ReqKind::GetVpnEnrollment(_)) {
        return matches!(
            access,
            MgmtAccess::GrantedMember | MgmtAccess::GrantedSelfKey
        );
    }
    match access {
        MgmtAccess::GrantedAdmin | MgmtAccess::GrantedSelfKey => true,
        // Exactly the request handled above, and nothing else. Every node on
        // the mesh holds a member certificate, so a request added to this arm
        // is a request granted to the entire mesh.
        MgmtAccess::GrantedMember => false,
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
                // What the node believes is wrong with itself. A read, and one
                // a viewer is exactly the audience for: the tier exists so
                // somebody can be shown the state of the network without being
                // handed the ability to change it, and "is this node healthy"
                // is the first question they will have. It discloses no more
                // than `GetSecurityStatus` beside it already does — peer
                // identifiers, and the fact that something was refused.
                | ReqKind::GetAlarms(_)
        ),
        MgmtAccess::GrantedEnrollment => matches!(
            request,
            ReqKind::SubmitCsr(_)
                | ReqKind::GetTrustAnchor(_)
                | ReqKind::AuthenticateUser(_)
                | ReqKind::BeginUserRegistration(_)
                | ReqKind::CompleteUserRegistration(_)
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
    is_revoked: impl FnOnce(Mac) -> bool,
) -> Result<MgmtAccess, MgmtDenied> {
    if is_revoked(cert.mac) {
        Err(MgmtDenied::Revoked)
    } else if cert.admin {
        Ok(MgmtAccess::GrantedAdmin)
    } else if cert.viewer {
        Ok(MgmtAccess::GrantedViewer)
    } else if cert.member && !cert.user {
        // `member` and `user` are documented as mutually exclusive in
        // everything the CA issues (`VerifiedCert::member`), but that
        // exclusivity is an issuer convention, not a wire invariant — nothing
        // stops a future same-crate caller of `issue_with_flags` (widened to
        // `pub(crate)` for tests) from setting both. The member tier mints a
        // device-scoped VPN credential, so a person's session certificate
        // must never earn it regardless of which other bits it carries.
        Ok(MgmtAccess::GrantedMember)
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
            member: false,
        }
    }

    /// A verified certificate for an enrolled device: the member bit and
    /// nothing else, which is what `issue_cert` produces.
    fn verified_member(m: Mac) -> VerifiedCert {
        VerifiedCert {
            member: true,
            ..verified(m, false)
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
        assert_eq!(decision, MgmtAccess::GrantedMember);
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

    /// Declares this build's entire request-oneof surface exactly once, and
    /// expands it into two things: `every_request_kind()`, one value per
    /// variant for the sweep tests below to iterate; and
    /// `all_kinds_exhaustive`, an exhaustive `match &ReqKind` whose only job is
    /// to fail to *compile* when this list falls behind the proto.
    ///
    /// That second function is the actual guarantee, and it replaced an
    /// `assert_eq!(all.len(), N, ..)` that could not be one. The list and the
    /// count were edited by the same human action — adding a proto variant and
    /// remembering to come here — so a variant added to the proto and never
    /// added to this list left the list and the count agreeing with each other
    /// at the old, wrong size. Not hypothetical: `SetUserRole`,
    /// `SetUserEnabled` and `SetUserPassword` were added to the proto and both
    /// sweeps below kept passing until a human updated this file by hand.
    ///
    /// The exhaustive matches in `wayfinder-protos`'s `service.rs`
    /// (`request_kind_name`, `audited`, `request_facet`) do force a decision on
    /// a new variant, and they caught those three. What none of them forces is
    /// an *authorization* decision: `permits` matches on the access tier, and
    /// the request appears only inside `matches!`, which has an implicit
    /// catch-all — so a new kind silently becomes permitted for admin and
    /// self-key and refused for viewer and enrollment. This is the check that
    /// makes somebody choose. A wildcard arm on `all_kinds_exhaustive` would
    /// restore the hole; do not add one.
    macro_rules! every_request_kind_variants {
        ($($variant:ident($ty:ty)),+ $(,)?) => {
            fn every_request_kind() -> Vec<ReqKind> {
                use wayfinder_protos::wayfinder::v1alpha::*;
                // `Default` uniformly, which every prost message implements,
                // rather than the mix of `Foo {}` and `Foo::default()` the
                // hand-written list had.
                vec![$(ReqKind::$variant(<$ty>::default())),+]
            }

            // Never called: the only property that matters is that it
            // compiles. See the comment above — a oneof variant this arm list
            // omits makes this match, and so this whole test module, fail to
            // build.
            #[allow(dead_code)]
            fn all_kinds_exhaustive(kind: &ReqKind) {
                match kind {
                    $(ReqKind::$variant(_) => (),)+
                }
            }
        };
    }

    every_request_kind_variants! {
        GetNodeInfo(GetNodeInfoRequest),
        GetRoutingTable(GetRoutingTableRequest),
        GetLinkQualityTable(GetLinkQualityTableRequest),
        ResolveRoute(ResolveRouteRequest),
        GetOgmSchedule(GetOgmScheduleRequest),
        GetThroughput(GetThroughputRequest),
        GetMetrics(GetMetricsRequest),
        SetAuth(SetAuthRequest),
        GetTrustAnchor(GetTrustAnchorRequest),
        SubmitCsr(SubmitCsrRequest),
        RevokeNode(RevokeNodeRequest),
        GetSecurityStatus(GetSecurityStatusRequest),
        ListCerts(ListCertsRequest),
        ListPendingCsrs(ListPendingCsrsRequest),
        ApproveCsr(ApproveCsrRequest),
        DenyCsr(DenyCsrRequest),
        SetConfig(SetConfigRequest),
        GetKeepaliveTable(GetKeepAliveTableRequest),
        Authenticate(AuthenticateRequest),
        GetLinkFeaturesTable(GetLinkFeaturesTableRequest),
        GetLogs(GetLogsRequest),
        SetLogLevel(SetLogLevelRequest),
        RevealEnrollmentToken(RevealEnrollmentTokenRequest),
        AuthenticateUser(AuthenticateUserRequest),
        ListUsers(ListUsersRequest),
        CreateUser(CreateUserRequest),
        RemoveUser(RemoveUserRequest),
        GetAlarms(GetAlarmsRequest),
        GetOwnCert(GetOwnCertRequest),
        GetVpnEnrollment(GetVpnEnrollmentRequest),
        ListVpnPeers(ListVpnPeersRequest),
        RevokeVpnPeer(RevokeVpnPeerRequest),
        CreateUserInvite(CreateUserInviteRequest),
        ListUserInvites(ListUserInvitesRequest),
        RevokeUserInvite(RevokeUserInviteRequest),
        BeginUserRegistration(BeginUserRegistrationRequest),
        CompleteUserRegistration(CompleteUserRegistrationRequest),
        RevokeUserSessions(RevokeUserSessionsRequest),
        SetUserRole(SetUserRoleRequest),
        SetUserEnabled(SetUserEnabledRequest),
        SetUserPassword(SetUserPasswordRequest),
    }

    /// The enrollment tier is a *closed* allowlist over the whole request
    /// surface: exactly `SubmitCsr`, `GetTrustAnchor`, `AuthenticateUser`,
    /// `BeginUserRegistration` and `CompleteUserRegistration`, and every other
    /// kind refused — including the ones that would otherwise be the prize
    /// (`ApproveCsr` on its own request, `SetAuth`, `SetConfig`, `GetLogs`).
    ///
    /// What makes this a sweep of the *whole* surface rather than a hand-picked
    /// sample is `every_request_kind_variants!`: its exhaustive match fails to
    /// compile when a proto variant is missing from the list, so
    /// `every_request_kind()` is guaranteed complete rather than asserted to be.
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
            assert_eq!(
                permits(MgmtAccess::GrantedAdmin, request),
                !matches!(request, ReqKind::GetVpnEnrollment(_)),
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
                    // Mints a credential scoped to a *device* identity a viewer
                    // does not hold — see the `GetVpnEnrollment` gate in
                    // `permits` itself.
                    | ReqKind::GetVpnEnrollment(_)
                    // Managing peers is ordinary administration: it drives
                    // outbound requests to the coordination server and must
                    // not be reachable from a read-only grant.
                    | ReqKind::ListVpnPeers(_)
                    | ReqKind::RevokeVpnPeer(_)
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
        assert_eq!(decision, MgmtAccess::GrantedMember);
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

    /// The member capability is its own signed bit, dominated by revocation
    /// like every other capability. A device's certificate earns it; a
    /// certificate carrying no bits at all still earns nothing, which is what
    /// keeps "device" from being inferable from absence.
    #[test]
    fn the_member_capability_is_its_own_bit() {
        assert_eq!(
            authorize_capability(&verified_member(mac(1)), |_| false),
            Ok(MgmtAccess::GrantedMember)
        );
        assert_eq!(
            authorize_capability(&verified_member(mac(1)), |m| m == mac(1)),
            Err(MgmtDenied::Revoked),
            "revocation dominates the member capability too"
        );
        assert_eq!(
            authorize_capability(&verified(mac(1), false), |_| false),
            Err(MgmtDenied::NoCapability),
            "a certificate with no capability bit at all earns no tier"
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

    /// The member tier is exactly one request wide: an enrolled device may ask
    /// for its own VPN credential and nothing else. Not the queries a viewer
    /// gets, not the trust anchor, and above all none of the provider actions —
    /// every node on the mesh holds a member certificate, so anything this tier
    /// admits is admitted to the entire mesh.
    ///
    /// Swept over `every_request_kind()`, not a hand-picked sample: the same
    /// forgotten-variant risk `permits_confines_the_enrollment_tier_to_a_closed_allowlist`
    /// guards against applies here too, and "one request wide" is only true if
    /// nothing outside that sample was missed.
    #[test]
    fn a_member_connection_may_only_fetch_its_vpn_credential() {
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let vpn_enrollment = ReqKind::GetVpnEnrollment(GetVpnEnrollmentRequest {});
        let member = MgmtAccess::GrantedMember;

        assert!(permits(member, &vpn_enrollment));

        for request in &every_request_kind() {
            let expected = matches!(request, ReqKind::GetVpnEnrollment(_));
            assert_eq!(
                permits(member, request),
                expected,
                "member tier verdict for {request:?}"
            );
        }
    }

    /// The VPN credential is minted for a *device*, so a tier that holds no
    /// device identity may not ask for one however privileged it is. An
    /// operator's session certificate is a person and a stranger holds nothing
    /// at all — for both the request has no meaning rather than being a
    /// privilege they lack. Refusing it here is what makes the design's "two
    /// gates in series" literal: the credential is reachable only by proving
    /// possession of a key that names a node.
    #[test]
    fn a_tier_holding_no_device_identity_cannot_mint_a_credential() {
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let vpn_enrollment = ReqKind::GetVpnEnrollment(GetVpnEnrollmentRequest {});

        for tier in [
            MgmtAccess::GrantedAdmin,
            MgmtAccess::GrantedViewer,
            MgmtAccess::GrantedEnrollment,
            MgmtAccess::Denied(MgmtDenied::NoCapability),
        ] {
            assert!(
                !permits(tier, &vpn_enrollment),
                "{tier:?} must not mint a device's VPN credential"
            );
        }
    }

    /// The self-key tier *is* a device identity — the node itself — so it may
    /// mint its own credential.
    ///
    /// This is the certificate authority's own case. It coordinates the tunnel
    /// and is also a node on it, and the only credential it can present to
    /// itself is its own seed. The tier was refused here for as long as the
    /// MAC came off the presented certificate, which the self-key path never
    /// verifies; the transport now takes it from the router instead
    /// (`AuthSnapshot::own_mac`), so there is a device identity to mint for
    /// and no client-supplied value anywhere in it.
    ///
    /// It gives its holder nothing new. Whoever holds the node's seed already
    /// signs that node's OGMs and terminates its TLS, and on a provider can
    /// reveal the enrollment token and approve its own CSR — so the long way
    /// round to the same credential was always open.
    #[test]
    fn the_self_key_tier_may_mint_its_own_nodes_credential() {
        use wayfinder_protos::wayfinder::v1alpha::GetVpnEnrollmentRequest;

        let vpn_enrollment = ReqKind::GetVpnEnrollment(GetVpnEnrollmentRequest {});

        assert!(permits(MgmtAccess::GrantedSelfKey, &vpn_enrollment));
    }

    /// Managing *other* peers' VPN registrations is ordinary administration, so
    /// it sits where every other provider action does: the full grants, and
    /// nothing less. In particular a member may not revoke a peer — that would
    /// let any node on the mesh cut any other node's tunnel.
    #[test]
    fn managing_vpn_peers_needs_a_full_grant() {
        use wayfinder_protos::wayfinder::v1alpha::ListVpnPeersRequest;
        use wayfinder_protos::wayfinder::v1alpha::RevokeVpnPeerRequest;

        let list = ReqKind::ListVpnPeers(ListVpnPeersRequest {});
        let revoke = ReqKind::RevokeVpnPeer(RevokeVpnPeerRequest::default());

        for full in [MgmtAccess::GrantedAdmin, MgmtAccess::GrantedSelfKey] {
            assert!(permits(full, &list));
            assert!(permits(full, &revoke));
        }
        for lesser in [
            MgmtAccess::GrantedViewer,
            MgmtAccess::GrantedMember,
            MgmtAccess::GrantedEnrollment,
        ] {
            assert!(!permits(lesser, &list));
            assert!(!permits(lesser, &revoke));
        }
    }

    /// An enrolled device reaching the CA with its own certificate lands on the
    /// member tier — the end-to-end path the VPN enrollment step depends on.
    /// Before the member bit existed this was `Denied(NoCapability)` and the
    /// connection was closed before a request could be sent at all.
    #[test]
    fn an_enrolled_device_presenting_its_own_cert_is_a_member() {
        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let anchor = authority.trust_anchor();
        let node = Keypair::from_seed(&[2u8; 32]);
        let ca_own = Keypair::from_seed(&[7u8; 32]);
        let cert = authority.issue_cert(mac(3), node.ed_pubkey(), node.x_pubkey(), 100, 200);

        assert_eq!(
            decide_access(
                &node.ed_pubkey(),
                Some(&cert),
                Some(&anchor),
                Some(&ca_own.ed_pubkey()),
                150,
                |_| false
            ),
            MgmtAccess::GrantedMember
        );

        // Revoked: the tier goes away, so a revoked node cannot renew a tunnel
        // credential even though its certificate has not yet expired.
        assert_eq!(
            decide_access(
                &node.ed_pubkey(),
                Some(&cert),
                Some(&anchor),
                Some(&ca_own.ed_pubkey()),
                150,
                |m| m == mac(3)
            ),
            MgmtAccess::Denied(MgmtDenied::Revoked)
        );

        // A cert replayed by a party that does not hold its key stays bound to
        // the handshake, member bit or not.
        assert_eq!(
            decide_access(
                &Keypair::from_seed(&[9u8; 32]).ed_pubkey(),
                Some(&cert),
                Some(&anchor),
                Some(&ca_own.ed_pubkey()),
                150,
                |_| false
            ),
            MgmtAccess::Denied(MgmtDenied::KeyMismatch)
        );
    }
}
