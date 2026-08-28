//! The RPC declaration table: every management request kind, declared once,
//! with everything the server needs to decide about it.
//!
//! # Why this exists
//!
//! Serving one management request means answering five questions about its
//! kind — what to call it in a log, whether it deserves an audit record, which
//! owner can answer it, which access tiers may invoke it, and which anonymous
//! rate-limit bucket it spends. Each of those used to be its own hand-written
//! `match` over `RequestKind`, scattered across two crates, and a new proto
//! variant had to be added to all five by hand.
//!
//! Four of the five were exhaustive matches, so a missing variant at least
//! failed to compile. The fifth — the access-tier lists in
//! `wayfinder-server`'s `authz::permits` — was a `matches!` with an implicit
//! catch-all, so a new kind silently became *permitted for admin and self-key
//! and refused for viewer and enrollment*. That is not hypothetical:
//! `SetUserRole`, `SetUserEnabled` and `SetUserPassword` reached the proto and
//! were authorized by default until a human noticed. `wayfinder-server` grew a
//! test-only macro whose whole job was to fail to compile in their place.
//!
//! `rpc_table!` closes that by making every one of the five answers a
//! **required field of the declaration**. A variant added to the proto and not
//! to this table fails to compile here; a variant added to this table without
//! an `access` list fails to parse the macro. There is no arm to forget and no
//! default to fall through to.
//!
//! # Adding a request kind
//!
//! Add the field to `wayfinder.proto`, then add one entry here. The five
//! classifiers, and the exhaustive sweep the authorization tests run, all come
//! from that entry. What is *not* generated is the handler itself — see
//! `service::handle_router` / `service::handle_authority`, which marshal each
//! request against the provider traits.

use crate::wayfinder::v1alpha::wayfinder_request::Request as RequestKind;

/// Which owner answers a given request.
///
/// The management API is served from three different places, and a caller that
/// knows which one *before* it sends anything can route a request to the right
/// owner rather than discovering the answer from an error. That is what lets
/// the certificate authority live off the router's event loop — see
/// `docs/design/implemented/13-certificate-authority-off-the-router-loop.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFacet {
    /// Answered from router state alone and *without mutating it*, by
    /// `service::handle_router_read`.
    ///
    /// Split from [`RequestFacet::RouterWrite`] because the two are served
    /// through different borrows on a host: a read runs on the connection's own
    /// task under a shared read lock, while a write is forwarded to the single
    /// task that holds `&mut CentralRouter`. A transport has to know which it
    /// is holding *before* it sends anything, which is what this distinction
    /// is for.
    RouterRead,
    /// Answered by changing router state, by `service::handle_router_write` on
    /// whichever task owns the router mutably.
    RouterWrite,
    /// Answered from certificate-authority state alone, by
    /// `service::handle_authority`.
    Authority,
    /// Answered by the transport itself rather than by either dispatcher: the
    /// VPN requests are served in the connection task (they are scoped to the
    /// caller's own identity, which no provider holds), and `Authenticate` is
    /// the transport's own first frame.
    ///
    /// A fork on this enum must still handle one arriving anyway — an
    /// `Authenticate` repeated mid-connection reaches the router half, which
    /// declines it. Answer that with `service::handle_unowned`, which names the
    /// protocol error, not with the not-a-provider message.
    Transport,
}

/// What kind of record a request deserves in the node's log.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Audited {
    /// Changes node or provider state: new auth material, a config change, a
    /// CSR issued/approved/denied, a node revoked.
    Mutation,
    /// Changes nothing but hands out a secret. Worth the same record as a
    /// mutation and for the same reason — an operator asking "who learned the
    /// enrollment token, and when?" has nowhere else to look — but it is not a
    /// mutation, and a log line calling it one would be a lie about what
    /// happened.
    Disclosure,
    /// Reads public state. Frequent (a dashboard polls several per second), so
    /// not recorded at all.
    Query,
}

/// One management access tier, as a value the declaration table can name.
///
/// Deliberately *not* `wayfinder-server`'s `MgmtAccess`: that type carries a
/// denial reason and is the outcome of authenticating a connection, while this
/// is the vocabulary a request is declared in. `authz::permits` maps one to the
/// other, which is the only place the two meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessTier {
    /// A verified, non-revoked admin certificate bound to the handshake key.
    Admin,
    /// The client proved possession of the node's *own* identity key.
    SelfKey,
    /// A verified, non-revoked certificate carrying the viewer capability:
    /// read-only.
    Viewer,
    /// A verified, non-revoked certificate carrying the member capability — an
    /// enrolled *device*, which is what every node on the mesh holds.
    ///
    /// Anything granted to this tier is granted to the entire mesh at once,
    /// which is why exactly one request names it.
    Member,
    /// The client presented no certificate at all. Admitted so that enrollment
    /// and first login are possible, and confined to the requests that hand
    /// out a credential to somebody who holds none.
    Enrollment,
}

/// The closed set of [`AccessTier`]s one request admits.
///
/// A plain slice, deliberately. This was a hand-rolled `u8` bitset, which
/// needed a test proving no two tiers shared a bit — because a collision
/// silently *widens* a grant, which is the worst direction for this type to
/// fail in. A slice cannot collide at all, so the guarantee comes from the
/// representation rather than from a test remembering to check it, and the five
/// tiers are consulted once per management request rather than in a hot loop,
/// so the bitset bought no speed worth that risk.
pub type AccessTiers = &'static [AccessTier];

/// Which per-source rate-limit bucket a request spends when it arrives on an
/// enrollment-tier (anonymous) connection.
///
/// A rate limit, not an admission decision: a fully-granted connection already
/// required a real credential, which is not the resource an anonymous flood is
/// spending. The buckets are separate because the cadences behind them are
/// unrelated — a node polling for CSR approval every five seconds, a person
/// retyping a password — so a shared budget would let either starve the other
/// from behind one address, which a dashboard fronting both flows makes the
/// ordinary case rather than a NAT coincidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimit {
    /// Costs an anonymous caller nothing beyond the connection itself.
    Unmetered,
    /// Spends the enrollment bucket, sized for a node's approval poll.
    SubmitCsr,
    /// Spends the login bucket, sized for a dashboard's sign-in wave against
    /// what one Argon2id at a time can actually serve.
    Login,
    /// Spends the invite-redemption bucket. Both halves of a redemption share
    /// it: they are two steps of one flow driven by one person, and bounding
    /// either alone bounds nothing.
    Registration,
}

/// Declare the management API's entire request surface, once.
///
/// Each entry names a [`RequestKind`] variant, its prost request type, and the
/// five answers the server needs about it. Every field is required — see this
/// module's header for why none of them may have a default.
///
/// Expands to the five classifiers ([`request_kind_name`], [`audited`],
/// [`request_facet`], [`access_tiers`], [`rate_limit`]) as exhaustive matches,
/// so a proto variant missing from the table fails to compile, plus
/// `every_request_kind` under the `test-support` feature.
macro_rules! rpc_table {
    ($(
        $(#[$meta:meta])*
        $variant:ident($request:ident) {
            owner: $owner:ident,
            audit: $audit:ident,
            access: [$($tier:ident),* $(,)?],
            limit: $limit:ident,
        }
    )+) => {
        /// A short, stable, non-secret name for a request variant, for logging.
        ///
        /// Never derived from `Debug` on the whole variant: some request
        /// payloads (`SetAuthRequest`'s identity seed, CSR key material) are
        /// secret, so only the kind — never the fields — may be logged.
        pub fn request_kind_name(kind: &RequestKind) -> &'static str {
            match kind {
                $(RequestKind::$variant(_) => stringify!($variant),)+
            }
        }

        /// Classify `kind` for the audit record `service::audit_request` emits.
        pub fn audited(kind: &RequestKind) -> Audited {
            match kind {
                $(RequestKind::$variant(_) => Audited::$audit,)+
            }
        }

        /// Classify `kind` by the owner that answers it.
        ///
        /// This is the fork a connection task takes *before* sending anything:
        /// a caller that discovers the owner from an error has already spent
        /// the wrong queue's time, and on a node whose authority is
        /// mid-Argon2id that queue is the one that stalls the mesh.
        pub fn request_facet(kind: &RequestKind) -> RequestFacet {
            match kind {
                $(RequestKind::$variant(_) => RequestFacet::$owner,)+
            }
        }

        /// The closed set of access tiers that may invoke `kind`.
        ///
        /// SECURITY ALERT: this projects security-critical access-control
        /// policy out of the declaration table. Changing an `access` list
        /// there changes who may invoke that request; consider it carefully.
        pub fn access_tiers(kind: &RequestKind) -> AccessTiers {
            match kind {
                $(RequestKind::$variant(_) => &[$(AccessTier::$tier),*],)+
            }
        }

        /// Which per-source bucket `kind` spends on an anonymous connection.
        pub fn rate_limit(kind: &RequestKind) -> RateLimit {
            match kind {
                $(RequestKind::$variant(_) => RateLimit::$limit,)+
            }
        }

        /// One value per request variant, for a test that must sweep the whole
        /// request surface rather than a hand-picked sample of it.
        ///
        /// Behind a feature because it is the one item here that costs
        /// something on a target that will never run it: constructing 41
        /// default messages is code an embedded node has no use for.
        /// `wayfinder-server` enables it as a dev-dependency, which keeps it
        /// out of every firmware build.
        #[cfg(feature = "test-support")]
        pub fn every_request_kind() -> alloc::vec::Vec<RequestKind> {
            use crate::wayfinder::v1alpha::*;
            alloc::vec![$(RequestKind::$variant(<$request>::default())),+]
        }
    };
}

rpc_table! {
    // ---- Router facet: answered from live router state -------------------

    GetNodeInfo(GetNodeInfoRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetRoutingTable(GetRoutingTableRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetLinkQualityTable(GetLinkQualityTableRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetLinkFeaturesTable(GetLinkFeaturesTableRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetKeepaliveTable(GetKeepAliveTableRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetOgmSchedule(GetOgmScheduleRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetThroughput(GetThroughputRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetMetrics(GetMetricsRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    ResolveRoute(ResolveRouteRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetLogs(GetLogsRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    /// What the node believes is wrong with itself. A read, and one a viewer is
    /// exactly the audience for: the tier exists so somebody can be shown the
    /// state of the network without being handed the ability to change it, and
    /// "is this node healthy" is the first question they will have. It
    /// discloses no more than `GetSecurityStatus` beside it already does.
    GetAlarms(GetAlarmsRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    GetSecurityStatus(GetSecurityStatusRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    /// Answered from the router's live auth state, like the security status
    /// beside it — never from wherever the certificate was loaded, which is the
    /// authority's business and not every node has one.
    ///
    /// Not a viewer read, unlike the queries around it: it returns this node's
    /// own certificate and the anchor it chains to.
    GetOwnCert(GetOwnCertRequest) {
        owner: RouterRead, audit: Query,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    SetAuth(SetAuthRequest) {
        owner: RouterWrite, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    SetConfig(SetConfigRequest) {
        owner: RouterWrite, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    /// Reads like a debugging convenience, but it changes what every sink on
    /// the node emits — node-wide state, and exactly the sort of thing a viewer
    /// exists not to touch.
    SetLogLevel(SetLogLevelRequest) {
        owner: RouterWrite, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }

    // ---- Authority facet: answered from certificate-authority state ------

    /// On the enrollment tier's allowlist: a node that has not enrolled needs
    /// the anchor before it can verify anything it is later handed.
    GetTrustAnchor(GetTrustAnchorRequest) {
        owner: Authority, audit: Query,
        access: [Admin, SelfKey, Viewer, Enrollment],
        limit: Unmetered,
    }
    SubmitCsr(SubmitCsrRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey, Enrollment],
        limit: SubmitCsr,
    }
    RevokeNode(RevokeNodeRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    ListCerts(ListCertsRequest) {
        owner: Authority, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    ListPendingCsrs(ListPendingCsrsRequest) {
        owner: Authority, audit: Query,
        access: [Admin, SelfKey, Viewer],
        limit: Unmetered,
    }
    ApproveCsr(ApproveCsrRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    DenyCsr(DenyCsrRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    /// A *read* by shape and the mesh's admission credential by content, so it
    /// is the one request classified as a disclosure — and the one `Get*` a
    /// viewer may not invoke. A read-only tier that could perform it would undo
    /// the discrete, logged, admin-gated act the design makes of it.
    RevealEnrollmentToken(RevealEnrollmentTokenRequest) {
        owner: Authority, audit: Disclosure,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    /// Somebody who has not logged in yet holds no credential of any kind, so
    /// the enrollment tier is the only door they can knock on. What confines
    /// them is the password, the second factor and the per-account lockout —
    /// not the tier.
    AuthenticateUser(AuthenticateUserRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey, Enrollment],
        limit: Login,
    }
    /// Not on the viewer's list, unlike the `List*` requests beside it: it
    /// enumerates the accounts that can administer this mesh.
    ListUsers(ListUsersRequest) {
        owner: Authority, audit: Query,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    CreateUser(CreateUserRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    RemoveUser(RemoveUserRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    SetUserRole(SetUserRoleRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    SetUserEnabled(SetUserEnabledRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    SetUserPassword(SetUserPasswordRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    RevokeUserSessions(RevokeUserSessionsRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    CreateUserInvite(CreateUserInviteRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    ListUserInvites(ListUserInvitesRequest) {
        owner: Authority, audit: Query,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    RevokeUserInvite(RevokeUserInviteRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    /// Redeeming an invitation: the invitee holds no credential yet, so a tier
    /// that required one would close the door they need to knock on. Note what
    /// is *not* admitted beside it — an enrollment connection can redeem an
    /// invite it already holds and can do nothing else to the account store: it
    /// cannot mint one, list one, or revoke one.
    BeginUserRegistration(BeginUserRegistrationRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey, Enrollment],
        limit: Registration,
    }
    CompleteUserRegistration(CompleteUserRegistrationRequest) {
        owner: Authority, audit: Mutation,
        access: [Admin, SelfKey, Enrollment],
        limit: Registration,
    }

    // ---- Transport facet: answered by the connection task itself ---------

    /// The transport's own first frame. Excluded from every tier but the two
    /// full grants because the connection has already authenticated: a second
    /// `Authenticate` on the same connection has no defined meaning and must
    /// not silently re-tier it.
    Authenticate(AuthenticateRequest) {
        owner: Transport, audit: Query,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    /// The one request decided by the request ahead of the tier, and the one an
    /// *admin* is refused. It does not grant its caller a capability — it mints
    /// a credential *for the caller's device identity*, so the question is not
    /// how privileged a tier is but whether it names a node the coordination
    /// server can register.
    ///
    /// Two tiers do. The member tier is an enrolled device presenting the
    /// certificate this mesh's CA issued it, and the transport takes the MAC
    /// from that verified certificate. The self-key tier is the node itself,
    /// and the transport takes the MAC from the router. An operator's session
    /// certificate is a person, not a device, so for admin the request has no
    /// meaning rather than being a privilege it lacks — which is also what
    /// makes design 08's two gates independent.
    GetVpnEnrollment(GetVpnEnrollmentRequest) {
        owner: Transport, audit: Mutation,
        access: [SelfKey, Member],
        limit: Unmetered,
    }
    /// A query, and *not* on the viewer's list unlike the `List*` requests
    /// beside it: it is answered by calling out to the coordination server, so
    /// admitting it on a read-only tier would let a viewer drive outbound
    /// requests from the CA at whatever rate it polls.
    ListVpnPeers(ListVpnPeersRequest) {
        owner: Transport, audit: Query,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
    RevokeVpnPeer(RevokeVpnPeerRequest) {
        owner: Transport, audit: Mutation,
        access: [Admin, SelfKey],
        limit: Unmetered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wayfinder::v1alpha::GetRoutingTableRequest;
    use crate::wayfinder::v1alpha::SetAuthRequest;
    use crate::wayfinder::v1alpha::SubmitCsrRequest;

    /// The table is the declaration site, so these spot-checks are about the
    /// *macro* projecting each field into the right classifier — not about the
    /// policy, which `wayfinder-server`'s sweeps cover over the whole surface.
    #[test]
    fn the_table_projects_each_field_into_its_classifier() {
        let read = RequestKind::GetRoutingTable(GetRoutingTableRequest {});
        assert_eq!(request_kind_name(&read), "GetRoutingTable");
        assert_eq!(audited(&read), Audited::Query);
        assert_eq!(request_facet(&read), RequestFacet::RouterRead);
        assert_eq!(rate_limit(&read), RateLimit::Unmetered);
        assert!(access_tiers(&read).contains(&AccessTier::Viewer));

        let write = RequestKind::SetAuth(SetAuthRequest::default());
        assert_eq!(audited(&write), Audited::Mutation);
        assert_eq!(request_facet(&write), RequestFacet::RouterWrite);
        assert!(!access_tiers(&write).contains(&AccessTier::Viewer));

        let csr = RequestKind::SubmitCsr(SubmitCsrRequest::default());
        assert_eq!(request_facet(&csr), RequestFacet::Authority);
        assert_eq!(rate_limit(&csr), RateLimit::SubmitCsr);
        assert!(access_tiers(&csr).contains(&AccessTier::Enrollment));
    }

    // The "exactly one of these exists" properties are asserted as *counts*
    // over the whole request surface, which needs `every_request_kind()` and so
    // the `test-support` feature. They live beside the other whole-surface
    // sweeps in `wayfinder-server`'s `authz.rs`, where that feature is already
    // on — see `the_singular_classifications_are_singular` there.
}
