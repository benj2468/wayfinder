//! Capacity-erased access to a [`CentralRouter`](crate::CentralRouter).
//!
//! [`CentralRouter`](crate::CentralRouter) is const-generic over eleven table
//! capacities so one routing core serves both a Linux gateway and a
//! kilobytes-of-RAM MCU. That is right for the *type*, but it is a tax on every
//! generic function written against it: each has to re-declare all eleven and
//! then re-apply them to the router type, which buries the arguments that
//! actually vary under thirty lines of boilerplate.
//!
//! [`RouterOps`] is that surface with the capacities erased. Code that merely
//! *drives* a router — the driver shells and their shared planning core — takes
//! `R: RouterOps` and never names a capacity. Capacity stays where it belongs:
//! at the point a node picks its profile, via
//! [`define_profile!`](crate::define_profile) and [`router_for!`](crate::router_for).
//!
//! # Scope
//!
//! Deliberately the *driver* surface, not everything a `CentralRouter` can do.
//! The read-only observability accessors the management API projects
//! (`link_quality_records`, `keepalive_table`, `ogm_schedule`,
//! `interface_throughput`, the occupancy gauges, …) are **not** here:
//! `wayfinder-server`'s `RouterAdapter` already exists to project those onto
//! `WayfinderDataProvider`, and duplicating ~25 accessors here would buy one
//! generic header while creating a second near-copy of that trait to keep in
//! step. `RouterAdapter` therefore stays const-generic; see its module docs.
//!
//! # Why an associated type for auth
//!
//! [`OgmAuth`](crate::auth::OgmAuth) is *itself* const-generic over four
//! capacities, so `auth_mut` cannot hand back a concrete type without
//! reintroducing the problem. It returns [`RouterOps::Auth`] instead, bounded by
//! [`OgmAuthOps`] — which needs only the operations generic code actually
//! performs. `dyn` is not an option: [`OgmAuth::revoked_macs`] returns an
//! `impl Iterator`, and this crate is `no_std` with no allocator to box one.
//!
//! [`OgmAuth::revoked_macs`]: crate::auth::OgmAuth::revoked_macs

use core::time::Duration;

use interfaces::frame::LinkFrame;
use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;
use interfaces::link::LinkMetrics;

use crate::CentralRouter;
use crate::EgressInterface;
use crate::RxOutcome;
use crate::auth::OgmAuth;
use crate::features::LinkFeatures;

/// The operations generic code performs on a router's opt-in authentication
/// state, with [`OgmAuth`]'s four table capacities erased.
///
/// Intentionally narrow: only what a driver needs on the send path. Anything
/// richer (cert-store inspection, revocation listing, the trust anchor) is read
/// through a concrete `OgmAuth`, which every non-generic caller already has.
pub trait OgmAuthOps {
    /// Write the pairwise authentication tag for a directed frame to `dst` into
    /// `trailer`, returning the tag length, or `None` when no pairwise key for
    /// `dst` is known (the frame must then be dropped rather than sent in the
    /// clear).
    ///
    /// `frame` is the frame body the tag covers; `trailer` is the reserved
    /// trailing bytes to write into.
    fn tag_directed(&mut self, dst: Mac, frame: &[u8], trailer: &mut [u8]) -> Option<usize>;

    /// Whether `trailer` is a valid pairwise tag from `src` over `frame`.
    ///
    /// `false` for a malformed trailer, an unverified or foreign neighbor, or a
    /// replayed counter — in every case the frame must be dropped rather than
    /// routed unauthenticated.
    fn verify_directed(&mut self, src: Mac, frame: &[u8], trailer: &[u8]) -> bool;
}

impl<
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
> OgmAuthOps for OgmAuth<NEIGHBOR_KEYS, REVOKED, IN_FLIGHT_CERT_REQUESTS, PENDING_REPLIES>
{
    fn tag_directed(&mut self, dst: Mac, frame: &[u8], trailer: &mut [u8]) -> Option<usize> {
        OgmAuth::tag_directed(self, dst, frame, trailer)
    }

    fn verify_directed(&mut self, src: Mac, frame: &[u8], trailer: &[u8]) -> bool {
        OgmAuth::verify_directed(self, src, frame, trailer)
    }
}

/// A mesh router, with its table capacities erased.
///
/// Implemented once for every [`CentralRouter`](crate::CentralRouter) capacity
/// profile, so a driver writes `R: RouterOps` instead of eleven const
/// arguments. See the [module docs](self) for scope and rationale.
pub trait RouterOps {
    /// This router's authentication state type — [`OgmAuth`] at whatever
    /// capacities the profile chose.
    type Auth: OgmAuthOps;

    /// How many mesh interfaces this router tracks.
    ///
    /// The one capacity deliberately *not* erased: it is part of the contract
    /// with a driver, which must not hold more links than the router can
    /// schedule. A surplus link is never given an OGM slot
    /// (`configure_interface_ogm` no-ops past the bound), so the node would go
    /// silently mute on a link it believes is up. Exposing it as an associated
    /// const lets a driver enforce `N <= R::INTERFACES` at compile time.
    const INTERFACES: usize;

    /// Build a router for node `self_ident` at this type's capacities.
    ///
    /// On the trait rather than left to the inherent constructor so a driver
    /// generic over `R` can build its own router. Mirrors
    /// [`CentralRouter::with_capacities`].
    fn with_capacities(self_ident: Mac) -> Self;

    // ---- receive path -----------------------------------------------------

    /// Process one received link frame, folding in its physical-layer metrics,
    /// and return anything to forward onto the mesh or deliver to the local
    /// host. See [`CentralRouter::handle_frame_with_metrics`].
    fn handle_frame_with_metrics<'rx, 'tx>(
        &mut self,
        now: Duration,
        iface_idx: usize,
        frame: &'rx LinkFrame,
        metrics: LinkMetrics,
        tx_buf: &'tx mut [u8],
    ) -> RxOutcome<'rx, 'tx>;

    // ---- periodic emission ------------------------------------------------

    /// Produce this node's due periodic OGM into `tx_buf`, if one is due.
    fn poll<'tx>(&mut self, now: Duration, tx_buf: &'tx mut [u8]) -> Option<LinkFrameData<'tx>>;

    /// Produce a due keep-alive into `tx_buf`, if one is due.
    fn poll_keepalive<'tx>(&mut self, tx_buf: &'tx mut [u8]) -> Option<LinkFrameData<'tx>>;

    /// Set interface `idx`'s Trickle bounds, so a fast LAN link and a slow LoRa
    /// link back off on their own schedules.
    fn configure_interface_ogm(
        &mut self,
        idx: usize,
        i_min: Duration,
        i_max: Duration,
        now: Duration,
    );

    /// Set interface `idx`'s keep-alive interval (`None` disables it).
    fn configure_interface_keepalive(
        &mut self,
        idx: usize,
        interval: Option<Duration>,
        now: Duration,
    );

    /// The interface whose OGM is due at `now`, if any.
    fn due_interface(&self, now: Duration) -> Option<usize>;

    /// The interface whose keep-alive is due at `now`, if any.
    fn due_keepalive_interface(&self, now: Duration) -> Option<usize>;

    /// Time from `now` until the soonest periodic OGM is due.
    fn next_broadcast_after(&self, now: Duration) -> Duration;

    /// Time from `now` until the soonest keep-alive is due.
    fn next_keepalive_after(&self, now: Duration) -> Duration;

    /// Record that interface `idx` emitted its OGM at `now`, advancing Trickle.
    fn on_interface_emitted(&mut self, idx: usize, now: Duration);

    /// Record that interface `idx` emitted its keep-alive at `now`.
    fn on_keepalive_emitted(&mut self, idx: usize, now: Duration);

    // ---- egress -----------------------------------------------------------

    /// Choose the egress interface for `dest`: one interface, every interface
    /// (a flood), or `None` when no route is known.
    fn get_egress_interface(&mut self, now: Duration, dest: Mac) -> Option<EgressInterface>;

    /// Whether interface `idx` may transmit a frame of this BATMAN packet type,
    /// per its configured [`LinkFeatures`]. `None` means "not a BATMAN frame",
    /// which is never gated.
    fn link_may_tx(&self, idx: usize, packet_type: Option<u8>) -> bool;

    /// This interface's participation gates.
    fn link_features(&self, idx: usize) -> LinkFeatures;

    /// Set this interface's participation gates.
    fn set_link_features(&mut self, idx: usize, features: LinkFeatures);

    // ---- observability the send path feeds --------------------------------

    /// Fold `bytes` transmitted on interface `idx` into its rate estimator.
    fn record_tx(&mut self, idx: usize, bytes: usize, now: Duration);

    /// Number of originators currently in the routing table.
    fn originator_count(&self) -> usize;

    // ---- auth -------------------------------------------------------------

    /// Install authentication state, enabling OGM signing and verification.
    fn set_auth(&mut self, auth: Self::Auth);

    /// This router's authentication state, or `None` when auth is off.
    fn auth_mut(&mut self) -> Option<&mut Self::Auth>;
}

impl<
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
> RouterOps
    for CentralRouter<
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >
{
    type Auth = OgmAuth<NEIGHBOR_KEYS, REVOKED, IN_FLIGHT_CERT_REQUESTS, PENDING_REPLIES>;

    const INTERFACES: usize = INTERFACES;

    fn with_capacities(self_ident: Mac) -> Self {
        Self::with_capacities(self_ident)
    }

    fn handle_frame_with_metrics<'rx, 'tx>(
        &mut self,
        now: Duration,
        iface_idx: usize,
        frame: &'rx LinkFrame,
        metrics: LinkMetrics,
        tx_buf: &'tx mut [u8],
    ) -> RxOutcome<'rx, 'tx> {
        Self::handle_frame_with_metrics(self, now, iface_idx, frame, metrics, tx_buf)
    }

    fn poll<'tx>(&mut self, now: Duration, tx_buf: &'tx mut [u8]) -> Option<LinkFrameData<'tx>> {
        Self::poll(self, now, tx_buf)
    }

    fn poll_keepalive<'tx>(&mut self, tx_buf: &'tx mut [u8]) -> Option<LinkFrameData<'tx>> {
        Self::poll_keepalive(self, tx_buf)
    }

    fn configure_interface_ogm(
        &mut self,
        idx: usize,
        i_min: Duration,
        i_max: Duration,
        now: Duration,
    ) {
        Self::configure_interface_ogm(self, idx, i_min, i_max, now);
    }

    fn configure_interface_keepalive(
        &mut self,
        idx: usize,
        interval: Option<Duration>,
        now: Duration,
    ) {
        Self::configure_interface_keepalive(self, idx, interval, now);
    }

    fn due_interface(&self, now: Duration) -> Option<usize> {
        Self::due_interface(self, now)
    }

    fn due_keepalive_interface(&self, now: Duration) -> Option<usize> {
        Self::due_keepalive_interface(self, now)
    }

    fn next_broadcast_after(&self, now: Duration) -> Duration {
        Self::next_broadcast_after(self, now)
    }

    fn next_keepalive_after(&self, now: Duration) -> Duration {
        Self::next_keepalive_after(self, now)
    }

    fn on_interface_emitted(&mut self, idx: usize, now: Duration) {
        Self::on_interface_emitted(self, idx, now);
    }

    fn on_keepalive_emitted(&mut self, idx: usize, now: Duration) {
        Self::on_keepalive_emitted(self, idx, now);
    }

    fn get_egress_interface(&mut self, now: Duration, dest: Mac) -> Option<EgressInterface> {
        Self::get_egress_interface(self, now, dest)
    }

    fn link_may_tx(&self, idx: usize, packet_type: Option<u8>) -> bool {
        Self::link_may_tx(self, idx, packet_type)
    }

    fn link_features(&self, idx: usize) -> LinkFeatures {
        Self::link_features(self, idx)
    }

    fn set_link_features(&mut self, idx: usize, features: LinkFeatures) {
        Self::set_link_features(self, idx, features);
    }

    fn record_tx(&mut self, idx: usize, bytes: usize, now: Duration) {
        Self::record_tx(self, idx, bytes, now);
    }

    fn originator_count(&self) -> usize {
        Self::originator_count(self)
    }

    fn set_auth(&mut self, auth: Self::Auth) {
        Self::set_auth(self, auth);
    }

    fn auth_mut(&mut self) -> Option<&mut Self::Auth> {
        Self::auth_mut(self)
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use interfaces::frame::LinkFrame;
    use interfaces::frame::Mac;
    use interfaces::link::LinkMetrics;
    use zerocopy::FromBytes;
    use zerocopy::IntoBytes;

    use crate::CentralRouter;
    use crate::EgressInterface;
    use crate::features::LinkFeatures;
    use crate::router_ops::RouterOps;

    /// Compact `u8` → `Mac`, matching the router/engine test convention.
    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Serialise a `LinkFrame`, Ethernet-shaped: `[dst][src][proto BE][payload]`.
    fn link_frame_bytes(src: u8, dst: u8, payload: &[u8]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::new();
        v.extend_from_slice(mac(dst).as_bytes());
        v.extend_from_slice(mac(src).as_bytes());
        v.extend_from_slice(&crate::DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    crate::define_profile! {
        /// A constrained node: a couple of radios and a handful of peers.
        pub tiny {
            originators: 16,
            interfaces: 2,
            mcast_members: 8,
            local_mcast: 4,
            ident_table: 16,
            ident_live: 12,
            link_quality: 16,
            neighbor_keys: 8,
            revoked: 4,
            in_flight_cert_requests: 2,
            pending_replies: 2,
            max_frame_len: 256,
        }
    }

    type TinyRouter = crate::router_for!(tiny);

    /// The whole point of the trait: **one** generic signature, naming a single
    /// type parameter instead of eleven const arguments, drives a router at any
    /// capacity profile.
    ///
    /// Returns the OGM this router emitted, so the caller can assert the
    /// generic path produced real work rather than silently doing nothing.
    fn drive_one_ogm<R: RouterOps>(
        router: &mut R,
        tx_buf: &mut [u8],
    ) -> Option<alloc::vec::Vec<u8>> {
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );

        // Advance to whenever interface 0 first becomes due — Trickle picks the
        // exact instant, so don't hard-code the schedule.
        let mut now = Duration::ZERO;
        while router.due_interface(now).is_none() && now < Duration::from_secs(60) {
            now += Duration::from_millis(100);
        }

        let due = router.due_interface(now)?;
        let frame = router.poll(now, tx_buf)?;
        let emitted = frame.payload.to_vec();
        router.on_interface_emitted(due, now);
        router.record_tx(due, emitted.len(), now);

        Some(emitted)
    }

    /// The contract, stated once: the same generic function drives the default
    /// (host) profile and a constrained profile, and both originate the *same*
    /// OGM. Capacity is a memory decision, never a behavioural one — so if this
    /// diverges, the trait is leaking capacity into behaviour.
    #[test]
    fn one_generic_signature_drives_both_profiles_identically() {
        let mut host: CentralRouter = CentralRouter::new(mac(1));
        let mut tiny = TinyRouter::with_capacities(mac(1));

        let mut host_buf = [0u8; 256];
        let mut tiny_buf = [0u8; 256];

        let host_ogm = drive_one_ogm(&mut host, &mut host_buf).expect("host emits an OGM");
        let tiny_ogm = drive_one_ogm(&mut tiny, &mut tiny_buf).expect("tiny emits an OGM");

        assert_eq!(
            host_ogm, tiny_ogm,
            "a capacity profile must not change the OGM a node originates"
        );
    }

    /// The trait must carry the whole hot path `wayfinder-driver-core` needs,
    /// including the widest signature in the router
    /// (`handle_frame_with_metrics`). Receiving a peer's OGM through the trait
    /// must reach the routing tables — proving the methods delegate to real
    /// state rather than compiling as inert stubs.
    #[test]
    fn receiving_a_peer_ogm_through_the_trait_populates_the_routing_table() {
        let mut originator: CentralRouter = CentralRouter::new(mac(2));
        let mut tx = [0u8; 256];
        let ogm = drive_one_ogm(&mut originator, &mut tx).expect("originator emits an OGM");

        fn receive<R: RouterOps>(router: &mut R, payload: &[u8]) -> usize {
            let bytes = link_frame_bytes(2, 0xff, payload);
            let frame = LinkFrame::ref_from_bytes(&bytes).expect("valid link frame");
            let mut tx = [0u8; 256];
            router.handle_frame_with_metrics(
                Duration::from_secs(1),
                0,
                frame,
                LinkMetrics::default(),
                &mut tx,
            );
            router.originator_count()
        }

        let mut host: CentralRouter = CentralRouter::new(mac(1));
        let mut tiny = TinyRouter::with_capacities(mac(1));

        assert_eq!(
            receive(&mut host, &ogm),
            1,
            "host router should learn the originator through the trait"
        );
        assert_eq!(
            receive(&mut tiny, &ogm),
            1,
            "tiny router should learn the same originator through the same signature"
        );
    }

    /// Per-link participation gating has to round-trip through the trait, since
    /// the driver shells consult it on every egress decision.
    #[test]
    fn link_features_round_trip_through_the_trait() {
        fn gate<R: RouterOps>(router: &mut R) -> (bool, bool) {
            let before = router.link_may_tx(0, None);
            let off = LinkFeatures {
                tx_ogm: false,
                ..Default::default()
            };
            router.set_link_features(0, off);
            (before, router.link_features(0).tx_ogm)
        }

        let mut tiny = TinyRouter::with_capacities(mac(1));
        let (before, after) = gate(&mut tiny);
        assert!(before, "a fresh link defaults to full participation");
        assert!(!after, "the trait must write through to the router's gate");
    }

    /// Egress resolution is what all three driver shells' `dispatch` calls, so
    /// it must be reachable generically.
    #[test]
    fn egress_resolution_is_reachable_generically() {
        fn resolve<R: RouterOps>(router: &mut R) -> Option<EgressInterface> {
            router.get_egress_interface(Duration::from_secs(1), Mac::BROADCAST)
        }

        let mut tiny = TinyRouter::with_capacities(mac(1));
        assert!(
            matches!(resolve(&mut tiny), Some(EgressInterface::All)),
            "a broadcast destination floods every interface"
        );
    }

    /// The auth seam is the one place the trait cannot simply hand back a
    /// concrete type: `OgmAuth` is itself const-generic over four capacities.
    /// It is reached through an associated type, so generic code can tag a
    /// directed frame without naming any of them.
    #[test]
    fn auth_is_reachable_through_an_associated_type() {
        fn auth_off<R: RouterOps>(router: &mut R) -> bool {
            router.auth_mut().is_none()
        }

        let mut tiny = TinyRouter::with_capacities(mac(1));
        assert!(
            auth_off(&mut tiny),
            "a fresh router has no auth installed, reported through the associated type"
        );
    }
}
