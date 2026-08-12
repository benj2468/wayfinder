//! Core abstractions shared by every layer of the mesh stack.
//!
//! These are the traits and types the protocol, engine, router, and driver
//! layers all speak: the [`frame`] link-layer frame and node-address ([`Mac`]),
//! the [`engine`] routing-engine trait and its action enum, and the [`link`]
//! per-frame metrics and error types. The crate is `no_std` (except under
//! `test`) so the same definitions compile for embedded and host builds.
//!
//! [`Mac`]: frame::Mac
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The routing-engine trait ([`MeshRoutingEngine`](engine::MeshRoutingEngine))
/// and its [`RoutingAction`](engine::RoutingAction) result.
pub mod engine;
/// The zero-copy link-layer frame ([`LinkFrame`](frame::LinkFrame)) and the
/// node-address type ([`Mac`](frame::Mac)).
pub mod frame;
/// Per-frame link measurements ([`LinkMetrics`](link::LinkMetrics)) and the
/// link-layer error type ([`LinkError`](link::LinkError)).
pub mod link;
/// Ethernet-shaped framing shared by every carrier whose medium is real
/// Ethernet ([`frame_into_buf`](wire::frame_into_buf),
/// [`retag_ethertype`](wire::retag_ethertype)).
pub mod wire;

/// Declare a capacity profile: the fixed table sizes one node's routing core
/// is built with, as a module of named constants.
///
/// The routing core's tables are const-generic so a constrained node can trade
/// mesh scale for RAM, but `CentralRouter` alone takes eleven const arguments —
/// far past what should be written positionally, where transposing two numbers
/// silently produces a working router with the wrong shape. A profile names
/// each capacity once; the applicator macro in each crate (`router_for!`,
/// `engine_for!`) turns it into the concrete type, keeping the argument order
/// owned by the crate that defines it rather than duplicated at every call
/// site.
///
/// Capacities are a purely **local** memory decision — none of them reaches the
/// wire, so nodes built with different profiles interoperate unchanged.
///
/// ```
/// interfaces::define_profile! {
///     /// A constrained node: a couple of radios and a handful of peers.
///     pub embedded {
///         originators: 16,
///         interfaces: 2,
///         mcast_members: 8,
///         local_mcast: 4,
///         ident_table: 16,
///         ident_live: 12,
///         link_quality: 16,
///         neighbor_keys: 8,
///         revoked: 4,
///         in_flight_cert_requests: 2,
///         pending_replies: 2,
///         max_frame_len: 256,
///     }
/// }
/// assert_eq!(embedded::ORIGINATORS, 16);
/// ```
///
/// `originators` and `ident_table` must each be a power of two (a `heapless`
/// map requirement); the types they parameterize assert this at compile time.
#[macro_export]
macro_rules! define_profile {
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident {
            originators: $originators:expr,
            interfaces: $interfaces:expr,
            mcast_members: $mcast_members:expr,
            local_mcast: $local_mcast:expr,
            ident_table: $ident_table:expr,
            ident_live: $ident_live:expr,
            link_quality: $link_quality:expr,
            neighbor_keys: $neighbor_keys:expr,
            revoked: $revoked:expr,
            in_flight_cert_requests: $in_flight:expr,
            pending_replies: $pending_replies:expr,
            max_frame_len: $max_frame_len:expr $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis mod $name {
            /// Originator (routing) table capacity; also bounds broadcast dedup.
            pub const ORIGINATORS: usize = $originators;
            /// Mesh interfaces tracked, timed and measured independently.
            pub const INTERFACES: usize = $interfaces;
            /// `(group, listener)` multicast memberships learned mesh-wide.
            pub const MCAST_MEMBERS: usize = $mcast_members;
            /// Multicast groups the local host may join at once.
            pub const LOCAL_MCAST: usize = $local_mcast;
            /// Ident-table slots; the power-of-two backing store.
            pub const IDENT_TABLE: usize = $ident_table;
            /// Live ident-table entries before LRU eviction begins.
            pub const IDENT_LIVE: usize = $ident_live;
            /// `(neighbor, interface)` link-quality rows.
            pub const LINK_QUALITY: usize = $link_quality;
            /// Verified neighbour key records cached by the auth layer.
            pub const NEIGHBOR_KEYS: usize = $neighbor_keys;
            /// Revocation records held locally.
            pub const REVOKED: usize = $revoked;
            /// Concurrent outstanding lazy-cert fetches.
            pub const IN_FLIGHT_CERT_REQUESTS: usize = $in_flight;
            /// Parked `CertReply`s awaiting a route to the requester.
            pub const PENDING_REPLIES: usize = $pending_replies;
            /// Largest link frame this node buffers, in bytes. Sized to the
            /// widest medium the node actually speaks (802.15.4 caps at 127,
            /// BLE advertising fragments near 250) rather than the 2 KB a
            /// tap/UDP host link needs -- the driver's staging buffers are
            /// this wide, per interface.
            pub const MAX_FRAME_LEN: usize = $max_frame_len;
        }
    };
}
