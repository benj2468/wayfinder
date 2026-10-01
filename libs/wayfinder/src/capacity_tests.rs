//! Capacity-profile tests for the router and its tables.
//!
//! [`CentralRouter`] aggregates every fixed-capacity table in the routing core,
//! so fully parameterizing it takes eleven const arguments. Nobody should write
//! that positionally: [`define_profile!`](crate::define_profile) declares the
//! capacities as named fields and [`router_for!`](crate::router_for) applies
//! them, keeping the argument order owned by the crate that defines it.
//!
//! The bounds here matter as much as the sizes: a profile that shrinks a table
//! must also shrink the bound enforced against it, or the router would accept
//! indices its own tables cannot hold.

use core::mem::size_of;
use core::time::Duration;

use interfaces::frame::Mac;

use crate::CentralRouter;
use crate::features::LinkFeatures;
use crate::link_quality::LinkQualityTable;
use crate::routing_table::IdentTable;

// Map a compact `u8` test identifier to a full MAC, matching the convention
// used by the router and engine tests.
fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n])
}

crate::define_profile! {
    /// A constrained node: a couple of radios and a handful of peers.
    pub embedded {
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

/// The tiny router profile, assembled from the named capacities above.
type TinyRouter = crate::router_for!(embedded);

/// The whole point: a constrained profile must reclaim most of the router.
#[test]
fn tiny_router_profile_is_substantially_smaller() {
    let tiny = size_of::<TinyRouter>();
    let default_router = size_of::<CentralRouter>();
    assert!(
        tiny * 4 < default_router,
        "tiny router ({tiny} B) should be well under a quarter of default ({default_router} B)"
    );
}

/// Naming no capacities at all must still mean exactly today's router, so the
/// existing call sites across the workspace keep their current sizing.
#[test]
fn router_defaults_preserve_todays_capacities() {
    crate::define_profile! {
        /// Today's capacities, spelled out.
        pub default_profile {
            originators: 128,
            interfaces: 8,
            mcast_members: 64,
            local_mcast: 16,
            ident_table: 128,
            ident_live: 100,
            link_quality: 64,
            neighbor_keys: 64,
            revoked: 32,
            in_flight_cert_requests: 16,
            pending_replies: 16,
            max_frame_len: 2048,
        }
    }
    type SpelledOutDefault = crate::router_for!(default_profile);

    assert_eq!(size_of::<CentralRouter>(), size_of::<SpelledOutDefault>());
}

/// A tiny router still routes, byte for byte: capacity is a memory decision,
/// not a behavioural one. If this fails, a profile changed more than sizes.
#[test]
fn tiny_router_originates_the_same_frame_as_a_default_router() {
    let now = Duration::from_secs(1);
    let mut tiny = TinyRouter::with_capacities(mac(1));
    let mut default_router = CentralRouter::new(mac(1));

    let payload = [0xAAu8; 32];
    let mut tiny_buf = [0u8; 256];
    let mut default_buf = [0u8; 256];

    let tiny_frame = tiny
        .handle_local(now, mac(2), &payload, &mut tiny_buf)
        .expect("tiny router originates");
    let default_frame = default_router
        .handle_local(now, mac(2), &payload, &mut default_buf)
        .expect("default router originates");

    assert_eq!(tiny_frame.protocol, default_frame.protocol);
    assert_eq!(tiny_frame.payload, default_frame.payload);
}

/// The interface bound must follow the profile: a two-interface router has to
/// ignore index 2 even though the crate default admits eight.
#[test]
fn link_features_respect_the_profile_interface_bound() {
    let mut tiny = TinyRouter::with_capacities(mac(1));
    let features = LinkFeatures::default();

    tiny.set_link_features(0, features);
    assert_eq!(tiny.num_interfaces(), 1);
    tiny.set_link_features(1, features);
    assert_eq!(tiny.num_interfaces(), 2);

    // Beyond this profile's bound: ignored rather than written out of range.
    tiny.set_link_features(2, features);
    assert_eq!(
        tiny.num_interfaces(),
        2,
        "index 2 is within the crate default but past this profile"
    );

    // The default profile still admits it, so the bound really is per-profile.
    let mut default_router = CentralRouter::new(mac(1));
    default_router.set_link_features(2, features);
    assert_eq!(default_router.num_interfaces(), 3);
}

// ── The individual tables ─────────────────────────────────────────────────

/// The ident table's LRU evicts at the profile's live-entry bound, not the
/// crate default of 100.
#[test]
fn ident_table_evicts_at_the_profile_bound() {
    let mut table: IdentTable<u8, 16, 12> = IdentTable::new();

    for n in 0..12u8 {
        table.add_record(0, n);
    }
    assert_eq!(
        table.peek_egress_interface(0),
        Some(0),
        "the first entry is present before the table overflows"
    );

    // A thirteenth identifier evicts the least-recently-used, which is the
    // first one inserted since nothing has touched it since.
    table.add_record(0, 99);
    assert_eq!(
        table.peek_egress_interface(0),
        None,
        "the LRU entry was evicted at the profile bound"
    );
    assert_eq!(table.peek_egress_interface(99), Some(0));
}

/// The link-quality table caps at the profile's capacity rather than 64.
#[test]
fn link_quality_table_caps_at_the_profile_bound() {
    let mut table: LinkQualityTable<u8, 16> = LinkQualityTable::new();

    for n in 0..20u8 {
        table.update(n, 0, Some(200));
    }

    assert_eq!(table.records().len(), 16);
}

/// Both tables must actually shrink, since they are what the profile is for.
#[test]
fn tables_shrink_with_the_profile() {
    assert!(size_of::<IdentTable<u8, 16, 12>>() * 4 < size_of::<IdentTable<u8>>());
    assert!(size_of::<LinkQualityTable<u8, 16>>() * 3 < size_of::<LinkQualityTable<u8>>());
}

/// What the probe session costs, stated as a number rather than left to
/// accumulate unnoticed. It lands in *every* profile — a session is fixed-size
/// on purpose, so a board pays the same bytes a gateway does — which is exactly
/// why it needs a ceiling somebody has to raise deliberately.
#[test]
fn a_ping_session_stays_small_enough_for_a_board() {
    let session = size_of::<Option<crate::ping::PingSession>>();
    assert!(
        session <= 512,
        "a ping session is {session} B; it is carried by every node including \
         an nRF52840, so growing it past 512 B should be a deliberate call"
    );
}

/// Every occupancy gauge must report the *router's own* capacity, not the
/// crate default.
///
/// These are `(used, capacity)` pairs the management API serves as
/// current-vs-capacity gauges, and the capacity half was read from the
/// crate-wide constants — so a profiled node reported a gateway's numbers. An
/// ESP32 at 32 originators answered `GetMetrics` with `originators: 0/128`,
/// found by pointing `wayfinderctl` at a real board.
///
/// It is the constrained node that this metric exists for: "how full is the
/// routing table" is the question a 32-entry table raises and a 128-entry one
/// does not, and reporting 128 understates occupancy by exactly the factor that
/// matters.
#[test]
fn occupancy_gauges_report_the_profile_capacity() {
    let tiny = TinyRouter::with_capacities(mac(1));

    assert_eq!(
        tiny.originator_occupancy(),
        (0, 16),
        "the originator table is the profile's 16, not the crate's 128"
    );
    assert_eq!(
        tiny.broadcast_dedup_occupancy(),
        (0, 16),
        "broadcast dedup is bounded by the same originator capacity"
    );
    assert_eq!(
        tiny.local_mcast_occupancy(),
        (0, 4),
        "locally joined groups are the profile's 4"
    );
    assert_eq!(
        tiny.mcast_member_occupancy(),
        (0, 8),
        "mesh-wide memberships are the profile's 8"
    );
}

/// The default profile keeps reporting today's numbers, so this is a fix to the
/// *profiled* case rather than a change to what a gateway says.
#[test]
fn a_default_router_still_reports_the_crate_capacities() {
    let default_router = CentralRouter::new(mac(1));

    assert_eq!(default_router.originator_occupancy(), (0, 128));
    assert_eq!(default_router.broadcast_dedup_occupancy(), (0, 128));
    assert_eq!(default_router.local_mcast_occupancy(), (0, 16));
    assert_eq!(default_router.mcast_member_occupancy(), (0, 64));
}

/// The `host` profile is sized so no mesh we run gets near it (design 26 §3).
/// Pinned number by number so a change to any of them is a deliberate edit
/// here rather than a drift nobody reviews.
#[test]
fn the_host_profile_pins_design_26s_capacities() {
    use crate::host;

    assert_eq!(host::ORIGINATORS, 4096);
    assert_eq!(host::INTERFACES, 8);
    assert_eq!(host::MCAST_MEMBERS, 1024);
    assert_eq!(host::LOCAL_MCAST, 64);
    assert_eq!(host::IDENT_TABLE, 4096);
    assert_eq!(host::IDENT_LIVE, 3500);
    assert_eq!(host::LINK_QUALITY, 1024);
    assert_eq!(host::NEIGHBOR_KEYS, 1024);
    assert_eq!(host::REVOKED, 1024);
    assert_eq!(host::IN_FLIGHT_CERT_REQUESTS, 256);
    assert_eq!(host::PENDING_REPLIES, 256);
    assert_eq!(host::MAX_FRAME_LEN, crate::default::MAX_FRAME_LEN);
}

/// Every `host` table must be at least the `default` one: a host node is the
/// same gateway with more memory, never a narrower one in some dimension.
#[test]
fn the_host_profile_is_no_smaller_than_default_in_any_table() {
    use crate::default;
    use crate::host;

    for (name, big, small) in [
        ("originators", host::ORIGINATORS, default::ORIGINATORS),
        ("interfaces", host::INTERFACES, default::INTERFACES),
        ("mcast_members", host::MCAST_MEMBERS, default::MCAST_MEMBERS),
        ("local_mcast", host::LOCAL_MCAST, default::LOCAL_MCAST),
        ("ident_table", host::IDENT_TABLE, default::IDENT_TABLE),
        ("ident_live", host::IDENT_LIVE, default::IDENT_LIVE),
        ("link_quality", host::LINK_QUALITY, default::LINK_QUALITY),
        ("neighbor_keys", host::NEIGHBOR_KEYS, default::NEIGHBOR_KEYS),
        ("revoked", host::REVOKED, default::REVOKED),
        (
            "in_flight",
            host::IN_FLIGHT_CERT_REQUESTS,
            default::IN_FLIGHT_CERT_REQUESTS,
        ),
        (
            "pending_replies",
            host::PENDING_REPLIES,
            default::PENDING_REPLIES,
        ),
    ] {
        assert!(
            big >= small,
            "host {name} ({big}) is below default ({small})"
        );
    }
}

/// A board-sized router's footprint, pinned so growth is a deliberate edit.
///
/// Measured on the host target, where pointers are wider than a Cortex-M's, so
/// the number is a proxy rather than a board's own — but every byte a table
/// adds shows up here too. Design 26 widened the identity table's slot index to
/// `u16` for every profile, which a board pays for (§3.1); anything more should
/// be a decision someone makes, not a drift. Pinned at 12,248 B: 12,240 after
/// the `u16` widening, plus 8 for `BatmanEngine`'s out-of-band broadcast seqno
/// refusal counter (3ee184e).
#[test]
fn embedded_router_size_is_pinned() {
    let size = size_of::<TinyRouter>();
    assert!(
        size <= 12_248,
        "a board-sized router is {size} B, up from 12,248 B; if that growth is \
         intended, raise this bound and say why in the commit"
    );
}
