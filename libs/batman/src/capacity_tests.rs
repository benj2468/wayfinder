//! Capacity-profile tests.
//!
//! [`BatmanEngine`]'s table sizes are const-generic so a constrained node can
//! trade mesh scale for RAM. Every bound the engine enforces at runtime must
//! come from *its own* generic parameters, not from the crate-wide
//! [`MAX_INTERFACES`](crate::MAX_INTERFACES) /
//! [`MAX_LOCAL_MCAST`](crate::MAX_LOCAL_MCAST) defaults — otherwise a small
//! profile would silently accept indices its tables cannot hold.

use core::mem::size_of;
use core::time::Duration;
use interfaces::frame::Mac;

use crate::BatmanEngine;

// Map a compact `u8` test identifier to a full MAC, e.g. `mac(2)` ->
// `00:00:00:00:00:02`, matching the convention in `engine_tests`.
fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n])
}

/// A deliberately tiny profile: 16 originators, 2 interfaces, 8 mesh-wide
/// multicast memberships, 4 locally joined groups.
type TinyEngine = BatmanEngine<16, 2, 8, 4>;

/// Today's host capacities, spelled out positionally.
type HostEngine = BatmanEngine<128, 8, 64, 16>;

/// The added parameters must default to today's values, so every existing
/// `BatmanEngine<N>` call site keeps compiling and keeps its current sizing.
#[test]
fn defaults_preserve_todays_capacities() {
    assert_eq!(size_of::<BatmanEngine<128>>(), size_of::<HostEngine>());
}

/// The whole point of the exercise: a small profile must actually reclaim RAM.
#[test]
fn tiny_profile_is_substantially_smaller() {
    let tiny = size_of::<TinyEngine>();
    let host = size_of::<HostEngine>();
    assert!(
        tiny * 4 < host,
        "tiny profile ({tiny} B) should be well under a quarter of host ({host} B)"
    );
}

/// `configure_interface_ogm` must reject an index beyond *this engine's*
/// `MAX_INTERFACES`, not the crate default of 8.
#[test]
fn configure_interface_ogm_respects_generic_bound() {
    let now = Duration::from_secs(0);
    let i_min = Duration::from_millis(100);
    let i_max = Duration::from_secs(1);
    let mut engine = TinyEngine::new(mac(1));

    engine.configure_interface_ogm(0, i_min, i_max, now);
    engine.configure_interface_ogm(1, i_min, i_max, now);
    assert_eq!(engine.ogm_timers.len(), 2);

    // Index 2 is within the crate-wide default (8) but beyond this profile's
    // bound (2), so it must be ignored rather than overflow the table.
    engine.configure_interface_ogm(2, i_min, i_max, now);
    assert_eq!(engine.ogm_timers.len(), 2);
}

/// The keep-alive timer bank shares the interface bound and must clamp to the
/// same generic parameter.
#[test]
fn configure_interface_keepalive_respects_generic_bound() {
    let now = Duration::from_secs(0);
    let mut engine = TinyEngine::new(mac(1));

    engine.configure_interface_keepalive(0, Some(Duration::from_secs(5)), now);
    engine.configure_interface_keepalive(1, Some(Duration::from_secs(5)), now);
    assert_eq!(engine.keepalive_timers.len(), 2);

    engine.configure_interface_keepalive(2, Some(Duration::from_secs(5)), now);
    assert_eq!(engine.keepalive_timers.len(), 2);
}

/// Locally joined groups past this profile's `MAX_LOCAL_MCAST` are dropped, at
/// the profile's bound rather than the crate default of 16.
#[test]
fn local_mcast_groups_cap_at_generic_bound() {
    let mut engine = TinyEngine::new(mac(1));
    let groups: [Mac; 6] = core::array::from_fn(|i| mac(i as u8 + 10));

    engine.set_local_mcast_groups(core::time::Duration::ZERO, &groups);

    assert_eq!(engine.local_mcast_groups().len(), 4);
    // The first four survive; the overflow is dropped from the tail.
    assert_eq!(engine.local_mcast_groups(), &groups[..4]);
}

/// A host-profile engine keeps today's behavior for the same call, so the
/// bound really is per-profile and not a new global clamp.
#[test]
fn host_profile_keeps_todays_local_mcast_capacity() {
    let mut engine = HostEngine::new(mac(1));
    let groups: [Mac; 6] = core::array::from_fn(|i| mac(i as u8 + 10));

    engine.set_local_mcast_groups(core::time::Duration::ZERO, &groups);

    assert_eq!(engine.local_mcast_groups().len(), 6);
}

// ── Record footprint ──────────────────────────────────────────────────────
//
// The originator table dominates the engine, and `NeighborStats` dominates the
// originator table: four paths per originator, each holding two timestamps.
// Stamping those with `interfaces::time::Millis` rather than
// `core::time::Duration` is worth twelve bytes on each of the nine stamps a
// record holds -- eight across its four paths, one its own. These are ceilings
// somebody has to raise deliberately,
// in the spirit of `a_ping_session_stays_small_enough_for_a_board`.

/// One path to an originator. The dominant term in the whole routing core: it
/// is held four times per originator and `MAX_ORIGINATORS` times over.
#[test]
fn a_path_record_stays_small() {
    let stats = size_of::<crate::NeighborStats>();
    assert!(
        stats <= 24,
        "NeighborStats is {stats} B; it is held four times per originator and \
         once per originator slot, so every byte here is multiplied by the \
         profile's whole originator capacity"
    );
}

/// One originator, paths included.
#[test]
fn an_originator_record_stays_small() {
    let record = size_of::<crate::OriginatorRecord>();
    assert!(
        record <= 160,
        "OriginatorRecord is {record} B; it was 264 B when its nine timestamps \
         were `Duration`s"
    );
}

/// The two ageing records that are held per neighbour rather than per path.
#[test]
fn the_ageing_records_stay_small() {
    let keepalive = size_of::<crate::KeepAliveStats>();
    let seqno = size_of::<crate::BroadcastSeqnoEntry>();
    assert!(keepalive <= 16, "KeepAliveStats is {keepalive} B, was 32 B");
    assert!(seqno <= 28, "BroadcastSeqnoEntry is {seqno} B, was 48 B");
}

/// What the whole exercise is for, stated end to end: a board-profile engine
/// against what it cost before the records were re-stamped.
#[test]
fn a_board_profile_engine_fits_a_board() {
    // The `nrf52840` profile exactly: 32 originators and -- since the LoRa link
    // came out -- **two** interfaces. The second parameter is `MAX_INTERFACES`,
    // so a `3` here would measure a shape no board is built at.
    let engine = size_of::<BatmanEngine<32, 2, 16, 4>>();
    assert!(
        engine <= 10_000,
        "a 32-originator engine is {engine} B; the equivalent three-interface \
         engine was 15,240 B when its records were stamped with `Duration`"
    );
}
