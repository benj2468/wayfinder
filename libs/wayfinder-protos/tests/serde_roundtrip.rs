//! Round-trip checks for the `serde` feature's derives.
//!
//! The feature exists so a host can move these types over a JSON boundary. That
//! has two directions, and only one of them used to be derived: `wayfinderctl
//! --output json` only ever serializes, so a missing `Deserialize` stayed
//! invisible there. `wayfinder-web` sends a snapshot of these same types from
//! its axum server to the browser and decodes it on the far side, so both halves
//! now have to hold.
//!
//! The cases below are chosen for the prost constructs whose generated shape is
//! least obviously round-trippable: a `bytes` field, an `enum` field (an `i32`
//! on the Rust side), a nested `repeated` message, and a `oneof` (a real Rust
//! enum, which serde treats quite differently from the flat structs).

#![cfg(feature = "serde")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use wayfinder_protos::wayfinder::v1alpha::LogLevel;
use wayfinder_protos::wayfinder::v1alpha::LogRecord;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::RoutingTable;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as ResponseKind;

/// A `bytes` field survives the trip: `node_id` is a `Vec<u8>`, the shape every
/// identifier in this API is carried as.
#[test]
fn node_info_round_trips_through_json() {
    let original = NodeInfo {
        node_id: vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        num_originators: 3,
        auth_locked: false,
        runtime_config_active: true,
    };

    let json = serde_json::to_string(&original).unwrap();
    let decoded: NodeInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, original);
}

/// A `repeated` message field plus an `enum` field. `level` is generated as a
/// bare `i32`, so this pins that it decodes back to the same variant rather
/// than to the default.
#[test]
fn log_records_round_trip_through_json() {
    let original = LogRecords {
        records: vec![
            LogRecord {
                seq: 41,
                uptime_ms: 12_345,
                level: LogLevel::Warn as i32,
                target: "wayfinder::router".into(),
                message: "drop: no route".into(),
            },
            LogRecord {
                seq: 42,
                uptime_ms: 12_400,
                level: LogLevel::Trace as i32,
                target: "batman".into(),
                message: "rx ogm".into(),
            },
        ],
        next_seq: 43,
        dropped: 7,
        filter: "info,batman=trace".into(),
    };

    let json = serde_json::to_string(&original).unwrap();
    let decoded: LogRecords = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, original);
    assert_eq!(decoded.records[0].level, LogLevel::Warn as i32);
}

/// An empty `repeated` field is the state every table is in before the first
/// fetch, so it is the one the web dashboard decodes most often at startup.
#[test]
fn empty_routing_table_round_trips_through_json() {
    let original = RoutingTable::default();

    let json = serde_json::to_string(&original).unwrap();
    let decoded: RoutingTable = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, original);
}

/// A `oneof` is generated as an `Option<enum>`, the construct most likely to
/// need a hand-written impl if the blanket derive cannot cover it.
#[test]
fn response_oneof_round_trips_through_json() {
    let original = WayfinderResponse {
        response: Some(ResponseKind::NodeInfo(NodeInfo {
            node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
            num_originators: 1,
            auth_locked: true,
            runtime_config_active: false,
        })),
    };

    let json = serde_json::to_string(&original).unwrap();
    let decoded: WayfinderResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, original);
}
