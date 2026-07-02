//! Renderers produce the expected human text and JSON (the latter via the
//! `serde::Serialize` derived on the proto types behind the `serde` feature).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use wayfinder_protos::wayfinder_v1alpha::{NeighborPath, NodeInfo, RoutingEntry, RoutingTable};
use wayfinderctl::output::{self, OutputFormat};

#[test]
fn node_info_human_renders_mac_and_count() {
    let v = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 3,
    };
    let human = output::node_info(&v, OutputFormat::Human).unwrap();
    assert!(human.contains("aa:bb:cc:dd:ee:01"), "got: {human}");
    assert!(human.contains("originators: 3"), "got: {human}");
}

#[test]
fn node_info_json_is_valid_and_complete() {
    let v = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 3,
    };
    let json = output::node_info(&v, OutputFormat::Json).unwrap();
    // Parse it back to confirm it is well-formed JSON with the expected fields.
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["num_originators"], 3);
    assert!(parsed["node_id"].is_array());
}

#[test]
fn empty_routing_table_reads_clearly() {
    let v = RoutingTable { entries: vec![] };
    assert_eq!(
        output::routing_table(&v, OutputFormat::Human).unwrap(),
        "no originators"
    );
}

#[test]
fn routing_table_human_lists_entries() {
    let v = RoutingTable {
        entries: vec![RoutingEntry {
            destination: vec![0, 0, 0, 0, 0, 2],
            next_hop: vec![0, 0, 0, 0, 0, 3],
            tq: 240,
            last_seqno: 17,
            paths: vec![NeighborPath {
                neighbor_id: vec![0, 0, 0, 0, 0, 3],
                tq: 240,
                last_seqno: 17,
            }],
        }],
    };
    let human = output::routing_table(&v, OutputFormat::Human).unwrap();
    assert!(human.contains("00:00:00:00:00:02"), "got: {human}");
    assert!(human.contains("00:00:00:00:00:03"), "got: {human}");
    assert!(human.contains("240"), "got: {human}");
}
