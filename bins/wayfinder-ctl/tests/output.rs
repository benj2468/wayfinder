//! Renderers produce the expected human text and JSON (the latter via the
//! `serde::Serialize` derived on the proto types behind the `serde` feature).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use wayfinder_protos::wayfinder_v1alpha::LogLevel;
use wayfinder_protos::wayfinder_v1alpha::LogRecord;
use wayfinder_protos::wayfinder_v1alpha::LogRecords;
use wayfinder_protos::wayfinder_v1alpha::NeighborPath;
use wayfinder_protos::wayfinder_v1alpha::NodeInfo;
use wayfinder_protos::wayfinder_v1alpha::RoutingEntry;
use wayfinder_protos::wayfinder_v1alpha::RoutingTable;
use wayfinderctl::output::OutputFormat;
use wayfinderctl::output::{self};

#[test]
fn node_info_human_renders_mac_and_count() {
    let v = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 3,
        auth_locked: true,
        runtime_config_active: true,
    };
    let human = output::node_info(&v, OutputFormat::Human).unwrap();
    assert!(human.contains("aa:bb:cc:dd:ee:01"), "got: {human}");
    assert!(human.contains("originators: 3"), "got: {human}");
    assert!(human.contains("locked: yes"), "got: {human}");
    assert!(human.contains("runtime config: yes"), "got: {human}");
}

#[test]
fn node_info_json_is_valid_and_complete() {
    let v = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 3,
        auth_locked: true,
        runtime_config_active: true,
    };
    let json = output::node_info(&v, OutputFormat::Json).unwrap();
    // Parse it back to confirm it is well-formed JSON with the expected fields.
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["num_originators"], 3);
    assert!(parsed["node_id"].is_array());
    assert_eq!(parsed["auth_locked"], true);
    assert_eq!(parsed["runtime_config_active"], true);
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

/// A record at `seq`, `uptime_ms` and `level`, with a recognisable target and
/// message so assertions can pin the column order.
fn record(seq: u64, uptime_ms: u64, level: LogLevel) -> LogRecord {
    LogRecord {
        seq,
        uptime_ms,
        level: level as i32,
        target: "wayfinder::router".to_string(),
        message: "rx frame src=02:00:00:00:00:01".to_string(),
    }
}

#[test]
fn empty_logs_reads_clearly() {
    let v = LogRecords {
        records: vec![],
        next_seq: 0,
        dropped: 0,
        filter: "info".to_string(),
    };
    let human = output::logs(&v, OutputFormat::Human).unwrap();
    assert!(human.contains("no log records retained"), "got: {human}");
}

#[test]
fn logs_human_renders_uptime_level_target_and_message() {
    let v = LogRecords {
        records: vec![record(7, 12_345, LogLevel::Warn)],
        next_seq: 8,
        dropped: 0,
        filter: "info,batman=trace".to_string(),
    };
    let human = output::logs(&v, OutputFormat::Human).unwrap();
    // Uptime is rendered as seconds.millis, matching the TUI's Logs tab so the
    // two views of the same ring are directly comparable.
    assert!(human.contains("12.345s"), "got: {human}");
    assert!(human.contains("WARN"), "got: {human}");
    assert!(human.contains("wayfinder::router"), "got: {human}");
    assert!(
        human.contains("rx frame src=02:00:00:00:00:01"),
        "got: {human}"
    );
}

#[test]
fn logs_human_reports_the_filter_and_resume_point() {
    let v = LogRecords {
        records: vec![record(7, 12_345, LogLevel::Info)],
        next_seq: 8,
        dropped: 0,
        filter: "info,batman=trace".to_string(),
    };
    let human = output::logs(&v, OutputFormat::Human).unwrap();
    // Without the filter an operator cannot tell "nothing happened" from
    // "nothing was being recorded"; without next_seq they cannot resume.
    assert!(human.contains("info,batman=trace"), "got: {human}");
    assert!(human.contains("next_seq: 8"), "got: {human}");
}

#[test]
fn logs_human_shows_a_gap_when_records_were_dropped() {
    let v = LogRecords {
        records: vec![record(900, 90_000, LogLevel::Trace)],
        next_seq: 901,
        dropped: 42,
        filter: "trace".to_string(),
    };
    let human = output::logs(&v, OutputFormat::Human).unwrap();
    // A gap must read as a gap rather than the numbering quietly closing over
    // it — same reasoning as the TUI's full-width rule.
    assert!(human.contains("42"), "got: {human}");
    assert!(human.contains("dropped"), "got: {human}");
}

#[test]
fn logs_json_is_valid_and_complete() {
    let v = LogRecords {
        records: vec![record(7, 12_345, LogLevel::Error)],
        next_seq: 8,
        dropped: 3,
        filter: "info".to_string(),
    };
    let json = output::logs(&v, OutputFormat::Json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["next_seq"], 8);
    assert_eq!(parsed["dropped"], 3);
    assert_eq!(parsed["filter"], "info");
    assert_eq!(parsed["records"][0]["seq"], 7);
    assert_eq!(parsed["records"][0]["target"], "wayfinder::router");
}
