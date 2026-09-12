//! Renderers produce the expected human text and JSON (the latter via the
//! `serde::Serialize` derived on the proto types behind the `serde` feature).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use wayfinder_protos::wayfinder::v1alpha::BuildInfo;
use wayfinder_protos::wayfinder::v1alpha::BuildSource;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;
use wayfinder_protos::wayfinder::v1alpha::LogRecord;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NeighborPath;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::RoutingEntry;
use wayfinder_protos::wayfinder::v1alpha::RoutingTable;
use wayfinderctl::output::OutputFormat;
use wayfinderctl::output::{self};

#[test]
fn node_info_human_renders_mac_and_count() {
    let v = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 3,
        auth_locked: true,
        runtime_config_active: true,
        clock_trusted: false,
        clock_posture: wayfinder_protos::wayfinder::v1alpha::ClockPosture::At as i32,
        build_info: Some(BuildInfo {
            version: "v0.4.0-12-g35dcaee-dirty".to_string(),
            commit: "35dcaee".to_string(),
            dirty: true,
            source: BuildSource::Git as i32,
        }),
    };
    let human = output::node_info(&v, OutputFormat::Human).unwrap();
    assert!(human.contains("aa:bb:cc:dd:ee:01"), "got: {human}");
    assert!(human.contains("originators: 3"), "got: {human}");
    assert!(human.contains("locked: yes"), "got: {human}");
    assert!(human.contains("runtime config: yes"), "got: {human}");
    // An untrusted clock has to say what it *means*, not just report a flag:
    // whoever is reading this is most likely here because something failed.
    assert!(human.contains("NOT SYNCHRONIZED"), "got: {human}");
    assert!(
        human.contains("credential operations refused"),
        "got: {human}"
    );
    assert!(human.contains("v0.4.0-12-g35dcaee-dirty"), "got: {human}");
}

/// A node that does not report its build must read as *unknown*, not as a
/// blank or a default-filled `BuildInfo` — the two mean different things to
/// whoever is deciding whether a fix is deployed.
#[test]
fn node_info_human_says_so_when_the_build_is_not_reported() {
    let v = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 3,
        auth_locked: false,
        runtime_config_active: false,
        clock_trusted: true,
        clock_posture: wayfinder_protos::wayfinder::v1alpha::ClockPosture::At as i32,
        build_info: None,
    };

    let human = output::node_info(&v, OutputFormat::Human).unwrap();

    assert!(human.contains("build: not reported"), "got: {human}");
}

/// A node that answered but could not identify its own build is a different
/// thing from one that did not answer, and both are different from a healthy
/// build. This is the arm a container built without the `--build-arg` hits.
#[test]
fn node_info_human_distinguishes_an_unidentified_build_from_a_missing_one() {
    let unidentified = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 0,
        auth_locked: false,
        runtime_config_active: false,
        clock_trusted: true,
        clock_posture: wayfinder_protos::wayfinder::v1alpha::ClockPosture::At as i32,
        build_info: Some(BuildInfo {
            version: "unknown".to_string(),
            commit: "unknown".to_string(),
            dirty: false,
            source: BuildSource::Unknown as i32,
        }),
    };

    let human = output::node_info(&unidentified, OutputFormat::Human).unwrap();

    assert!(human.contains("could not identify itself"), "got: {human}");
    assert!(!human.contains("not reported"), "got: {human}");
}

/// A default-filled `BuildInfo` is a legal proto3 encoding — a zero-length
/// submessage — so it is reachable from a truncated or forward-compatible
/// encoder. Rendering it verbatim would print a bare `build: `, which reads as a
/// bug in this tool rather than as a node that said nothing useful.
#[test]
fn node_info_human_does_not_render_an_empty_build_as_a_blank() {
    let empty = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 0,
        auth_locked: false,
        runtime_config_active: false,
        clock_trusted: true,
        clock_posture: wayfinder_protos::wayfinder::v1alpha::ClockPosture::At as i32,
        build_info: Some(BuildInfo::default()),
    };

    let human = output::node_info(&empty, OutputFormat::Human).unwrap();

    assert!(human.contains("build: reported empty"), "got: {human}");
}

/// A dirty build is the case an operator most needs to notice, and the `-dirty`
/// suffix is easy to miss at the end of a long hash. Say it in words too.
#[test]
fn node_info_human_calls_out_a_modified_tree() {
    let v = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 0,
        auth_locked: false,
        runtime_config_active: false,
        clock_trusted: true,
        clock_posture: wayfinder_protos::wayfinder::v1alpha::ClockPosture::At as i32,
        build_info: Some(BuildInfo {
            version: "35dcaee-dirty".to_string(),
            commit: "35dcaee".to_string(),
            dirty: true,
            source: BuildSource::Git as i32,
        }),
    };

    let human = output::node_info(&v, OutputFormat::Human).unwrap();

    assert!(human.contains("modified"), "got: {human}");
}

#[test]
fn node_info_json_is_valid_and_complete() {
    let v = NodeInfo {
        node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        num_originators: 3,
        auth_locked: true,
        runtime_config_active: true,
        clock_trusted: true,
        clock_posture: wayfinder_protos::wayfinder::v1alpha::ClockPosture::At as i32,
        build_info: Some(BuildInfo {
            version: "v0.4.0".to_string(),
            commit: "35dcaee".to_string(),
            dirty: false,
            source: BuildSource::Injected as i32,
        }),
    };
    let json = output::node_info(&v, OutputFormat::Json).unwrap();
    // Parse it back to confirm it is well-formed JSON with the expected fields.
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["num_originators"], 3);
    assert!(parsed["node_id"].is_array());
    assert_eq!(parsed["auth_locked"], true);
    assert_eq!(parsed["runtime_config_active"], true);
    // A nested message, so this also pins that it does not flatten away.
    assert_eq!(parsed["build_info"]["version"], "v0.4.0");
    assert_eq!(parsed["build_info"]["dirty"], false);
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
                proven: true,
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
