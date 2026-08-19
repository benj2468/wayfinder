//! Checks that the tabs actually render the data they are given.
//!
//! The other integration tests stop at the snapshot: they prove the right
//! values arrive. This proves they reach the screen. Without it, a tab that
//! reads the wrong field, or silently renders an empty table because a
//! condition is inverted, passes everything else.
//!
//! Each tab is rendered to a string with a seeded dashboard, rather than driven
//! through a browser — the markup is what a reader ultimately sees, and it is
//! assertable here without a headless browser in the loop.

#![cfg(feature = "mock-node")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicyStatus;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder::v1alpha::InterfaceThroughput;
use wayfinder_protos::wayfinder::v1alpha::KeepAliveEntry;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesEntry;
use wayfinder_protos::wayfinder::v1alpha::LinkQualityEntry;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;
use wayfinder_protos::wayfinder::v1alpha::LogRecord;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NeighborPath;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder::v1alpha::NodeSecurity;
use wayfinder_protos::wayfinder::v1alpha::OgmScheduleEntry;
use wayfinder_protos::wayfinder::v1alpha::PendingCsr;
use wayfinder_protos::wayfinder::v1alpha::RoutingEntry;
use wayfinder_protos::wayfinder::v1alpha::TableOccupancy;
use wayfinder_web::components::dashboard::Dashboard;
use wayfinder_web::components::link_quality::LinkQuality;
use wayfinder_web::components::links::Links;
use wayfinder_web::components::logs::Logs;
use wayfinder_web::components::metrics::Metrics;
use wayfinder_web::components::overview::Overview;
use wayfinder_web::components::routing::Routing;
use wayfinder_web::components::security::Security;
use wayfinder_web::snapshot::NodeSnapshot;
use wayfinder_web::state::History;
use wayfinder_web::state::ThroughputSample;

/// A snapshot with one reachable destination via one neighbour.
fn seeded_snapshot() -> NodeSnapshot {
    let mut snap = NodeSnapshot {
        node_info: Some(NodeInfo {
            node_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
            num_originators: 2,
            auth_locked: false,
            runtime_config_active: false,
        }),
        ..Default::default()
    };
    snap.routing.entries.push(RoutingEntry {
        destination: vec![0, 0, 0, 0, 0, 2],
        next_hop: vec![0, 0, 0, 0, 0, 3],
        tq: 240,
        last_seqno: 17,
        paths: vec![NeighborPath {
            neighbor_id: vec![0, 0, 0, 0, 0, 3],
            tq: 240,
            last_seqno: 17,
        }],
    });
    snap.link_features.entries.push(LinkFeaturesEntry {
        iface_idx: 0,
        tx_ogm: true,
        rx_ogm: true,
        tx_data: false,
        rx_data: true,
        tx_keepalive_interval_ms: Some(2000),
        iface_name: "lora0".into(),
    });
    snap.link_quality.entries.push(LinkQualityEntry {
        neighbor_id: vec![0, 0, 0, 0, 0, 3],
        iface_idx: 0,
        ewma_quality: Some(200),
        sample_count: 9,
        iface_name: "lora0".into(),
    });
    snap.keepalive.entries.push(KeepAliveEntry {
        neighbor_id: vec![0, 0, 0, 0, 0, 3],
        ms_since_last_heard: 4200,
        interval_estimate_ms: 1000,
        missed: true,
    });
    snap.ogm_schedule.entries.push(OgmScheduleEntry {
        iface_idx: 0,
        current_interval_ms: 4000,
        min_interval_ms: 1000,
        max_interval_ms: 64000,
        iface_name: "lora0".into(),
    });
    snap.throughput.interfaces.push(InterfaceThroughput {
        iface_idx: 0,
        rx_bps: 1500.0,
        rx_fps: 12.0,
        tx_bps: 800.0,
        tx_fps: 6.0,
        iface_name: "lora0".into(),
    });
    snap.throughput.total_rx_bps = 1500.0;
    snap.throughput.total_tx_bps = 800.0;
    snap.security = Some(GetSecurityStatusResponse {
        auth_enabled: true,
        mesh_id: 42,
        node_mac: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        cert_not_after: 1_800_000_000,
        revocation_count: 1,
        nodes: vec![
            NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 2],
                verified: true,
                cert_not_after: 1_800_000_000,
                revoked: false,
            },
            NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 3],
                verified: false,
                cert_not_after: 0,
                revoked: true,
            },
            NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 4],
                verified: false,
                cert_not_after: 0,
                revoked: false,
            },
        ],
        require_auth: true,
        lazy_cert_distribution: false,
        // A plain member: no enrollment policy, matching its absent CSR queue.
        // `provider_snapshot` adds both together, the way a real provider has
        // them.
        enrollment: None,
        own_ed_pubkey: vec![0x11; 32],
        own_x_pubkey: vec![0x22; 32],
    });
    snap.metrics = Some(NodeMetrics {
        uptime_secs: 7384,
        neighbor_count: 1,
        originators: Some(TableOccupancy {
            used: 1,
            capacity: 128,
        }),
        tq_min: 240,
        tq_max: 240,
        tq_mean: 240.0,
        paths_max: 1,
        paths_mean: 1.0,
        ..Default::default()
    });
    snap
}

/// The enrollment token `provider_snapshot` requires.
///
/// Distinctive so a test can assert it is *absent* from the rendered markup:
/// the provider panel offers it for copying without ever drawing it.
const PROVIDER_TOKEN: &str = "seeded-join-secret-4c71";

/// The seeded snapshot as a certificate authority: an enrollment policy and a
/// CSR queue, which a real node either has both of or neither.
fn provider_snapshot() -> NodeSnapshot {
    let mut snap = seeded_snapshot();
    if let Some(sec) = snap.security.as_mut() {
        sec.enrollment = Some(EnrollmentPolicyStatus {
            auto_approve: false,
            cert_ttl_secs: 86_400,
            enrollment_token_set: true,
        });
    }
    snap.pending_csrs = Some(ListPendingCsrsResponse { pending: vec![] });
    snap
}

/// A throughput trend with enough samples to draw.
fn seeded_history() -> History {
    let mut history = History::default();
    for i in 0..20 {
        history.throughput.push_back(ThroughputSample {
            rx_bps: 1000.0 + f64::from(i) * 50.0,
            tx_bps: 500.0 + f64::from(i) * 20.0,
        });
    }
    history
}

/// Render a tab with both a snapshot and an accumulated history.
fn render_with_history<V: IntoView + 'static>(
    snapshot: NodeSnapshot,
    history: History,
    tab: impl Fn() -> V + Send + 'static,
) -> String {
    let owner = Owner::new();
    owner
        .with(|| {
            let dash = Dashboard::new();
            dash.connected.set(true);
            dash.snapshot.set(Some(snapshot));
            dash.history.set(history);
            dash.label.set("127.0.0.1:7700".to_string());
            provide_context(dash);
            tab().to_html()
        })
        .to_string()
}

/// Render one tab with a dashboard holding `snapshot`, and return its markup.
fn render_with<V: IntoView + 'static>(
    snapshot: Option<NodeSnapshot>,
    tab: impl Fn() -> V + Send + 'static,
) -> String {
    let owner = Owner::new();
    owner
        .with(|| {
            let dash = Dashboard::new();
            if let Some(snapshot) = snapshot {
                dash.connected.set(true);
                dash.snapshot.set(Some(snapshot));
            }
            dash.label.set("127.0.0.1:7700".to_string());
            provide_context(dash);
            tab().to_html()
        })
        .to_string()
}

/// The Overview leads with the things someone arrives asking about.
#[test]
fn overview_renders_the_node_identity_and_health() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Overview /> });

    assert!(
        html.contains("aa:bb:cc:dd:ee:01"),
        "the node address: {html}"
    );
    assert!(html.contains("Enrolled"), "membership state: {html}");
    assert!(html.contains("127.0.0.1:7700"), "the node it is pointed at");
    // Throughput totals, formatted rather than raw.
    assert!(html.contains("1.5 KiB/s"), "receive rate: {html}");
}

/// Before the first poll, the tab says so rather than showing a plausible
/// blank — "starting up" and "a node with nothing on it" look identical
/// otherwise, and mean very different things.
#[test]
fn overview_says_it_is_waiting_before_the_first_poll() {
    let html = render_with(None, || view! { <Overview /> });

    assert!(html.contains("Waiting for the node"), "{html}");
    assert!(html.contains("Connecting"), "{html}");
}

/// The Routing tab renders a row per destination, with quality as a percentage.
#[test]
fn routing_renders_a_row_per_destination() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Routing /> });

    assert!(
        html.contains("00:00:00:00:00:02"),
        "the destination: {html}"
    );
    assert!(html.contains("00:00:00:00:00:03"), "its next hop: {html}");
    // TQ 240 of 255 leads as a percentage, with the raw value kept as detail.
    assert!(html.contains("94%"), "quality as a percentage: {html}");
    assert!(html.contains("TQ 240"), "raw TQ retained: {html}");
    assert!(html.contains("1 node"), "the row count: {html}");
}

/// With nothing selected the detail panel prompts rather than sitting blank.
#[test]
fn routing_prompts_for_a_selection() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Routing /> });

    assert!(html.contains("Select a destination"), "{html}");
}

/// An empty table says why it is empty.
#[test]
fn routing_distinguishes_no_routes_from_no_connection() {
    let connected = render_with(Some(NodeSnapshot::default()), || view! { <Routing /> });
    assert!(
        connected.contains("No other nodes reachable yet"),
        "connected but alone: {connected}"
    );

    let waiting = render_with(None, || view! { <Routing /> });
    assert!(
        waiting.contains("Waiting for the node"),
        "not yet connected: {waiting}"
    );
}

// ------------------------------------------------------------- Link Quality --

/// Link quality is per (neighbour, interface), and leads with a percentage.
#[test]
fn link_quality_renders_a_row_per_neighbour_and_interface() {
    let html = render_with(Some(seeded_snapshot()), || view! { <LinkQuality /> });

    assert!(html.contains("00:00:00:00:00:03"), "the neighbour: {html}");
    // EWMA quality 200 of 255.
    assert!(html.contains("78%"), "quality as a percentage: {html}");
    assert!(html.contains("9"), "the sample count: {html}");
}

/// A link with no physical-layer metrics reads as unmeasured, not as 0%.
///
/// Raw-L2/UDP transports report no signal on any frame. Showing that as 0%
/// painted a healthy wired neighbour as the worst possible link — the bug this
/// case exists to keep fixed.
#[test]
fn link_quality_shows_an_unmeasured_link_as_not_applicable() {
    let mut snap = seeded_snapshot();
    snap.link_quality.entries.push(LinkQualityEntry {
        neighbor_id: vec![0, 0, 0, 0, 0, 4],
        iface_idx: 1,
        ewma_quality: None,
        sample_count: 9,
        iface_name: "rawl20".into(),
    });

    let html = render_with(Some(snap), || view! { <LinkQuality /> });

    assert!(html.contains("00:00:00:00:00:04"), "the neighbour: {html}");
    assert!(html.contains("n/a"), "quality reads as unmeasured: {html}");
    assert!(
        !html.contains("0%"),
        "an unmeasured link must never render as a percentage: {html}"
    );
    // The measured row is unaffected — the two states coexist in one table.
    assert!(html.contains("78%"), "the measured row still reads: {html}");
}

/// Keep-alive liveness is the direct-link signal, so a lapsed neighbour has to
/// read as lapsed rather than as another row.
#[test]
fn link_quality_flags_a_missed_keepalive() {
    let html = render_with(Some(seeded_snapshot()), || view! { <LinkQuality /> });

    assert!(html.contains("Missed"), "the missed heartbeat: {html}");
}

// -------------------------------------------------------------------- Links --

/// Each interface shows its gates, and mixed gates read as mixed rather than
/// collapsing to on or off.
#[test]
fn links_renders_the_gate_status_per_interface() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Links /> });

    // The seeded interface has tx_data off and the rest on.
    assert!(html.contains("mixed"), "the aggregate gate status: {html}");
    assert!(html.contains("4.0 s"), "the OGM interval: {html}");
    assert!(html.contains("2.0 s"), "the keep-alive cadence: {html}");
}

/// The four gates are individually visible and individually switchable, since
/// the aggregate status alone cannot say *which* gate is closed.
#[test]
fn links_exposes_each_gate_as_a_control() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Links /> });

    for gate in ["Send OGMs", "Receive OGMs", "Send data", "Receive data"] {
        assert!(html.contains(gate), "{gate} is listed: {html}");
    }
    assert!(
        html.contains("role=\"switch\""),
        "gates are switches: {html}"
    );
}

// ------------------------------------------------------------------ Metrics --

/// The metrics summary leads with the health numbers, not the capacity tables.
#[test]
fn metrics_renders_the_node_summary() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Metrics /> });

    assert!(html.contains("2h 3m 4s"), "uptime, formatted: {html}");
    assert!(html.contains("1 / 128"), "table occupancy: {html}");
}

/// The throughput trend is a real two-series chart: both series drawn, both
/// named, so identity never rests on colour alone.
#[test]
fn metrics_renders_the_throughput_chart() {
    let html = render_with_history(seeded_snapshot(), seeded_history(), || {
        view! { <Metrics /> }
    });

    assert!(html.contains("<svg"), "the chart is drawn: {html}");
    assert_eq!(
        html.matches("wf-chart-line").count(),
        2,
        "one line per series: {html}"
    );
    assert!(html.contains("Received"), "the rx series is named: {html}");
    assert!(html.contains("Sent"), "the tx series is named: {html}");
}

/// One sample is not a trend. Rather than drawing a degenerate chart, say so.
#[test]
fn metrics_chart_waits_for_enough_samples() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Metrics /> });

    assert!(!html.contains("wf-chart-line"), "nothing drawn yet: {html}");
    assert!(html.contains("Collecting"), "and it says why: {html}");
}

// ----------------------------------------------------------------- Security --

/// The security header says whether the mesh is authenticated at all, since
/// every per-node row below means something different depending on it.
#[test]
fn security_renders_the_mesh_posture() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(html.contains("aa:bb:cc:dd:ee:01"), "own identity: {html}");
    assert!(html.contains("Enabled"), "auth is on: {html}");
}

/// A revoked node must not read as merely unverified — one is a node whose
/// identity is unknown, the other one the mesh has actively ejected.
#[test]
fn security_distinguishes_revoked_from_unverified() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(html.contains("Revoked"), "the revoked node: {html}");
    assert!(html.contains("Unverified"), "the unverified node: {html}");
    assert!(html.contains("Verified"), "the verified node: {html}");
}

/// Destructive actions are offered, but only behind a confirmation.
#[test]
fn security_puts_destructive_actions_behind_a_confirmation() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(html.contains("Revoke"), "revoke is offered: {html}");
    // The dialog is only rendered once armed, so nothing is one click from
    // ejecting a node from the mesh.
    assert!(!html.contains("wf-modal"), "not armed yet: {html}");
}

/// A node that is not a certificate authority has no CSR queue, and saying so
/// beats rendering an empty table that looks like "no one is waiting".
#[test]
fn security_omits_the_csr_queue_on_a_non_provider() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(!html.contains("Approve"), "no approvals offered: {html}");
}

/// On a provider, each pending request shows the key being vouched for.
#[test]
fn security_lists_pending_requests_on_a_provider() {
    let mut snap = seeded_snapshot();
    snap.pending_csrs = Some(ListPendingCsrsResponse {
        pending: vec![PendingCsr {
            node_mac: vec![0, 0, 0, 0, 0, 9],
            ed_pubkey: vec![0xab; 32],
            x_pubkey: vec![0xcd; 32],
            requested_at: 1_700_000_000,
        }],
    });
    let html = render_with(Some(snap), || view! { <Security /> });

    assert!(html.contains("00:00:00:00:00:09"), "the applicant: {html}");
    assert!(html.contains("Approve"), "approval offered: {html}");
    assert!(html.contains("Deny"), "denial offered: {html}");
    // The key is what an operator is actually vouching for, so it has to be
    // visible before they can approve it.
    assert!(
        html.contains("abababab"),
        "the key being vouched for: {html}"
    );
}

// --------------------------------------------------------------------- Logs --

/// Records render newest-last with their level and source.
#[test]
fn logs_render_records_with_level_and_target() {
    let mut history = History::default();
    history.ingest_logs(LogRecords {
        records: vec![LogRecord {
            seq: 1,
            uptime_ms: 12_345,
            level: LogLevel::Warn as i32,
            target: "wayfinder::router".into(),
            message: "drop: no route".into(),
        }],
        next_seq: 2,
        dropped: 0,
        filter: "info,batman=trace".into(),
    });

    let html = render_with_history(seeded_snapshot(), history, || view! { <Logs /> });

    assert!(html.contains("WARN"), "the level: {html}");
    assert!(html.contains("wayfinder::router"), "the source: {html}");
    assert!(html.contains("drop: no route"), "the message: {html}");
    assert!(html.contains("wf-level-warn"), "coloured by level: {html}");
}

/// Newest records come first, so the interesting end of a live stream is where
/// the reader is already looking and no scroll position has to be managed.
#[test]
fn logs_render_newest_first() {
    let mut history = History::default();
    history.ingest_logs(LogRecords {
        records: vec![
            LogRecord {
                seq: 1,
                uptime_ms: 1,
                level: LogLevel::Info as i32,
                target: "a".into(),
                message: "older".into(),
            },
            LogRecord {
                seq: 2,
                uptime_ms: 2,
                level: LogLevel::Info as i32,
                target: "a".into(),
                message: "newer".into(),
            },
        ],
        next_seq: 3,
        dropped: 0,
        filter: "info".into(),
    });

    let html = render_with_history(seeded_snapshot(), history, || view! { <Logs /> });

    let newer = html.find("newer").expect("the newer record");
    let older = html.find("older").expect("the older record");
    assert!(newer < older, "the newest record is at the top");
}

/// A gap renders in stream position, so a discontinuity is visible rather than
/// something a reader has to infer from jumping sequence numbers.
#[test]
fn logs_render_a_gap_between_the_records_it_separates() {
    let mut history = History::default();
    history.ingest_logs(LogRecords {
        records: vec![LogRecord {
            seq: 1,
            uptime_ms: 1,
            level: LogLevel::Info as i32,
            target: "a".into(),
            message: "first".into(),
        }],
        next_seq: 2,
        dropped: 0,
        filter: "info".into(),
    });
    history.ingest_logs(LogRecords {
        records: vec![LogRecord {
            seq: 40,
            uptime_ms: 2,
            level: LogLevel::Info as i32,
            target: "a".into(),
            message: "second".into(),
        }],
        next_seq: 41,
        dropped: 38,
        filter: "info".into(),
    });

    let html = render_with_history(seeded_snapshot(), history, || view! { <Logs /> });

    assert!(html.contains("38"), "the dropped count: {html}");
    // Newest-first, so the later record precedes the gap and the earlier one
    // follows it — the gap still separates exactly the two records it fell
    // between, which is the property that matters.
    let gap = html.find("wf-log-gap").expect("a gap marker was rendered");
    let first = html.find("first").expect("the earlier record");
    let second = html.find("second").expect("the later record");
    assert!(second < gap && gap < first, "the gap sits between them");
}

/// The filter line reports what the node says is in force, which is not
/// necessarily what this client last asked for.
#[test]
fn logs_show_the_filter_the_node_reports() {
    let mut history = History::default();
    history.ingest_logs(LogRecords {
        records: Vec::new(),
        next_seq: 1,
        dropped: 0,
        filter: "info,batman=trace".into(),
    });

    let html = render_with_history(seeded_snapshot(), history, || view! { <Logs /> });

    assert!(html.contains("info,batman=trace"), "{html}");
}

/// The posture switches render against the node's reported state, so an
/// operator sees what is actually in force before touching anything.
#[test]
fn security_renders_the_posture_switches_from_the_node() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(
        html.contains("Refuse to run unauthenticated"),
        "the fail-closed switch: {html}"
    );
    assert!(
        html.contains("Send certificate fingerprints"),
        "the lazy-cert switch: {html}"
    );
    // The seed has require_auth on and lazy cert distribution off, so exactly
    // one of the two switches must read as on. A component that ignored the
    // snapshot and defaulted both the same way would pass a mere presence check.
    assert_eq!(
        html.matches(r#"aria-checked="true""#).count(),
        1,
        "require_auth is on and lazy cert distribution is off: {html}"
    );
}

/// Neither posture switch acts on click — both stage a confirmation first,
/// because either can take this node off the mesh.
#[test]
fn security_settings_are_not_one_click_from_leaving_the_mesh() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(!html.contains("wf-modal"), "nothing armed yet: {html}");
}

/// A provider's enrollment policy is shown in the units an operator set it in,
/// and reports whether a token is required without ever showing the token.
#[test]
fn security_renders_the_enrollment_policy_on_a_provider() {
    let html = render_with(Some(provider_snapshot()), || view! { <Security /> });

    assert!(html.contains("How nodes join"), "the policy panel: {html}");
    assert!(
        html.contains("Approve each request by hand"),
        "the approval switch: {html}"
    );
    assert!(
        html.contains("1 day"),
        "the 86400s lifetime reads as a day: {html}"
    );
    assert!(
        html.contains("Remove token"),
        "clearing a set token is offered: {html}"
    );
}

/// With authentication off, the tab says so in words and renders none of the
/// identity fields — every one of which would be empty or zero.
///
/// The state with the least data on the screen, and the one the other cases
/// never reach: a node with no `OgmAuth` reports an empty MAC, a zero mesh id
/// and no per-node rows, so anything that reads them has nothing to read.
#[test]
fn security_says_plainly_when_the_mesh_is_unauthenticated() {
    let mut snap = seeded_snapshot();
    snap.security = Some(GetSecurityStatusResponse {
        auth_enabled: false,
        require_auth: false,
        ..Default::default()
    });
    let html = render_with(Some(snap), || view! { <Security /> });

    assert!(
        html.contains("Disabled"),
        "authentication reads off: {html}"
    );
    assert!(
        html.contains("does not authenticate its members"),
        "and what that means is spelled out: {html}"
    );
    assert!(
        !html.contains("Mesh id"),
        "no identity fields, which would all be empty: {html}"
    );
    assert!(
        html.contains("No other nodes known yet"),
        "the node table says why it is empty: {html}"
    );
}

/// The posture switches are still offered with authentication off — and
/// `require_auth` most of all, since turning it on is exactly what takes such a
/// node off the mesh, and hiding the control would hide the reason.
#[test]
fn security_still_offers_the_posture_switches_when_unauthenticated() {
    let mut snap = seeded_snapshot();
    snap.security = Some(GetSecurityStatusResponse {
        auth_enabled: false,
        require_auth: false,
        ..Default::default()
    });
    let html = render_with(Some(snap), || view! { <Security /> });

    assert!(
        html.contains("Refuse to run unauthenticated"),
        "the fail-closed switch: {html}"
    );
    assert_eq!(
        html.matches(r#"aria-checked="true""#).count(),
        0,
        "both switches read off, as the node reports them: {html}"
    );
}

/// An un-enrolled node is offered the one thing that would change its
/// situation: asking a provider to certify it. This is the counterpart to the
/// provider's "Requests to join" panel, and on a node with no certificate it is
/// the only control on the tab that can give it one.
#[test]
fn security_offers_an_unauthenticated_node_a_mesh_to_join() {
    let mut snap = seeded_snapshot();
    snap.security = Some(GetSecurityStatusResponse {
        auth_enabled: false,
        require_auth: false,
        ..Default::default()
    });
    let html = render_with(Some(snap), || view! { <Security /> });

    assert!(html.contains("Join a mesh"), "the panel: {html}");
    assert!(
        html.contains("Provider address") && html.contains("Provider key"),
        "where the provider is, and what pins it: {html}"
    );
    assert!(
        html.contains("keeps the identity and address it already has"),
        "and says the node is not being replaced: {html}"
    );
    // Nothing has been asked yet, so no status is claimed.
    assert!(!html.contains("Waiting for an operator"), "idle: {html}");
}

/// On a node that already holds a certificate the same panel is about *moving*
/// mesh, and says so — asking a new provider replaces the membership it has,
/// which is a different act from acquiring a first one.
#[test]
fn security_frames_joining_as_a_move_for_an_enrolled_node() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(html.contains("Move to another mesh"), "the panel: {html}");
    assert!(
        !html.contains("Join a mesh"),
        "not framed as joining from nothing: {html}"
    );
    // Leaving a mesh is behind the same confirmation as everything else that
    // cannot be casually walked back.
    assert!(!html.contains("wf-modal"), "nothing armed yet: {html}");
}

/// A plain member has no enrollment policy at all, and the panel is omitted
/// rather than rendered with defaults — "nothing to change here" and "a policy
/// that happens to be all zeros" are different claims.
#[test]
fn security_omits_the_enrollment_policy_on_a_non_provider() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(!html.contains("How nodes join"), "no policy panel: {html}");
}

/// A provider shows what a joining node has to be told: where it is, the key
/// that pins it, and the token it will be asked for. This is the other end of
/// the "Join a mesh" panel, and the values have to be copyable because two of
/// the three are not readable back off the screen.
#[test]
fn security_offers_a_provider_the_details_a_joining_node_needs() {
    let html = render_with(Some(provider_snapshot()), || view! { <Security /> });

    assert!(
        html.contains("What a node needs to join"),
        "the panel: {html}"
    );
    assert!(
        html.contains("Provider address") && html.contains("Provider key"),
        "the two non-secret values: {html}"
    );
    // The two values that ride the poll each offer a copy button, since neither
    // can be retyped reliably — the key least of all. The token has none yet:
    // it is not in the snapshot at all until an operator asks for it.
    assert_eq!(
        html.matches("wf-copy-button").count(),
        2,
        "address and key are copyable: {html}"
    );
    assert!(
        html.contains("Show token"),
        "and the token is fetched on request: {html}"
    );
    // The address comes from the connection, not from the snapshot.
    assert!(
        html.contains("127.0.0.1:7700"),
        "the address this dashboard reaches the node at: {html}"
    );
}

/// The rendered page carries no enrollment token, because the snapshot it is
/// rendered from carries none.
///
/// This test used to assert that a token the snapshot *did* carry was masked in
/// the markup — true, and a weaker property than its name claimed: the value
/// still crossed the wire on every poll and sat in the browser's memory. The
/// polled status now reports only that a token is required, and the value comes
/// back from `reveal_enrollment_token` when an operator asks. What is asserted
/// here is therefore the absence, not the masking.
#[test]
fn security_renders_no_enrollment_token_because_the_poll_carries_none() {
    let html = render_with(Some(provider_snapshot()), || view! { <Security /> });

    assert!(
        !html.contains(PROVIDER_TOKEN),
        "no token value in the markup: {html}"
    );
    assert!(
        html.contains("Show token"),
        "the row offers to fetch it instead: {html}"
    );
}

/// The provider's own key is shown abbreviated — enough to tell two providers
/// apart, not enough to retype — while the copy button carries all 64
/// characters, which is what the far end actually parses.
#[test]
fn security_abbreviates_the_provider_key_it_shows() {
    let html = render_with(Some(provider_snapshot()), || view! { <Security /> });

    // The seed's own key is 32 bytes of 0x11.
    assert!(
        html.contains("11111111…"),
        "abbreviated for recognition: {html}"
    );
    assert!(
        !html.contains(&"11".repeat(32)),
        "the full key is not drawn on screen: {html}"
    );
}

/// A plain member is offered none of it: it issues no certificates, so there is
/// no key to pin *it* by and no token to hand out.
#[test]
fn security_omits_the_join_details_on_a_non_provider() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(
        !html.contains("What a node needs to join"),
        "no join details on a plain member: {html}"
    );
    assert!(!html.contains("wf-copy-button"), "nothing to copy: {html}");
}

/// With no token required the row says so rather than offering a copy button
/// for an empty string — "copy the token" on a mesh with no token is an
/// instruction that cannot be followed.
#[test]
fn security_says_when_there_is_no_token_to_hand_over() {
    let mut snap = provider_snapshot();
    if let Some(policy) = snap.security.as_mut().and_then(|s| s.enrollment.as_mut()) {
        policy.enrollment_token_set = false;
    }
    let html = render_with(Some(snap), || view! { <Security /> });

    assert!(
        html.contains("Not required"),
        "the token row states there is none: {html}"
    );
    assert!(
        !html.contains("Show token"),
        "and offers nothing to fetch: {html}"
    );
    assert_eq!(
        html.matches("wf-copy-button").count(),
        2,
        "only the address and the key are copyable: {html}"
    );
}

/// A required token that has not been fetched must never read as "no token
/// required".
///
/// The two are opposite claims about whether the mesh is gated, and only one of
/// them stops an operator looking for the token they need. Nothing about the
/// value's absence from the snapshot says the mesh is open — the flag says
/// that, and the flag is what the panel branches on. Inferring from emptiness
/// is a bug this once had.
#[test]
fn security_does_not_read_an_unfetched_token_as_an_open_mesh() {
    let html = render_with(Some(provider_snapshot()), || view! { <Security /> });

    assert!(
        !html.contains("Not required"),
        "a gated mesh must not be described as open: {html}"
    );
    assert!(
        html.contains("Show token"),
        "it offers to fetch the value instead: {html}"
    );
    assert_eq!(
        html.matches("wf-copy-button").count(),
        2,
        "nothing to copy for a value that has not been asked for: {html}"
    );
}

/// With no token set, the panel says enrollment is open and offers no "remove
/// token" button — there is nothing to remove, and offering it would imply
/// the mesh is gated when it is not.
#[test]
fn security_says_so_when_enrollment_is_open() {
    let mut snap = provider_snapshot();
    if let Some(policy) = snap.security.as_mut().and_then(|s| s.enrollment.as_mut()) {
        policy.enrollment_token_set = false;
    }
    let html = render_with(Some(snap), || view! { <Security /> });

    assert!(
        html.contains("anyone in range may join"),
        "open enrollment is stated plainly: {html}"
    );
    assert!(!html.contains("Remove token"), "nothing to remove: {html}");
}
