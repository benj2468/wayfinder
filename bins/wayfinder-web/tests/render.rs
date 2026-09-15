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
use wayfinder_protos::wayfinder::v1alpha::ListVpnPeersResponse;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;
use wayfinder_protos::wayfinder::v1alpha::LogRecord;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NeighborPath;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder::v1alpha::NodeSecurity;
use wayfinder_protos::wayfinder::v1alpha::OgmScheduleEntry;
use wayfinder_protos::wayfinder::v1alpha::PendingCsr;
use wayfinder_protos::wayfinder::v1alpha::RenewalProviderStatus;
use wayfinder_protos::wayfinder::v1alpha::RoutingEntry;
use wayfinder_protos::wayfinder::v1alpha::TableOccupancy;
use wayfinder_protos::wayfinder::v1alpha::UserAccount;
use wayfinder_protos::wayfinder::v1alpha::VpnPeerStatus;
use wayfinder_web::components::dashboard::Dashboard;
use wayfinder_web::components::link_quality::LinkQuality;
use wayfinder_web::components::links::Links;
use wayfinder_web::components::logs::Logs;
use wayfinder_web::components::metrics::Metrics;
use wayfinder_web::components::overview::Overview;
use wayfinder_web::components::provider::accounts::Accounts;
use wayfinder_web::components::provider::accounts::UserTable;
use wayfinder_web::components::provider::enrollment::Enrollment;
use wayfinder_web::components::provider::members::Members;
use wayfinder_web::components::provider::requests::Requests;
use wayfinder_web::components::provider::vpn::Vpn;
use wayfinder_web::components::register::TotpEnrolment;
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
            clock_trusted: true,
            clock_posture: wayfinder_protos::wayfinder::v1alpha::ClockPosture::At as i32,
            build_info: Some(wayfinder_protos::wayfinder::v1alpha::BuildInfo {
                version: "v0.4.0-12-g35dcaee".to_string(),
                commit: "35dcaee".to_string(),
                dirty: false,
                source: wayfinder_protos::wayfinder::v1alpha::BuildSource::Git as i32,
            }),
        }),
        // Explicit, because `Default` gives `logs: None` — which now means "a
        // read-only poll withheld the ring", not "an empty batch". A fixture
        // standing in for an administrator's poll has to say which it is.
        logs: Some(Default::default()),
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
            proven: true,
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
        // A healthy certificate: the Security tab renders the expiry plainly
        // rather than the renewal-due wording.
        cert_due_renewal: false,
        revocation_count: 1,
        self_revoked: false,
        self_revocation_not_after: 0,
        // Enrolled online, so the node knows where it renews and the Security
        // tab has a target to render rather than the by-hand wording.
        renewal_provider: Some(RenewalProviderStatus {
            address: "ca.example:7700".into(),
            node_key: vec![9u8; 32],
        }),
        // A node that renews over its management API, not over the mesh: both
        // zero, and so the mesh-renewal row is not rendered at all.
        renewal_requests_sent: 0,
        renewal_replies_accepted: 0,
        nodes: vec![
            NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 2],
                verified: true,
                cert_not_after: 1_800_000_000,
                revoked: false,
                revocation_not_after: 0,
            },
            NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 3],
                verified: false,
                cert_not_after: 0,
                revoked: true,
                revocation_not_after: 0,
            },
            NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 4],
                verified: false,
                cert_not_after: 0,
                revoked: false,
                revocation_not_after: 0,
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

/// Install an async executor for the reactive runtime, once per test process.
///
/// A tab holding a `Resource` — the Provider tab does, for the account roster —
/// spawns its fetcher as soon as it renders, *including* when all that renders
/// is the suspense fallback. Outside a server there is no executor installed,
/// and the spawn panics rather than failing quietly. A second call is an error
/// and is ignored, which is what makes this callable from every test.
fn install_executor() {
    // The futures executor rather than tokio's: these are plain `#[test]`s with
    // no runtime around them, and tokio's spawner panics without a reactor.
    let _ = any_spawner::Executor::init_futures_executor();
}

/// Render a tab with a dashboard holding `snapshot` and `history`, as a viewer
/// who either may or may not change the node.
///
/// The capability is a parameter because half of what these tests assert is
/// what a *read-only* account is not offered, and that is a property of the
/// markup rather than of anything the node answers — the node refuses the call
/// too, but a button that only fails when pressed is a promise the dashboard
/// should never have made.
fn render_seeded<V: IntoView + 'static>(
    snapshot: Option<NodeSnapshot>,
    history: Option<History>,
    admin: bool,
    tab: impl Fn() -> V + Send + 'static,
) -> String {
    install_executor();
    let owner = Owner::new();
    owner
        .with(|| {
            let dash = Dashboard::new();
            if let Some(snapshot) = snapshot {
                dash.connected.set(true);
                dash.snapshot.set(Some(snapshot));
            }
            if let Some(history) = history {
                dash.history.set(history);
            }
            dash.label.set("127.0.0.1:7700".to_string());
            // Deliberately not the label. The two are different questions —
            // where this process dials the node, and where a joining device
            // has to reach the authority — and a fixture where they agree
            // could not tell a panel reading the wrong one apart.
            dash.provider_address
                .set(Some("ca.example:7700".to_string()));
            dash.admin.set(admin);
            provide_context(dash);
            tab().to_html()
        })
        .to_string()
}

/// Render a tab with both a snapshot and an accumulated history, as an
/// administrator.
fn render_with_history<V: IntoView + 'static>(
    snapshot: NodeSnapshot,
    history: History,
    tab: impl Fn() -> V + Send + 'static,
) -> String {
    render_seeded(Some(snapshot), Some(history), true, tab)
}

/// Render one tab with a dashboard holding `snapshot`, as an administrator —
/// the viewer every panel here is written for.
fn render_with<V: IntoView + 'static>(
    snapshot: Option<NodeSnapshot>,
    tab: impl Fn() -> V + Send + 'static,
) -> String {
    render_seeded(snapshot, None, true, tab)
}

/// Render one tab as a **read-only** account: signed in, allowed to look at
/// everything the node will answer, and allowed to change nothing.
fn render_as_viewer<V: IntoView + 'static>(
    snapshot: Option<NodeSnapshot>,
    tab: impl Fn() -> V + Send + 'static,
) -> String {
    render_seeded(snapshot, None, false, tab)
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

/// The node roster on this tab reports and does not act.
///
/// Revoking a node is a decision the certificate authority makes about somebody
/// else's membership, so it moved to the provider scope with the rest of them.
/// What is left here is this node's own view of who it can verify — a router
/// fact, and one every viewer of the mesh has a reason to read.
#[test]
fn security_reports_the_nodes_it_knows_without_acting_on_them() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(html.contains("00:00:00:00:00:02"), "the roster: {html}");
    assert!(
        !html.contains(">Revoke</button>"),
        "and no revocation from the router scope: {html}"
    );
}

/// Destructive settings are offered, but only behind a confirmation.
#[test]
fn security_puts_destructive_actions_behind_a_confirmation() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(
        html.contains("Refuse to run unauthenticated"),
        "a switch that can take this node off the mesh: {html}"
    );
    // The dialog is only rendered once armed, so nothing is one click from
    // taking the node off the mesh.
    assert!(!html.contains("wf-modal"), "not armed yet: {html}");
}

// ----------------------------------------------------------------- Provider --

/// Render one snapshot through every tab in the provider scope, labelled.
///
/// The gate each of these tabs sits behind is the same gate, and a tab that
/// forgot to ask is invisible in a test that only renders the tab it was added
/// beside. Driving all five from one list is what makes a new provider tab
/// covered by the two tests below on the day it is added.
fn each_provider_tab(snapshot: NodeSnapshot, admin: bool) -> Vec<(&'static str, String)> {
    vec![
        (
            "Requests",
            render_seeded(Some(snapshot.clone()), None, admin, || {
                view! { <Requests /> }
            }),
        ),
        (
            "Members",
            render_seeded(Some(snapshot.clone()), None, admin, || {
                view! { <Members /> }
            }),
        ),
        (
            "Enrollment",
            render_seeded(Some(snapshot.clone()), None, admin, || {
                view! { <Enrollment /> }
            }),
        ),
        (
            "Accounts",
            render_seeded(Some(snapshot.clone()), None, admin, || {
                view! { <Accounts /> }
            }),
        ),
        (
            "VPN",
            render_seeded(Some(snapshot), None, admin, || {
                view! { <Vpn /> }
            }),
        ),
    ]
}

/// The provider scope belongs to administrators, whole and entire.
///
/// The tab bar does not offer it to a read-only account, but a link can be
/// pasted and a bookmark can outlive a demotion — so the refusal is in the
/// page, not only in the navigation. It is stated rather than rendered as an
/// empty panel: the node refuses every call these tabs make, so "nothing here"
/// and "not yours to see" would otherwise look identical.
#[test]
fn every_provider_tab_refuses_a_read_only_viewer() {
    for (tab, html) in each_provider_tab(provider_snapshot(), false) {
        assert!(
            html.contains("Only an administrator"),
            "{tab} says who this is for: {html}"
        );
        assert!(
            !html.contains("wf-button-danger"),
            "{tab} offers nothing destructive: {html}"
        );
    }
}

/// Most nodes are not certificate authorities, and every tab in the scope says
/// so in one sentence rather than rendering an empty panel each.
#[test]
fn every_provider_tab_says_when_the_node_is_not_a_certificate_authority() {
    for (tab, html) in each_provider_tab(seeded_snapshot(), true) {
        assert!(
            html.contains("not a certificate authority"),
            "{tab} says why it is empty: {html}"
        );
    }
}

/// Each pending request shows the key being vouched for, because that is what
/// approving it endorses.
#[test]
fn provider_requests_lists_what_is_waiting() {
    let mut snap = provider_snapshot();
    snap.pending_csrs = Some(ListPendingCsrsResponse {
        pending: vec![PendingCsr {
            node_mac: vec![0, 0, 0, 0, 0, 9],
            ed_pubkey: vec![0xab; 32],
            x_pubkey: vec![0xcd; 32],
            requested_at: 1_700_000_000,
        }],
    });
    let html = render_with(Some(snap), || view! { <Requests /> });

    assert!(html.contains("00:00:00:00:00:09"), "the applicant: {html}");
    assert!(html.contains("Approve"), "approval offered: {html}");
    assert!(html.contains("Deny"), "denial offered: {html}");
    assert!(
        html.contains("abababab"),
        "the key being vouched for: {html}"
    );
    assert!(!html.contains("wf-modal"), "nothing armed yet: {html}");
}

/// A waiting request carries its own lifetime chooser: how long a device stays
/// a member is decided when it is admitted, not by whatever the policy happened
/// to say that week.
///
/// The default option names the policy value rather than saying "default", so
/// an operator who just takes it still knows what they took.
#[test]
fn provider_requests_offers_a_certificate_lifetime() {
    let mut snap = provider_snapshot();
    snap.pending_csrs = Some(ListPendingCsrsResponse {
        pending: vec![PendingCsr {
            node_mac: vec![0, 0, 0, 0, 0, 9],
            ed_pubkey: vec![0xab; 32],
            x_pubkey: vec![0xcd; 32],
            requested_at: 1_700_000_000,
        }],
    });
    let html = render_with(Some(snap), || view! { <Requests /> });

    assert!(
        html.contains("Valid for"),
        "the lifetime is labelled: {html}"
    );
    assert!(
        html.contains("This mesh's default (1 day)"),
        "the default names the policy value: {html}"
    );
    for preset in ["1 month", "3 months", "1 year", "10 years"] {
        assert!(html.contains(preset), "the {preset} preset: {html}");
    }
    assert!(
        html.contains("Until a date"),
        "a date can be picked instead of a preset: {html}"
    );
}

/// An empty queue says nobody is waiting, which is not the same claim as a
/// node that has no queue at all.
#[test]
fn provider_requests_says_when_nobody_is_waiting() {
    let html = render_with(Some(provider_snapshot()), || view! { <Requests /> });

    assert!(
        html.contains("No nodes are waiting to join"),
        "the empty queue: {html}"
    );
    assert!(!html.contains("Approve"), "nothing to approve: {html}");
}

/// Revoking a node is the certificate authority's call, so the control is in
/// the provider scope — and it names each node's state, since revoking one
/// that is already revoked is a wasted flood.
#[test]
fn provider_members_offers_a_revocation() {
    let html = render_with(Some(provider_snapshot()), || view! { <Members /> });

    assert!(html.contains("00:00:00:00:00:02"), "a member: {html}");
    assert!(html.contains(">Revoke</button>"), "the control: {html}");
    // The seed has one verified node, one revoked and one unverified; only the
    // two that are still members can be revoked.
    assert_eq!(
        html.matches(">Revoke</button>").count(),
        2,
        "the already-revoked node is not offered again: {html}"
    );
}

/// A revoked node must not read as merely unverified — one is a node whose
/// identity could not be established, the other one the mesh has ejected.
#[test]
fn provider_members_distinguishes_revoked_from_unverified() {
    let html = render_with(Some(provider_snapshot()), || view! { <Members /> });

    assert!(html.contains("Revoked"), "the revoked node: {html}");
    assert!(html.contains("Unverified"), "the unverified node: {html}");
    assert!(html.contains("Verified"), "the verified node: {html}");
}

/// A revocation floods the mesh and re-approving does not undo it, so nothing
/// here is one click from ejecting a node.
#[test]
fn provider_members_puts_a_revocation_behind_a_confirmation() {
    let html = render_with(Some(provider_snapshot()), || view! { <Members /> });

    assert!(!html.contains("wf-modal"), "not armed yet: {html}");
}

/// The enrollment policy is shown in the units an operator set it in, and
/// reports whether a token is required without ever drawing the token.
#[test]
fn provider_enrollment_renders_the_policy() {
    let html = render_with(Some(provider_snapshot()), || view! { <Enrollment /> });

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

/// The Security tab shows what a joining node has to be told: where the
/// authority is, the key that pins it, and the token it will be asked for.
///
/// It sits beside "Join a mesh" rather than on the administrators-only
/// Enrollment tab, because the two are the same handover seen from each end and
/// the person carrying a device to a mesh is not necessarily the person who
/// governs it. The values have to be copyable: two of the three are not
/// readable back off the screen.
#[test]
fn security_offers_the_details_a_joining_node_needs() {
    let html = render_with(Some(provider_snapshot()), || view! { <Security /> });

    assert!(
        html.contains("What a node needs to join"),
        "the panel: {html}"
    );
    assert!(
        html.contains("Provider address") && html.contains("Provider key"),
        "the two non-secret values: {html}"
    );
    assert_eq!(
        html.matches("wf-copy-button").count(),
        2,
        "address and key are copyable: {html}"
    );
    // Abbreviated on screen, and the whole key only on the clipboard. The
    // fixture's key is 32 bytes of 0x11, and both renderings are formatted from
    // those same bytes — `JoinDetails` takes the key as bytes precisely so the
    // abbreviation cannot come to describe a different key from the copy.
    assert!(
        html.contains("11111111…"),
        "the key is abbreviated on screen: {html}"
    );
    assert!(
        !html.contains(&"11".repeat(32)),
        "and the full 64 characters are not in the markup — the copy button \
         carries them, so they are never on screen or in a screenshot: {html}"
    );
    assert!(
        html.contains("Show token"),
        "and the token is fetched on request: {html}"
    );
}

/// A read-only account can read the address and the key, and cannot read the
/// token.
///
/// The whole point of moving this panel: enrolling a device needs the address
/// and the key, neither of which is a secret, and needing an administrator to
/// read out 64 characters of hex is what the issue behind this was. The token
/// is the one value that stays behind the capability check, and the *fact* that
/// one is required stays visible — it is what explains a device in range that
/// has not joined.
#[test]
fn security_shows_a_read_only_viewer_the_address_and_key_but_not_the_token() {
    let html = render_as_viewer(Some(provider_snapshot()), || view! { <Security /> });

    assert!(
        html.contains("Provider address") && html.contains("Provider key"),
        "both non-secret values are readable: {html}"
    );
    assert_eq!(
        html.matches("wf-copy-button").count(),
        2,
        "and both are copyable: {html}"
    );
    assert!(
        html.contains("an administrator can show it"),
        "the token is required, and says who can produce it: {html}"
    );
    assert!(
        !html.contains("Show token"),
        "but a read-only session is not offered the reveal the node would \
         refuse anyway: {html}"
    );
}

/// The address shown is the one a *joining node* has to reach, not the one this
/// dashboard dials.
///
/// They differ on every deployment where the dashboard and the node share a
/// host: the dashboard reaches it over loopback, and `127.0.0.1:7700` handed to
/// somebody enrolling a device points them at their own machine.
#[test]
fn security_shows_the_advertised_provider_address_not_the_dialled_one() {
    let html = render_with(Some(provider_snapshot()), || view! { <Security /> });

    assert!(
        html.contains("ca.example:7700"),
        "the address a device is told to use: {html}"
    );
    assert!(
        !html.contains("127.0.0.1:7700"),
        "and not the loopback address this process dials: {html}"
    );
}

/// A node that issues no certificates has no join details to give, and an
/// address-and-key panel on one would be describing a mesh it cannot admit
/// anybody to.
#[test]
fn security_omits_the_join_details_on_a_node_that_is_not_an_authority() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(
        !html.contains("What a node needs to join"),
        "no panel on a plain member: {html}"
    );
}

/// The Enrollment tab keeps the policy and hands the join details off, rather
/// than carrying a second copy of them.
///
/// Two tabs showing the same panel is two places to keep in step and a reader
/// wondering which one is authoritative. The pointer stays, because an
/// administrator setting a token is exactly who then goes looking for it.
#[test]
fn provider_enrollment_points_at_the_join_details_rather_than_repeating_them() {
    let html = render_with(Some(provider_snapshot()), || view! { <Enrollment /> });

    assert!(
        !html.contains("Provider key"),
        "the values are not duplicated here: {html}"
    );
    assert!(
        html.contains("Security tab"),
        "and the reader is told where they are: {html}"
    );
}

/// The rendered page carries no enrollment token, because the snapshot it is
/// rendered from carries none — the polled status reports only that one is
/// required, and the value comes back from `reveal_enrollment_token`.
#[test]
fn security_renders_no_token_because_the_poll_carries_none() {
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

/// With no token required the row says so rather than offering a copy button
/// for an empty string.
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
/// them stops an operator looking for the token they need. Inferring the mesh
/// is open from the value's absence is a bug this once had.
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

/// With no token set, the tab says enrollment is open and offers no "remove
/// token" button — there is nothing to remove, and offering it would imply the
/// mesh is gated when it is not.
#[test]
fn provider_enrollment_says_so_when_enrollment_is_open() {
    let mut snap = provider_snapshot();
    if let Some(policy) = snap.security.as_mut().and_then(|s| s.enrollment.as_mut()) {
        policy.enrollment_token_set = false;
    }
    let html = render_with(Some(snap), || view! { <Enrollment /> });

    assert!(
        html.contains("anyone in range may join"),
        "open enrollment is stated plainly: {html}"
    );
    assert!(!html.contains("Remove token"), "nothing to remove: {html}");
}

/// The accounts tab carries the roster and the form that adds to it, and says
/// plainly that the first account is not created here.
#[test]
fn provider_accounts_offers_the_roster_and_the_form_beneath_it() {
    let html = render_with(Some(provider_snapshot()), || view! { <Accounts /> });

    assert!(html.contains("Accounts"), "the panel: {html}");
    assert!(html.contains("New account"), "the create form: {html}");
    assert!(
        html.contains("Administrator — may change anything"),
        "and the capability it grants: {html}"
    );
}

/// The roster offers both account controls, and the hint that tells them apart.
///
/// Two buttons whose names cannot carry the difference between them, where
/// pressing the wrong one costs somebody their account — so what is asserted is
/// not only that both exist but that the explanation ships with them.
#[test]
fn provider_accounts_offers_revoke_and_remove_and_explains_the_difference() {
    let account = UserAccount {
        username: "watcher".into(),
        admin: false,
        session_ttl_secs: 900,
        totp_enrolled: true,
        disabled: false,
        locked: false,
    };
    let html = render_with(Some(provider_snapshot()), move || {
        view! {
            <UserTable
                users=vec![account.clone()]
                on_revoke=Callback::new(|_| {})
                on_remove=Callback::new(|_| {})
            />
        }
    });

    assert!(html.contains(">Revoke<"), "the revoke control: {html}");
    assert!(html.contains(">Remove<"), "and the remove control: {html}");
    assert!(
        html.contains("aria-label=\"Revoke watcher's sessions\""),
        "each control names the account it acts on, for a reader who cannot see \
         which row the button is in: {html}"
    );
    assert!(
        html.contains("What does Revoke do?"),
        "the explanation is reachable by name rather than only by hovering a \
         mouse, which is the whole reason it is not a title= tooltip: {html}"
    );
    assert!(
        html.contains("deletes the account"),
        "and it says what Remove does that Revoke does not: {html}"
    );
    assert!(
        html.contains("popover=\"auto\"") && html.contains("popovertarget="),
        "the explanation is a popover, so the browser renders it in the top layer \
         rather than inside the scroll container that would clip it: {html}"
    );
    assert!(
        html.contains("anchor-name: --wf-hint-account-actions")
            && html.contains("position-anchor: --wf-hint-account-actions"),
        "and its anchor is derived from the hint's own id, so a second hint on \
         the page would not steal its placement: {html}"
    );
}

/// Registered tunnel peers are listed with the address the coordination server
/// gave them, which is what a UDP mesh link on that host points at.
#[test]
fn provider_vpn_lists_registered_peers() {
    let mut snap = provider_snapshot();
    snap.vpn_peers = Some(ListVpnPeersResponse {
        peers: vec![VpnPeerStatus {
            node_mac: vec![0, 0, 0, 0, 0, 2],
            raw_hostname: "000000000002".into(),
            tailscale_ip: "100.64.0.7".into(),
            online: true,
            last_seen_unix: 1_700_000_000,
            key_expiry_unix: 0,
        }],
    });
    let html = render_with(Some(snap), || view! { <Vpn /> });

    assert!(html.contains("00:00:00:00:00:02"), "the peer: {html}");
    assert!(html.contains("100.64.0.7"), "its tunnel address: {html}");
    assert!(
        html.contains("online"),
        "and whether it is connected: {html}"
    );
}

/// A provider that coordinates a tunnel nobody has joined says so, rather than
/// rendering the same blank table as a provider with no tunnel at all.
#[test]
fn provider_vpn_says_when_no_peer_has_joined() {
    let mut snap = provider_snapshot();
    snap.vpn_peers = Some(ListVpnPeersResponse { peers: Vec::new() });
    let html = render_with(Some(snap), || view! { <Vpn /> });

    assert!(
        html.contains("No nodes have joined the tunnel yet"),
        "the empty state says why: {html}"
    );
}

/// A provider with no tunnel configured is a different state again, and must
/// not read as one whose peers have all left.
#[test]
fn provider_vpn_distinguishes_no_tunnel_from_an_empty_one() {
    let html = render_with(Some(provider_snapshot()), || view! { <Vpn /> });

    assert!(
        html.contains("does not coordinate a tunnel"),
        "no tunnel is configured: {html}"
    );
    assert!(
        !html.contains("No nodes have joined the tunnel yet"),
        "which is not the same as an empty one: {html}"
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

// ------------------------------------------------------- Read-only viewers --

/// A read-only account sees what this node's security posture *is*, and is
/// offered nothing that would change it.
///
/// The settings are deliberately shown rather than hidden: "is this node
/// refusing to run unauthenticated?" is exactly the question a read-only
/// account is signed in to answer. What goes is the ability to act — the
/// switches are inert, and the panel that would move this node to another mesh
/// is gone.
#[test]
fn security_shows_a_read_only_viewer_the_posture_it_cannot_change() {
    let html = render_as_viewer(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(
        html.contains("Security settings") && html.contains("Refuse to run unauthenticated"),
        "the settings are readable: {html}"
    );
    assert_eq!(
        html.matches(r#"aria-checked="true""#).count(),
        1,
        "and still report the node's own state: {html}"
    );
    assert_eq!(
        html.matches("disabled").count(),
        2,
        "both switches are inert: {html}"
    );

    assert!(
        !html.contains("Move to another mesh"),
        "no leaving the mesh: {html}"
    );
    assert!(
        html.contains("Mesh authentication"),
        "everything that only reports is untouched: {html}"
    );
}

/// The same holds for a node with no certificate: a read-only account is not
/// the one that gets to go and find it a mesh.
#[test]
fn security_does_not_offer_a_read_only_viewer_a_mesh_to_join() {
    let mut snap = seeded_snapshot();
    if let Some(sec) = snap.security.as_mut() {
        sec.auth_enabled = false;
    }
    let html = render_as_viewer(Some(snap), || view! { <Security /> });

    assert!(!html.contains("Join a mesh"), "{html}");
    assert!(!html.contains("Ask to join"), "{html}");
    assert!(
        html.contains("does not authenticate its members"),
        "the state is still reported: {html}"
    );
}

/// An administrator still gets all of it — the assertions above are about the
/// capability, not about the panels having quietly gone away.
#[test]
fn security_still_offers_an_administrator_every_control() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Security /> });

    assert!(html.contains("Move to another mesh"), "{html}");
    assert!(!html.contains("disabled"), "and nothing is inert: {html}");
}

/// The Logs pane distinguishes its three empty states, and the one it shows an
/// administrator before the first poll is not the viewer's.
///
/// `dash.admin` defaults to `false` and is corrected only by a client-side
/// effect, so keying the message on it rendered "administrators only" into
/// server-rendered markup for an administrator — a false statement to the one
/// person it is false about. The message is keyed on `snapshot.logs.is_none()`
/// instead, which is what the poll actually did, and this pins all three arms.
#[test]
fn logs_say_why_they_are_empty_to_a_read_only_session() {
    // Before any poll: neither claim is available yet, so neither is made.
    let waiting = render_with(None, || view! { <Logs /> });
    assert!(waiting.contains("Waiting for the node"), "{waiting}");
    assert!(!waiting.contains("administrator"), "{waiting}");

    // An administrator polled and the node had nothing at the current filter.
    let quiet = render_with(Some(seeded_snapshot()), || view! { <Logs /> });
    assert!(quiet.contains("Nothing recorded yet"), "{quiet}");

    // A read-only poll never asked, and says so rather than reporting silence.
    let mut withheld = seeded_snapshot();
    withheld.logs = None;
    let viewer = render_as_viewer(Some(withheld), || view! { <Logs /> });
    assert!(
        viewer.contains("administrator"),
        "a viewer is told the ring is not theirs to read: {viewer}"
    );
    assert!(
        !viewer.contains("Nothing recorded yet"),
        "and not that the node was quiet: {viewer}"
    );
}

/// A read-only account is told why the log pane is empty, and does not re-aim
/// what the node records.
///
/// It cannot read the ring at all — `GetLogs` is an administrator's read — so
/// this seeds the scrollback directly to exercise the *controls*, which is what
/// the test is about. `logs_say_why_they_are_empty_to_a_read_only_session`
/// covers what a viewer actually sees.
///
/// `SetLogLevel` changes what the node records for *everyone*, so it is an
/// administrator's call. The filter in force is still shown: it is the
/// difference between "nothing is happening" and "nothing is being recorded".
#[test]
fn logs_show_a_read_only_viewer_the_filter_without_offering_to_change_it() {
    let mut history = History::default();
    history.ingest_logs(LogRecords {
        records: Vec::new(),
        next_seq: 1,
        dropped: 0,
        filter: "info,batman=trace".into(),
    });

    let html = render_seeded(
        Some(seeded_snapshot()),
        Some(history),
        false,
        || view! { <Logs /> },
    );

    assert!(
        html.contains("info,batman=trace"),
        "the filter in force: {html}"
    );
    assert!(!html.contains("Change"), "and no way to re-aim it: {html}");
}

/// The link participation gates are a change to the node like any other, and a
/// read-only account is shown them without being able to flip them.
#[test]
fn links_shows_a_read_only_viewer_the_gates_without_letting_them_flip() {
    let html = render_as_viewer(Some(seeded_snapshot()), || view! { <Links /> });

    for gate in ["Send OGMs", "Receive OGMs", "Send data", "Receive data"] {
        assert!(html.contains(gate), "{gate} is still listed: {html}");
    }
    assert_eq!(
        html.matches("disabled").count(),
        4,
        "and every one of them is inert: {html}"
    );
}

/// A representative `otpauth://` URI, the shape the provider actually mints.
const ENROLMENT_URI: &str = "otpauth://totp/Wayfinder:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX\
                             P&issuer=Wayfinder&algorithm=SHA1&digits=6&period=30";

/// The second factor is set up on a *phone*, and the page showing it is often
/// on something else. A camera is the only route between the two that neither
/// retypes 32 characters of base32 nor mails a shared secret to yourself, so
/// the code is drawn into the page rather than left to the copy button.
#[test]
fn registration_draws_the_authenticator_secret_as_a_scannable_code() {
    let html = render_with(None, || {
        view! { <TotpEnrolment uri=ENROLMENT_URI.to_string() /> }
    });

    assert!(html.contains("<svg"), "a code is drawn: {html}");
    assert!(html.contains("wf-qr"), "and it is the QR code: {html}");
    assert!(
        html.contains("<path d=\"M"),
        "with modules in it, not an empty frame: {html}"
    );
}

/// The code and the copy button carry the same URI. They are two routes to one
/// secret, and a code encoding anything but what the button copies would send
/// a registrant to an authenticator holding a different secret from the one
/// the provider recorded.
#[test]
fn the_scannable_code_and_the_copy_button_carry_the_same_uri() {
    let html = render_with(None, || {
        view! { <TotpEnrolment uri=ENROLMENT_URI.to_string() /> }
    });

    let expected = wayfinder_web::qr::svg(ENROLMENT_URI, "Authenticator setup code")
        .expect("a URI this short fits");
    let modules = expected
        .split_once("<path d=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .expect("the encoded modules")
        .0;

    assert!(
        html.contains(modules),
        "the drawn code is the encoding of the URI beside it: {html}"
    );
    assert!(
        html.contains(&ENROLMENT_URI.replace('&', "&amp;")),
        "which is also the text beside it, HTML-escaped as any text node is"
    );
}

/// Every opening tag named `tag` in `html`, as the raw text from `<tag` up to
/// (not including) its closing `>`.
///
/// A scan rather than a parser: these tests assert on attributes that are
/// written literally in the `view!` macro a few lines away, and pulling an HTML
/// parser into the dev-dependency graph to read them back would be a heavier
/// dependency than the thing it checks.
fn opening_tags<'a>(html: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(&open) {
        rest = &rest[i..];
        // `<th` is a prefix of `<thead`, so a match only counts where the name
        // actually ends — otherwise every table header would be read as a cell.
        let ends_name = rest[open.len()..]
            .chars()
            .next()
            .is_some_and(|c| c == '>' || c == '/' || c.is_whitespace());
        let end = rest.find('>').expect("a closed tag");
        if ends_name {
            out.push(&rest[..end]);
        }
        rest = &rest[end + 1..];
    }
    out
}

/// Every body cell names the column it came from.
///
/// On a narrow screen a table cannot stay a table: four columns of MACs and
/// intervals need about twice the width a phone has, and the old treatment —
/// `overflow-x: auto` on the panel — answered that by cutting the last columns
/// off behind a sideways scroll inside a card. So each row is stacked into a
/// list of `label: value` lines instead, and the label is the column header
/// carried on the cell.
///
/// The header row is `display: none` there, which is what makes this
/// load-bearing rather than decorative: a cell with no `data-label` renders on
/// a phone as a bare value with nothing saying what it is a value *of* — a MAC
/// with no "Neighbour" in front of it, a duration that could be either of the
/// two the row carries.
#[test]
fn every_table_cell_names_its_column_for_a_stacked_row() {
    let snapshot = seeded_snapshot();
    let provider = provider_snapshot();
    let tabs: Vec<(&str, String)> = vec![
        (
            "routing",
            render_with(Some(snapshot.clone()), || view! { <Routing /> }),
        ),
        (
            "link quality",
            render_with(Some(snapshot.clone()), || view! { <LinkQuality /> }),
        ),
        (
            "links",
            render_with(Some(snapshot.clone()), || view! { <Links /> }),
        ),
        (
            "metrics",
            render_with(Some(snapshot.clone()), || view! { <Metrics /> }),
        ),
        (
            "security",
            render_with(Some(snapshot.clone()), || view! { <Security /> }),
        ),
        (
            "members",
            render_with(Some(provider.clone()), || view! { <Members /> }),
        ),
        // The roster rather than the whole tab: `Accounts` fetches its rows
        // rather than reading them off the snapshot, so the tab alone renders
        // "Reading the accounts…" and no table at all.
        ("accounts", {
            let account = UserAccount {
                username: "watcher".into(),
                admin: false,
                session_ttl_secs: 900,
                totp_enrolled: true,
                disabled: false,
                locked: false,
            };
            render_with(Some(provider), move || {
                view! {
                    <UserTable
                        users=vec![account.clone()]
                        on_revoke=Callback::new(|_| {})
                        on_remove=Callback::new(|_| {})
                    />
                }
            })
        }),
    ];

    for (tab, html) in tabs {
        let cells = opening_tags(&html, "td");
        assert!(!cells.is_empty(), "{tab} rendered no rows to check: {html}");
        for cell in cells {
            // Two cells carry no column: the disclosure that opens the row, and
            // the per-row controls under a blank header. Neither is a value,
            // so neither has a name to put in front of it.
            let unlabelled = cell.contains("wf-cell-more") || cell.contains("wf-row-actions");
            assert!(
                unlabelled || cell.contains("data-label=\""),
                "{tab} has a cell with no column name: {cell}"
            );
        }
    }
}

/// A row's secondary columns collapse behind a disclosure, and the disclosure
/// is per row.
///
/// Stacking alone trades one problem for another: a four-column table becomes
/// four lines per row, so a mesh of ten destinations is forty lines to scroll
/// past. So the columns that identify a row stay, and the rest fold away behind
/// a control on the row itself.
///
/// It is a checkbox and a `<label>`, not a signal: the open/closed state of a
/// row is DOM state, so there is nothing for the server and the browser to
/// disagree about, nothing to reset on a route change, and the rows still open
/// on the page whose hydration failed.
#[test]
fn a_table_row_folds_its_secondary_columns_behind_a_disclosure() {
    let html = render_with(Some(seeded_snapshot()), || view! { <Routing /> });

    assert!(
        html.contains("wf-cell-detail"),
        "the secondary columns are marked: {html}"
    );
    assert!(
        html.contains("wf-row-more-input"),
        "and a control opens them: {html}"
    );

    // One disclosure per body row, not one per table: the point is to open the
    // row you are looking at, and a single control at the top would open all of
    // them together.
    let rows = html.matches("class=\"wf-row\"").count();
    let toggles = html.matches("wf-row-more-input").count();
    assert_eq!(rows, toggles, "one disclosure per row: {html}");
}
