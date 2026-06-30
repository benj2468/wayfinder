//! Application state for the Wayfinder TUI: the most recent data snapshot
//! pulled from the management API plus the UI's navigation state.

use std::time::Instant;

use ratatui::widgets::TableState;
use wayfinder_protos::wayfinder_v1alpha::{
    GetSecurityStatusResponse, LinkQualityTable, NodeInfo, NodeMetrics, NodeSecurity, OgmSchedule,
    RoutingTable, Throughput,
};

/// The top-level views the TUI cycles between.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    /// Node identity, originator count, and connection status.
    Overview,
    /// The BATMAN originator table with a per-originator path detail panel.
    Routing,
    /// The per-(neighbor, interface) link-quality table.
    LinkQuality,
    /// The per-interface adaptive OGM emission schedule (current publish rate).
    OgmSchedule,
    /// Aggregate node metrics: uptime, neighbour count, table occupancy, TQ /
    /// path-diversity distribution, and per-interface throughput.
    Metrics,
    /// Mesh authentication posture: the trust-anchor/own-cert header and a
    /// per-originator verified / expiry / revoked table.
    Security,
}

impl Tab {
    /// All tabs in display order.
    pub const ALL: [Tab; 6] = [
        Tab::Overview,
        Tab::Routing,
        Tab::LinkQuality,
        Tab::OgmSchedule,
        Tab::Metrics,
        Tab::Security,
    ];

    /// Short title shown in the tab bar.
    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Routing => "Routing Table",
            Tab::LinkQuality => "Link Quality",
            Tab::OgmSchedule => "OGM Schedule",
            Tab::Metrics => "Metrics",
            Tab::Security => "Security",
        }
    }

    /// Index of this tab within [`Tab::ALL`].
    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    /// The next tab, wrapping around.
    pub fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    /// The previous tab, wrapping around.
    pub fn prev(self) -> Tab {
        let len = Tab::ALL.len();
        Tab::ALL[(self.index() + len - 1) % len]
    }
}

/// The latest successful snapshot of router state.
#[derive(Default)]
pub struct Snapshot {
    /// Identity and capacity, or `None` until the first successful fetch.
    pub node_info: Option<NodeInfo>,
    /// Originator table; empty until first fetch.
    pub routing: RoutingTable,
    /// Link-quality table; empty until first fetch.
    pub link_quality: LinkQualityTable,
    /// Per-interface adaptive OGM emission schedule; empty until first fetch.
    pub ogm_schedule: OgmSchedule,
    /// Per-interface throughput rates and node-wide totals; empty until first
    /// fetch.
    pub throughput: Throughput,
    /// Aggregate node health/topology metrics, or `None` until the first fetch.
    pub metrics: Option<NodeMetrics>,
    /// Mesh authentication / security posture, or `None` until the first fetch.
    pub security: Option<GetSecurityStatusResponse>,
}

impl Snapshot {
    /// The security posture recorded for originator `node_id`, if any — used to
    /// annotate the Routing tab's per-endpoint detail with its verification /
    /// expiry / revocation state.
    pub fn security_for(&self, node_id: &[u8]) -> Option<&NodeSecurity> {
        self.security
            .as_ref()?
            .nodes
            .iter()
            .find(|n| n.node_id == node_id)
    }
}

/// Whole-application state driven by the event loop and rendered each frame.
pub struct App {
    /// Whether the event loop should keep running.
    pub running: bool,
    /// The currently focused tab.
    pub tab: Tab,
    /// Latest data snapshot from the server.
    pub snapshot: Snapshot,
    /// Selection state for the routing table.
    pub routing_state: TableState,
    /// Selection state for the link-quality table.
    pub link_state: TableState,
    /// Selection state for the OGM schedule table.
    pub ogm_state: TableState,
    /// Selection state for the per-interface throughput table on the Metrics tab.
    pub metrics_state: TableState,
    /// Selection state for the per-originator table on the Security tab.
    pub security_state: TableState,
    /// Last error message from a failed refresh, cleared on success.
    pub last_error: Option<String>,
    /// When the snapshot was last refreshed successfully.
    pub last_update: Option<Instant>,
    /// True once at least one successful refresh has completed.
    pub connected: bool,
    /// The management-API address, for display.
    pub addr: String,
    /// Refresh interval in milliseconds, for display.
    pub interval_ms: u64,
}

impl App {
    /// Create the initial application state for a given server `addr`.
    pub fn new(addr: String, interval_ms: u64) -> Self {
        Self {
            running: true,
            tab: Tab::Overview,
            snapshot: Snapshot::default(),
            routing_state: TableState::default(),
            link_state: TableState::default(),
            ogm_state: TableState::default(),
            metrics_state: TableState::default(),
            security_state: TableState::default(),
            last_error: None,
            last_update: None,
            connected: false,
            addr,
            interval_ms,
        }
    }

    /// Move the selection cursor in the table belonging to the active tab.
    pub fn move_selection(&mut self, delta: isize) {
        let (state, len) = match self.tab {
            Tab::Routing => (&mut self.routing_state, self.snapshot.routing.entries.len()),
            Tab::LinkQuality => (
                &mut self.link_state,
                self.snapshot.link_quality.entries.len(),
            ),
            Tab::OgmSchedule => (
                &mut self.ogm_state,
                self.snapshot.ogm_schedule.entries.len(),
            ),
            Tab::Metrics => (
                &mut self.metrics_state,
                self.snapshot.throughput.interfaces.len(),
            ),
            Tab::Security => (
                &mut self.security_state,
                self.snapshot.security.as_ref().map_or(0, |s| s.nodes.len()),
            ),
            Tab::Overview => return,
        };
        if len == 0 {
            state.select(None);
            return;
        }
        let current = state.selected().unwrap_or(0) as isize;
        let next = (current + delta).rem_euclid(len as isize) as usize;
        state.select(Some(next));
    }
}

/// Format an opaque mesh identifier for display.
///
/// 6-byte identifiers are rendered as colon-delimited MAC addresses; any other
/// length falls back to space-free hex so 1-byte LoRa short addresses and
/// unexpected lengths both stay readable.
pub fn format_id(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "—".to_string();
    }
    if bytes.len() == 6 {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder_protos::wayfinder_v1alpha::RoutingEntry;

    #[test]
    fn format_id_renders_mac_short_and_empty() {
        assert_eq!(
            format_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            "aa:bb:cc:dd:ee:01"
        );
        assert_eq!(format_id(&[0x07]), "07"); // 1-byte LoRa short address
        assert_eq!(format_id(&[]), "—");
    }

    #[test]
    fn tab_cycles_both_directions_and_wraps() {
        assert_eq!(Tab::Overview.next(), Tab::Routing);
        assert_eq!(Tab::Routing.next(), Tab::LinkQuality);
        assert_eq!(Tab::LinkQuality.next(), Tab::OgmSchedule);
        assert_eq!(Tab::OgmSchedule.next(), Tab::Metrics);
        assert_eq!(Tab::Metrics.next(), Tab::Security);
        assert_eq!(Tab::Security.next(), Tab::Overview); // wrap forward
        assert_eq!(Tab::Overview.prev(), Tab::Security); // wrap backward
        assert_eq!(Tab::Overview.index(), 0);
        assert_eq!(Tab::LinkQuality.index(), 2);
        assert_eq!(Tab::OgmSchedule.index(), 3);
        assert_eq!(Tab::Metrics.index(), 4);
        assert_eq!(Tab::Security.index(), 5);
    }

    #[test]
    fn security_for_looks_up_a_node_by_id() {
        use wayfinder_protos::wayfinder_v1alpha::{GetSecurityStatusResponse, NodeSecurity};

        let mut app = App::new("test".to_string(), 1000);
        assert!(app.snapshot.security_for(&[0, 0, 0, 0, 0, 2]).is_none());

        app.snapshot.security = Some(GetSecurityStatusResponse {
            auth_enabled: true,
            mesh_id: 0xABCD,
            node_mac: vec![0, 0, 0, 0, 0, 1],
            cert_not_after: 1100,
            revocation_count: 0,
            nodes: vec![NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 2],
                verified: true,
                cert_not_after: 1100,
                revoked: false,
            }],
        });
        let n = app
            .snapshot
            .security_for(&[0, 0, 0, 0, 0, 2])
            .expect("found");
        assert!(n.verified);
        assert_eq!(n.cert_not_after, 1100);
        assert!(app.snapshot.security_for(&[0, 0, 0, 0, 0, 9]).is_none());
    }

    fn app_with_routes(n: usize) -> App {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Routing;
        app.snapshot.routing.entries = (0..n).map(|_| RoutingEntry::default()).collect();
        app
    }

    #[test]
    fn selection_wraps_and_no_ops_on_empty() {
        // Empty table: selection stays None regardless of movement.
        let mut empty = app_with_routes(0);
        empty.move_selection(1);
        assert_eq!(empty.routing_state.selected(), None);

        // Three rows: down past the end wraps to the top, up past the top wraps
        // to the bottom.
        let mut app = app_with_routes(3);
        app.routing_state.select(Some(2));
        app.move_selection(1);
        assert_eq!(app.routing_state.selected(), Some(0));
        app.move_selection(-1);
        assert_eq!(app.routing_state.selected(), Some(2));
    }

    #[test]
    fn move_selection_ignored_on_overview() {
        let mut app = app_with_routes(3);
        app.tab = Tab::Overview;
        app.move_selection(1);
        // Routing selection is untouched while on the overview tab.
        assert_eq!(app.routing_state.selected(), None);
    }
}
