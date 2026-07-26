//! Application state for the Wayfinder TUI: the most recent data snapshot
//! pulled from the management API plus the UI's navigation state.

use std::collections::VecDeque;
use std::time::Instant;

use ratatui::widgets::TableState;
use serde::Deserialize;
use serde::Serialize;
use wayfinder_protos::wayfinder_v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder_v1alpha::KeepAliveTable;
use wayfinder_protos::wayfinder_v1alpha::LinkFeaturesTable;
use wayfinder_protos::wayfinder_v1alpha::LinkQualityTable;
use wayfinder_protos::wayfinder_v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder_v1alpha::NodeInfo;
use wayfinder_protos::wayfinder_v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder_v1alpha::NodeSecurity;
use wayfinder_protos::wayfinder_v1alpha::OgmSchedule;
use wayfinder_protos::wayfinder_v1alpha::RoutingTable;
use wayfinder_protos::wayfinder_v1alpha::Throughput;

/// The top-level views the TUI cycles between.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    /// Node identity, originator count, and connection status.
    Overview,
    /// The BATMAN originator table with a per-originator path detail panel.
    Routing,
    /// The per-(neighbor, interface) link-quality table.
    LinkQuality,
    /// Per-interface OGM emission schedule and participation-feature state
    /// (tx/rx OGM/data gates, keep-alive cadence), editable: the selected
    /// interface's gates can be toggled directly from this tab.
    Links,
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
        Tab::Links,
        Tab::Metrics,
        Tab::Security,
    ];

    /// Short title shown in the tab bar.
    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Routing => "Routing Table",
            Tab::LinkQuality => "Link Quality",
            Tab::Links => "Links",
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

/// An operator action queued by a keypress on the Security tab, to be executed
/// against the connected provider node by the async event loop (which owns the
/// client).  The synchronous key handler cannot do I/O itself, so it parks the
/// intent here and the loop drains it.
/// Every variant carries the target node MAC (raw bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperatorAction {
    /// Approve the pending CSR bound to this node MAC.
    ApproveCsr(Vec<u8>),
    /// Deny the pending CSR bound to this node MAC.
    DenyCsr(Vec<u8>),
    /// Revoke this node from the mesh (the provider signs and floods a
    /// revocation record).
    RevokeNode(Vec<u8>),
}

/// Which participation gate a keypress on the Links tab toggles.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkFeatureGate {
    /// Send OGMs (own + re-flooded) onto the link.
    TxOgm,
    /// Accept inbound OGMs on the link and learn routes from them.
    RxOgm,
    /// Send data-plane traffic (unicast/multicast/broadcast) onto the link.
    TxData,
    /// Accept inbound data-plane traffic on the link.
    RxData,
}

/// A single participation-gate flip queued by a keypress on the Links tab,
/// to be executed against the connected node by the async event loop (which
/// owns the client). Applied immediately once queued (no confirmation step)
/// since flipping one gate is low-stakes and trivially reversible — unlike
/// the Security tab's approve/deny/revoke actions, which stay behind
/// [`OperatorAction`]'s confirm popup.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LinkFeatureToggle {
    /// Interface to reconfigure, in registration order.
    pub iface_idx: u32,
    /// Which gate to set.
    pub gate: LinkFeatureGate,
    /// The value to set it to (the flip of its current displayed state).
    pub new_value: bool,
}

/// Which panel on the Security tab has navigation focus.  Only meaningful on a
/// certificate-authority provider, where the tab shows two actionable tables;
/// a non-provider node shows only the originator table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityFocus {
    /// The pending-CSR table (approve/deny).
    PendingCsrs,
    /// The originator table (revoke).
    Originators,
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
    /// Per-interface participation-feature state; empty until first fetch.
    pub link_features: LinkFeaturesTable,
    /// Per-neighbor keep-alive heartbeat liveness table; empty until first
    /// fetch.
    pub keepalive: KeepAliveTable,
    /// Per-interface adaptive OGM emission schedule; empty until first fetch.
    pub ogm_schedule: OgmSchedule,
    /// Per-interface throughput rates and node-wide totals; empty until first
    /// fetch.
    pub throughput: Throughput,
    /// Aggregate node health/topology metrics, or `None` until the first fetch.
    pub metrics: Option<NodeMetrics>,
    /// Mesh authentication / security posture, or `None` until the first fetch.
    pub security: Option<GetSecurityStatusResponse>,
    /// CSRs awaiting operator approval, when the connected node is a
    /// certificate-authority provider.  `None` when it is not a provider (the
    /// enrollment RPCs error) or before the first fetch.
    pub pending_csrs: Option<ListPendingCsrsResponse>,
}

/// Maximum number of throughput samples retained for the Metrics tab history
/// chart. At the default 1 s refresh this is two minutes of history; the buffer
/// is bounded so a long-lived TUI session cannot grow without limit.
pub const THROUGHPUT_HISTORY: usize = 120;

/// One time-ordered throughput sample: the node-wide receive and transmit rates
/// (bytes/sec) captured at a single refresh. Samples are pushed in refresh order
/// so the chart's x-axis is implicitly time.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThroughputSample {
    /// Node-wide receive rate in bytes/sec at sample time.
    pub rx_bps: f64,
    /// Node-wide transmit rate in bytes/sec at sample time.
    pub tx_bps: f64,
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
    /// Selection state for the Links tab's interface table (OGM schedule +
    /// participation features, merged).
    pub links_state: TableState,
    /// Selection state for the per-interface throughput table on the Metrics tab.
    pub metrics_state: TableState,
    /// Selection state for the per-originator table on the Security tab.
    pub security_state: TableState,
    /// Selection state for the pending-CSR table on the Security tab (provider
    /// mode).  When the connected node is a provider, this panel takes the tab's
    /// `j`/`k` navigation and `a`/`d` approve/deny keys while it holds focus.
    pub csr_state: TableState,
    /// Which Security-tab panel has navigation focus on a provider node.  `Tab`
    /// switches focus between the pending-CSR and originator tables; ignored on a
    /// non-provider node (which shows only the originator table).
    pub security_focus: SecurityFocus,
    /// A proposed action (approve/deny a CSR, or revoke a node) awaiting operator
    /// confirmation.  While `Some`, a modal popup is shown and captures all keys
    /// until the operator confirms (moving it to `pending_action`) or cancels.
    pub confirm: Option<OperatorAction>,
    /// A confirmed approve/deny action awaiting execution by the event loop
    /// against the connected node (only this loop owns the client).  Set by
    /// [`App::confirm_action`] and taken by the loop.
    pub pending_action: Option<OperatorAction>,
    /// A link-feature gate flip awaiting execution by the event loop, queued
    /// by [`App::toggle_link_feature`] and taken by the loop. Unlike
    /// `pending_action` this is set (and executed) directly on keypress, with
    /// no confirmation step.
    pub pending_link_feature_toggle: Option<LinkFeatureToggle>,
    /// Rolling history of node-wide throughput totals, oldest first, capped at
    /// [`THROUGHPUT_HISTORY`] samples. Drives the Metrics tab RX/TX line chart.
    pub throughput_history: VecDeque<ThroughputSample>,
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
            links_state: TableState::default(),
            metrics_state: TableState::default(),
            security_state: TableState::default(),
            csr_state: TableState::default(),
            security_focus: SecurityFocus::PendingCsrs,
            confirm: None,
            pending_action: None,
            pending_link_feature_toggle: None,
            throughput_history: VecDeque::with_capacity(THROUGHPUT_HISTORY),
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
            // The interface list is keyed off `link_features` (one row per
            // registered interface); `ogm_schedule` is zipped in by iface_idx
            // for display only, so its length doesn't drive selection bounds.
            Tab::Links => (
                &mut self.links_state,
                self.snapshot.link_features.entries.len(),
            ),
            Tab::Metrics => (
                &mut self.metrics_state,
                self.snapshot.throughput.interfaces.len(),
            ),
            // On a provider node navigation drives whichever panel holds focus;
            // a non-provider node has only the originator table.
            Tab::Security => {
                let nodes = self.snapshot.security.as_ref().map_or(0, |s| s.nodes.len());
                let pending = self.snapshot.pending_csrs.as_ref().map(|p| p.pending.len());
                match (pending, self.security_focus) {
                    (Some(n), SecurityFocus::PendingCsrs) => (&mut self.csr_state, n),
                    (Some(_), SecurityFocus::Originators) | (None, _) => {
                        (&mut self.security_state, nodes)
                    }
                }
            }
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

    /// The node MAC of the currently-selected pending CSR, if the Security tab's
    /// provider panel has a selection.  `None` when the node is not a provider or
    /// nothing is selected.
    pub fn selected_pending_csr_mac(&self) -> Option<Vec<u8>> {
        let pending = self.snapshot.pending_csrs.as_ref()?;
        let idx = self.csr_state.selected()?;
        pending.pending.get(idx).map(|c| c.node_mac.clone())
    }

    /// The node MAC of the currently-selected originator, if the Security tab's
    /// originator table has a selection.  `None` otherwise.
    pub fn selected_originator_mac(&self) -> Option<Vec<u8>> {
        let security = self.snapshot.security.as_ref()?;
        let idx = self.security_state.selected()?;
        security.nodes.get(idx).map(|n| n.node_id.clone())
    }

    /// Switch navigation focus between the two Security-tab panels.  A no-op
    /// unless the Security tab is showing both (i.e. a provider node).
    pub fn toggle_security_focus(&mut self) {
        if self.tab != Tab::Security || self.snapshot.pending_csrs.is_none() {
            return;
        }
        self.security_focus = match self.security_focus {
            SecurityFocus::PendingCsrs => SecurityFocus::Originators,
            SecurityFocus::Originators => SecurityFocus::PendingCsrs,
        };
    }

    /// Propose an approve (`approve = true`) or deny action for the selected
    /// pending CSR, opening a confirmation popup.  A no-op unless the Security
    /// tab's pending-CSR panel is focused and a CSR is selected, so the keys are
    /// inert elsewhere.  The action does not execute until [`confirm_action`] is
    /// called.
    ///
    /// [`confirm_action`]: App::confirm_action
    pub fn request_csr_action(&mut self, approve: bool) {
        if self.tab != Tab::Security || self.security_focus != SecurityFocus::PendingCsrs {
            return;
        }
        if let Some(mac) = self.selected_pending_csr_mac() {
            self.confirm = Some(if approve {
                OperatorAction::ApproveCsr(mac)
            } else {
                OperatorAction::DenyCsr(mac)
            });
        }
    }

    /// Propose revoking the selected originator, opening a confirmation popup.  A
    /// no-op unless the Security tab's originator panel is focused on a provider
    /// node with an originator selected (revocation requires the CA).  Does not
    /// execute until [`confirm_action`] is called.
    ///
    /// [`confirm_action`]: App::confirm_action
    pub fn request_revoke(&mut self) {
        if self.tab != Tab::Security
            || self.security_focus != SecurityFocus::Originators
            || self.snapshot.pending_csrs.is_none()
        {
            return;
        }
        if let Some(mac) = self.selected_originator_mac() {
            self.confirm = Some(OperatorAction::RevokeNode(mac));
        }
    }

    /// Queue a flip of `gate` on the currently selected interface of the
    /// Links tab, for the event loop to execute immediately (no confirmation
    /// step — see [`LinkFeatureToggle`]). A no-op unless the Links tab is
    /// focused and a row is selected.
    pub fn toggle_link_feature(&mut self, gate: LinkFeatureGate) {
        if self.tab != Tab::Links {
            return;
        }
        let Some(idx) = self.links_state.selected() else {
            return;
        };
        let Some(entry) = self.snapshot.link_features.entries.get(idx) else {
            return;
        };
        let current = match gate {
            LinkFeatureGate::TxOgm => entry.tx_ogm,
            LinkFeatureGate::RxOgm => entry.rx_ogm,
            LinkFeatureGate::TxData => entry.tx_data,
            LinkFeatureGate::RxData => entry.rx_data,
        };
        self.pending_link_feature_toggle = Some(LinkFeatureToggle {
            iface_idx: entry.iface_idx,
            gate,
            new_value: !current,
        });
    }

    /// Confirm the proposed action: move it from the popup to the execution
    /// queue, which the event loop drains.  A no-op if no popup is open.
    pub fn confirm_action(&mut self) {
        self.pending_action = self.confirm.take();
    }

    /// Dismiss the confirmation popup without acting.
    pub fn cancel_action(&mut self) {
        self.confirm = None;
    }

    /// Append the latest node-wide throughput totals from the current snapshot
    /// to the rolling history, evicting the oldest sample once
    /// [`THROUGHPUT_HISTORY`] is exceeded. Call once per successful refresh so
    /// the Metrics tab chart advances one step per refresh interval.
    pub fn record_throughput(&mut self) {
        let tp = &self.snapshot.throughput;
        self.throughput_history.push_back(ThroughputSample {
            rx_bps: tp.total_rx_bps,
            tx_bps: tp.total_tx_bps,
        });
        while self.throughput_history.len() > THROUGHPUT_HISTORY {
            self.throughput_history.pop_front();
        }
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
        assert_eq!(Tab::LinkQuality.next(), Tab::Links);
        assert_eq!(Tab::Links.next(), Tab::Metrics);
        assert_eq!(Tab::Metrics.next(), Tab::Security);
        assert_eq!(Tab::Security.next(), Tab::Overview); // wrap forward
        assert_eq!(Tab::Overview.prev(), Tab::Security); // wrap backward
        assert_eq!(Tab::Overview.index(), 0);
        assert_eq!(Tab::LinkQuality.index(), 2);
        assert_eq!(Tab::Links.index(), 3);
        assert_eq!(Tab::Metrics.index(), 4);
        assert_eq!(Tab::Security.index(), 5);
    }

    #[test]
    fn security_for_looks_up_a_node_by_id() {
        use wayfinder_protos::wayfinder_v1alpha::GetSecurityStatusResponse;
        use wayfinder_protos::wayfinder_v1alpha::NodeSecurity;

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

    #[test]
    fn csr_action_is_queued_only_on_the_security_tab_of_a_provider() {
        use wayfinder_protos::wayfinder_v1alpha::ListPendingCsrsResponse;
        use wayfinder_protos::wayfinder_v1alpha::PendingCsr;

        let mut app = App::new("test".to_string(), 1000);
        app.snapshot.pending_csrs = Some(ListPendingCsrsResponse {
            pending: vec![
                PendingCsr {
                    node_mac: vec![2, 0, 0, 0, 0, 9],
                    ..Default::default()
                },
                PendingCsr {
                    node_mac: vec![2, 0, 0, 0, 0, 10],
                    ..Default::default()
                },
            ],
        });

        // Off the Security tab, the keys are inert.
        app.tab = Tab::Routing;
        app.request_csr_action(true);
        assert!(app.confirm.is_none());

        // On the Security tab, a pending CSR is selected and requesting an action
        // opens a confirmation popup (it does not execute yet).
        app.tab = Tab::Security;
        app.csr_state.select(Some(1)); // target the second pending CSR
        app.request_csr_action(true);
        assert_eq!(
            app.confirm,
            Some(OperatorAction::ApproveCsr(vec![2, 0, 0, 0, 0, 10])),
            "approve proposes but waits for confirmation"
        );
        assert!(
            app.pending_action.is_none(),
            "nothing executes until confirmed"
        );

        // Cancelling clears the popup without queueing anything.
        app.cancel_action();
        assert!(app.confirm.is_none());
        assert!(app.pending_action.is_none());

        // Confirming commits the proposed action for the loop to execute.
        app.request_csr_action(false);
        assert_eq!(
            app.confirm,
            Some(OperatorAction::DenyCsr(vec![2, 0, 0, 0, 0, 10]))
        );
        app.confirm_action();
        assert!(app.confirm.is_none());
        assert_eq!(
            app.pending_action,
            Some(OperatorAction::DenyCsr(vec![2, 0, 0, 0, 0, 10]))
        );
    }

    #[test]
    fn csr_action_is_inert_on_a_non_provider_node() {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Security;
        app.snapshot.pending_csrs = None; // not a provider
        app.request_csr_action(true);
        assert!(app.confirm.is_none());
        assert!(app.pending_action.is_none());
    }

    /// A small provider snapshot: one pending CSR and one known originator.
    fn provider_app() -> App {
        use wayfinder_protos::wayfinder_v1alpha::GetSecurityStatusResponse;
        use wayfinder_protos::wayfinder_v1alpha::ListPendingCsrsResponse;
        use wayfinder_protos::wayfinder_v1alpha::NodeSecurity;
        use wayfinder_protos::wayfinder_v1alpha::PendingCsr;
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Security;
        app.snapshot.pending_csrs = Some(ListPendingCsrsResponse {
            pending: vec![PendingCsr {
                node_mac: vec![2, 0, 0, 0, 0, 9],
                ..Default::default()
            }],
        });
        app.snapshot.security = Some(GetSecurityStatusResponse {
            auth_enabled: true,
            nodes: vec![NodeSecurity {
                node_id: vec![2, 0, 0, 0, 0, 7],
                verified: true,
                ..Default::default()
            }],
            ..Default::default()
        });
        app
    }

    #[test]
    fn tab_switches_security_focus_only_on_a_provider() {
        let mut app = provider_app();
        assert_eq!(app.security_focus, SecurityFocus::PendingCsrs);
        app.toggle_security_focus();
        assert_eq!(app.security_focus, SecurityFocus::Originators);
        app.toggle_security_focus();
        assert_eq!(app.security_focus, SecurityFocus::PendingCsrs);

        // Non-provider: focus toggle is inert.
        app.snapshot.pending_csrs = None;
        app.toggle_security_focus();
        assert_eq!(app.security_focus, SecurityFocus::PendingCsrs);
    }

    #[test]
    fn revoke_is_proposed_only_with_originator_focus_on_a_provider() {
        let mut app = provider_app();
        app.security_state.select(Some(0));

        // With CSR focus, `x` does not revoke (it belongs to the originator pane).
        app.security_focus = SecurityFocus::PendingCsrs;
        app.request_revoke();
        assert!(app.confirm.is_none());

        // Switching focus to the originator pane, `x` proposes revoking it.
        app.security_focus = SecurityFocus::Originators;
        app.request_revoke();
        assert_eq!(
            app.confirm,
            Some(OperatorAction::RevokeNode(vec![2, 0, 0, 0, 0, 7]))
        );
        app.confirm_action();
        assert_eq!(
            app.pending_action,
            Some(OperatorAction::RevokeNode(vec![2, 0, 0, 0, 0, 7]))
        );

        // A non-provider node cannot revoke.
        let mut app = provider_app();
        app.snapshot.pending_csrs = None;
        app.security_focus = SecurityFocus::Originators;
        app.security_state.select(Some(0));
        app.request_revoke();
        assert!(app.confirm.is_none());
    }

    #[test]
    fn approve_is_inert_while_the_originator_pane_is_focused() {
        let mut app = provider_app();
        app.csr_state.select(Some(0));
        app.security_focus = SecurityFocus::Originators;
        app.request_csr_action(true);
        assert!(app.confirm.is_none(), "approve belongs to the CSR pane");
    }

    fn app_with_link_features(
        entries: Vec<wayfinder_protos::wayfinder_v1alpha::LinkFeaturesEntry>,
    ) -> App {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Links;
        app.snapshot.link_features.entries = entries;
        app
    }

    #[test]
    fn toggle_link_feature_is_inert_off_the_links_tab() {
        use wayfinder_protos::wayfinder_v1alpha::LinkFeaturesEntry;
        let mut app = app_with_link_features(vec![LinkFeaturesEntry {
            iface_idx: 0,
            tx_ogm: true,
            rx_ogm: true,
            tx_data: true,
            rx_data: true,
            tx_keepalive_interval_ms: None,
        }]);
        app.links_state.select(Some(0));
        app.tab = Tab::Overview;

        app.toggle_link_feature(LinkFeatureGate::TxOgm);
        assert!(app.pending_link_feature_toggle.is_none());
    }

    #[test]
    fn toggle_link_feature_is_inert_without_a_selection() {
        use wayfinder_protos::wayfinder_v1alpha::LinkFeaturesEntry;
        let mut app = app_with_link_features(vec![LinkFeaturesEntry {
            iface_idx: 0,
            tx_ogm: true,
            rx_ogm: true,
            tx_data: true,
            rx_data: true,
            tx_keepalive_interval_ms: None,
        }]);

        app.toggle_link_feature(LinkFeatureGate::TxOgm);
        assert!(app.pending_link_feature_toggle.is_none());
    }

    #[test]
    fn toggle_link_feature_queues_the_flipped_value_for_the_selected_iface() {
        use wayfinder_protos::wayfinder_v1alpha::LinkFeaturesEntry;
        let mut app = app_with_link_features(vec![LinkFeaturesEntry {
            iface_idx: 2,
            tx_ogm: true,
            rx_ogm: false,
            tx_data: true,
            rx_data: false,
            tx_keepalive_interval_ms: None,
        }]);
        app.links_state.select(Some(0));

        app.toggle_link_feature(LinkFeatureGate::TxOgm);
        assert_eq!(
            app.pending_link_feature_toggle,
            Some(LinkFeatureToggle {
                iface_idx: 2,
                gate: LinkFeatureGate::TxOgm,
                new_value: false,
            }),
            "tx_ogm was true, so the queued flip sets it false"
        );

        app.pending_link_feature_toggle = None;
        app.toggle_link_feature(LinkFeatureGate::RxOgm);
        assert_eq!(
            app.pending_link_feature_toggle,
            Some(LinkFeatureToggle {
                iface_idx: 2,
                gate: LinkFeatureGate::RxOgm,
                new_value: true,
            }),
            "rx_ogm was false, so the queued flip sets it true"
        );
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
    fn throughput_history_records_in_order_and_caps_at_capacity() {
        let mut app = App::new("test".to_string(), 1000);
        assert!(app.throughput_history.is_empty());

        // Each refresh folds the current snapshot totals into the history,
        // newest at the back, oldest at the front.
        for i in 0..3 {
            app.snapshot.throughput.total_rx_bps = i as f64;
            app.snapshot.throughput.total_tx_bps = (i * 10) as f64;
            app.record_throughput();
        }
        assert_eq!(app.throughput_history.len(), 3);
        assert_eq!(app.throughput_history.front().unwrap().rx_bps, 0.0);
        assert_eq!(app.throughput_history.back().unwrap().rx_bps, 2.0);
        assert_eq!(app.throughput_history.back().unwrap().tx_bps, 20.0);

        // Past capacity the oldest samples are evicted while the buffer stays
        // bounded and the newest sample is retained.
        for i in 0..THROUGHPUT_HISTORY {
            app.snapshot.throughput.total_rx_bps = (100 + i) as f64;
            app.record_throughput();
        }
        assert_eq!(app.throughput_history.len(), THROUGHPUT_HISTORY);
        assert_eq!(
            app.throughput_history.back().unwrap().rx_bps,
            (100 + THROUGHPUT_HISTORY - 1) as f64
        );
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
