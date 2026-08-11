//! The shared reactive state every tab reads, and the loop that keeps it fresh.
//!
//! One poll feeds all seven tabs (see [`crate::snapshot`]), so there is exactly
//! one [`Dashboard`] in context and the tabs are pure functions of it. A tab
//! switch is then instant and free: the data is already here.
//!
//! # Why polling starts in the browser
//!
//! Nothing is fetched during server rendering. The server *could* render the
//! first snapshot into the HTML, but a live dashboard's data is stale the
//! moment it is serialised, and doing it would mean every page load polls the
//! node twice — once for the markup and again when the interval starts. The
//! page instead renders its "connecting" state and fills in one round trip
//! later.
//!
//! # Losing the node is a state, not an error
//!
//! A failed poll keeps the last good snapshot on screen and raises a banner,
//! rather than blanking the tabs. Stale data clearly labelled stale is more use
//! to someone diagnosing a mesh than an empty screen — and the node going away
//! *is* the thing they are diagnosing. This mirrors how the TUI holds its last
//! snapshot and shows `last_error` alongside it.

use std::time::Duration;

use leptos::prelude::*;

use crate::api::fetch_snapshot;
use crate::snapshot::NodeSnapshot;
use crate::state::History;

/// How often the dashboard polls the node, in milliseconds.
///
/// Matches the TUI's default. Fast enough that a route change or a link drop
/// shows up while someone is still looking at it, slow enough to be negligible
/// load on a node whose day job is routing.
pub const POLL_INTERVAL_MS: u64 = 1000;

/// The reactive state shared by every tab.
///
/// `Copy`, because every field is a signal handle rather than the data itself,
/// so it can be pulled out of context and moved into closures freely.
#[derive(Clone, Copy)]
pub struct Dashboard {
    /// The most recent successful poll, or `None` before the first one lands.
    /// Deliberately retained when a later poll fails.
    pub snapshot: RwSignal<Option<NodeSnapshot>>,
    /// What successive polls accumulate: log scrollback and the throughput trend.
    pub history: RwSignal<History>,
    /// The last poll's failure, or `None` while polls are succeeding.
    pub error: RwSignal<Option<String>>,
    /// Whether the most recent poll succeeded.
    pub connected: RwSignal<bool>,
    /// What the server is pointed at, for the header.
    pub label: RwSignal<String>,
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Dashboard {
    /// Build an empty dashboard, before any poll has run.
    pub fn new() -> Self {
        Self {
            snapshot: RwSignal::new(None),
            history: RwSignal::new(History::default()),
            error: RwSignal::new(None),
            connected: RwSignal::new(false),
            label: RwSignal::new(String::new()),
        }
    }

    /// Whether a first snapshot has arrived. Distinguishes "starting up" from
    /// "connected to a node that has nothing to show", which look identical in
    /// an empty table but mean very different things.
    pub fn has_data(&self) -> bool {
        self.snapshot.with(Option::is_some)
    }
}

/// Create the dashboard, put it in context, and start polling.
///
/// The polling loop is client-only: [`Effect`]s do not run during server
/// rendering, so the server renders the "connecting" state and the browser takes
/// it from there.
pub fn provide_dashboard() -> Dashboard {
    let dash = Dashboard::new();
    provide_context(dash);

    Effect::new(move |_| {
        // The label cannot change while the server runs, so it is fetched once
        // rather than riding along on every poll.
        leptos::task::spawn_local(async move {
            if let Ok(label) = crate::api::node_label().await {
                dash.label.set(label);
            }
        });

        poll_once(dash);
        leptos::leptos_dom::helpers::set_interval(
            move || poll_once(dash),
            Duration::from_millis(POLL_INTERVAL_MS),
        );
    });

    dash
}

/// Issue one poll and fold the result into the dashboard.
///
/// Reads the log cursor untracked: this runs from a timer, not from a reactive
/// dependency, and tracking the cursor it is about to advance would make the
/// poll retrigger itself.
fn poll_once(dash: Dashboard) {
    let since_seq = dash.history.with_untracked(|h| h.next_seq);

    leptos::task::spawn_local(async move {
        match fetch_snapshot(since_seq).await {
            Ok(snapshot) => {
                dash.history.update(|h| {
                    h.ingest_logs(snapshot.logs.clone());
                    h.record_throughput(&snapshot);
                });
                dash.snapshot.set(Some(snapshot));
                dash.connected.set(true);
                dash.error.set(None);
            }
            Err(e) => {
                // The snapshot is left alone on purpose; see the module docs.
                dash.connected.set(false);
                dash.error.set(Some(e.to_string()));
            }
        }
    });
}

/// Read the dashboard out of context.
///
/// Panics only on a wiring bug — every tab renders beneath [`provide_dashboard`]
/// — and a component has no way to return an error, so there is nothing more
/// graceful available here.
pub fn use_dashboard() -> Dashboard {
    #[expect(
        clippy::expect_used,
        reason = "every tab renders beneath provide_dashboard; absence is a wiring bug"
    )]
    use_context::<Dashboard>().expect("dashboard provided by App")
}
