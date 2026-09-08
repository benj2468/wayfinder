//! The Overview tab: who this node is and whether it is healthy.
//!
//! The landing tab, so it answers the questions someone arrives with — am I
//! looking at the right node, is it reaching the mesh, is anything wrong — before
//! any of the detail tabs. Everything here is a headline; the tables that explain
//! each number live one tab away.

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::ClockPosture;

use crate::components::dashboard::use_dashboard;
use crate::components::widgets::Empty;
use crate::components::widgets::Field;
use crate::components::widgets::Panel;
use crate::components::widgets::Stat;
use crate::format;

/// Render the Overview tab.
#[component]
pub fn Overview() -> impl IntoView {
    let dash = use_dashboard();

    view! {
        <div class="wf-grid">
            <Panel title="Node">
                {move || {
                    dash.snapshot
                        .with(|s| {
                            let Some(info) = s.as_ref().and_then(|s| s.node_info.as_ref()) else {
                                return view! { <Empty message="Waiting for the node…" /> }
                                    .into_any();
                            };
                            view! {
                                <Field label="Address" value=format::id(&info.node_id) mono=true />
                                <Field
                                    label="Nodes reachable"
                                    value=info.num_originators.to_string()
                                />
                                <Field
                                    label="Mesh membership"
                                    value=if info.auth_locked {
                                        "Waiting to be enrolled"
                                    } else {
                                        "Enrolled"
                                    }
                                />
                                <Field
                                    label="Configuration"
                                    value=if info.runtime_config_active {
                                        "Runtime override applied"
                                    } else {
                                        "As started"
                                    }
                                />
                                // Phrased for the audience this dashboard
                                // exists for: someone who will not think to
                                // connect "enrollment keeps failing" to NTP.
                                <Field
                                    label="Clock"
                                    value=if info.clock_trusted {
                                        "OK"
                                    } else {
                                        "Not synchronized — sign-in and enrollment are paused"
                                    }
                                />
                                // A different question from the row above, and
                                // phrased for the same audience: "Clock" is
                                // whether this node will act on a credential,
                                // this is whether it checks that other nodes'
                                // credentials have expired. A node with no
                                // anchor routes perfectly well while checking
                                // neither, which is exactly why it needs
                                // saying out loud (design 20 §7).
                                <Field
                                    label="Certificate expiry"
                                    value=match ClockPosture::try_from(info.clock_posture) {
                                        Ok(ClockPosture::At) => "Checked",
                                        Ok(ClockPosture::AtLeast) => {
                                            "Checked (this node estimates the time)"
                                        }
                                        Ok(ClockPosture::Unknown) => {
                                            "Not checked — this node has never been told the time"
                                        }
                                        Ok(ClockPosture::Unspecified) | Err(_) => "Not reported",
                                    }
                                />
                            }
                                .into_any()
                        })
                }}
            </Panel>

            <Panel title="Health">
                {move || {
                    dash.snapshot
                        .with(|s| {
                            let Some(snap) = s.as_ref() else {
                                return view! { <Empty message="Waiting for the node…" /> }
                                    .into_any();
                            };
                            let uptime = snap
                                .metrics
                                .as_ref()
                                .map_or_else(|| "—".to_string(), |m| format::uptime(m.uptime_secs));
                            let neighbours = snap
                                .metrics
                                .as_ref()
                                .map_or_else(|| "—".to_string(), |m| m.neighbor_count.to_string());
                            view! {
                                <div class="wf-stat-row">
                                    <Stat label="Uptime" value=uptime />
                                    <Stat label="Direct neighbours" value=neighbours />
                                    <Stat
                                        label="Receiving"
                                        value=format::rate(snap.throughput.total_rx_bps)
                                    />
                                    <Stat
                                        label="Sending"
                                        value=format::rate(snap.throughput.total_tx_bps)
                                    />
                                </div>
                            }
                                .into_any()
                        })
                }}
            </Panel>

            <Panel title="Connection">
                <Field label="Management API" value=move || dash.label.get() mono=true />
                <Field
                    label="Status"
                    value=move || {
                        if dash.connected.get() {
                            "Connected".to_string()
                        } else if dash.has_data() {
                            "Lost — showing the last data received".to_string()
                        } else {
                            "Connecting…".to_string()
                        }
                    }
                />
                <Field
                    label="Refresh"
                    value=format!(
                        "every {:.0}s",
                        crate::components::dashboard::POLL_INTERVAL_MS as f64 / 1000.0,
                    )
                />
            </Panel>
        </div>
    }
}
