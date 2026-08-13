//! The Metrics tab: the node's own health and how hard it is working.
//!
//! Two kinds of number here, and the layout separates them deliberately. The
//! headline stats and the throughput trend are *here and now* — what the mesh is
//! doing at this moment. The occupancy figures are *headroom* — how close the
//! node is to a limit it will start dropping things at. An operator reads the
//! first continuously and the second when something is going wrong.

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::TableOccupancy;

use crate::components::chart::ThroughputChart;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::Stat;
use crate::format;

/// Render the Metrics tab.
#[component]
pub fn Metrics() -> impl IntoView {
    let dash = use_dashboard();

    let history = Signal::derive(move || dash.history.with(|h| h.throughput.clone()));

    view! {
        <div class="wf-stack">
            <Panel title="Node">
                {move || {
                    dash.snapshot
                        .with(|s| {
                            let Some(m) = s.as_ref().and_then(|s| s.metrics.as_ref()) else {
                                return view! { <Empty message="Waiting for the node…" /> }
                                    .into_any();
                            };
                            view! {
                                <div class="wf-stat-row">
                                    <Stat label="Uptime" value=format::uptime(m.uptime_secs) />
                                    <Stat
                                        label="Direct neighbours"
                                        value=m.neighbor_count.to_string()
                                    />
                                    <Stat
                                        label="Average link quality"
                                        value=format!(
                                            "{}%",
                                            format::tq_percent(m.tq_mean.round() as u32),
                                        )
                                        detail=format!(
                                            "worst {}% · best {}%",
                                            format::tq_percent(m.tq_min),
                                            format::tq_percent(m.tq_max),
                                        )
                                    />
                                    <Stat
                                        label="Alternate paths"
                                        value=format!("{:.1}", m.paths_mean)
                                        detail=format!("most {}", m.paths_max)
                                    />
                                </div>
                            }
                                .into_any()
                        })
                }}
            </Panel>

            <Panel title="Traffic" subtitle="node-wide, over the last few minutes">
                <ThroughputChart samples=history />
            </Panel>

            <div class="wf-grid">
                <Panel title="Per interface">
                    {move || {
                        let rows = dash
                            .snapshot
                            .with(|s| {
                                s.as_ref().map(|s| s.throughput.interfaces.clone())
                            })
                            .unwrap_or_default();
                        if rows.is_empty() {
                            return view! { <Empty message="No interface traffic reported." /> }
                                .into_any();
                        }
                        view! {
                            <div class="wf-table-scroll">
                                <table class="wf-table">
                                    <thead>
                                        <tr>
                                            <th>"Interface"</th>
                                            <th class="wf-num">"Received"</th>
                                            <th class="wf-num">"Sent"</th>
                                            <th class="wf-num">"Frames in"</th>
                                            <th class="wf-num">"Frames out"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {rows
                                            .into_iter()
                                            .map(|t| {
                                                view! {
                                                    <tr>
                                                        <td>
                                                            {format::iface_label(&t.iface_name, t.iface_idx)}
                                                        </td>
                                                        <td class="wf-num">{format::rate(t.rx_bps)}</td>
                                                        <td class="wf-num">{format::rate(t.tx_bps)}</td>
                                                        <td class="wf-num">{format::fps(t.rx_fps)}</td>
                                                        <td class="wf-num">{format::fps(t.tx_fps)}</td>
                                                    </tr>
                                                }
                                            })
                                            .collect_view()}
                                    </tbody>
                                </table>
                            </div>
                        }
                            .into_any()
                    }}
                </Panel>

                <Panel title="Headroom" subtitle="how close to a limit">
                    {move || {
                        dash.snapshot
                            .with(|s| {
                                let Some(m) = s.as_ref().and_then(|s| s.metrics.as_ref()) else {
                                    return view! { <Empty message="Waiting for the node…" /> }
                                        .into_any();
                                };
                                view! {
                                    <Occupancy label="Known nodes" table=m.originators />
                                    <Occupancy
                                        label="Broadcast history"
                                        table=m.broadcast_dedup
                                    />
                                    <Occupancy
                                        label="Multicast groups joined"
                                        table=m.local_mcast_groups
                                    />
                                    <Occupancy
                                        label="Multicast listeners known"
                                        table=m.mcast_memberships
                                    />
                                    <Occupancy label="Certificates held" table=m.cert_store />
                                }
                                    .into_any()
                            })
                    }}
                </Panel>
            </div>
        </div>
    }
}

/// One `used / capacity` row with a fill bar.
///
/// The bar is what makes this scannable: an operator is looking for the one row
/// that is nearly full, and finding it by reading five pairs of numbers is
/// exactly the work a dashboard should be doing for them.
#[component]
fn Occupancy(
    /// What the table holds, in plain language.
    #[prop(into)]
    label: String,
    /// The occupancy figures, absent when the node did not report them.
    table: Option<TableOccupancy>,
) -> impl IntoView {
    let Some(table) = table else {
        return view! {
            <div class="wf-field">
                <span class="wf-field-label">{label}</span>
                <span class="wf-field-value">"—"</span>
            </div>
        }
        .into_any();
    };

    // A zero capacity means the node reported no such table (auth disabled, say),
    // not a full one — it has to read as empty rather than as 100%.
    let percent = (table.used * 100).checked_div(table.capacity).unwrap_or(0);
    // Inverted against the link-quality bar on purpose: there, full is good;
    // here, full means the next entry gets dropped.
    let band = if percent >= 90 {
        "wf-bar-fill wf-bar-poor"
    } else if percent >= 70 {
        "wf-bar-fill wf-bar-fair"
    } else {
        "wf-bar-fill wf-bar-good"
    };

    view! {
        <div class="wf-occupancy">
            <span class="wf-field-label">{label}</span>
            <div class="wf-bar-wrap">
                <div class="wf-bar">
                    <div class=band style=format!("width:{}%", percent.min(100)) />
                </div>
                <span class="wf-bar-text wf-mono">
                    {format!("{} / {}", table.used, table.capacity)}
                </span>
            </div>
        </div>
    }
    .into_any()
}
