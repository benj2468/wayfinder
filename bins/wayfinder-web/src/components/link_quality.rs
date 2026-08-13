//! The Link Quality tab: how well this node hears each neighbour.
//!
//! Two views of the same relationship, deliberately side by side. Link quality
//! is a smoothed average of what has been heard over time; keep-alive liveness
//! is whether the neighbour's heartbeat is arriving *now*. A link can look
//! healthy by the first and be lapsed by the second — still OGM-fresh through a
//! relayed path while its direct heartbeat has stopped — and that gap is exactly
//! the early warning an operator wants before a route quietly moves.

use leptos::prelude::*;

use crate::components::dashboard::use_dashboard;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::QualityBar;
use crate::format;

/// Render the Link Quality tab.
#[component]
pub fn LinkQuality() -> impl IntoView {
    let dash = use_dashboard();

    let links = move || {
        dash.snapshot
            .with(|s| s.as_ref().map(|s| s.link_quality.entries.clone()))
            .unwrap_or_default()
    };
    let keepalive = move || {
        dash.snapshot
            .with(|s| s.as_ref().map(|s| s.keepalive.entries.clone()))
            .unwrap_or_default()
    };

    view! {
        <div class="wf-grid">
            <Panel title="Signal quality" subtitle="averaged over recent traffic">
                {move || {
                    let rows = links();
                    if rows.is_empty() {
                        return view! {
                            <Empty message=if dash.has_data() {
                                "No neighbours heard yet."
                            } else {
                                "Waiting for the node…"
                            } />
                        }
                            .into_any();
                    }
                    view! {
                        <div class="wf-table-scroll">
                            <table class="wf-table">
                                <thead>
                                    <tr>
                                        <th>"Neighbour"</th>
                                        <th>"Interface"</th>
                                        <th>"Quality"</th>
                                        <th class="wf-num">"Samples"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows
                                        .into_iter()
                                        .map(|e| {
                                            view! {
                                                <tr>
                                                    <td class="wf-mono">{format::id(&e.neighbor_id)}</td>
                                                    <td>{format::iface_label(&e.iface_name, e.iface_idx)}</td>
                                                    <td>
                                                        <QualityBar
                                                            percent=format::tq_percent(e.ewma_quality)
                                                            title=format!("EWMA {}", e.ewma_quality)
                                                        />
                                                    </td>
                                                    <td class="wf-num">{e.sample_count}</td>
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

            <Panel title="Heartbeats" subtitle="is the neighbour still answering">
                {move || {
                    let rows = keepalive();
                    if rows.is_empty() {
                        return view! {
                            <Empty message=if dash.has_data() {
                                "No heartbeats heard yet."
                            } else {
                                "Waiting for the node…"
                            } />
                        }
                            .into_any();
                    }
                    view! {
                        <div class="wf-table-scroll">
                            <table class="wf-table">
                                <thead>
                                    <tr>
                                        <th>"Neighbour"</th>
                                        <th>"Status"</th>
                                        <th class="wf-num">"Last heard"</th>
                                        <th class="wf-num">"Every"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows
                                        .into_iter()
                                        .map(|e| {
                                            // The cadence is 0 until a second heartbeat gives a
                                            // real gap to measure; showing "0 ms" would read as a
                                            // pathologically fast link rather than as "not known".
                                            let cadence = if e.interval_estimate_ms == 0 {
                                                "learning…".to_string()
                                            } else {
                                                format::interval(e.interval_estimate_ms as u32)
                                            };
                                            let (status, class) = if e.missed {
                                                ("Missed", "wf-status-off")
                                            } else {
                                                ("Answering", "wf-status-on")
                                            };
                                            view! {
                                                <tr>
                                                    <td class="wf-mono">{format::id(&e.neighbor_id)}</td>
                                                    <td class=class>{status}</td>
                                                    <td class="wf-num">
                                                        {format::interval(e.ms_since_last_heard as u32)}
                                                    </td>
                                                    <td class="wf-num">{cadence}</td>
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
        </div>
    }
}
