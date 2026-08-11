//! The Routing tab: where this node can reach, and how.
//!
//! A row per destination with its chosen next hop, and — for a selected row —
//! the alternate paths BATMAN knows about. The alternates are the interesting
//! part: they are what turns "the route changed" from a mystery into a visible
//! consequence of one path's quality overtaking another's.

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::RoutingEntry;

use crate::components::dashboard::use_dashboard;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::QualityBar;
use crate::format;

/// Render the Routing tab.
#[component]
pub fn Routing() -> impl IntoView {
    let dash = use_dashboard();
    // Held as the destination's bytes rather than a row index: a table that
    // reorders between polls — which this one does, as qualities change — would
    // otherwise slide the selection onto a different node under the reader.
    let (selected, set_selected) = signal::<Option<Vec<u8>>>(None);

    let entries = move || {
        dash.snapshot
            .with(|s| s.as_ref().map(|s| s.routing.entries.clone()))
            .unwrap_or_default()
    };

    view! {
        <div class="wf-split">
            <Panel
                title="Destinations"
                subtitle=move || {
                    let n = entries().len();
                    if n == 1 { "1 node".to_string() } else { format!("{n} nodes") }
                }
            >
                {move || {
                    let rows = entries();
                    if rows.is_empty() {
                        return view! {
                            <Empty message=if dash.has_data() {
                                "No other nodes reachable yet."
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
                                        <th>"Destination"</th>
                                        <th>"Via"</th>
                                        <th>"Quality"</th>
                                        <th class="wf-num">"Paths"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows
                                        .into_iter()
                                        .map(|entry| {
                                            let dest = entry.destination.clone();
                                            let is_selected = {
                                                let dest = dest.clone();
                                                move || selected.with(|s| s.as_ref() == Some(&dest))
                                            };
                                            view! {
                                                <tr
                                                    class="wf-row"
                                                    class:wf-row-selected=is_selected
                                                    on:click=move |_| set_selected.set(Some(dest.clone()))
                                                >
                                                    <td class="wf-mono">
                                                        {format::id(&entry.destination)}
                                                    </td>
                                                    <td class="wf-mono">{format::id(&entry.next_hop)}</td>
                                                    <td>
                                                        <QualityBar
                                                            percent=format::tq_percent(entry.tq)
                                                            title=format!("TQ {}", entry.tq)
                                                        />
                                                    </td>
                                                    <td class="wf-num">{entry.paths.len()}</td>
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

            <Panel title="Paths">
                {move || {
                    let Some(entry) = selected
                        .with(|sel| {
                            sel.as_ref()
                                .and_then(|dest| {
                                    entries().into_iter().find(|e| &e.destination == dest)
                                })
                        })
                    else {
                        return view! {
                            <Empty message="Select a destination to see its alternate paths." />
                        }
                            .into_any();
                    };
                    view! { <PathDetail entry=entry /> }.into_any()
                }}
            </Panel>
        </div>
    }
}

/// Every path to one destination, best first, with the chosen one marked.
#[component]
fn PathDetail(
    /// The routing entry whose paths to break down.
    entry: RoutingEntry,
) -> impl IntoView {
    let next_hop = entry.next_hop.clone();
    let mut paths = entry.paths.clone();
    // Best first, so the chosen path is at the top and a challenger closing the
    // gap is the row directly beneath it.
    paths.sort_by_key(|p| std::cmp::Reverse(p.tq));

    view! {
        <p class="wf-detail-head">
            "To " <span class="wf-mono">{format::id(&entry.destination)}</span>
        </p>
        {if paths.is_empty() {
            view! { <Empty message="No path detail reported." /> }.into_any()
        } else {
            view! {
                <div class="wf-table-scroll">
                    <table class="wf-table">
                        <thead>
                            <tr>
                                <th>"Neighbour"</th>
                                <th>"Quality"</th>
                                <th class="wf-num">"Last seq"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {paths
                                .into_iter()
                                .map(|path| {
                                    let chosen = path.neighbor_id == next_hop;
                                    view! {
                                        <tr class:wf-row-chosen=chosen>
                                            <td class="wf-mono">
                                                {format::id(&path.neighbor_id)}
                                                {chosen
                                                    .then(|| view! { <span class="wf-tag">"in use"</span> })}
                                            </td>
                                            <td>
                                                <QualityBar
                                                    percent=format::tq_percent(path.tq)
                                                    title=format!("TQ {}", path.tq)
                                                />
                                            </td>
                                            <td class="wf-num wf-mono">{path.last_seqno}</td>
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
    }
}
