//! The Links tab: what each interface is allowed to carry, and how often it
//! announces itself.
//!
//! The only tab so far that changes the node rather than describing it. The four
//! participation gates are switchable in place, with no confirmation step: one
//! gate is low-stakes and trivially reversible, unlike the Security tab's
//! actions. What makes them safe to expose is that each says in plain language
//! what closing it does — "stop announcing routes on this link" rather than
//! `tx_ogm`.
//!
//! A flip is applied optimistically and then confirmed by the next poll. The
//! node is the authority: if the change did not take, the switch snaps back
//! within a second rather than lying about the node's state.

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesEntry;
use wayfinder_protos::wayfinder::v1alpha::OgmSchedule;

use crate::api::Gate;
use crate::api::set_link_gate;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::Empty;
use crate::components::widgets::Field;
use crate::components::widgets::Panel;
use crate::format;

/// Render the Links tab.
#[component]
pub fn Links() -> impl IntoView {
    let dash = use_dashboard();
    let (selected, set_selected) = signal::<Option<u32>>(None);

    let entries = move || {
        dash.snapshot
            .with(|s| s.as_ref().map(|s| s.link_features.entries.clone()))
            .unwrap_or_default()
    };
    let schedule = move || {
        dash.snapshot
            .with(|s| s.as_ref().map(|s| s.ogm_schedule.clone()))
            .unwrap_or_default()
    };

    view! {
        <div class="wf-split">
            <Panel title="Interfaces">
                {move || {
                    let rows = entries();
                    if rows.is_empty() {
                        return view! {
                            <Empty message=if dash.has_data() {
                                "No interfaces configured."
                            } else {
                                "Waiting for the node…"
                            } />
                        }
                            .into_any();
                    }
                    let sched = schedule();
                    view! {
                        <div class="wf-table-scroll">
                            <table class="wf-table">
                                <thead>
                                    <tr>
                                        <th class="wf-num">"Interface"</th>
                                        <th>"Carrying"</th>
                                        <th class="wf-num">"Announces every"</th>
                                        <th class="wf-num">"Heartbeat"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows
                                        .into_iter()
                                        .map(|e| {
                                            let idx = e.iface_idx;
                                            let status = format::gate_status(&e);
                                            let interval = ogm_interval(&sched, idx);
                                            let keepalive = e
                                                .tx_keepalive_interval_ms
                                                .map_or_else(
                                                    || "off".to_string(),
                                                    |ms| format::interval(ms as u32),
                                                );
                                            view! {
                                                <tr
                                                    class="wf-row"
                                                    class:wf-row-selected=move || {
                                                        selected.get() == Some(idx)
                                                    }
                                                    on:click=move |_| set_selected.set(Some(idx))
                                                >
                                                    <td class="wf-num">{idx}</td>
                                                    <td class=status.css_class()>{status.label()}</td>
                                                    <td class="wf-num">{interval}</td>
                                                    <td class="wf-num">{keepalive}</td>
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

            <Panel title="Participation">
                {move || {
                    // Default to the first interface: the common case is a node
                    // with one, where making someone click it first is friction
                    // with no purpose.
                    let rows = entries();
                    let chosen = selected.get().or_else(|| rows.first().map(|e| e.iface_idx));
                    let Some(entry) = chosen.and_then(|idx| {
                        rows.into_iter().find(|e| e.iface_idx == idx)
                    }) else {
                        return view! { <Empty message="No interface selected." /> }.into_any();
                    };
                    let sched = schedule();
                    view! { <LinkDetail entry=entry schedule=sched /> }.into_any()
                }}
            </Panel>
        </div>
    }
}

/// One interface's gates and emission schedule.
#[component]
fn LinkDetail(
    /// The interface's current gate state.
    entry: LinkFeaturesEntry,
    /// The node's OGM schedule, zipped by interface index.
    schedule: OgmSchedule,
) -> impl IntoView {
    let idx = entry.iface_idx;
    let sched = schedule
        .entries
        .iter()
        .find(|s| s.iface_idx == idx)
        .cloned();

    view! {
        <p class="wf-detail-head">"Interface " {idx}</p>

        <div class="wf-gates">
            <GateSwitch iface_idx=idx gate=Gate::TxOgm on=entry.tx_ogm />
            <GateSwitch iface_idx=idx gate=Gate::RxOgm on=entry.rx_ogm />
            <GateSwitch iface_idx=idx gate=Gate::TxData on=entry.tx_data />
            <GateSwitch iface_idx=idx gate=Gate::RxData on=entry.rx_data />
        </div>

        {sched
            .map(|s| {
                view! {
                    <div class="wf-detail-section">
                        <Field
                            label="Announcing every"
                            value=format::interval(s.current_interval_ms)
                            mono=true
                        />
                        <Field
                            label="Range"
                            value=format!(
                                "{} – {}",
                                format::interval(s.min_interval_ms),
                                format::interval(s.max_interval_ms),
                            )
                            mono=true
                        />
                    </div>
                }
            })}
    }
}

/// One gate, as a switch that applies immediately.
#[component]
fn GateSwitch(
    /// Interface to reconfigure.
    iface_idx: u32,
    /// Which gate this switch controls.
    gate: Gate,
    /// The gate's state as of the last poll.
    on: bool,
) -> impl IntoView {
    let dash = use_dashboard();
    // Seeded from the poll and flipped on click, so the switch responds at once
    // rather than a poll later. The next poll overwrites this component wholesale
    // with the node's own answer, which is what makes the optimism safe.
    let (checked, set_checked) = signal(on);

    let toggle = move |_| {
        let next = !checked.get();
        set_checked.set(next);
        leptos::task::spawn_local(async move {
            if let Err(e) = set_link_gate(iface_idx, gate, next).await {
                // Put the switch back and say so: a control that silently does
                // nothing is worse than one that reports it failed.
                set_checked.set(!next);
                dash.error
                    .set(Some(format!("could not change {}: {e}", gate.label())));
            }
        });
    };

    view! {
        <button
            type="button"
            role="switch"
            class="wf-gate"
            aria-checked=move || if checked.get() { "true" } else { "false" }
            title=gate.help()
            on:click=toggle
        >
            <span class="wf-gate-track" class:wf-gate-on=move || checked.get()>
                <span class="wf-gate-knob" />
            </span>
            <span class="wf-gate-label">
                <span class="wf-gate-name">{gate.label()}</span>
                <span class="wf-gate-help">{gate.help()}</span>
            </span>
        </button>
    }
}

/// The announcement interval for `iface_idx`, or a dash when the schedule has no
/// row for it.
///
/// Zipped by index rather than assumed positional: the two tables come from
/// separate RPCs and there is no guarantee they list interfaces in the same
/// order.
fn ogm_interval(schedule: &OgmSchedule, iface_idx: u32) -> String {
    schedule
        .entries
        .iter()
        .find(|s| s.iface_idx == iface_idx)
        .map_or_else(
            || "—".to_string(),
            |s| format::interval(s.current_interval_ms),
        )
}
