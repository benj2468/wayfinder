//! The header's alarm strip: what the node believes is wrong, and the card
//! behind it.
//!
//! # Why this lives in the header
//!
//! Every other view here answers a question somebody went looking for. An alarm
//! is the opposite: it is the thing a person needs to know *without* having
//! thought to ask, which means it cannot live on a tab, because a tab is only
//! seen by someone who already suspects something. So it sits in the chrome,
//! beside the liveness dot, on every page — the two facts that are true
//! regardless of which view is open.
//!
//! # Why it speaks when nothing is wrong
//!
//! The strip is always present, and reads "All systems normal" on a healthy
//! node rather than disappearing. A badge that only appears on trouble is
//! indistinguishable from a badge that has stopped working, and an operator
//! cannot tell "checked, fine" from "never checked" — which is the failure
//! worth catching, since it is silent.
//!
//! # Opened by CSS, like the viewer strip
//!
//! The card opens on `:hover` and `:focus-within` in the stylesheet, with no
//! open/closed signal in the app. Same reasoning as `ViewerStrip`: there is no
//! state to get wrong, nothing to reset on a route change, and `:focus-within`
//! is what makes it reachable without a pointer — tab to the trigger and it
//! opens, which is also what a touch tap does.

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::Alarm;

use crate::components::dashboard::Dashboard;
use crate::format;

/// The header's alarm indicator, and the card of detail behind it.
#[component]
pub fn AlarmStrip(
    /// Shared dashboard state.
    dash: Dashboard,
) -> impl IntoView {
    // Read out of the snapshot rather than held separately: the board arrives on
    // the same poll as every table, so a second source of truth here could only
    // ever be a way for the header and the tabs to disagree about the same
    // instant.
    let board = Memo::new(move |_| {
        dash.snapshot
            .with(|s| s.as_ref().map(|s| s.alarms.clone()).unwrap_or_default())
    });
    let summary = Memo::new(move |_| board.with(format::summarize_board));

    // Worst-severity colour when something is firing; the all-clear colour
    // otherwise. Chosen here rather than in the stylesheet because "worst" is a
    // fact about the data, and the data is what this crate can test.
    let tone = move || {
        summary.with(|s| match s.worst {
            Some(worst) => format::alarm_severity_class(worst as i32),
            None => "wf-sev-clear",
        })
    };

    view! {
        <div class="wf-header-alarms">
            <button class=move || format!("wf-alarm-trigger {}", tone()) aria-haspopup="true">
                <span class="wf-alarm-mark" aria-hidden="true">
                    {move || if summary.with(|s| s.all_clear()) { "●" } else { "▲" }}
                </span>
                // In a span of its own so a narrow header can truncate the
                // headline rather than let it push the rest of the header off
                // the page — which is what it did, because the trigger's text
                // does not wrap and a flex item does not shrink below its
                // content. The mark beside it keeps its full meaning at any
                // width, so what a phone loses is the wording and not the
                // signal.
                <span class="wf-alarm-headline">
                    {move || board.with(|b| format::board_headline(format::summarize_board(b)))}
                </span>
                // The quiet count rides on the trigger rather than only in the
                // card: "nothing is wrong now, but something was" is a
                // different state from "nothing has been wrong", and the
                // difference is invisible if it takes a hover to see.
                {move || {
                    let quiet = summary.with(|s| s.quiet);
                    (quiet > 0 && summary.with(|s| s.all_clear()))
                        .then(|| {
                            view! { <span class="wf-alarm-quiet-count">{format!("· {quiet} recent")}</span> }
                        })
                }}
            </button>

            <div class="wf-alarm-card" role="status">
                <AlarmCard board=board />
            </div>
        </div>
    }
}

/// The card's contents: every row the node holds, worst first.
///
/// Every row, not only the firing ones. A condition that has stopped is dimmed
/// rather than dropped, because the board latches precisely so that somebody
/// who arrived after the burst still learns it happened — filtering on `active`
/// here would throw away the thing the node went to the trouble of keeping.
#[component]
fn AlarmCard(
    /// The board this poll reported.
    board: Memo<wayfinder_protos::wayfinder::v1alpha::Alarms>,
) -> impl IntoView {
    view! {
        {move || {
            board
                .with(|b| {
                    if b.alarms.is_empty() {
                        // An empty state that says why it is empty, per this
                        // crate's conventions — and here the "why" is the whole
                        // message, because an empty alarm board is good news
                        // and should read like it.
                        return view! {
                            <p class="wf-alarm-none">
                                "The node is holding no conditions. Nothing has gone wrong
                                since it started."
                            </p>
                        }
                            .into_any();
                    }
                    let now_ms = b.now_ms;
                    let rows: Vec<_> = b
                        .alarms
                        .iter()
                        .map(|a| view! { <AlarmRow alarm=a.clone() now_ms=now_ms /> })
                        .collect();
                    let dropped = b.dropped;
                    view! {
                        <ul class="wf-alarm-list">{rows}</ul>
                        // A gap is reported as a gap, exactly as a gap in the
                        // log stream is: a row that silently vanished would be
                        // indistinguishable from a condition that never
                        // happened.
                        {(dropped > 0)
                            .then(|| {
                                view! {
                                    <p class="wf-alarm-dropped">
                                        {format!(
                                            "{dropped} further condition(s) could not be recorded — the board was full.",
                                        )}
                                    </p>
                                }
                            })}
                    }
                        .into_any()
                })
        }}
    }
}

/// One condition: what it is, who it is about, how much of it there has been,
/// and when it was last seen.
#[component]
fn AlarmRow(
    /// The row to render.
    alarm: Alarm,
    /// The instant the node evaluated the board at, which every age here is
    /// measured back from.
    now_ms: u64,
) -> impl IntoView {
    let quiet = !alarm.active;
    let class = format!(
        "wf-alarm-row {}{}",
        format::alarm_severity_class(alarm.severity),
        if quiet { " wf-alarm-row-quiet" } else { "" }
    );
    let title = format::alarm_title(alarm.kind);
    let severity = format::alarm_severity(alarm.severity);
    let subject = format::alarm_subject(&alarm);
    let age = format::alarm_age(now_ms, alarm.last_ms);
    let started = format::alarm_age(now_ms, alarm.first_ms);
    let count = alarm.count;
    let detail = alarm.detail.clone();
    let code = format::alarm_code(alarm.kind);

    view! {
        <li class=class>
            <span class="wf-alarm-row-mark" aria-hidden="true" />
            <div class="wf-alarm-row-body">
                <div class="wf-alarm-row-head">
                    <span class="wf-alarm-row-title">{title}</span>
                    <span class="wf-alarm-row-sev">
                        // A condition that has gone quiet says so where its
                        // severity would otherwise be: it is the one fact about
                        // the row that changes what an operator should do about
                        // it, so it goes where the eye already is.
                        {if quiet { "stopped".to_string() } else { severity.to_string() }}
                    </span>
                </div>
                <div class="wf-alarm-row-meta">
                    <span class="wf-mono">{subject}</span>
                    <span class="wf-alarm-dot" aria-hidden="true">
                        "·"
                    </span>
                    <span>
                        {if count == 1 {
                            "seen once".to_string()
                        } else {
                            format!("seen {count} times")
                        }}
                    </span>
                    <span class="wf-alarm-dot" aria-hidden="true">
                        "·"
                    </span>
                    <span title=format!("first seen {started}")>{age}</span>
                </div>
                {(!detail.is_empty())
                    .then(|| view! { <div class="wf-alarm-row-detail wf-mono">{detail}</div> })}
                // The node's own name for the condition, last and quietest: it
                // is what to grep the logs for, not what to read first.
                <div class="wf-alarm-row-code wf-mono">{code}</div>
            </div>
        </li>
    }
}
