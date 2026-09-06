//! The Logs tab: the node's own record of what it has been doing.
//!
//! On a board with no debug probe attached this is the only way to read its logs
//! at all — the node keeps a bounded ring and the management API serves it. The
//! dashboard accumulates far more scrollback than any node retains (see
//! [`crate::state::LOG_SCROLLBACK`]), because the two bound different things:
//! the node's ring bounds what is lost while nobody is polling, this bounds what
//! an operator can scroll back through in a session.
//!
//! Two details carry most of the value here. Records evicted before this client
//! read them appear as a gap **in stream position**, not as a counter in a
//! corner — a discontinuity between two adjacent lines is exactly the thing a
//! reader must not have to infer — and it stays between the two records it fell
//! between, which under newest-first ordering means the later one precedes it.
//! And the filter line reports what the *node*
//! says is in force, which is not necessarily what this client asked for: it
//! survives a node restart, a startup `RUST_LOG` this session never set, and a
//! change made by somebody else.

use leptos::prelude::*;

use crate::api::set_log_level;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::format;
use crate::state::LogEntry;

/// Render the Logs tab.
#[component]
pub fn Logs() -> impl IntoView {
    let dash = use_dashboard();
    // The edit buffer is separate from the filter in force, so a poll landing
    // mid-word cannot rewrite the field under the cursor.
    let (draft, set_draft) = signal::<Option<String>>(None);

    let filter = move || dash.history.with(|h| h.filter.clone());
    let entries = move || dash.history.with(|h| h.entries.clone());
    // Whether the last poll declined to ask for the ring at all, read from the
    // snapshot rather than inferred from the viewer's capability — see the
    // empty state below for why the two are not interchangeable.
    let logs_withheld = move || {
        dash.snapshot
            .with(|s| s.as_ref().is_some_and(|s| s.logs.is_none()))
    };

    let submit = move || {
        let Some(spec) = draft.get() else { return };
        set_draft.set(None);
        leptos::task::spawn_local(async move {
            match set_log_level(spec).await {
                // The node answers with what it actually applied; the next poll
                // reports the same thing, so nothing is written back here.
                Ok(_) => dash.error.set(None),
                // A rejected spec is a well-formed answer, not a lost node: the
                // previous filter is still running and the line still shows it.
                Err(e) => dash.error.set(Some(format!("log filter rejected: {e}"))),
            }
        });
    };

    view! {
        <div class="wf-stack">
            <Panel title="Filter" subtitle="what the node is currently recording">
                {move || {
                    match draft.get() {
                        None => {
                            view! {
                                <div class="wf-filter">
                                    <code class="wf-filter-current">
                                        {move || {
                                            let f = filter();
                                            if f.is_empty() { "—".to_string() } else { f }
                                        }}
                                    </code>
                                    // `SetLogLevel` re-aims what the node
                                    // records for everyone reading it, so it is
                                    // an administrator's call.
                                    //
                                    // The filter line above used to be shown to
                                    // everybody on the argument that it
                                    // separates "nothing is happening" from
                                    // "nothing is being recorded". It no longer
                                    // can be: the node reports the filter in
                                    // force on the `GetLogs` *response*, and a
                                    // read-only session does not make that call,
                                    // so the line reads "—" for a viewer no
                                    // matter what the node is doing. The empty
                                    // state below is what answers the question
                                    // for them instead. Carrying the filter on a
                                    // read a viewer does hold — `GetNodeInfo` —
                                    // would restore it for one string.
                                    {move || {
                                        dash.admin
                                            .get()
                                            .then(|| {
                                                view! {
                                                    <button
                                                        class="wf-button"
                                                        on:click=move |_| set_draft.set(Some(filter()))
                                                    >
                                                        "Change"
                                                    </button>
                                                }
                                            })
                                    }}
                                </div>
                            }
                                .into_any()
                        }
                        Some(text) => {
                            view! {
                                <div class="wf-filter">
                                    <input
                                        class="wf-input wf-mono"
                                        prop:value=text
                                        placeholder="info,batman=trace"
                                        on:input=move |ev| {
                                            set_draft.set(Some(event_target_value(&ev)))
                                        }
                                        on:keydown=move |ev| {
                                            match ev.key().as_str() {
                                                "Enter" => submit(),
                                                "Escape" => set_draft.set(None),
                                                _ => {}
                                            }
                                        }
                                    />
                                    <button
                                        class="wf-button wf-button-primary"
                                        on:click=move |_| submit()
                                    >
                                        "Apply"
                                    </button>
                                    <button
                                        class="wf-button"
                                        on:click=move |_| set_draft.set(None)
                                    >
                                        "Cancel"
                                    </button>
                                </div>
                                <p class="wf-note">
                                    "A comma-separated list, most general first. \
                                     For example " <code>"info,batman=trace"</code>
                                    " records everything at info and above, plus all \
                                     routing-engine detail."
                                </p>
                            }
                                .into_any()
                        }
                    }
                }}
            </Panel>

            <Panel title="Records">
                {move || {
                    let rows = entries();
                    if rows.is_empty() {
                        return view! {
                            // Keyed on what the poll actually did, not on
                            // `dash.admin`. That signal defaults to `false` and
                            // is corrected only by a client-side `Effect`, so
                            // reading it first told an *administrator*, in
                            // server-rendered markup and every frame before
                            // hydration, that the ring was not theirs to read —
                            // a false statement to the one person it is false
                            // about. It also lags a mid-session demotion, where
                            // the poll is already being withheld.
                            //
                            // `logs.is_none()` is the poll's own answer, from
                            // the snapshot in front of us. "Waiting" comes
                            // first because before any snapshot there is
                            // nothing to have withheld.
                            <Empty message=if !dash.has_data() {
                                "Waiting for the node…"
                            } else if logs_withheld() {
                                "The node serves its log ring to an administrator, \
                                 or to a client holding the node's own key."
                            } else {
                                "Nothing recorded yet at the current filter."
                            } />
                        }
                            .into_any();
                    }
                    view! {
                        // Newest first. A terminal reads the other way, but a
                        // terminal is not repainting itself every second: here,
                        // putting the newest at the top means an arriving record
                        // appears where the reader is already looking, and there
                        // is no scroll position to keep pinned to the bottom —
                        // and so no fight with a reader who has scrolled up.
                        <div class="wf-logs">
                            {rows
                                .into_iter()
                                .rev()
                                .map(|entry| match entry {
                                    LogEntry::Record(r) => {
                                        view! {
                                            <div class="wf-log-row">
                                                <span class="wf-log-time wf-mono">
                                                    {format::log_uptime(r.uptime_ms)}
                                                </span>
                                                <span class=format!(
                                                    "wf-log-level {}",
                                                    format::level_class(r.level),
                                                )>{format::level_label(r.level)}</span>
                                                <span class="wf-log-target wf-mono">{r.target}</span>
                                                <span class="wf-log-message">{r.message}</span>
                                            </div>
                                        }
                                            .into_any()
                                    }
                                    LogEntry::Gap(n) => {
                                        view! {
                                            <div class="wf-log-gap">
                                                {format!(
                                                    "{n} record{} were dropped before this client read them",
                                                    if n == 1 { "" } else { "s" },
                                                )}
                                            </div>
                                        }
                                            .into_any()
                                    }
                                })
                                .collect_view()}
                        </div>
                    }
                        .into_any()
                }}
            </Panel>
        </div>
    }
}
