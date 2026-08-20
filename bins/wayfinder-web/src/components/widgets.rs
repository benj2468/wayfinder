//! Small presentational pieces the tabs share.
//!
//! Kept deliberately dumb: each takes already-formatted values and renders
//! markup. Anything that decides *what* a value should say belongs in
//! [`crate::format`], where it can be tested.

use leptos::prelude::*;

/// A titled card. The standard container for a table or a group of fields.
#[component]
pub fn Panel(
    /// Heading shown above the content.
    #[prop(into)]
    title: String,
    /// Optional secondary text beside the heading — a count, a unit, a caveat.
    /// Reactive, so a row count can track the table it sits above.
    #[prop(into, optional)]
    subtitle: Option<Signal<String>>,
    /// The card's contents.
    children: Children,
) -> impl IntoView {
    view! {
        <section class="wf-panel">
            <div class="wf-panel-head">
                <h2 class="wf-panel-title">{title}</h2>
                {subtitle.map(|s| view! { <span class="wf-panel-sub">{move || s.get()}</span> })}
            </div>
            {children()}
        </section>
    }
}

/// A `label: value` row, for identity and summary panels.
#[component]
pub fn Field(
    /// The field name.
    #[prop(into)]
    label: String,
    /// The already-formatted value. Reactive, so a field can track a signal
    /// without its whole panel having to re-render.
    #[prop(into)]
    value: Signal<String>,
    /// Render the value in the monospace face. On for identifiers and numbers,
    /// off for prose.
    #[prop(optional)]
    mono: bool,
) -> impl IntoView {
    let value_class = if mono {
        "wf-field-value wf-mono"
    } else {
        "wf-field-value"
    };

    view! {
        <div class="wf-field">
            <span class="wf-field-label">{label}</span>
            <span class=value_class>{move || value.get()}</span>
        </div>
    }
}

/// A headline number with a caption, for the metrics summary.
#[component]
pub fn Stat(
    /// What the number measures.
    #[prop(into)]
    label: String,
    /// The already-formatted number.
    #[prop(into)]
    value: String,
    /// Optional detail below the number — a capacity, a rate, a raw value.
    #[prop(into, optional)]
    detail: Option<String>,
) -> impl IntoView {
    view! {
        <div class="wf-stat">
            <span class="wf-stat-value">{value}</span>
            <span class="wf-stat-label">{label}</span>
            {detail.map(|d| view! { <span class="wf-stat-detail">{d}</span> })}
        </div>
    }
}

/// A 0–100% bar with its percentage beside it, for link quality.
///
/// The bar is what makes a table of these scannable: a reader sees which links
/// are weak from the shape of the column, without reading a single number.
/// `title` carries the underlying value for anyone who wants it.
#[component]
pub fn QualityBar(
    /// Fill level, 0–100.
    percent: u32,
    /// Tooltip text, conventionally the raw value the percentage came from.
    #[prop(into)]
    title: String,
) -> impl IntoView {
    let percent = percent.min(100);
    // Three bands rather than a continuous gradient: a reader is deciding
    // "is this link fine, marginal, or bad", not reading an exact hue.
    let band = if percent >= 75 {
        "wf-bar-fill wf-bar-good"
    } else if percent >= 40 {
        "wf-bar-fill wf-bar-fair"
    } else {
        "wf-bar-fill wf-bar-poor"
    };

    view! {
        <div class="wf-bar-wrap" title=title>
            <div class="wf-bar">
                <div class=band style=format!("width:{percent}%") />
            </div>
            <span class="wf-bar-text">{format!("{percent}%")}</span>
        </div>
    }
}

/// The quality column for a link that reports no physical-layer measurement.
///
/// Deliberately *not* a [`QualityBar`] at 0%: a metric-less transport (raw L2,
/// UDP, Unix) has no signal to measure, and such a link is usually excellent —
/// an empty red bar would read as a failing link and send an operator chasing a
/// problem that isn't there. Keeps the bar's footprint so the column stays
/// aligned against measured rows.
#[component]
pub fn QualityUnmeasured() -> impl IntoView {
    view! {
        <div
            class="wf-bar-wrap"
            title="This link exposes no signal metrics (wired or socket transport), so quality cannot be measured. It is not a weak link."
        >
            <div class="wf-bar" />
            <span class="wf-bar-text wf-bar-text-absent">"n/a"</span>
        </div>
    }
}

/// Placeholder shown where a table would be, when there is nothing in it.
///
/// Always says *why* it is empty rather than just showing blank space —
/// "no neighbours yet" and "not connected" produce the same empty table and
/// mean entirely different things.
#[component]
pub fn Empty(
    /// The reason there is nothing to show.
    #[prop(into)]
    message: String,
) -> impl IntoView {
    view! { <p class="wf-empty">{message}</p> }
}

/// An action awaiting confirmation, held until the operator commits or cancels.
///
/// Generic over what the action *is*, because the two tabs that raise one have
/// nothing in common but the dialog: the Security tab revokes and switches
/// postures, the Provider tab approves and denies. Sharing the enum instead
/// would give each tab a set of variants it must handle and can never receive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending<K> {
    /// What will happen, in plain language, for the dialog body.
    pub prompt: String,
    /// The label on the confirming button.
    pub verb: &'static str,
    /// Whether this is the destructive kind, which the dialog styles louder.
    pub destructive: bool,
    /// Which call to make on confirmation.
    pub kind: K,
}

/// The modal that stands between a consequential button and what it does.
///
/// Not generic itself — it renders three already-decided values — so the
/// `#[component]` machinery stays out of the way and each tab keeps its own
/// action type.
///
/// # Why anything is behind one at all
///
/// Revoking a node floods a revocation every node acts on and re-approving does
/// not undo it; the fail-closed gate can take a node off the mesh mid-session.
/// In a terminal those sit behind a keystroke an operator had to know; in a
/// browser they are buttons anyone can reach. What is *not* behind one matters
/// as much: making a mesh harder to join is trivially reversible, and a dialog
/// in front of every switch trains an operator to dismiss them.
#[component]
pub fn ConfirmDialog(
    /// What will happen, in plain language.
    #[prop(into)]
    prompt: String,
    /// The label on the confirming button.
    verb: &'static str,
    /// Whether to style the confirming button as destructive.
    destructive: bool,
    /// Run when the operator commits.
    on_confirm: Callback<()>,
    /// Run when the operator backs out.
    on_cancel: Callback<()>,
) -> impl IntoView {
    view! {
        <div class="wf-modal-backdrop">
            <div class="wf-modal" role="alertdialog" aria-modal="true">
                <p class="wf-modal-body">{prompt}</p>
                <div class="wf-modal-actions">
                    <button class="wf-button" on:click=move |_| on_cancel.run(())>
                        "Cancel"
                    </button>
                    <button
                        class="wf-button"
                        class:wf-button-danger=destructive
                        class:wf-button-primary=!destructive
                        on:click=move |_| on_confirm.run(())
                    >
                        {verb}
                    </button>
                </div>
            </div>
        </div>
    }
}
