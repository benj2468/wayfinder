//! The provider scope: what this node governs as the mesh's certificate
//! authority.
//!
//! The counterpart to [`crate::components::security`], and the line between
//! them is whose membership is being decided. Security is about *this* node —
//! who it believes it is, who it believes its neighbours are, what it refuses
//! to do without a certificate — and every viewer of the mesh has a reason to
//! read it. This scope is about the node's other job, which most nodes do not
//! have at all: deciding who *else* gets in, and ejecting who is already in.
//!
//! Five tabs, because they are five different sittings rather than one page an
//! operator scrolls: [`requests`] is a queue somebody is waiting in,
//! [`members`] is the roster and the one control that removes from it,
//! [`enrollment`] is the front door's policy and the details a joining node
//! must be told, [`accounts`] is who may make any of these decisions, and
//! [`vpn`] is the tunnel registration that rides alongside mesh membership.
//!
//! # Every tab is behind the same two gates
//!
//! [`ProviderGate`] asks both, so no tab can answer one and forget the other:
//!
//! * **An administrator.** The node refuses every call these tabs make to a
//!   read-only session — `list_users` is not even readable — so a rendered
//!   panel would be a promise the page had no business making. The tab bar
//!   already leaves them out ([`crate::session::Viewer::can_view`]), but a URL
//!   can be pasted and a bookmark can outlive a demotion, so the page says so
//!   itself.
//! * **A certificate authority.** A node that issues no certificates has no
//!   policy, no queue, no roster and no accounts. One sentence saying so beats
//!   five tabs of empty panels that each read as "nothing has happened yet".
//!
//! # Accounts are created here *and* from the CLI
//!
//! `wayfinderctl user` administers the same store over this same management
//! API — including the *first* account, which cannot be created by an account
//! because creating one needs the credential it creates: an operator on the
//! provider host presents the node's own identity seed instead, which
//! authenticates at the self-key tier. (It once did this by editing the
//! provider's state file; design 15 has why that raced the provider's own
//! writes.) What [`accounts`] adds is doing it without an SSH session — and it
//! is a real widening of the surface, since an admin session can now mint
//! another account. The trade is stated in the proto (`CreateUserRequest`): an admin
//! can already revoke nodes and rewrite the enrollment policy, so this grants
//! no new class of power, but it does put the user store on the network.

pub mod accounts;
pub mod enrollment;
pub mod members;
pub mod requests;
pub mod vpn;

use std::time::Duration;

use leptos::prelude::*;

use crate::components::dashboard::Dashboard;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::ConfirmDialog;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;

/// How long a copy button's "Copied" confirmation stays on screen.
///
/// Long enough to be read after the eye moves back from the button, short
/// enough that it is gone before it could be mistaken for a statement about a
/// *later* click.
const COPY_FLASH_FOR: Duration = Duration::from_secs(3);

/// The two questions every tab in this scope has to ask before rendering
/// anything, asked once.
///
/// Order matters, and it is capability first. "You may not see this" and "there
/// is nothing here" are different answers, and telling a read-only viewer that
/// a node is not a certificate authority would be answering a question they
/// were not allowed to ask.
#[component]
pub fn ProviderGate(
    /// What to render once both gates pass.
    children: ChildrenFn,
) -> impl IntoView {
    let dash = use_dashboard();
    // The same field the header's scope switch reads, so the switch and the
    // page it leads to cannot disagree about whether this node is an authority.
    let is_authority = Memo::new(move |_| {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.security.as_ref()?.enrollment))
            .is_some()
    });

    view! {
        {move || {
            if !dash.admin.get() {
                return view! {
                    <Panel title="Certificate authority">
                        <Empty message="Only an administrator can see how this mesh admits and ejects nodes. Everything about the node itself is on the router views." />
                    </Panel>
                }
                    .into_any();
            }
            if !is_authority.get() {
                return view! {
                    <Panel title="Certificate authority">
                        <Empty message="This node is not a certificate authority. Nothing here applies to it — the mesh's accounts and enrollment policy live on the node that holds the mesh root key." />
                    </Panel>
                }
                    .into_any();
            }
            view! { <div class="wf-stack">{children()}</div> }.into_any()
        }}
    }
}

/// The confirmation dialog, wired to a tab's own staged action.
///
/// A plain function rather than a `#[component]`, because it is generic over
/// what the action *is* and each tab's action type is its own — see
/// [`Pending`]. Five near-identical copies of this closure is what it replaces.
///
/// `pending` is where the tab stages an action; `on_confirm` runs once the
/// operator commits, and the staged action is cleared either way.
pub fn confirmation<K>(
    pending: RwSignal<Option<Pending<K>>>,
    on_confirm: impl Fn(K) + Copy + Send + Sync + 'static,
) -> impl IntoView
where
    K: Clone + Send + Sync + 'static,
{
    move || {
        pending.get().map(|action| {
            let kind = action.kind.clone();
            view! {
                <ConfirmDialog
                    prompt=action.prompt.clone()
                    verb=action.verb
                    destructive=action.destructive
                    on_confirm=Callback::new(move |()| {
                        pending.set(None);
                        on_confirm(kind.clone());
                    })
                    on_cancel=Callback::new(move |()| pending.set(None))
                />
            }
        })
    }
}

/// Report a failed mutation in the dashboard's banner and leave the panel
/// showing the node's state.
///
/// The next poll re-renders from what the node actually has, which is the
/// "node is the authority" rule: a change that did not take must visibly snap
/// back rather than being papered over locally.
///
/// `verb` is what was being attempted, as a gerund — "Revoking", "Approving" —
/// and is the first word of the banner.
pub fn report_failure<T, E: std::fmt::Display>(dash: Dashboard, verb: &str, result: Result<T, E>) {
    if let Err(e) = result {
        dash.error.set(Some(format!("{verb} failed: {e}")));
    }
}

/// A value an operator has to carry somewhere else: shown abbreviated or
/// masked, copied in full.
///
/// The copy button is the only way out of a masked field, so it reports what
/// actually happened — [`crate::clipboard::copy`] answers `false` when the
/// browser refused, and this says so rather than claiming a copy that did not
/// happen and leaving someone to paste whatever was on the clipboard before.
#[component]
pub fn CopyField(
    /// The field name.
    label: &'static str,
    /// What is drawn on screen. Never the full value when that is a secret.
    #[prop(into)]
    shown: Signal<String>,
    /// What the copy button puts on the clipboard, in full.
    #[prop(into)]
    value: Signal<String>,
) -> impl IntoView {
    // `None` until a copy is attempted, then the outcome for a few seconds.
    // Transient rather than sticky: it is feedback on one click, and a "Copied"
    // still sitting there a minute later says nothing true about the clipboard.
    let (flash, set_flash) = signal::<Option<&'static str>>(None);

    let copy = move |_| {
        let copied = crate::clipboard::copy(&value.get());
        set_flash.set(Some(if copied {
            "Copied"
        } else {
            "Could not copy — this browser refused clipboard access"
        }));
        leptos::leptos_dom::helpers::set_timeout(move || set_flash.set(None), COPY_FLASH_FOR);
    };

    view! {
        <div class="wf-copy-row">
            <span class="wf-copy-label">{label}</span>
            <span class="wf-copy-value wf-mono">{move || shown.get()}</span>
            <button
                type="button"
                class="wf-button wf-copy-button"
                aria-label=format!("Copy the {label} to the clipboard")
                title=format!("Copy the {label} to the clipboard")
                on:click=copy
            >
                // The word, not a clipboard emoji: this dashboard ships in a
                // container, and a minimal image has no emoji font — the glyph
                // renders as a tofu box there, leaving three unlabelled
                // buttons. Verified as exactly that in a headless browser.
                "Copy"
            </button>
            <span class="wf-copy-flash" aria-live="polite">
                {move || flash.get().unwrap_or_default()}
            </span>
        </div>
    }
}

/// Decode hex back to bytes, for handing a key to [`crate::format::key`].
///
/// The key arrives here already hex-encoded (it is what the copy button hands
/// out), and abbreviating it means counting bytes rather than characters. A
/// malformed pair yields no byte, so a garbled key abbreviates to something
/// visibly wrong rather than to something plausible.
fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .filter_map(|pair| {
            let pair = core::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format;

    /// The abbreviation the enrollment tab shows is derived from the same hex
    /// the copy button hands out, so the two cannot describe different keys.
    #[test]
    fn a_copied_key_and_its_abbreviation_agree() {
        let key = vec![0xab; 32];
        let hex = format::hex(&key);

        assert_eq!(hex_bytes(&hex), key, "the hex round-trips");
        assert_eq!(format::key(&hex_bytes(&hex)), format::key(&key));
    }
}
