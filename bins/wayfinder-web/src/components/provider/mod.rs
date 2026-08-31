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

use leptos::prelude::*;

use crate::components::dashboard::Dashboard;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::ConfirmDialog;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;

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
