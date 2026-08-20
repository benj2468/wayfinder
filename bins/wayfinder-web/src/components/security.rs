//! The Security tab: who the mesh believes each node is, and who may join.
//!
//! Everything here is read against the header at the top. With authentication
//! disabled, "unverified" is simply the normal state of every node and means
//! nothing is wrong; with it enabled, the same word means the node's identity
//! could not be established. Showing the rows without the header would make the
//! two indistinguishable.
//!
//! # The confirmation is the point
//!
//! Approving a request admits a node to the mesh. Revoking one floods a
//! revocation that every node acts on, and re-approving does not undo it. In a
//! terminal these sit behind a keystroke an operator had to know; in a browser
//! they are buttons anyone can reach, so each states what it is about to do,
//! names the node, and waits.
//!
//! The same reasoning governs the settings below them, but not uniformly —
//! confirmation is spent where an action is hard to walk back, not on every
//! control. Turning the fail-closed gate on can take this node off the mesh
//! mid-session; switching lazy cert distribution is a flag-day change no
//! un-upgraded peer survives; clearing the enrollment token opens the mesh to
//! anyone who can reach it. Those three ask. Tightening enrollment, or setting
//! a token, does not: making the mesh harder to join is trivially reversible,
//! and a dialog in front of every switch trains an operator to dismiss them.
//!
//! # What persists
//!
//! Whether a change outlives a restart is the node's decision, not this
//! dashboard's — a node configured with a runtime state path records what it
//! accepts, one without it does not. The dashboard therefore never claims a
//! setting is permanent; it shows what the node reports, and the next poll is
//! what confirms an edit took.

use std::time::Duration;

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;

use crate::api::request_enrollment;
use crate::api::revoke_node;
use crate::api::set_lazy_cert_distribution;
use crate::api::set_require_auth;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::ConfirmDialog;
use crate::components::widgets::Empty;
use crate::components::widgets::Field;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::enroll::EnrollmentOutcome;
use crate::enroll::ProviderTarget;
use crate::format;

/// How long to wait before asking a provider again about a request it is
/// holding for approval.
///
/// The operator approving it is a human in another window, so this is paced for
/// a person rather than a machine: long enough that a provider is not being
/// hammered while someone reads the request, short enough that the node picks
/// up its certificate while they are still watching this screen.
const APPROVAL_POLL: Duration = Duration::from_secs(5);

/// The parts of the security status the "join a mesh" panel is built from:
/// whether this node holds a certificate, and the mesh it belongs to.
///
/// Extracted, and deliberately narrow. Everything on this tab is re-read from a
/// snapshot that is replaced once a second, and that panel holds an address and
/// a token an operator is part-way through typing — so it is driven from a
/// [`Memo`] over *this*, which only fires when the node's membership actually
/// moves. Widening it to anything that changes on its own (a node list, a
/// timestamp, a revocation count) would rebuild the panel on every poll and
/// wipe the form mid-keystroke, which is a bug this once had.
fn membership_of(sec: &GetSecurityStatusResponse) -> (bool, u32) {
    (sec.auth_enabled, sec.mesh_id)
}

/// Which management call a confirmed [`Pending`] performs.
///
/// Each variant carries its own argument rather than the struct carrying a
/// `node_mac` every variant would have to share: only one of these is about
/// another node at all, and a settings change that had to name one would be
/// carrying a field it has no meaning for.
///
/// What is *not* here is what moved to the Provider tab — approving and denying
/// requests to join, and clearing the enrollment token. Those are decisions
/// about who else gets in; these are about this node.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SecurityAction {
    /// Eject the node with this MAC from the mesh.
    Revoke(Vec<u8>),
    /// Switch the fail-closed gate on or off.
    RequireAuth(bool),
    /// Switch lazy cert distribution on or off.
    LazyCertDistribution(bool),
    /// Ask this provider to admit the node — confirmed only when the node is
    /// already a member of some other mesh, which it would be leaving.
    Join(ProviderTarget),
}

/// How far a request to join a mesh has got.
///
/// "Waiting for an operator" is a state of its own rather than an error,
/// because it is the normal path on any provider that reviews requests: the
/// node has asked, correctly, and someone elsewhere has to say yes.
#[derive(Clone, Debug, PartialEq, Eq)]
enum JoinState {
    /// Nothing has been asked yet.
    Idle,
    /// A request is in flight.
    Asking,
    /// The provider is holding the request until an operator approves it. The
    /// target is kept so it can be asked again.
    Waiting(ProviderTarget),
    /// The node was admitted to the mesh with this id.
    Joined(u32),
    /// The provider refused, or the attempt could not be made at all.
    Failed(String),
}

/// Ask `target` to admit this node, folding the answer into `state`.
///
/// A held request re-asks itself on a timer: re-submitting an identical request
/// is how a certificate is collected once approved, and it costs the operator
/// nothing to watch. Any failure ends the loop — retrying a rejection or a bad
/// address would only bury the reason under repetition.
fn ask_to_join(state: RwSignal<JoinState>, target: ProviderTarget) {
    state.set(JoinState::Asking);
    leptos::task::spawn_local(async move {
        match request_enrollment(target.clone()).await {
            Ok(EnrollmentOutcome::Enrolled { mesh_id }) => {
                state.set(JoinState::Joined(mesh_id));
            }
            Ok(EnrollmentOutcome::AwaitingApproval) => {
                state.set(JoinState::Waiting(target.clone()));
                leptos::leptos_dom::helpers::set_timeout(
                    move || {
                        // Only re-ask if this is still what the screen is
                        // waiting on: an operator who has since asked something
                        // else must not have it overwritten by a stale timer.
                        if matches!(state.get_untracked(), JoinState::Waiting(ref t) if *t == target)
                        {
                            ask_to_join(state, target.clone());
                        }
                    },
                    APPROVAL_POLL,
                );
            }
            Ok(EnrollmentOutcome::Rejected { reason }) => {
                state.set(JoinState::Failed(format!("The provider refused: {reason}")));
            }
            Err(e) => state.set(JoinState::Failed(format!("{e}"))),
        }
    });
}

/// Render the Security tab.
#[component]
pub fn Security() -> impl IntoView {
    let dash = use_dashboard();
    let (pending, set_pending) = signal::<Option<Pending<SecurityAction>>>(None);
    let join = RwSignal::new(JoinState::Idle);

    let security = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.security.clone()))
    };
    let csrs = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.pending_csrs.clone()))
            .map(|p| p.pending)
    };

    // The two panels below own operator input — a provider address, a token, a
    // certificate lifetime — so neither may be rebuilt by a poll. A plain
    // closure over the snapshot would construct a fresh component every second
    // and reset its fields to empty; a `Memo` re-runs but only *notifies* when
    // its own value changes, so the panels are rebuilt when the thing they are
    // about changes and at no other time. See [`membership_of`].
    let membership = Memo::new(move |_| security().as_ref().map(membership_of));

    let confirm = move |kind: SecurityAction| {
        set_pending.set(None);
        // Joining runs its own state machine rather than reporting a one-shot
        // result, so it is dispatched before the uniform actions below.
        if let SecurityAction::Join(target) = kind {
            ask_to_join(join, target);
            return;
        }
        let verb = match &kind {
            SecurityAction::Revoke(_) => "Revoking",
            SecurityAction::RequireAuth(_) => "Changing the fail-closed gate",
            SecurityAction::LazyCertDistribution(_) => "Changing certificate distribution",
            SecurityAction::Join(_) => unreachable!("joining is dispatched above"),
        };
        leptos::task::spawn_local(async move {
            let result = match kind {
                SecurityAction::Revoke(mac) => revoke_node(mac).await,
                SecurityAction::RequireAuth(require) => set_require_auth(require).await,
                SecurityAction::LazyCertDistribution(enabled) => {
                    set_lazy_cert_distribution(enabled).await
                }
                SecurityAction::Join(_) => unreachable!("joining is dispatched above"),
            };
            if let Err(e) = result {
                dash.error.set(Some(format!("{verb} failed: {e}")));
            }
        });
    };

    view! {
        <div class="wf-stack">
            <Panel title="Mesh authentication">
                {move || {
                    let Some(sec) = security() else {
                        return view! { <Empty message="Waiting for the node…" /> }.into_any();
                    };
                    if !sec.auth_enabled {
                        return view! {
                            <Field label="Authentication" value="Disabled" />
                            <p class="wf-note">
                                "This mesh does not authenticate its members. Any node in range \
                                 can join and route traffic."
                            </p>
                        }
                            .into_any();
                    }
                    view! {
                        <Field label="Authentication" value="Enabled" />
                        <Field label="Mesh id" value=sec.mesh_id.to_string() mono=true />
                        <Field
                            label="This node"
                            value=format::id(&sec.node_mac)
                            mono=true
                        />
                        <Field
                            label="Certificate expires"
                            value=format::timestamp(sec.cert_not_after)
                            mono=true
                        />
                        <Field
                            label="Revocations held"
                            value=sec.revocation_count.to_string()
                        />
                    }
                        .into_any()
                }}
            </Panel>

            {move || {
                // A read-only account is not the one that decides which mesh
                // this node belongs to, and the node refuses the enrollment
                // call from their session — so the panel is omitted rather than
                // offered inert. Unlike the settings below it holds no state
                // worth reading: it is three empty fields and a button.
                if !dash.admin.get() {
                    return None;
                }
                membership
                    .get()
                    .map(|(enrolled, mesh_id)| {
                        view! {
                            <JoinMesh
                                enrolled=enrolled
                                mesh_id=mesh_id
                                state=join
                                set_pending=set_pending
                            />
                        }
                    })
            }}

            <Panel title="Security settings">
                {move || {
                    let Some(sec) = security() else {
                        return view! { <Empty message="Waiting for the node…" /> }.into_any();
                    };
                    // Both are read straight off the last poll, so a change
                    // made elsewhere — another operator, the CLI, the node's own
                    // config — shows up here rather than this tab believing
                    // whatever it last set.
                    let require_auth = sec.require_auth;
                    let lazy = sec.lazy_cert_distribution;
                    let has_cert = sec.auth_enabled;
                    view! {
                        <PostureSwitch
                            label="Refuse to run unauthenticated"
                            help="Stay off the mesh entirely until this node has a certificate. \
                                  Nothing is routed, received or announced while it does not."
                            on=require_auth
                            set_pending=set_pending
                            action=move |next| Pending {
                                prompt: if next && !has_cert {
                                    "Refuse to run unauthenticated? This node has no certificate, \
                                     so it will go off the mesh immediately and stay off until one \
                                     is installed — including anything that reaches this dashboard \
                                     through the mesh."
                                        .to_string()
                                } else if next {
                                    "Refuse to run unauthenticated? This node keeps routing while \
                                     its certificate is valid, but goes inert if it ever loses it."
                                        .to_string()
                                } else {
                                    "Allow running unauthenticated? If this node loses its \
                                     certificate it will keep routing in the open rather than \
                                     going inert."
                                        .to_string()
                                },
                                verb: if next { "Refuse" } else { "Allow" },
                                destructive: next && !has_cert,
                                kind: SecurityAction::RequireAuth(next),
                            }
                        />
                        <PostureSwitch
                            label="Send certificate fingerprints"
                            help="Announce an 8-byte fingerprint instead of the full certificate, \
                                  and fetch certificates on demand. The large airtime saving on a \
                                  slow link."
                            on=lazy
                            set_pending=set_pending
                            action=move |next| Pending {
                                prompt: if next {
                                    "Send certificate fingerprints? Every node on this mesh must \
                                     already be upgraded to understand them. Any node that is not \
                                     will stop being able to verify this one."
                                        .to_string()
                                } else {
                                    "Send full certificates on every announcement? This is \
                                     understood by every node, at a cost in airtime on slow links."
                                        .to_string()
                                },
                                verb: if next { "Send fingerprints" } else { "Send full certificates" },
                                destructive: next,
                                kind: SecurityAction::LazyCertDistribution(next),
                            }
                        />
                    }
                        .into_any()
                }}
            </Panel>

            <Panel title="Nodes">
                {move || {
                    let Some(sec) = security() else {
                        return view! { <Empty message="Waiting for the node…" /> }.into_any();
                    };
                    if sec.nodes.is_empty() {
                        return view! { <Empty message="No other nodes known yet." /> }.into_any();
                    }
                    // The column exists on a provider, which is the node that
                    // can actually act on a revocation — and only for a viewer
                    // who may ask for one.
                    let can_revoke = csrs().is_some() && dash.admin.get();
                    view! {
                        <div class="wf-table-scroll">
                            <table class="wf-table">
                                <thead>
                                    <tr>
                                        <th>"Node"</th>
                                        <th>"Identity"</th>
                                        <th>"Certificate expires"</th>
                                        {can_revoke.then(|| view! { <th></th> })}
                                    </tr>
                                </thead>
                                <tbody>
                                    {sec
                                        .nodes
                                        .clone()
                                        .into_iter()
                                        .map(|n| {
                                            let mac = n.node_id.clone();
                                            // Ordered by severity: revocation is a
                                            // statement about the node, verification
                                            // only about what we could establish.
                                            let (state, class) = if n.revoked {
                                                ("Revoked", "wf-status-off")
                                            } else if n.verified {
                                                ("Verified", "wf-status-on")
                                            } else {
                                                ("Unverified", "wf-status-mixed")
                                            };
                                            let expiry = if n.verified {
                                                format::timestamp(n.cert_not_after)
                                            } else {
                                                "—".to_string()
                                            };
                                            let revoke_mac = mac.clone();
                                            view! {
                                                <tr>
                                                    <td class="wf-mono">{format::id(&mac)}</td>
                                                    <td class=class>{state}</td>
                                                    <td class="wf-mono">{expiry}</td>
                                                    {can_revoke
                                                        .then(|| {
                                                            view! {
                                                                <td class="wf-num">
                                                                    {(!n.revoked)
                                                                        .then(|| {
                                                                            view! {
                                                                                <button
                                                                                    class="wf-button wf-button-danger"
                                                                                    on:click=move |_| {
                                                                                        set_pending
                                                                                            .set(
                                                                                                Some(Pending {
                                                                                                    prompt: format!(
                                                                                                        "Revoke {}? Every node in the mesh will drop its traffic. \
                                                                                                         This floods across the mesh and cannot be undone by \
                                                                                                         re-approving it.",
                                                                                                        format::id(&revoke_mac),
                                                                                                    ),
                                                                                                    verb: "Revoke",
                                                                                                    destructive: true,
                                                                                                    kind: SecurityAction::Revoke(revoke_mac.clone()),
                                                                                                }),
                                                                                            )
                                                                                    }
                                                                                >
                                                                                    "Revoke"
                                                                                </button>
                                                                            }
                                                                        })}
                                                                </td>
                                                            }
                                                        })}
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

            {move || {
                pending
                    .get()
                    .map(|action| {
                        let kind = action.kind.clone();
                        view! {
                            <ConfirmDialog
                                prompt=action.prompt.clone()
                                verb=action.verb
                                destructive=action.destructive
                                on_confirm=Callback::new(move |()| confirm(kind.clone()))
                                on_cancel=Callback::new(move |()| set_pending.set(None))
                            />
                        }
                    })
            }}
        </div>
    }
}

/// Ask a provider to admit this node to its mesh.
///
/// The counterpart to the "Requests to join" panel a provider shows: this is
/// the end that asks, that one is the end that decides. On a node with no
/// certificate this is the only control on the tab that changes anything about
/// its membership, so it sits directly under the header that says it has none.
///
/// The node's own keys are what get certified — nothing is generated here, and
/// no key material passes through the browser. The three fields are about the
/// *provider*: where it is, which key proves it is the right one, and the
/// token it asks for.
#[component]
fn JoinMesh(
    /// Whether the node already holds a membership certificate. Joining then
    /// means *leaving* the mesh it is in, which is what the confirmation is for.
    enrolled: bool,
    /// The mesh the node currently belongs to, named in that confirmation.
    mesh_id: u32,
    /// How far the current request has got.
    state: RwSignal<JoinState>,
    /// Where a staged confirmation is written for the dialog to pick up.
    set_pending: WriteSignal<Option<Pending<SecurityAction>>>,
) -> impl IntoView {
    let (address, set_address) = signal(String::new());
    let (key, set_key) = signal(String::new());
    let (token, set_token) = signal(String::new());

    let submit = move |_| {
        let target = ProviderTarget {
            address: address.get().trim().to_string(),
            node_key: key.get().trim().to_string(),
            token: token.get(),
        };
        if target.address.is_empty() || target.node_key.is_empty() {
            state.set(JoinState::Failed(
                "Enter the provider's address and its key.".to_string(),
            ));
            return;
        }
        // Asking to join while already a member replaces this node's
        // certificate and trust anchor: it leaves one mesh for another, and
        // stops being able to verify anyone it used to. Worth a question.
        // Joining from nothing takes nothing away, so it just goes.
        if enrolled {
            set_pending.set(Some(Pending {
                prompt: format!(
                    "Ask this provider to admit the node? It currently belongs to mesh {mesh_id:#x}, \
                     and being admitted elsewhere replaces that membership — it will no longer be \
                     able to verify the nodes it is with now.",
                ),
                verb: "Ask to join",
                destructive: true,
                kind: SecurityAction::Join(target),
            }));
        } else {
            ask_to_join(state, target);
        }
    };

    view! {
        <Panel title=if enrolled { "Move to another mesh" } else { "Join a mesh" }>
            <p class="wf-note">
                {if enrolled {
                    "Ask a different provider to certify this node. Its identity does not \
                     change — it keeps the same address on the mesh — but its membership \
                     moves."
                } else {
                    "This node has no certificate. Ask a provider to issue one: it keeps the \
                     identity and address it already has, and simply becomes a verified member \
                     of that provider's mesh."
                }}
            </p>

            <div class="wf-setting-row">
                <label class="wf-setting-label" for="wf-provider-address">
                    "Provider address"
                </label>
                <input
                    id="wf-provider-address"
                    class="wf-input"
                    type="text"
                    placeholder="host:port"
                    prop:value=move || address.get()
                    on:input=move |ev| set_address.set(event_target_value(&ev))
                />
            </div>
            <div class="wf-setting-row">
                <label class="wf-setting-label" for="wf-provider-key">
                    "Provider key"
                </label>
                <input
                    id="wf-provider-key"
                    class="wf-input wf-mono"
                    type="text"
                    placeholder="64 hex characters"
                    prop:value=move || key.get()
                    on:input=move |ev| set_key.set(event_target_value(&ev))
                />
            </div>
            <div class="wf-setting-row">
                <label class="wf-setting-label" for="wf-join-token">
                    "Enrollment token"
                </label>
                <input
                    id="wf-join-token"
                    class="wf-input"
                    type="password"
                    autocomplete="off"
                    placeholder="if the provider requires one"
                    prop:value=move || token.get()
                    on:input=move |ev| set_token.set(event_target_value(&ev))
                />
                <button
                    class="wf-button wf-button-primary"
                    disabled=move || matches!(state.get(), JoinState::Asking)
                    on:click=submit
                >
                    "Ask to join"
                </button>
            </div>
            <p class="wf-note">
                "The key pins the provider, so nothing else can answer in its place and \
                 enroll this node into the wrong mesh."
            </p>

            {move || match state.get() {
                JoinState::Idle => ().into_any(),
                JoinState::Asking => {
                    view! { <p class="wf-note">"Asking…"</p> }.into_any()
                }
                JoinState::Waiting(_) => {
                    view! {
                        <p class="wf-note wf-status-mixed">
                            "Waiting for an operator to approve this request on the provider. \
                             Asking again every few seconds — leave this open."
                        </p>
                    }
                        .into_any()
                }
                JoinState::Joined(mesh_id) => {
                    view! {
                        <p class="wf-note wf-status-on">
                            {format!(
                                "Admitted to mesh {mesh_id:#x}. The certificate is installed; the \
                                 panels above show it from the node's next poll.",
                            )}
                        </p>
                    }
                        .into_any()
                }
                JoinState::Failed(reason) => {
                    view! { <p class="wf-note wf-status-off">{reason}</p> }.into_any()
                }
            }}
        </Panel>
    }
}

/// One node-wide posture flag, as a switch that asks before it acts.
///
/// Unlike the Links tab's gates, which apply on click, both flags here can take
/// the node off the mesh — so the switch stages a [`Pending`] and the dialog
/// commits it. It therefore shows the node's state, never an optimistic one: an
/// operator who cancels must be left looking at what is actually in force.
///
/// For a read-only account it is drawn and disabled rather than omitted. The
/// two are not interchangeable here: "is this node refusing to run
/// unauthenticated?" is precisely the sort of question a read-only account is
/// signed in to answer, and a missing switch answers it with nothing. A
/// disabled one still carries `aria-checked`, so the state reads the same to a
/// screen reader as it does on screen.
#[component]
fn PostureSwitch(
    /// Plain-language name of the setting.
    label: &'static str,
    /// What turning it on actually does, beneath the label.
    help: &'static str,
    /// The setting's state as of the last poll.
    on: bool,
    /// Where the staged action is written for the dialog to pick up.
    set_pending: WriteSignal<Option<Pending<SecurityAction>>>,
    /// Builds the confirmation for flipping this switch to the given state.
    action: impl Fn(bool) -> Pending<SecurityAction> + Copy + Send + 'static,
) -> impl IntoView {
    let dash = use_dashboard();
    view! {
        <button
            type="button"
            role="switch"
            class="wf-gate"
            aria-checked=if on { "true" } else { "false" }
            title=help
            disabled=move || !dash.admin.get()
            on:click=move |_| set_pending.set(Some(action(!on)))
        >
            <span class="wf-gate-track" class:wf-gate-on=on>
                <span class="wf-gate-knob" />
            </span>
            <span class="wf-gate-label">
                <span class="wf-gate-name">{label}</span>
                <span class="wf-gate-help">{help}</span>
            </span>
        </button>
    }
}

#[cfg(test)]
mod tests {
    use wayfinder_protos::wayfinder::v1alpha::NodeSecurity;

    use super::*;

    /// The join panel is driven from `membership_of` precisely because it does
    /// *not* move when the rest of the security status does. A poll arrives
    /// once a second carrying a fresh node list and fresh timestamps; if any of
    /// that reached the projection, the panel would be rebuilt on every one of
    /// them and an operator would watch the address they were typing vanish.
    #[test]
    fn membership_ignores_everything_that_changes_on_its_own() {
        let mut before = GetSecurityStatusResponse {
            auth_enabled: true,
            mesh_id: 0xBEEF,
            ..Default::default()
        };
        let mut after = before.clone();
        // Everything a quiet second on a live mesh changes anyway.
        after.nodes.push(NodeSecurity {
            node_id: vec![0, 0, 0, 0, 0, 7],
            verified: true,
            cert_not_after: 1_800_000_000,
            revoked: false,
        });
        after.revocation_count = before.revocation_count + 1;
        after.cert_not_after = 1_900_000_000;

        assert_eq!(
            membership_of(&before),
            membership_of(&after),
            "a poll that changes none of the membership must not move the projection"
        );

        // And the two things that *are* about membership do move it, or the
        // panel would never notice the node being enrolled at all.
        before.auth_enabled = false;
        assert_ne!(membership_of(&before), membership_of(&after));
        before.auth_enabled = true;
        before.mesh_id = 0xF00D;
        assert_ne!(membership_of(&before), membership_of(&after));
    }
}
