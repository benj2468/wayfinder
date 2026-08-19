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
use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicyStatus;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;

use crate::api::TokenChange;
use crate::api::approve_csr;
use crate::api::deny_csr;
use crate::api::request_enrollment;
use crate::api::reveal_enrollment_token;
use crate::api::revoke_node;
use crate::api::set_enrollment_policy;
use crate::api::set_lazy_cert_distribution;
use crate::api::set_require_auth;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::Empty;
use crate::components::widgets::Field;
use crate::components::widgets::Panel;
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

/// How long a copy button's "Copied" confirmation stays on screen.
///
/// Long enough to be read after the eye moves back from the button, short
/// enough that it is gone before it could be mistaken for a statement about a
/// *later* click.
const COPY_FLASH_FOR: Duration = Duration::from_secs(3);

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

/// An action awaiting confirmation, held until the operator commits or cancels.
#[derive(Clone, Debug, PartialEq)]
struct Pending {
    /// What will happen, in plain language, for the dialog body.
    prompt: String,
    /// The label on the confirming button.
    verb: &'static str,
    /// Whether this is the destructive kind, which the dialog styles louder.
    destructive: bool,
    /// Which call to make on confirmation.
    kind: ActionKind,
}

/// Which management call a confirmed [`Pending`] performs.
///
/// Each variant carries its own argument rather than the struct carrying a
/// `node_mac` every variant would have to share: only three of these are about
/// a node at all, and a settings change that had to name one would be carrying
/// a field it has no meaning for.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ActionKind {
    /// Admit the node with this MAC to the mesh.
    Approve(Vec<u8>),
    /// Refuse the request from the node with this MAC.
    Deny(Vec<u8>),
    /// Eject the node with this MAC from the mesh.
    Revoke(Vec<u8>),
    /// Switch the fail-closed gate on or off.
    RequireAuth(bool),
    /// Switch lazy cert distribution on or off.
    LazyCertDistribution(bool),
    /// Clear the shared enrollment token, opening enrollment.
    ClearEnrollmentToken,
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
    let (pending, set_pending) = signal::<Option<Pending>>(None);
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
    let enrollment = Memo::new(move |_| security().and_then(|s| s.enrollment));
    // What a joining node must be told, on a provider: the key that pins this
    // node and the token it will be asked for. Memoised on the same grounds,
    // though this panel has no input of its own — it is rendered from the same
    // poll and there is no reason to rebuild it either.
    let join_details = Memo::new(move |_| {
        security().and_then(|s| {
            s.enrollment
                .map(|policy| (format::hex(&s.own_ed_pubkey), policy.enrollment_token_set))
        })
    });

    let confirm = move || {
        let Some(action) = pending.get() else { return };
        set_pending.set(None);
        // Joining runs its own state machine rather than reporting a one-shot
        // result, so it is dispatched before the uniform actions below.
        if let ActionKind::Join(target) = action.kind {
            ask_to_join(join, target);
            return;
        }
        leptos::task::spawn_local(async move {
            let result = match action.kind {
                ActionKind::Approve(mac) => approve_csr(mac).await,
                ActionKind::Deny(mac) => deny_csr(mac).await,
                ActionKind::Revoke(mac) => revoke_node(mac).await,
                ActionKind::RequireAuth(require) => set_require_auth(require).await,
                ActionKind::LazyCertDistribution(enabled) => {
                    set_lazy_cert_distribution(enabled).await
                }
                ActionKind::ClearEnrollmentToken => {
                    set_enrollment_policy(None, None, TokenChange::Clear).await
                }
                ActionKind::Join(_) => unreachable!("joining is dispatched above"),
            };
            if let Err(e) = result {
                dash.error.set(Some(format!("{} failed: {e}", action.verb)));
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
                                kind: ActionKind::RequireAuth(next),
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
                                kind: ActionKind::LazyCertDistribution(next),
                            }
                        />
                    }
                        .into_any()
                }}
            </Panel>

            {move || {
                // Absent on a node that is not a certificate authority — a plain
                // member has no enrollment policy to show or to change.
                enrollment
                    .get()
                    .map(|policy| {
                        view! {
                            <EnrollmentSettings policy=policy set_pending=set_pending />
                        }
                    })
            }}

            {move || {
                // Provider-only, for the same reason: a node that issues no
                // certificates has nothing for a joining node to be given.
                join_details
                    .get()
                    .map(|(node_key, token_set)| {
                        view! { <ProviderJoinDetails node_key=node_key token_set=token_set /> }
                    })
            }}

            {move || {
                // Absent on a node that is not a certificate authority. Omitted
                // entirely rather than shown empty: an empty queue reads as "no
                // one is waiting", which is a different claim.
                csrs()
                    .map(|requests| {
                        let count = requests.len();
                        view! {
                            <Panel
                                title="Requests to join"
                                subtitle=Signal::derive(move || format!("{count} waiting"))
                            >
                                {if requests.is_empty() {
                                    view! { <Empty message="No nodes are waiting to join." /> }
                                        .into_any()
                                } else {
                                    requests
                                        .clone()
                                        .into_iter()
                                        .map(|csr| {
                                            let mac = csr.node_mac.clone();
                                            let approve_mac = mac.clone();
                                            let deny_mac = mac.clone();
                                            view! {
                                                <div class="wf-csr">
                                                    <div class="wf-csr-id">
                                                        <span class="wf-mono">{format::id(&mac)}</span>
                                                        <span class="wf-csr-key wf-mono">
                                                            {format::key(&csr.ed_pubkey)}
                                                        </span>
                                                        <span class="wf-csr-when">
                                                            "requested " {format::timestamp(csr.requested_at)}
                                                        </span>
                                                    </div>
                                                    <div class="wf-csr-actions">
                                                        <button
                                                            class="wf-button wf-button-primary"
                                                            on:click=move |_| {
                                                                set_pending
                                                                    .set(
                                                                        Some(Pending {
                                                                            prompt: format!(
                                                                                "Admit {} to the mesh? It will be able to route traffic.",
                                                                                format::id(&approve_mac),
                                                                            ),
                                                                            verb: "Approve",
                                                                            destructive: false,
                                                                            kind: ActionKind::Approve(approve_mac.clone()),
                                                                        }),
                                                                    )
                                                            }
                                                        >
                                                            "Approve"
                                                        </button>
                                                        <button
                                                            class="wf-button"
                                                            on:click=move |_| {
                                                                set_pending
                                                                    .set(
                                                                        Some(Pending {
                                                                            prompt: format!(
                                                                                "Refuse {}'s request to join?",
                                                                                format::id(&deny_mac),
                                                                            ),
                                                                            verb: "Deny",
                                                                            destructive: false,
                                                                            kind: ActionKind::Deny(deny_mac.clone()),
                                                                        }),
                                                                    )
                                                            }
                                                        >
                                                            "Deny"
                                                        </button>
                                                    </div>
                                                </div>
                                            }
                                        })
                                        .collect_view()
                                        .into_any()
                                }}
                            </Panel>
                        }
                    })
            }}

            <Panel title="Nodes">
                {move || {
                    let Some(sec) = security() else {
                        return view! { <Empty message="Waiting for the node…" /> }.into_any();
                    };
                    if sec.nodes.is_empty() {
                        return view! { <Empty message="No other nodes known yet." /> }.into_any();
                    }
                    let is_provider = csrs().is_some();
                    view! {
                        <div class="wf-table-scroll">
                            <table class="wf-table">
                                <thead>
                                    <tr>
                                        <th>"Node"</th>
                                        <th>"Identity"</th>
                                        <th>"Certificate expires"</th>
                                        {is_provider.then(|| view! { <th></th> })}
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
                                                    {is_provider
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
                                                                                                    kind: ActionKind::Revoke(revoke_mac.clone()),
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
                        view! {
                            <div class="wf-modal-backdrop">
                                <div class="wf-modal" role="alertdialog" aria-modal="true">
                                    <p class="wf-modal-body">{action.prompt.clone()}</p>
                                    <div class="wf-modal-actions">
                                        <button
                                            class="wf-button"
                                            on:click=move |_| set_pending.set(None)
                                        >
                                            "Cancel"
                                        </button>
                                        <button
                                            class="wf-button"
                                            class:wf-button-danger=action.destructive
                                            class:wf-button-primary=!action.destructive
                                            on:click=move |_| confirm()
                                        >
                                            {action.verb}
                                        </button>
                                    </div>
                                </div>
                            </div>
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
    set_pending: WriteSignal<Option<Pending>>,
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
                kind: ActionKind::Join(target),
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

/// What a node needs in order to ask *this* provider to admit it.
///
/// The other end of [`JoinMesh`]: that panel has three fields to fill in, and
/// this one is where the values come from. Handing them over is otherwise a
/// job of reading 64 hex characters aloud, or — for the token — of replacing a
/// working secret just to learn what it was, which kicks out every node still
/// holding the old one.
///
/// # Shown, hidden, and copied are three different things
///
/// Neither value is drawn in full. The key is abbreviated to its leading bytes,
/// which is enough to tell two providers apart but not to retype; the token is
/// masked outright. Both are copied to the clipboard in full. This is
/// deliberate: a dashboard on a screen someone else can see, or in a
/// screenshot pasted into a chat, must not be where the mesh's shared secret
/// leaks — but an operator who is deliberately handing it on should not be
/// fighting the UI to do it.
///
/// # The token is fetched, not polled
///
/// The snapshot behind this panel is refreshed once a second and says only
/// *whether* a token is required. The value arrives on its own request, when
/// the operator asks for it — which is the difference between a secret
/// disclosed continuously to everything that touches the snapshot and one
/// disclosed in a discrete act the node writes to its log.
#[component]
fn ProviderJoinDetails(
    /// This provider's own Ed25519 public key, as 64 hex characters — what the
    /// joining node pins so nothing else can answer in this one's place.
    node_key: String,
    /// Whether a token is required at all.  The authoritative flag, and the
    /// only part of the token that rides the poll.
    token_set: bool,
) -> impl IntoView {
    let dash = use_dashboard();
    let key_shown = format::key(&hex_bytes(&node_key));
    let key_value = node_key.clone();
    // The revealed token, once asked for. Local to this panel and dropped when
    // the operator navigates away.
    let (revealed, set_revealed) = signal(None::<String>);
    let reveal = move |_| {
        leptos::task::spawn_local(async move {
            match reveal_enrollment_token().await {
                // `None` is "no token required" — but this button is only
                // rendered when the poll says one is, so the two disagreeing
                // means the policy changed under the operator. Say so rather
                // than rendering an empty field.
                Ok(Some(token)) => set_revealed.set(Some(token)),
                Ok(None) => dash.error.set(Some(
                    "This provider no longer requires a token — enrollment is open.".to_string(),
                )),
                Err(e) => dash
                    .error
                    .set(Some(format!("Reading the token failed: {e}"))),
            }
        });
    };

    view! {
        <Panel title="What a node needs to join">
            <p class="wf-note">
                "These three go into the joining node's own \"Join a mesh\" panel, on its \
                 Security tab. Copy them rather than reading them out — the key is 64 \
                 characters and one wrong character reads as a provider that cannot be \
                 reached."
            </p>

            // Where this dashboard reaches the node, which is the address a
            // joining node needs too — subject to the one caveat in the note
            // below, that the two are not always on the same network.
            <CopyField
                label="Provider address"
                shown=Signal::derive(move || dash.label.get())
                value=Signal::derive(move || dash.label.get())
            />
            <CopyField
                label="Provider key"
                shown=key_shown
                value=key_value
            />
            {move || {
                if !token_set {
                    return view! {
                        <Field
                            label="Enrollment token"
                            value="Not required — anyone in range may join"
                        />
                    }
                        .into_any();
                }
                match revealed.get() {
                    Some(token) => {
                        view! {
                            <CopyField label="Enrollment token" shown="••••••••" value=token />
                        }
                            .into_any()
                    }
                    // Required, and not asked for yet. The button is the ask:
                    // until it is pressed the value has not left the node, and
                    // pressing it is what the node records.
                    None => {
                        view! {
                            <div class="wf-field">
                                <span class="wf-field-label">"Enrollment token"</span>
                                <button type="button" class="wf-btn" on:click=reveal>
                                    "Show token"
                                </button>
                            </div>
                        }
                            .into_any()
                    }
                }
            }}

            <p class="wf-note">
                "The address is the one this dashboard is pointed at. A node on a different \
                 network may have to reach this one at a different address; the key and the \
                 token do not change with it."
            </p>
        </Panel>
    }
}

/// Decode hex back to bytes, for handing a key to [`format::key`].
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

/// A value an operator has to carry somewhere else: shown abbreviated or
/// masked, copied in full.
///
/// The copy button is the only way out of a masked field, so it reports what
/// actually happened — [`crate::clipboard::copy`] answers `false` when the
/// browser refused, and this says so rather than claiming a copy that did not
/// happen and leaving someone to paste whatever was on the clipboard before.
#[component]
fn CopyField(
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

/// One node-wide posture flag, as a switch that asks before it acts.
///
/// Unlike the Links tab's gates, which apply on click, both flags here can take
/// the node off the mesh — so the switch stages a [`Pending`] and the dialog
/// commits it. It therefore shows the node's state, never an optimistic one: an
/// operator who cancels must be left looking at what is actually in force.
#[component]
fn PostureSwitch(
    /// Plain-language name of the setting.
    label: &'static str,
    /// What turning it on actually does, beneath the label.
    help: &'static str,
    /// The setting's state as of the last poll.
    on: bool,
    /// Where the staged action is written for the dialog to pick up.
    set_pending: WriteSignal<Option<Pending>>,
    /// Builds the confirmation for flipping this switch to the given state.
    action: impl Fn(bool) -> Pending + Copy + Send + 'static,
) -> impl IntoView {
    view! {
        <button
            type="button"
            role="switch"
            class="wf-gate"
            aria-checked=if on { "true" } else { "false" }
            title=help
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

/// The enrollment policy of a certificate-authority node: how a node asking to
/// join is admitted.
///
/// Only rendered on a provider. Each control submits on its own, rather than
/// the panel having one Save: an operator closing open enrollment in a hurry
/// should not also be resubmitting a certificate lifetime they were halfway
/// through editing.
#[component]
fn EnrollmentSettings(
    /// The policy as of the last poll.
    policy: EnrollmentPolicyStatus,
    /// Where a staged confirmation is written for the dialog to pick up.
    set_pending: WriteSignal<Option<Pending>>,
) -> impl IntoView {
    let dash = use_dashboard();
    // The switch is framed as the operator's own action — "approve by hand" —
    // which is the inverse of the posture the node reports. A control you turn
    // *on* to add a check reads correctly; one you turn off to add a check does
    // not, and this one guards who joins the mesh.
    let approval_required = !policy.auto_approve;
    let token_set = policy.enrollment_token_set;
    // Seeded from the node and edited locally. Not reseeded on every poll: that
    // would overwrite what the operator is in the middle of typing.
    let (ttl_input, set_ttl_input) = signal(policy.cert_ttl_secs.to_string());
    let (token_input, set_token_input) = signal(String::new());

    // Report a failed change and leave the panel showing the node's state —
    // the next poll re-renders from what the node actually has.
    let report = move |verb: &'static str, result: Result<(), ServerFnError>| {
        if let Err(e) = result {
            dash.error.set(Some(format!("{verb} failed: {e}")));
        }
    };

    let toggle_approval = move |_| {
        // Flip the switch, then say it the way the node's field is spelled.
        let next_approval = !approval_required;
        let open = !next_approval;
        leptos::task::spawn_local(async move {
            let result = set_enrollment_policy(Some(open), None, TokenChange::Unchanged).await;
            report("Changing the approval requirement", result);
        });
    };

    let save_ttl = move |_| {
        // Parsed here rather than leaning on the input's `type=number`: a
        // browser will happily hand back an empty string, and the node rejects
        // zero, so the operator gets the reason locally either way.
        let raw = ttl_input.get();
        let Ok(secs) = raw.trim().parse::<u64>() else {
            dash.error
                .set(Some(format!("\"{raw}\" is not a number of seconds")));
            return;
        };
        if secs == 0 {
            dash.error.set(Some(
                "A certificate lifetime of zero would issue certificates that have already \
                 expired."
                    .to_string(),
            ));
            return;
        }
        leptos::task::spawn_local(async move {
            let result = set_enrollment_policy(None, Some(secs), TokenChange::Unchanged).await;
            report("Changing the certificate lifetime", result);
        });
    };

    let save_token = move |_| {
        let value = token_input.get();
        if value.trim().is_empty() {
            dash.error.set(Some(
                "Enter a token, or clear the token to open enrollment.".to_string(),
            ));
            return;
        }
        leptos::task::spawn_local(async move {
            let result = set_enrollment_policy(None, None, TokenChange::Set(value)).await;
            report("Setting the enrollment token", result);
        });
        // Cleared whatever the outcome: leaving a shared secret sitting in a
        // form field in a browser is how it ends up on someone's screen.
        set_token_input.set(String::new());
    };

    view! {
        <Panel title="How nodes join">
            <button
                type="button"
                role="switch"
                class="wf-gate"
                aria-checked=if approval_required { "true" } else { "false" }
                title="Hold each request until an operator approves it here."
                on:click=toggle_approval
            >
                <span class="wf-gate-track" class:wf-gate-on=approval_required>
                    <span class="wf-gate-knob" />
                </span>
                <span class="wf-gate-label">
                    <span class="wf-gate-name">"Approve each request by hand"</span>
                    <span class="wf-gate-help">
                        "Hold every request to join until someone approves it below. \
                         With this off, a node that satisfies the token is admitted \
                         the moment it asks."
                    </span>
                </span>
            </button>

            <Field
                label="Certificates are valid for"
                value=format::duration_secs(policy.cert_ttl_secs)
            />
            <div class="wf-setting-row">
                <label class="wf-setting-label" for="wf-cert-ttl">
                    "New lifetime, in seconds"
                </label>
                <input
                    id="wf-cert-ttl"
                    class="wf-input"
                    type="number"
                    min="1"
                    prop:value=move || ttl_input.get()
                    on:input=move |ev| set_ttl_input.set(event_target_value(&ev))
                />
                <button class="wf-button" on:click=save_ttl>
                    "Save"
                </button>
            </div>
            <p class="wf-note">
                "Applies to certificates issued from now on. Keep it short — a mesh \
                 removes a node mainly by letting its certificate expire."
            </p>

            <Field
                label="Token required to join"
                value=if token_set { "Yes" } else { "No — anyone in range may join" }
            />
            <div class="wf-setting-row">
                <label class="wf-setting-label" for="wf-enrollment-token">
                    "New token"
                </label>
                <input
                    id="wf-enrollment-token"
                    class="wf-input"
                    type="password"
                    autocomplete="off"
                    prop:value=move || token_input.get()
                    on:input=move |ev| set_token_input.set(event_target_value(&ev))
                />
                <button class="wf-button" on:click=save_token>
                    "Set token"
                </button>
                {token_set
                    .then(|| {
                        view! {
                            <button
                                class="wf-button wf-button-danger"
                                on:click=move |_| {
                                    set_pending
                                        .set(
                                            Some(Pending {
                                                prompt: "Remove the token? Any node that can reach this \
                                                         one will then be able to join the mesh without \
                                                         presenting anything."
                                                    .to_string(),
                                                verb: "Remove token",
                                                destructive: true,
                                                kind: ActionKind::ClearEnrollmentToken,
                                            }),
                                        )
                                }
                            >
                                "Remove token"
                            </button>
                        }
                    })}
            </div>
            <p class="wf-note">
                "What you type here is not echoed. The token currently in force can be \
                 copied from the panel below, so setting a new one is not the way to find \
                 out what the old one was."
            </p>
        </Panel>
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

    /// The abbreviation the provider panel shows is derived from the same hex
    /// the copy button hands out, so the two cannot describe different keys.
    #[test]
    fn a_copied_key_and_its_abbreviation_agree() {
        let key = vec![0xab; 32];
        let hex = format::hex(&key);

        assert_eq!(hex_bytes(&hex), key, "the hex round-trips");
        assert_eq!(format::key(&hex_bytes(&hex)), format::key(&key));
    }
}
