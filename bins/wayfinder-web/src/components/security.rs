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

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicyStatus;

use crate::api::TokenChange;
use crate::api::approve_csr;
use crate::api::deny_csr;
use crate::api::revoke_node;
use crate::api::set_enrollment_policy;
use crate::api::set_lazy_cert_distribution;
use crate::api::set_require_auth;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::Empty;
use crate::components::widgets::Field;
use crate::components::widgets::Panel;
use crate::format;

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
}

/// Render the Security tab.
#[component]
pub fn Security() -> impl IntoView {
    let dash = use_dashboard();
    let (pending, set_pending) = signal::<Option<Pending>>(None);

    let security = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.security.clone()))
    };
    let csrs = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.pending_csrs.clone()))
            .map(|p| p.pending)
    };

    let confirm = move || {
        let Some(action) = pending.get() else { return };
        set_pending.set(None);
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
                security()
                    .and_then(|sec| sec.enrollment)
                    .map(|policy| {
                        view! {
                            <EnrollmentSettings policy=policy set_pending=set_pending />
                        }
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
    let require_approval = policy.require_approval;
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
        let next = !require_approval;
        leptos::task::spawn_local(async move {
            let result = set_enrollment_policy(Some(next), None, TokenChange::Unchanged).await;
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
                aria-checked=if require_approval { "true" } else { "false" }
                title="Hold each request until an operator approves it here."
                on:click=toggle_approval
            >
                <span class="wf-gate-track" class:wf-gate-on=require_approval>
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
                "The token is never shown back — the node reports only whether one is set."
            </p>
        </Panel>
    }
}
