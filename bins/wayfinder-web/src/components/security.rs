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

use leptos::prelude::*;

use crate::api::approve_csr;
use crate::api::deny_csr;
use crate::api::revoke_node;
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
    /// The node the action applies to.
    node_mac: Vec<u8>,
    /// Which call to make on confirmation.
    kind: ActionKind,
}

/// Which management call a confirmed [`Pending`] performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionKind {
    /// Admit the node to the mesh.
    Approve,
    /// Refuse the node's request.
    Deny,
    /// Eject the node from the mesh.
    Revoke,
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
                ActionKind::Approve => approve_csr(action.node_mac).await,
                ActionKind::Deny => deny_csr(action.node_mac).await,
                ActionKind::Revoke => revoke_node(action.node_mac).await,
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
                                                                            node_mac: approve_mac.clone(),
                                                                            kind: ActionKind::Approve,
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
                                                                            node_mac: deny_mac.clone(),
                                                                            kind: ActionKind::Deny,
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
                                                                                                    node_mac: revoke_mac.clone(),
                                                                                                    kind: ActionKind::Revoke,
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
