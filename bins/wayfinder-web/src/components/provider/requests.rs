//! The Requests tab: nodes waiting to be admitted to the mesh.
//!
//! The other end of the Security tab's "Join a mesh" panel — that one asks,
//! this one decides. A request is a node's public keys and its MAC, and
//! approving it is a statement that those belong together and belong here; the
//! key is therefore on screen before either button is, because it is what is
//! being vouched for.
//!
//! # An empty queue is not an absent one
//!
//! Both render as no rows, and they are different facts: one says nobody is
//! waiting, the other says this node does not take requests at all. The second
//! is [`super::ProviderGate`]'s answer; this tab only ever renders the first.

use leptos::prelude::*;

use crate::api::approve_csr;
use crate::api::deny_csr;
use crate::components::dashboard::use_dashboard;
use crate::components::provider::ProviderGate;
use crate::components::provider::confirmation;
use crate::components::provider::report_failure;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::format;

/// Which decision a confirmed [`Pending`] carries out.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Decision {
    /// Admit the node with this MAC to the mesh.
    Approve(Vec<u8>),
    /// Refuse the request from the node with this MAC.
    Deny(Vec<u8>),
}

/// Render the Requests tab.
#[component]
pub fn Requests() -> impl IntoView {
    let dash = use_dashboard();
    let pending = RwSignal::new(None::<Pending<Decision>>);

    let csrs = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.pending_csrs.clone()))
            .map(|p| p.pending)
    };

    let confirm = move |decision: Decision| {
        let verb = match &decision {
            Decision::Approve(_) => "Approving",
            Decision::Deny(_) => "Denying",
        };
        leptos::task::spawn_local(async move {
            let result = match decision {
                Decision::Approve(mac) => approve_csr(mac).await,
                Decision::Deny(mac) => deny_csr(mac).await,
            };
            report_failure(dash, verb, result);
        });
    };

    view! {
        <ProviderGate>
            {move || {
                let requests = csrs().unwrap_or_default();
                let count = requests.len();
                view! {
                    <Panel
                        title="Requests to join"
                        subtitle=Signal::derive(move || format!("{count} waiting"))
                    >
                        {if requests.is_empty() {
                            view! { <Empty message="No nodes are waiting to join." /> }.into_any()
                        } else {
                            requests
                                .clone()
                                .into_iter()
                                .map(|csr| {
                                    let approve_mac = csr.node_mac.clone();
                                    let deny_mac = csr.node_mac.clone();
                                    view! {
                                        <div class="wf-csr">
                                            <div class="wf-csr-id">
                                                <span class="wf-mono">{format::id(&csr.node_mac)}</span>
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
                                                        pending
                                                            .set(
                                                                Some(Pending {
                                                                    prompt: format!(
                                                                        "Admit {} to the mesh? It will be able to route traffic.",
                                                                        format::id(&approve_mac),
                                                                    ),
                                                                    verb: "Approve",
                                                                    destructive: false,
                                                                    kind: Decision::Approve(approve_mac.clone()),
                                                                }),
                                                            )
                                                    }
                                                >
                                                    "Approve"
                                                </button>
                                                <button
                                                    class="wf-button"
                                                    on:click=move |_| {
                                                        pending
                                                            .set(
                                                                Some(Pending {
                                                                    prompt: format!(
                                                                        "Refuse {}'s request to join?",
                                                                        format::id(&deny_mac),
                                                                    ),
                                                                    verb: "Deny",
                                                                    destructive: false,
                                                                    kind: Decision::Deny(deny_mac.clone()),
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
            }}
            {confirmation(pending, confirm)}
        </ProviderGate>
    }
}
