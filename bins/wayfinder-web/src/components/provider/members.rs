//! The Members tab: who is in this mesh, and the one control that removes
//! them.
//!
//! The roster itself is also on the Security tab, and that duplication is
//! deliberate rather than an oversight. The two are answering different
//! questions from the same rows: Security asks "can this node verify its
//! neighbours?", which is a fact about the node an operator reads while
//! diagnosing a link, and it reports without acting. This tab asks "who is
//! still a member?", which only the mesh's certificate authority can change,
//! and the Revoke button is the whole reason it exists.
//!
//! # Why revocation is not left on the Security tab
//!
//! Revoking floods a statement every node in the mesh acts on and re-approving
//! does not undo it. It is a decision about *someone else's* membership, made
//! by the node that holds the mesh root key — which is the definition of this
//! scope. Leaving it inline on a generally-available tab put the single most
//! consequential control on the dashboard next to a link-quality reading.
//!
//! A node that is already revoked is offered no button: the revocation is
//! flooded and held, and re-sending it costs airtime to say something the mesh
//! already believes.

use leptos::prelude::*;

use crate::api::revoke_node;
use crate::components::dashboard::use_dashboard;
use crate::components::provider::ProviderGate;
use crate::components::provider::confirmation;
use crate::components::provider::report_failure;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::components::widgets::RowMore;
use crate::components::widgets::RowMoreHeader;
use crate::format;

/// Render the Members tab.
#[component]
pub fn Members() -> impl IntoView {
    let dash = use_dashboard();
    let pending = RwSignal::new(None::<Pending<Vec<u8>>>);

    let nodes = move || {
        dash.snapshot.with(|s| {
            s.as_ref()
                .and_then(|s| s.security.as_ref().map(|s| s.nodes.clone()))
        })
    };

    let confirm = move |mac: Vec<u8>| {
        leptos::task::spawn_local(async move {
            report_failure(dash, "Revoking", revoke_node(mac).await);
        });
    };

    view! {
        <ProviderGate>
            <Panel title="Members">
                {move || {
                    let Some(nodes) = nodes() else {
                        return view! { <Empty message="Waiting for the node…" /> }.into_any();
                    };
                    if nodes.is_empty() {
                        return view! {
                            <Empty message="This authority has certified no other node yet." />
                        }
                            .into_any();
                    }
                    view! {
                        <div class="wf-table-scroll">
                            <table class="wf-table">
                                <thead>
                                    <tr>
                                        <th>"Node"</th>
                                        <th>"Identity"</th>
                                        <th>"Certificate expires"</th>
                                        // Visually unlabelled — the column is
                                        // one button per row, and a heading
                                        // over it tells a sighted reader
                                        // nothing the button does not.
                                        <th>
                                            <span class="wf-sr-only">"Actions"</span>
                                        </th>
                                        <RowMoreHeader />
                                    </tr>
                                </thead>
                                <tbody>
                                    {nodes
                                        .into_iter()
                                        .map(|n| {
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
                                            let revoke_mac = n.node_id.clone();
                                            view! {
                                                <tr>
                                                    <td class="wf-mono" data-label="Node">
                                                        {format::id(&n.node_id)}
                                                    </td>
                                                    <td class=class data-label="Identity">
                                                        {state}
                                                    </td>
                                                    // Folded away behind the
                                                    // verdict beside it, as on
                                                    // the Security tab: it says
                                                    // when the row will change,
                                                    // not what it says now.
                                                    <td
                                                        class="wf-mono wf-cell-detail"
                                                        data-label="Certificate expires"
                                                    >
                                                        {expiry}
                                                    </td>
                                                    <td class="wf-num wf-row-actions">
                                                        {(!n.revoked)
                                                            .then(|| {
                                                                view! {
                                                                    <button
                                                                        class="wf-button wf-button-danger"
                                                                        on:click=move |_| {
                                                                            pending
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
                                                                                        kind: revoke_mac.clone(),
                                                                                    }),
                                                                                )
                                                                        }
                                                                    >
                                                                        "Revoke"
                                                                    </button>
                                                                }
                                                            })}
                                                    </td>
                                                    <RowMore />
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
            {confirmation(pending, confirm)}
        </ProviderGate>
    }
}
