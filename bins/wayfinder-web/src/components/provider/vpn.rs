//! The VPN tab: the tunnel registrations that ride alongside mesh membership.
//!
//! A node's host may also join a coordinated tunnel when it enrolls, which is
//! how a mesh reaches across the internet rather than only across the air. That
//! registration outlives nothing on its own: removing it takes tunnel
//! reachability away and leaves mesh membership alone, which is why it is a
//! separate control from [`super::members`]'s revocation rather than a second
//! effect of it.
//!
//! # Three states that must not look alike
//!
//! * **No tunnel at all** — every deployment reaching the mesh over radio
//!   alone. The poll reports `None`, and the tab bar leaves this tab out
//!   entirely; arriving by URL gets the sentence below.
//! * **A tunnel nobody has joined** — an empty list, which is a real answer
//!   from a working coordination server.
//! * **A coordination server that is configured and unreachable** — which
//!   never lands here at all: it fails the whole poll, deliberately, because
//!   an empty peer list and a broken control plane must not look the same.
//!
//! A peer whose hostname is not one wayfinder registered has no MAC to show,
//! and is exactly the peer an operator most needs to see — it has tunnel
//! reachability with no mesh identity behind it. It is named by its raw
//! hostname rather than hidden, and its Remove button is disabled, because
//! there is no MAC to name in the call.

use leptos::prelude::*;

use crate::api::revoke_vpn_peer;
use crate::components::dashboard::use_dashboard;
use crate::components::provider::ProviderGate;
use crate::components::provider::confirmation;
use crate::components::provider::report_failure;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::format;

/// Render the VPN tab.
#[component]
pub fn Vpn() -> impl IntoView {
    let dash = use_dashboard();
    let pending = RwSignal::new(None::<Pending<Vec<u8>>>);

    let peers = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.vpn_peers.clone()))
            .map(|p| p.peers)
    };

    let confirm = move |mac: Vec<u8>| {
        leptos::task::spawn_local(async move {
            report_failure(
                dash,
                "Removing the VPN registration",
                revoke_vpn_peer(mac).await,
            );
        });
    };

    view! {
        <ProviderGate>
            {move || {
                let Some(peers) = peers() else {
                    return view! {
                        <Panel title="VPN peers">
                            <Empty message="This provider does not coordinate a tunnel. Its mesh is reached over its own links — nothing here applies to it." />
                        </Panel>
                    }
                        .into_any();
                };
                let count = peers.len();
                view! {
                    <Panel
                        title="VPN peers"
                        subtitle=Signal::derive(move || format!("{count} registered"))
                    >
                        {if peers.is_empty() {
                            view! {
                                <Empty message="No nodes have joined the tunnel yet. A node joins when it enrolls, if its host runs the tunnel daemon." />
                            }
                                .into_any()
                        } else {
                            peers
                                .clone()
                                .into_iter()
                                .map(|peer| {
                                    let revoke_mac = peer.node_mac.clone();
                                    let known = !peer.node_mac.is_empty();
                                    let label = if known {
                                        format::id(&peer.node_mac)
                                    } else {
                                        peer.raw_hostname.clone()
                                    };
                                    let confirm_label = label.clone();
                                    view! {
                                        <div class="wf-csr">
                                            <div class="wf-csr-id">
                                                <span class="wf-mono">{label}</span>
                                                <span class="wf-csr-key wf-mono">
                                                    {peer.tailscale_ip.clone()}
                                                </span>
                                                <span class="wf-csr-when">
                                                    {if peer.online {
                                                        "online".to_string()
                                                    } else if peer.last_seen_unix == 0 {
                                                        "never connected".to_string()
                                                    } else {
                                                        format!(
                                                            "last seen {}",
                                                            format::timestamp(peer.last_seen_unix as u64),
                                                        )
                                                    }}
                                                </span>
                                            </div>
                                            <div class="wf-csr-actions">
                                                <button
                                                    class="wf-button wf-button-danger"
                                                    on:click=move |_| {
                                                        pending
                                                            .set(
                                                                Some(Pending {
                                                                    prompt: format!(
                                                                        "Remove {confirm_label}'s VPN registration? It loses tunnel \
                                                                         reachability but keeps its mesh membership — revoke the node \
                                                                         itself to remove both.",
                                                                    ),
                                                                    verb: "Remove",
                                                                    destructive: true,
                                                                    kind: revoke_mac.clone(),
                                                                }),
                                                            )
                                                    }
                                                    disabled=!known
                                                >
                                                    "Remove"
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
                    .into_any()
            }}
            {confirmation(pending, confirm)}
        </ProviderGate>
    }
}
