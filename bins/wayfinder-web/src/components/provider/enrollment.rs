//! The Enrollment tab: the mesh's front door, from the inside.
//!
//! One panel, and it is the *policy* this authority applies — whether a request
//! waits for someone, how long a certificate lasts, whether a token is
//! demanded. Deciding those is an administrator's job, which is why this tab
//! lives in the provider scope behind [`ProviderGate`].
//!
//! Each control submits on its own rather than the tab having one Save. An
//! operator closing open enrollment in a hurry should not also be resubmitting
//! a certificate lifetime they were halfway through editing.
//!
//! # What a joining node is *told* is not here
//!
//! The provider's address, its key and its token — the three values that go
//! into a joining node's "Join a mesh" panel — used to sit beside the policy,
//! as its other half. They now live next to that panel, on the Security tab
//! ([`crate::components::security`]), and the move was not tidying.
//!
//! Setting the policy and carrying a device to the mesh are two different jobs
//! done by two different people. The second needs an address and a key, neither
//! of which is a secret, and neither of which anyone can retype off a screen —
//! so leaving them in the administrators-only scope meant every device
//! enrolment went through somebody reading 64 characters of hex aloud. The
//! token is the one value there that *is* a secret, and it stays behind the
//! capability check on the panel itself rather than behind the whole tab.
//!
//! What is left here is a pointer, in the note under the token field: an
//! administrator who has just set a token is exactly the reader who then goes
//! looking for it.
//!
//! # The panel may not be rebuilt by a poll
//!
//! It holds operator input — a certificate lifetime, a token — and the
//! snapshot behind it is replaced once a second. A plain closure over it
//! constructs a *fresh* component every second, whose `signal(String::new())`
//! fields are re-created empty: the field is wiped mid-keystroke and the focus
//! goes with it. It is therefore driven from a [`Memo`] over the narrowest
//! projection it needs, since a memo re-runs but only *notifies* when its own
//! value changes. Widening that projection to something that moves on its own
//! — a node list, a timestamp — silently restores the bug, and no markup test
//! can see it.

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicyStatus;

use crate::api::TokenChange;
use crate::api::set_enrollment_policy;
use crate::components::dashboard::use_dashboard;
use crate::components::provider::ProviderGate;
use crate::components::provider::confirmation;
use crate::components::provider::report_failure;
use crate::components::widgets::Field;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::format;

/// The one action on this tab worth a confirmation: clearing the token opens
/// the mesh to anything that can reach this node. Setting one, or tightening
/// the policy, makes the mesh *harder* to join and is trivially reversible — a
/// dialog in front of every switch only trains an operator to dismiss them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClearEnrollmentToken;

/// Render the Enrollment tab.
#[component]
pub fn Enrollment() -> impl IntoView {
    let dash = use_dashboard();
    let pending = RwSignal::new(None::<Pending<ClearEnrollmentToken>>);

    let security = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.security.clone()))
    };
    // Memoised; see the module docs.
    let policy = Memo::new(move |_| security().and_then(|s| s.enrollment));

    let confirm = move |ClearEnrollmentToken| {
        leptos::task::spawn_local(async move {
            let result = set_enrollment_policy(None, None, TokenChange::Clear).await;
            report_failure(dash, "Removing the token", result);
        });
    };

    view! {
        <ProviderGate>
            {move || {
                policy
                    .get()
                    .map(|policy| view! { <EnrollmentSettings policy=policy pending=pending /> })
            }}
            {confirmation(pending, confirm)}
        </ProviderGate>
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
    pending: RwSignal<Option<Pending<ClearEnrollmentToken>>>,
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

    let toggle_approval = move |_| {
        // Flip the switch, then say it the way the node's field is spelled.
        let next_approval = !approval_required;
        let open = !next_approval;
        leptos::task::spawn_local(async move {
            let result = set_enrollment_policy(Some(open), None, TokenChange::Unchanged).await;
            report_failure(dash, "Changing the approval requirement", result);
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
            report_failure(dash, "Changing the certificate lifetime", result);
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
            report_failure(dash, "Setting the enrollment token", result);
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
                                    pending
                                        .set(
                                            Some(Pending {
                                                prompt: "Remove the token? Any node that can reach this \
                                                         one will then be able to join the mesh without \
                                                         presenting anything."
                                                    .to_string(),
                                                verb: "Remove token",
                                                destructive: true,
                                                kind: ClearEnrollmentToken,
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
                 copied from \"What a node needs to join\", on the Security tab, so setting \
                 a new one is not the way to find out what the old one was."
            </p>
        </Panel>
    }
}
