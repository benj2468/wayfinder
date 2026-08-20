//! The Provider tab: what this node governs as the mesh's certificate
//! authority.
//!
//! Split out of the Security tab, which had grown to cover two different
//! questions at once. Security is about *this node* — who it believes it is,
//! who it believes its neighbours are, what it refuses to do without a
//! certificate. This tab is about the node's other job, which most nodes do not
//! have at all: deciding who else gets in. The accounts, the enrollment policy,
//! the details a joining node must be told, and the queue of nodes waiting.
//!
//! Every panel here is provider-only, so the whole tab is gated on one fact
//! from the poll — whether the node reports an enrollment policy. A node that
//! is not an authority gets one sentence saying so, rather than four empty
//! panels that read as "nothing has happened yet".
//!
//! # Accounts are created here *and* offline
//!
//! `wayfinderctl user` administers the same store against the provider's state
//! file, and remains the only way to create the *first* account: creating one
//! over the management API needs the credential it creates. What this tab adds
//! is every account after that, without an SSH session — and it is a real
//! widening of the surface, since an admin session can now mint another
//! account. The trade is stated in the proto (`CreateUserRequest`): an admin
//! can already revoke nodes and rewrite the enrollment policy, so this grants
//! no new class of power, but it does put the user store on the network.

use std::time::Duration;

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::EnrollmentPolicyStatus;
use wayfinder_protos::wayfinder::v1alpha::UserAccount;

use crate::api::TokenChange;
use crate::api::approve_csr;
use crate::api::create_user;
use crate::api::deny_csr;
use crate::api::list_users;
use crate::api::remove_user;
use crate::api::reveal_enrollment_token;
use crate::api::set_enrollment_policy;
use crate::components::dashboard::use_dashboard;
use crate::components::widgets::ConfirmDialog;
use crate::components::widgets::Empty;
use crate::components::widgets::Field;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::format;

/// How long a copy button's "Copied" confirmation stays on screen.
///
/// Long enough to be read after the eye moves back from the button, short
/// enough that it is gone before it could be mistaken for a statement about a
/// *later* click.
const COPY_FLASH_FOR: Duration = Duration::from_secs(3);

/// Which provider action a confirmed [`Pending`] performs.
///
/// Three, and all three are decisions about *other* nodes and the mesh's front
/// door — which is what makes them this tab's rather than the Security tab's.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ProviderAction {
    /// Admit the node with this MAC to the mesh.
    Approve(Vec<u8>),
    /// Refuse the request from the node with this MAC.
    Deny(Vec<u8>),
    /// Clear the shared enrollment token, opening enrollment.
    ClearEnrollmentToken,
}

/// Render the Provider tab.
#[component]
pub fn Provider() -> impl IntoView {
    let dash = use_dashboard();
    let pending = RwSignal::new(None::<Pending<ProviderAction>>);

    let security = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.security.clone()))
    };
    let csrs = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.pending_csrs.clone()))
            .map(|p| p.pending)
    };

    // Memoised for the reason the Security tab's panels are: the snapshot is
    // replaced once a second, and both panels below hold operator input — a
    // certificate lifetime, a token — that a rebuild would wipe mid-keystroke.
    let enrollment = Memo::new(move |_| security().and_then(|s| s.enrollment));
    let join_details = Memo::new(move |_| {
        security().and_then(|s| {
            s.enrollment
                .map(|policy| (format::hex(&s.own_ed_pubkey), policy.enrollment_token_set))
        })
    });

    let confirm = move |kind: ProviderAction| {
        pending.set(None);
        let verb = match &kind {
            ProviderAction::Approve(_) => "Approving",
            ProviderAction::Deny(_) => "Denying",
            ProviderAction::ClearEnrollmentToken => "Removing the token",
        };
        leptos::task::spawn_local(async move {
            let result = match kind {
                ProviderAction::Approve(mac) => approve_csr(mac).await,
                ProviderAction::Deny(mac) => deny_csr(mac).await,
                ProviderAction::ClearEnrollmentToken => {
                    set_enrollment_policy(None, None, TokenChange::Clear).await
                }
            };
            if let Err(e) = result {
                dash.error.set(Some(format!("{verb} failed: {e}")));
            }
        });
    };

    view! {
        <div class="wf-stack">
            {move || {
                // One gate for the whole tab. A node that issues no
                // certificates has no policy, no queue and no accounts, and
                // four empty panels would each have to explain that separately.
                if enrollment.get().is_none() {
                    return view! {
                        <Panel title="Certificate authority">
                            <Empty message="This node is not a certificate authority. Nothing here applies to it — the mesh's accounts and enrollment policy live on the node that holds the mesh root key." />
                        </Panel>
                    }
                        .into_any();
                }
                view! {
                    // Three of the four panels below exist only to change
                    // something, and a read-only account may change nothing —
                    // the node refuses every call they make, `list_users`
                    // included. They are omitted rather than disabled: a panel
                    // that cannot even load its own data has nothing to show in
                    // a disabled state, and a form nobody may submit is not
                    // information.
                    {move || dash.admin.get().then(|| view! { <Users /> })}
                    {move || {
                        if !dash.admin.get() {
                            return None;
                        }
                        enrollment
                            .get()
                            .map(|policy| {
                                view! { <EnrollmentSettings policy=policy pending=pending /> }
                            })
                    }}
                    {move || {
                        join_details
                            .get()
                            .map(|(node_key, token_set)| {
                                view! {
                                    <ProviderJoinDetails node_key=node_key token_set=token_set />
                                }
                            })
                    }}
            {move || {
                // Absent on a node that is not a certificate authority. Omitted
                // entirely rather than shown empty: an empty queue reads as "no
                // one is waiting", which is a different claim. Absent for a
                // read-only account too: the queue is a list of decisions, and
                // they are not the one deciding.
                if !dash.admin.get() {
                    return None;
                }
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
                                                                pending
                                                                    .set(
                                                                        Some(Pending {
                                                                            prompt: format!(
                                                                                "Admit {} to the mesh? It will be able to route traffic.",
                                                                                format::id(&approve_mac),
                                                                            ),
                                                                            verb: "Approve",
                                                                            destructive: false,
                                                                            kind: ProviderAction::Approve(approve_mac.clone()),
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
                                                                            kind: ProviderAction::Deny(deny_mac.clone()),
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


                }
                    .into_any()
            }}

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
                                on_cancel=Callback::new(move |()| pending.set(None))
                            />
                        }
                    })
            }}
        </div>
    }
}

/// The mesh's user accounts, and the form that adds one.
///
/// Not on the snapshot, deliberately. The roster changes when somebody creates
/// an account and at no other time, so it is fetched once and re-fetched after
/// a change rather than riding a once-a-second poll — which would also mean
/// re-rendering a form somebody is typing into, the failure this crate has
/// already had once.
///
/// # The enrolment URI is shown once
///
/// Creating an account with a second factor returns an `otpauth://` URI, and
/// the authority cannot serve it again: the secret is not recoverable from the
/// store. So the panel holds it on screen until the operator dismisses it, says
/// plainly that it will not be shown again, and offers it through the clipboard
/// rather than only as text on a screen someone else can see.
#[component]
fn Users() -> impl IntoView {
    let dash = use_dashboard();
    let users = Resource::new(|| (), |()| async move { list_users().await });

    let name = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let admin = RwSignal::new(false);
    let no_totp = RwSignal::new(false);
    // Empty means "the authority's default", which is what the wire's zero
    // means too — so an operator with no opinion states none.
    let ttl = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    // The account just created and the enrolment URI it will never show again.
    let created = RwSignal::new(None::<(String, String)>);

    // The panel's own pending action, rather than the tab's. `Pending` is
    // generic precisely so a panel keeps an action type it can actually
    // receive, and the roster's `Resource` — which the removal has to refetch —
    // lives here and nowhere else.
    let pending = RwSignal::new(None::<Pending<String>>);

    let confirm_removal = move |username: String| {
        pending.set(None);
        leptos::task::spawn_local(async move {
            match remove_user(username).await {
                // Wrong by exactly one row, the same as after a creation.
                Ok(()) => users.refetch(),
                Err(e) => dash
                    .error
                    .set(Some(format!("Removing the account failed: {e}"))),
            }
        });
    };

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        let raw_ttl = ttl.get_untracked();
        let session_ttl_secs = if raw_ttl.trim().is_empty() {
            0
        } else {
            match raw_ttl.trim().parse::<u64>() {
                Ok(secs) => secs,
                Err(_) => {
                    dash.error
                        .set(Some(format!("\"{raw_ttl}\" is not a number of seconds")));
                    return;
                }
            }
        };
        let username = name.get_untracked();
        busy.set(true);
        leptos::task::spawn_local(async move {
            let result = create_user(
                username.clone(),
                password.get_untracked(),
                admin.get_untracked(),
                session_ttl_secs,
                no_totp.get_untracked(),
            )
            .await;
            busy.set(false);
            // Cleared whatever the outcome: a password left in a form field is
            // a password left on screen.
            password.set(String::new());
            match result {
                Ok(uri) => {
                    name.set(String::new());
                    ttl.set(String::new());
                    created.set(Some((username, uri)));
                    // The roster is now wrong by exactly one row.
                    users.refetch();
                }
                Err(e) => dash
                    .error
                    .set(Some(format!("Creating the account failed: {e}"))),
            }
        });
    };

    view! {
        <Panel title="Accounts">
            <p class="wf-note">
                "Signing in to a dashboard obtains a short-lived certificate from this node. \
                 An administrator can change anything the management API exposes; a read-only \
                 account can look and change nothing."
            </p>

            <Suspense fallback=|| view! { <Empty message="Reading the accounts…" /> }>
                {move || {
                    Some(
                        match users.get()? {
                            Ok(list) if list.is_empty() => {
                                view! {
                                    <Empty message="No accounts yet. The first one is created offline, with `wayfinderctl user add`." />
                                }
                                    .into_any()
                            }
                            Ok(list) => {
                                view! {
                                    <UserTable
                                        users=list
                                        on_remove=Callback::new(move |username: String| {
                                            pending
                                                .set(
                                                    Some(Pending {
                                                        prompt: format!(
                                                            "Remove {username}? It can obtain no new sessions after this. \
                                                             A certificate already issued to it keeps working until it \
                                                             expires, so revoke that too if the account is compromised.",
                                                        ),
                                                        verb: "Remove",
                                                        destructive: true,
                                                        kind: username,
                                                    }),
                                                )
                                        })
                                    />
                                }
                                    .into_any()
                            }
                            Err(e) => {
                                view! {
                                    <Empty message=format!(
                                        "The accounts could not be read: {e}",
                                    ) />
                                }
                                    .into_any()
                            }
                        },
                    )
                }}
            </Suspense>

            {move || {
                created
                    .get()
                    .map(|(username, uri)| {
                        view! {
                            <div class="wf-note wf-note-strong">
                                <p>
                                    "Created " <span class="wf-mono">{username}</span> "."
                                    {(!uri.is_empty())
                                        .then_some({
                                            " Enrol this in an authenticator app now — it is not shown again."
                                        })}
                                </p>
                                {(!uri.is_empty())
                                    .then(|| {
                                        view! {
                                            <CopyField
                                                label="Authenticator setup"
                                                shown="••••••••"
                                                value=uri
                                            />
                                        }
                                    })}
                                <button class="wf-button" on:click=move |_| created.set(None)>
                                    "Done"
                                </button>
                            </div>
                        }
                    })
            }}

            <form class="wf-user-form" on:submit=submit>
                <div class="wf-setting-row">
                    <label class="wf-setting-label" for="wf-new-user">
                        "New account"
                    </label>
                    <input
                        id="wf-new-user"
                        class="wf-input"
                        type="text"
                        autocomplete="off"
                        placeholder="user name"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                    />
                    <input
                        class="wf-input"
                        type="password"
                        autocomplete="new-password"
                        placeholder="password"
                        prop:value=move || password.get()
                        on:input=move |ev| password.set(event_target_value(&ev))
                    />
                </div>
                <div class="wf-setting-row">
                    <label class="wf-setting-label" for="wf-new-user-ttl">
                        "Session length, in seconds"
                    </label>
                    <input
                        id="wf-new-user-ttl"
                        class="wf-input"
                        type="number"
                        min="1"
                        placeholder="default (8 hours)"
                        prop:value=move || ttl.get()
                        on:input=move |ev| ttl.set(event_target_value(&ev))
                    />
                </div>
                <label class="wf-check">
                    <input
                        type="checkbox"
                        prop:checked=move || admin.get()
                        on:change=move |ev| admin.set(event_target_checked(&ev))
                    />
                    "Administrator — may change anything, not only read it"
                </label>
                <label class="wf-check">
                    <input
                        type="checkbox"
                        prop:checked=move || no_totp.get()
                        on:change=move |ev| no_totp.set(event_target_checked(&ev))
                    />
                    "No authenticator code — the password is the whole credential"
                </label>
                <button
                    class="wf-button wf-button-primary"
                    type="submit"
                    disabled=move || busy.get()
                >
                    {move || if busy.get() { "Creating…" } else { "Create account" }}
                </button>
            </form>
            <p class="wf-note">
                "Disabling and renaming an account are done on the provider host with \
                 `wayfinderctl user`, which needs no network at all. The last account that \
                 can administer this mesh cannot be removed here — leaving none would mean \
                 no further change to this list from any dashboard."
            </p>

            {move || {
                pending
                    .get()
                    .map(|action| {
                        let username = action.kind.clone();
                        view! {
                            <ConfirmDialog
                                prompt=action.prompt.clone()
                                verb=action.verb
                                destructive=action.destructive
                                on_confirm=Callback::new(move |()| confirm_removal(username.clone()))
                                on_cancel=Callback::new(move |()| pending.set(None))
                            />
                        }
                    })
            }}
        </Panel>
    }
}

/// The account roster.
#[component]
fn UserTable(
    /// The accounts as the authority reported them.
    users: Vec<UserAccount>,
    /// Raise the confirmation for removing the named account.
    on_remove: Callback<String>,
) -> impl IntoView {
    view! {
        <div class="wf-table-scroll">
            <table class="wf-table">
                <thead>
                    <tr>
                        <th>"Account"</th>
                        <th>"Access"</th>
                        <th>"Session length"</th>
                        <th>"Second factor"</th>
                        <th>"Status"</th>
                        // Visually unlabelled — the column is one button per
                        // row, and a heading over it tells a sighted reader
                        // nothing the button does not. A non-visual reader has
                        // no such context, so the name is there for them.
                        <th>
                            <span class="wf-sr-only">"Actions"</span>
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {users
                        .into_iter()
                        .map(|u| {
                            // Ordered by what stops a sign-in: disabled is an
                            // operator's decision and permanent until reversed,
                            // locked is temporary and clears on its own.
                            let (status, class) = if u.disabled {
                                ("Disabled", "wf-status-off")
                            } else if u.locked {
                                ("Locked", "wf-status-mixed")
                            } else {
                                ("Active", "wf-status-on")
                            };
                            let username = u.username.clone();
                            view! {
                                <tr>
                                    <td class="wf-mono">{u.username}</td>
                                    <td>{if u.admin { "Administrator" } else { "Read-only" }}</td>
                                    <td>{format::duration_secs(u.session_ttl_secs)}</td>
                                    <td class=if u.totp_enrolled {
                                        "wf-status-on"
                                    } else {
                                        "wf-status-mixed"
                                    }>{if u.totp_enrolled { "Enrolled" } else { "None" }}</td>
                                    <td class=class>{status}</td>
                                    <td>
                                        <button
                                            class="wf-button"
                                            aria-label=format!("Remove {username}")
                                            on:click=move |_| on_remove.run(username.clone())
                                        >
                                            "Remove"
                                        </button>
                                    </td>
                                </tr>
                            }
                        })
                        .collect_view()}
                </tbody>
            </table>
        </div>
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
    pending: RwSignal<Option<Pending<ProviderAction>>>,
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
                                    pending
                                        .set(
                                            Some(Pending {
                                                prompt: "Remove the token? Any node that can reach this \
                                                         one will then be able to join the mesh without \
                                                         presenting anything."
                                                    .to_string(),
                                                verb: "Remove token",
                                                destructive: true,
                                                kind: ProviderAction::ClearEnrollmentToken,
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
                    //
                    // Not offered to a read-only account: reading the mesh's
                    // shared secret is an administrator's call, and the node
                    // refuses it. That a token is required is a different fact,
                    // already on the poll, and it stays — it is what explains a
                    // node in range that has not joined.
                    None if !dash.admin.get() => {
                        view! {
                            <Field
                                label="Enrollment token"
                                value="Required — an administrator can show it"
                            />
                        }
                            .into_any()
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
