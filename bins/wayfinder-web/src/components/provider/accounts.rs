//! The Accounts tab: who may sign in to a dashboard, and what that gets them.
//!
//! The surface with the longest reach in this scope — an account here obtains
//! certificates the whole mesh honours — and the reason the whole scope is an
//! administrator's.
//!
//! # The roster is fetched, not polled
//!
//! It changes when somebody creates or removes an account and at no other time,
//! so it rides a `Resource` this tab refetches after its own mutations rather
//! than the once-a-second snapshot. That is also what keeps the create form
//! from being rebuilt mid-keystroke, which is the same failure the memoised
//! panels on the Enrollment tab avoid.
//!
//! # The enrolment URI is shown once
//!
//! Creating an account with a second factor returns an `otpauth://` URI, and
//! the authority cannot serve it again: the secret is not recoverable from the
//! store. So the panel holds it on screen until the operator dismisses it, says
//! plainly that it will not be shown again, and offers it through the clipboard
//! rather than only as text on a screen someone else can see.
//!
//! # The node refuses to strand itself, and this does not second-guess it
//!
//! `MeshAuthority::remove_user` rejects removing the last account that can
//! still administer the mesh. The refusal is shown as an error rather than
//! pre-computed here, per "the node is the authority": the browser's idea of
//! which account that is comes from a poll it does not control.

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::UserAccount;

use crate::api::create_user;
use crate::api::list_users;
use crate::api::remove_user;
use crate::components::dashboard::use_dashboard;
use crate::components::provider::CopyField;
use crate::components::provider::ProviderGate;
use crate::components::provider::confirmation;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::format;

/// Render the Accounts tab.
#[component]
pub fn Accounts() -> impl IntoView {
    view! {
        <ProviderGate>
            <Users />
        </ProviderGate>
    }
}

/// The account roster and the form that adds to it.
///
/// Split from the tab so the `Resource` behind the roster, and the form state
/// beside it, belong to one component rather than to the gate above them — the
/// gate re-renders when the node's answer changes, and would take the
/// half-typed form with it.
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

    // `Pending` is generic precisely so a panel keeps an action type it can
    // actually receive — here, the name of the account being removed — and the
    // roster's `Resource`, which the removal has to refetch, lives here and
    // nowhere else.
    let pending = RwSignal::new(None::<Pending<String>>);

    let confirm_removal = move |username: String| {
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

            {confirmation(pending, confirm_removal)}
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
