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
//! # Two controls, because there are two acts
//!
//! **Revoke** ends every session certificate the account is currently holding
//! and leaves the account able to sign in again. **Remove** does both: it
//! revokes and then deletes.
//!
//! Remove used to do only the second half, which made the destructive-looking
//! control the one that left a compromised account's certificates working for
//! up to their whole lifetime. Both now go through the node as one act each —
//! see `docs/design/implemented/14-account-scoped-session-revocation.md`.
//!
//! The distinction is carried by a [`Hint`] beside the pair rather than by
//! their names, because no two verbs make it obvious and the cost of guessing
//! wrong is somebody's account. It is a focusable button, not a `title=`
//! tooltip: this is precisely the explanation somebody needs *before* pressing
//! an irreversible control, and `title` never reaches a keyboard or touch user.
//!
//! It sits in the table header rather than on every row — what it explains is
//! the pair of controls, not any one account — and its panel is a `popover`,
//! because this table scrolls and anything positioned inside that scroll
//! container is clipped by it. See [`Hint`]'s own docs.
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
use crate::api::create_user_invite;
use crate::api::list_user_invites;
use crate::api::list_users;
use crate::api::remove_user;
use crate::api::revoke_user_invite;
use crate::api::revoke_user_sessions;
use crate::components::dashboard::use_dashboard;
use crate::components::provider::CopyField;
use crate::components::provider::ProviderGate;
use crate::components::provider::confirmation;
use crate::components::provider::report_failure;
use crate::components::widgets::Empty;
use crate::components::widgets::Hint;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::format;
use crate::invite::InviteMinted;
use crate::invite::InviteRow;

/// Render the Accounts tab.
#[component]
pub fn Accounts() -> impl IntoView {
    view! {
        <ProviderGate>
            <Users />
            <Invitations />
        </ProviderGate>
    }
}

/// Which of the two account controls an operator has pressed.
///
/// Both are destructive and neither can be undone, so they share the
/// confirmation dialog — but they are genuinely different acts and the dialog
/// has to say which one it is about. A bare username could not.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AccountAction {
    /// End every session the account currently holds, leaving the account.
    RevokeSessions(String),
    /// Revoke those sessions *and* delete the account.
    Remove(String),
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
    // actually receive — here, which of the two account controls was pressed
    // and against whom — and the roster's `Resource`, which both of them have
    // to refetch, lives here and nowhere else.
    let pending = RwSignal::new(None::<Pending<AccountAction>>);
    // What the last action did, held until the next one replaces it. A
    // revocation's whole result is a number, and "revoked nothing" and "revoked
    // three" call for different follow-up — so it is reported rather than left
    // to be inferred from a table that looks identical either way.
    let outcome = RwSignal::new(None::<String>);

    let confirm = move |action: AccountAction| {
        leptos::task::spawn_local(async move {
            outcome.set(None);
            match action {
                AccountAction::RevokeSessions(username) => {
                    match revoke_user_sessions(username.clone()).await {
                        Ok(revoked) => {
                            outcome.set(Some(format::sessions_revoked(&username, revoked)));
                            // The roster itself is unchanged — the account is
                            // still there — but its Status may not be, and a
                            // refetch is cheaper than reasoning about which.
                            users.refetch();
                        }
                        Err(e) => report_failure(dash, "Revoking the sessions", Err::<(), _>(e)),
                    }
                }
                AccountAction::Remove(username) => match remove_user(username.clone()).await {
                    Ok(()) => {
                        outcome.set(Some(format!(
                            "Removed {username} and revoked the sessions it held."
                        )));
                        // Wrong by exactly one row, the same as after a creation.
                        users.refetch();
                    }
                    Err(e) => report_failure(dash, "Removing the account", Err::<(), _>(e)),
                },
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
                                        on_revoke=Callback::new(move |username: String| {
                                            pending
                                                .set(
                                                    Some(Pending {
                                                        prompt: format!(
                                                            "End every session {username} is currently signed in with? \
                                                             The account stays and can sign in again; what it is holding \
                                                             now stops working everywhere on the mesh, and that cannot \
                                                             be undone.",
                                                        ),
                                                        verb: "Revoke sessions",
                                                        destructive: true,
                                                        kind: AccountAction::RevokeSessions(username),
                                                    }),
                                                )
                                        })
                                        on_remove=Callback::new(move |username: String| {
                                            pending
                                                .set(
                                                    Some(Pending {
                                                        prompt: format!(
                                                            "Remove {username}? This revokes every session it is holding \
                                                             and deletes the account, so it cannot sign in again. \
                                                             Neither half can be undone.",
                                                        ),
                                                        verb: "Remove",
                                                        destructive: true,
                                                        kind: AccountAction::Remove(username),
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
                outcome
                    .get()
                    .map(|message| view! { <p class="wf-note">{message}</p> })
            }}

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
                "Disabling an account stops it signing in again and revokes the sessions \
                 it already holds, as one act — so access ends now, not when the last \
                 certificate expires. `wayfinderctl user` does the same over this same \
                 management API. The last account that can administer this mesh cannot be \
                 removed, demoted or disabled here — leaving none would mean no further \
                 change to this list from any dashboard."
            </p>

            {confirmation(pending, confirm)}
        </Panel>
    }
}

/// The account roster.
///
/// `pub` for the render tests, and for a reason particular to this panel: the
/// roster arrives on a `Resource`, which the SSR test harness does not resolve
/// — a test that rendered the whole tab would only ever see "Reading the
/// accounts…". Every other tab's table hangs off the polled snapshot and needs
/// no such seam.
#[component]
pub fn UserTable(
    /// The accounts as the authority reported them.
    users: Vec<UserAccount>,
    /// Raise the confirmation for ending the named account's sessions.
    on_revoke: Callback<String>,
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
                        // Visually unlabelled — the column is buttons, and a
                        // heading over it tells a sighted reader nothing they
                        // do not. A non-visual reader has no such context, so
                        // the name is there for them.
                        //
                        // The hint is in the header rather than repeated on
                        // every row: the distinction it explains is about the
                        // two controls, not about any one account.
                        <th>
                            <span class="wf-sr-only">"Actions"</span>
                            // A definition list, not paragraphs: the reader is
                            // here to tell two buttons apart, and the terms
                            // being the words on those buttons is the whole
                            // answer. Prose made both names something to find
                            // rather than something to compare.
                            <Hint label="Revoke" id="wf-hint-account-actions">
                                <dl class="wf-hint-defs">
                                    <dt>"Revoke"</dt>
                                    <dd>
                                        "Signs the account out on every device. It can sign \
                                         in again right away — reach for it when a laptop or \
                                         phone goes missing."
                                    </dd>
                                    <dt>"Remove"</dt>
                                    <dd>
                                        "Signs it out everywhere, then deletes the account. \
                                         It cannot sign in again."
                                    </dd>
                                </dl>
                                <p class="wf-hint-foot">
                                    "Both apply across the whole mesh and neither can be \
                                     undone. A connection already open can keep working for \
                                     up to a minute."
                                </p>
                            </Hint>
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
                                    <td class="wf-row-actions">
                                        <button
                                            class="wf-button"
                                            aria-label=format!("Revoke {username}'s sessions")
                                            on:click={
                                                let username = username.clone();
                                                move |_| on_revoke.run(username.clone())
                                            }
                                        >
                                            "Revoke"
                                        </button>
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

/// Invitations: the way to create an account without ever holding its secrets.
///
/// Sits beside [`Users`] because they are two answers to one question, and this
/// is the one to reach for. "Create account" mints both of an account's secrets
/// here and hands the operator its `otpauth://` URI, so the account's second
/// factor ends up permanently known to somebody who is not its owner — which is
/// not a second factor, it is a second thing the operator knows. An invitation
/// hands over a link instead: whoever opens it is the first party to see the
/// TOTP secret.
///
/// # What the operator is actually watching for
///
/// The `Started` column. An invitation that is still listed and shows a start
/// means somebody took the account's second factor and did not finish — a
/// completed registration deletes its invitation, so a started one is never a
/// finished one. That is either an abandoned registration or a disclosure, and
/// the response to both is the same: revoke, and invite again.
///
/// That column is also the whole of what this buys, and it is worth being exact
/// about the limit. An operator holds the token between minting it and
/// delivering it, and could always redeem it themselves; nothing prevents that.
/// What is guaranteed is that doing so **spends** the invitation, so the
/// intended registration fails, the person says so, and this list shows a start
/// nobody expected.
///
/// # The token is shown once
///
/// The authority stores only a hash of it, so this panel is the only place it
/// exists in readable form. It is offered through the clipboard as a whole
/// registration URL rather than as bare text, because the URL is the part that
/// has to be right — the token belongs after the `#`, where no server, no
/// access log and no chat-app link preview ever sees it.
#[component]
fn Invitations() -> impl IntoView {
    let dash = use_dashboard();
    let invites = Resource::new(|| (), |()| async move { list_user_invites().await });

    let name = RwSignal::new(String::new());
    let admin = RwSignal::new(false);
    let busy = RwSignal::new(false);
    // The invitation just minted, held on screen until dismissed: its token is
    // not recoverable, exactly like the enrolment URI above.
    let minted = RwSignal::new(None::<InviteMinted>);
    let pending = RwSignal::new(None::<Pending<String>>);

    let confirm_revoke = move |username: String| {
        leptos::task::spawn_local(async move {
            match revoke_user_invite(username).await {
                Ok(()) => invites.refetch(),
                Err(e) => report_failure(dash, "Revoking the invitation", Err::<(), _>(e)),
            }
        });
    };

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        let username = name.get_untracked();
        if username.trim().is_empty() {
            dash.error.set(Some("A user name is required.".to_string()));
            return;
        }
        busy.set(true);
        leptos::task::spawn_local(async move {
            // Zero for both lifetimes: the authority's defaults, which are the
            // right answer unless somebody has a reason. An operator who does
            // have one sets them with `wayfinderctl user invite`, which reaches
            // this same request over the management API. Naming it here is a
            // pointer to where the knobs exist, not a workaround.
            let result = create_user_invite(username, admin.get_untracked(), 0, 0).await;
            busy.set(false);
            match result {
                Ok(invite) => {
                    name.set(String::new());
                    minted.set(Some(invite));
                    invites.refetch();
                }
                Err(e) => report_failure(dash, "Creating the invitation", Err::<(), _>(e)),
            }
        });
    };

    view! {
        <Panel title="Invitations">
            <p class="wf-note">
                "An invitation creates an account without you ever holding its password or its \
                 authenticator secret. Send the link to the person it is for; they set both \
                 themselves. The link works once and expires."
            </p>

            <Suspense fallback=|| view! { <Empty message="Reading the invitations…" /> }>
                {move || {
                    Some(
                        match invites.get()? {
                            Ok(listing) if listing.invites.is_empty() => {
                                view! { <Empty message="No invitations outstanding." /> }.into_any()
                            }
                            Ok(listing) => {
                                let capacity = listing.capacity;
                                let outstanding = listing.invites.len();
                                view! {
                                    <InviteTable
                                        invites=listing.invites
                                        on_revoke=Callback::new(move |username: String| {
                                            pending
                                                .set(
                                                    Some(Pending {
                                                        prompt: format!(
                                                            "Revoke the invitation for {username}? The link stops working \
                                                             immediately. If it was already started, revoking is the right \
                                                             move — somebody has that account's authenticator secret.",
                                                        ),
                                                        verb: "Revoke",
                                                        destructive: true,
                                                        kind: username,
                                                    }),
                                                )
                                        })
                                    />
                                    <p class="wf-note">
                                        {format!(
                                            "{outstanding} of {capacity} invitations outstanding.",
                                        )}
                                    </p>
                                }
                                    .into_any()
                            }
                            Err(e) => {
                                view! {
                                    <Empty message=format!(
                                        "The invitations could not be read: {e}",
                                    ) />
                                }
                                    .into_any()
                            }
                        },
                    )
                }}
            </Suspense>

            {move || {
                minted
                    .get()
                    .map(|invite| {
                        let username = invite.username.clone();
                        view! {
                            <div class="wf-note wf-note-strong">
                                <p>
                                    "Invited " <span class="wf-mono">{username}</span>
                                    ". Send them this link now — it is not shown again, and it \
                                     works once."
                                </p>
                                <CopyField
                                    label="Registration link"
                                    shown="••••••••"
                                    value=registration_url(&invite.token)
                                />
                                <button class="wf-button" on:click=move |_| minted.set(None)>
                                    "Done"
                                </button>
                            </div>
                        }
                    })
            }}

            <form class="wf-user-form" on:submit=submit>
                <div class="wf-setting-row">
                    <label class="wf-setting-label" for="wf-invite-user">
                        "Invite"
                    </label>
                    <input
                        id="wf-invite-user"
                        class="wf-input"
                        type="text"
                        autocomplete="off"
                        placeholder="user name"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
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
                <button
                    class="wf-button wf-button-primary"
                    type="submit"
                    disabled=move || busy.get()
                >
                    {move || if busy.get() { "Inviting…" } else { "Create invitation" }}
                </button>
            </form>

            {confirmation(pending, confirm_revoke)}
        </Panel>
    }
}

/// The outstanding invitations.
#[component]
fn InviteTable(
    /// The invitations as the authority reported them.
    invites: Vec<InviteRow>,
    /// Raise the confirmation for revoking the named invitation.
    on_revoke: Callback<String>,
) -> impl IntoView {
    view! {
        <div class="wf-table-scroll">
            <table class="wf-table">
                <thead>
                    <tr>
                        <th>"Account"</th>
                        <th>"Access"</th>
                        <th>"Expires"</th>
                        <th>"Started"</th>
                        // Unlabelled for a sighted reader, named for everyone
                        // else — the same reason the account table's is.
                        <th>
                            <span class="wf-sr-only">"Actions"</span>
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {invites
                        .into_iter()
                        .map(|invite| {
                            let username = invite.username.clone();
                            let started = invite.started_unix.is_some();
                            view! {
                                <tr>
                                    <td class="wf-mono">{invite.username.clone()}</td>
                                    <td>
                                        {if invite.admin { "Administrator" } else { "Read-only" }}
                                    </td>
                                    <td>{format::timestamp(invite.expires_unix)}</td>
                                    <td>
                                        {
                                            // Spelled out, not shown as a
                                            // timestamp. This is the row an
                                            // operator is scanning for, and the
                                            // fact that somebody holds the
                                            // account's second factor matters
                                            // more than when they took it.
                                            if started {
                                                "Yes — someone has the secret"
                                            } else {
                                                "Not yet"
                                            }
                                        }
                                    </td>
                                    <td>
                                        <button
                                            class="wf-button wf-button-danger"
                                            on:click=move |_| on_revoke.run(username.clone())
                                        >
                                            "Revoke"
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

/// The registration URL for `token`, as it should be sent.
///
/// The token goes in the **fragment**, and that is the whole reason this is a
/// function rather than string concatenation at the call site. A fragment is
/// never transmitted to a server, so the token stays out of the dashboard's
/// access logs and any reverse proxy's, is not sent in a `Referer` header, and
/// is invisible to the link unfurlers that fetch any URL pasted into Slack,
/// Signal or iMessage — that fetch is a plain `GET` running no wasm, and with
/// the token in a query string it would reach the platform's logs instead.
///
/// Built from the browser's own origin, so a dashboard reached through a tunnel
/// produces the name the recipient can actually open, rather than whatever the
/// server thinks it is bound to.
#[cfg(feature = "hydrate")]
fn registration_url(token: &str) -> String {
    let origin = web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default();
    format!("{origin}/register#{token}")
}

/// The `ssr` build's stand-in: there is no window to read an origin from.
///
/// Never actually rendered — a minted token only ever exists in a browser-side
/// response to a click — but the click handler still has to *compile* into the
/// server binary. Kept as a real relative URL rather than a panic so the shape
/// under test here is the shape that ships.
#[cfg(not(feature = "hydrate"))]
fn registration_url(token: &str) -> String {
    format!("/register#{token}")
}

#[cfg(test)]
mod tests {
    use super::registration_url;

    /// The token goes after a `#`, and never after a `?`.
    ///
    /// A one-character regression to a query string still produces a link that
    /// works end to end, so every behavioural test in this crate keeps passing
    /// while the token starts reaching the dashboard's access log, any reverse
    /// proxy's, the `Referer` header, and every chat-app unfurler that fetches
    /// a pasted URL. Nothing else in the suite can see that difference.
    #[test]
    fn the_token_rides_in_the_fragment_not_the_query_string() {
        let url = registration_url("TOKEN");

        assert!(
            url.ends_with("/register#TOKEN"),
            "the token belongs after the '#': {url}"
        );
        assert!(
            !url.contains('?'),
            "a query string would put the token on every server between here \
             and the reader: {url}"
        );
    }
}
