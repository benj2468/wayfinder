//! The page somebody opens from an invitation link, to create their own
//! account.
//!
//! # Why it is not part of the dashboard
//!
//! It is routed (`/register`) so `generate_route_list` registers it, but it
//! renders *without* the shell: no header, no tab bar, no status strip, and —
//! critically — no sign-in overlay. A registrant is signed out by definition,
//! which is exactly the state that overlay covers the page for, so a
//! registration page inside the shell would be a page nobody could reach. And
//! giving somebody who has no account a dashboard's tab bar to look at is
//! misleading about what they are doing here.
//!
//! # The token is in the fragment, and the fragment never leaves the browser
//!
//! The link is `https://…/register#<token>`. A fragment is not transmitted to
//! any server, which buys three things for a bearer credential: it stays out of
//! the dashboard's access logs and any reverse proxy's, it is not sent in a
//! `Referer` header, and the link unfurlers that fetch any URL pasted into
//! Slack, Signal or iMessage never see it — that fetch is a plain `GET` running
//! no wasm, so with the token in the query string it would reach the platform's
//! logs, and any implementation that redeemed on `GET` would burn the
//! invitation on a chat preview.
//!
//! So the server renders this page knowing no token at all; the wasm bundle
//! reads `window.location.hash` after hydration and calls a `#[server]`
//! function with it. The fragment is cleared with `history.replaceState`
//! immediately after it is read.
//!
//! What that does *not* fix is the URL landing in browser history, a clipboard,
//! or the messaging app that carried it. The short expiry, the single use, and
//! the administrator's own listing are what bound those.
//!
//! # Starting spends the invitation, so it happens once and the handle is kept
//!
//! `begin_registration` consumes the token — that is the design's load-bearing
//! decision, and the reason this page cannot simply re-derive its state from
//! the URL on a refresh. It stores the handle in `sessionStorage` (same tab,
//! same origin, cleared when the tab closes) so a refresh resumes, and it
//! stores nothing else: the `otpauth://` URI has no reason to outlive the
//! moment it is scanned.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::logo::Logo;
use crate::invite::RegistrationStart;

/// Where a registration in progress keeps its handle.
///
/// `sessionStorage`, not `localStorage`: the handle is a single-use credential
/// with a fifteen-minute life, and it has no business outliving the tab that is
/// using it.
#[cfg(feature = "hydrate")]
const HANDLE_KEY: &str = "wf_registration_handle";

/// Where the account name is kept beside the handle, so a resumed page can say
/// whose account it is finishing.
///
/// The name is not a secret — the person redeeming the invitation was just
/// shown it — and without it a refresh produces a form that asks for a password
/// without saying what for.
#[cfg(feature = "hydrate")]
const USERNAME_KEY: &str = "wf_registration_username";

/// What the page is currently doing, which is also what it renders.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Stage {
    /// Before hydration, and while the invitation is being redeemed. The
    /// server-rendered state, so it must be the one that says nothing about
    /// whether a token is valid — the server has not seen one.
    Opening,
    /// The invitation was redeemed: enrol the second factor, choose a password.
    Enrolling(RegistrationStart),
    /// A refresh resumed a registration whose secret has already been shown.
    /// The handle survived; the URI deliberately did not.
    Resumed {
        /// The account being registered, so the form still says whose it is.
        username: String,
        /// The handle that finishes it.
        handle: String,
    },
    /// The account exists. Nothing left to do here but sign in.
    Done {
        /// The account that now exists.
        username: String,
    },
    /// The invitation could not be redeemed, and this is why.
    Failed {
        /// What to show. The provider's own wording where there is one.
        message: String,
    },
}

/// The account-registration page.
#[component]
pub fn Register() -> impl IntoView {
    let stage = RwSignal::new(Stage::Opening);
    let busy = RwSignal::new(false);
    let message = RwSignal::new(Option::<String>::None);

    // Client-only: an `Effect` does not run during server rendering, which is
    // what keeps the server from trying to redeem an invitation it has no
    // token for. It also runs exactly once, which matters more here than
    // anywhere else on this dashboard — a second run would spend a second
    // invitation.
    Effect::new(move |_| open_registration(stage));

    view! {
        <div class="wf-login-page wf-register-page">
            <div class="wf-login-mark">
                <span class="wf-brand">
                    <Logo />
                    "Wayfinder"
                </span>
            </div>
            {move || match stage.get() {
                Stage::Opening => view! { <Opening /> }.into_any(),
                Stage::Enrolling(start) => {
                    view! { <Enrol start=start stage=stage busy=busy message=message /> }.into_any()
                }
                Stage::Resumed { username, handle } => {
                    view! {
                        <Finish
                            username=username
                            handle=handle
                            uri=None
                            stage=stage
                            busy=busy
                            message=message
                        />
                    }
                        .into_any()
                }
                Stage::Done { username } => view! { <Done username=username /> }.into_any(),
                Stage::Failed { message } => view! { <Failed message=message /> }.into_any(),
            }}
        </div>
    }
}

/// Read the fragment, resume or redeem, and move `stage` on.
///
/// Split out of the component so the ordering is readable in one place: a
/// resumable handle wins over a token, because the token that produced that
/// handle is already spent and re-presenting it would fail.
fn open_registration(stage: RwSignal<Stage>) {
    // Resuming beats starting. A refresh still has the fragment in the address
    // bar only if `replaceState` did not run, and re-sending that token would
    // be refused as already-started — which is correct behaviour producing the
    // wrong outcome for the person in front of it.
    if let Some((username, handle)) = stored_registration() {
        stage.set(Stage::Resumed { username, handle });
        return;
    }

    let Some(token) = token_from_fragment() else {
        stage.set(Stage::Failed {
            message: "This page needs an invitation link. Ask whoever invited you for one — the \
                      link carries the invitation after a '#'."
                .to_string(),
        });
        return;
    };

    leptos::task::spawn_local(async move {
        match crate::api::begin_registration(token).await {
            Ok(start) => {
                // Stored before anything is rendered: the invitation is spent
                // by now, so a page that showed the QR code and *then* failed
                // to keep the handle would leave nothing to recover with.
                remember_registration(&start.username, &start.handle);
                stage.set(Stage::Enrolling(start));
            }
            Err(error) => stage.set(Stage::Failed {
                message: error.to_string(),
            }),
        }
    });
}

/// The invitation token from `window.location.hash`, clearing the fragment once
/// it has been read.
///
/// `None` on the server (there is no window), and for a `/register` opened with
/// no fragment at all — which is somebody who followed a bare link, and is told
/// so rather than shown a form that cannot work.
#[cfg(feature = "hydrate")]
fn token_from_fragment() -> Option<String> {
    let window = web_sys::window()?;
    let hash = window.location().hash().ok()?;
    let token = hash.trim_start_matches('#').trim().to_string();

    // Cleared immediately, whether or not it turns out to be redeemable: the
    // address bar is read over shoulders and copied into chats, and the token
    // has no further use on this page — the handle has replaced it.
    if let Ok(history) = window.history() {
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some("/register"));
    }

    (!token.is_empty()).then_some(token)
}

/// No fragment exists on the server, which is the whole point of putting the
/// token in one.
#[cfg(not(feature = "hydrate"))]
fn token_from_fragment() -> Option<String> {
    None
}

/// The registration this tab is part-way through, if any.
#[cfg(feature = "hydrate")]
fn stored_registration() -> Option<(String, String)> {
    let storage = web_sys::window()?.session_storage().ok()??;
    let handle = storage.get_item(HANDLE_KEY).ok()??;
    let username = storage.get_item(USERNAME_KEY).ok()??;
    (!handle.is_empty()).then_some((username, handle))
}

/// Nothing is stored during server rendering.
#[cfg(not(feature = "hydrate"))]
fn stored_registration() -> Option<(String, String)> {
    None
}

/// Keep the handle so a refresh resumes rather than stranding the registration.
#[cfg(feature = "hydrate")]
fn remember_registration(username: &str, handle: &str) {
    let Some(Ok(Some(storage))) = web_sys::window().map(|w| w.session_storage()) else {
        // Storage can be denied outright (a locked-down browser, some private
        // modes). The registration still works — it just will not survive a
        // refresh, which is a worse day and not a broken one.
        return;
    };
    let _ = storage.set_item(HANDLE_KEY, handle);
    let _ = storage.set_item(USERNAME_KEY, username);
}

/// Server rendering keeps nothing.
#[cfg(not(feature = "hydrate"))]
fn remember_registration(_username: &str, _handle: &str) {}

/// Drop the stored handle: the registration finished, or is beyond finishing.
#[cfg(feature = "hydrate")]
fn forget_registration() {
    let Some(Ok(Some(storage))) = web_sys::window().map(|w| w.session_storage()) else {
        return;
    };
    let _ = storage.remove_item(HANDLE_KEY);
    let _ = storage.remove_item(USERNAME_KEY);
}

/// Server rendering has nothing to forget.
#[cfg(not(feature = "hydrate"))]
fn forget_registration() {}

/// What the server renders, and what the browser shows for the moment the
/// invitation is being redeemed.
#[component]
fn Opening() -> impl IntoView {
    view! {
        <div class="wf-panel wf-login">
            <div class="wf-panel-head">
                <h2 class="wf-panel-title">"Setting up your account"</h2>
                <p class="wf-panel-sub">"One moment."</p>
            </div>
        </div>
    }
}

/// The second factor, and the form that finishes the registration.
#[component]
fn Enrol(
    /// What the redemption revealed.
    start: RegistrationStart,
    /// The page's stage, moved on when the account is created.
    stage: RwSignal<Stage>,
    /// Whether a submit is in flight.
    busy: RwSignal<bool>,
    /// What went wrong with the last submit, if anything.
    message: RwSignal<Option<String>>,
) -> impl IntoView {
    let username = start.username.clone();
    let handle = start.handle.clone();
    let uri = start.totp_enrolment_uri.clone();
    view! {
        <Finish
            username=username
            handle=handle
            uri=Some(uri)
            stage=stage
            busy=busy
            message=message
        />
    }
}

/// The form that creates the account, with or without the enrolment URI beside
/// it.
///
/// One component for both, because a resumed registration differs from a fresh
/// one in exactly one thing — whether the second factor can still be shown —
/// and splitting them would be two forms to keep in step.
#[component]
fn Finish(
    /// The account being registered.
    username: String,
    /// The handle that finishes it.
    handle: String,
    /// The enrolment URI, or `None` on a resumed registration.
    uri: Option<String>,
    /// The page's stage, moved on when the account is created.
    stage: RwSignal<Stage>,
    /// Whether a submit is in flight.
    busy: RwSignal<bool>,
    /// What went wrong with the last submit, if anything.
    message: RwSignal<Option<String>>,
) -> impl IntoView {
    let password = RwSignal::new(String::new());
    let repeat = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());

    let name_for_submit = username.clone();
    let submit = move |ev: SubmitEvent| {
        // The browser's own navigation would post this form to the page and
        // take the reactive runtime with it.
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        let chosen = password.get_untracked();
        if chosen.is_empty() {
            message.set(Some("Choose a password.".to_string()));
            return;
        }
        if chosen != repeat.get_untracked() {
            // Checked here rather than at the provider: the provider sees one
            // password and cannot know it was mistyped, and a mistyped password
            // on this path is not recoverable by the person who typed it — they
            // would find out at their first sign-in, with nothing to point at.
            message.set(Some("Those passwords do not match.".to_string()));
            return;
        }
        busy.set(true);
        message.set(None);
        let handle = handle.clone();
        let username = name_for_submit.clone();
        leptos::task::spawn_local(async move {
            let result =
                crate::api::complete_registration(handle, chosen, code.get_untracked()).await;
            busy.set(false);
            // Cleared whatever the outcome: a password left in a signal is a
            // password left in the page's memory for as long as the tab is open.
            password.set(String::new());
            repeat.set(String::new());
            code.set(String::new());
            match result {
                Ok(()) => {
                    forget_registration();
                    stage.set(Stage::Done { username });
                }
                // A wrong code does not spend the handle, so this really is a
                // "try again" rather than a dead end — and saying so is the
                // difference between retyping six digits and giving up.
                Err(error) => message.set(Some(error.to_string())),
            }
        });
    };

    view! {
        <form class="wf-panel wf-login" on:submit=submit>
            <div class="wf-panel-head">
                <h2 class="wf-panel-title">"Create your account"</h2>
                <p class="wf-panel-sub">
                    "You are setting up the account "
                    <strong class="wf-mono">{username.clone()}</strong>
                    ". Nobody else sees the password or the authenticator secret you set here."
                </p>
            </div>

            {uri
                .map(|uri| {
                    view! {
                        <div class="wf-register-enrol">
                            <p class="wf-panel-sub">
                                "Add this to an authenticator app now. It is shown once and cannot be shown again — if you lose it, ask for a new invitation."
                            </p>
                            <code class="wf-register-uri wf-mono">{uri.clone()}</code>
                            <button
                                type="button"
                                class="wf-button"
                                on:click=move |_| {
                                    let _ = crate::clipboard::copy(&uri);
                                }
                            >
                                "Copy setup link"
                            </button>
                        </div>
                    }
                })}

            <label class="wf-login-field">
                "Password"
                <input
                    class="wf-input"
                    type="password"
                    autocomplete="new-password"
                    prop:value=move || password.get()
                    on:input=move |ev| password.set(event_target_value(&ev))
                />
            </label>
            <label class="wf-login-field">
                "Repeat password"
                <input
                    class="wf-input"
                    type="password"
                    autocomplete="new-password"
                    prop:value=move || repeat.get()
                    on:input=move |ev| repeat.set(event_target_value(&ev))
                />
            </label>
            <label class="wf-login-field">
                "Code from your authenticator"
                <input
                    class="wf-input wf-mono"
                    type="text"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    prop:value=move || code.get()
                    on:input=move |ev| code.set(event_target_value(&ev))
                />
            </label>

            {move || {
                message
                    .get()
                    .map(|text| view! { <p class="wf-login-error">{text}</p> })
            }}

            <button class="wf-button wf-button-primary" type="submit" disabled=move || busy.get()>
                {move || if busy.get() { "Creating…" } else { "Create account" }}
            </button>
        </form>
    }
}

/// The account exists; the next act is an ordinary sign-in.
#[component]
fn Done(
    /// The account that now exists.
    username: String,
) -> impl IntoView {
    view! {
        <div class="wf-panel wf-login">
            <div class="wf-panel-head">
                <h2 class="wf-panel-title">"Your account is ready"</h2>
                <p class="wf-panel-sub">
                    <strong class="wf-mono">{username}</strong>
                    " can now sign in with the password you chose and a code from your authenticator."
                </p>
            </div>
            // A plain link, not a router navigation: this page is outside the
            // dashboard shell, and arriving at the sign-in form through a fresh
            // page load is the same thing the person would do by hand.
            <a class="wf-button wf-button-primary" href="/">
                "Go to sign in"
            </a>
        </div>
    }
}

/// The invitation could not be redeemed.
#[component]
fn Failed(
    /// What to tell the reader. The provider's own wording where there is one.
    message: String,
) -> impl IntoView {
    view! {
        <div class="wf-panel wf-login">
            <div class="wf-panel-head">
                <h2 class="wf-panel-title">"This invitation cannot be used"</h2>
                <p class="wf-panel-sub">{message}</p>
                <p class="wf-panel-sub">
                    "An invitation is good once and expires. If somebody else opened your link, it is already spent — tell whoever invited you, and ask for a new one."
                </p>
            </div>
        </div>
    }
}
