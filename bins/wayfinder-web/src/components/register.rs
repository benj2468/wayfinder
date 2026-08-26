//! The page somebody opens from an invitation link, to create their own
//! account.
//!
//! # Why it is not part of the dashboard
//!
//! It is routed (`/register`) so `generate_route_list` registers it, but it
//! renders inside the shell with the shell's chrome suppressed: no header, no
//! tab bar, no status strip, and — critically — no sign-in overlay. (Inside,
//! not outside: `<Routes>` sits within `.wf-shell` unconditionally, which is
//! why the stylesheet needs `wf-shell-bare` to stop the sign-in rule hiding
//! this page along with it.) A registrant is signed out by definition,
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

/// Where the handle's deadline is kept beside it.
///
/// Without it a lapsed registration is indistinguishable from a live one until
/// the provider refuses it — and an unrecognisable dead handle is what lets it
/// shadow the next invitation opened in this tab.
#[cfg(feature = "hydrate")]
const EXPIRES_KEY: &str = "wf_registration_expires";

/// A registration this tab is part-way through.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredRegistration {
    /// The account being registered, so a resumed page still says whose it is.
    username: String,
    /// The handle that finishes it.
    handle: String,
    /// Unix seconds after which the handle is dead. Zero when it was written by
    /// a build that did not record one, which is treated as live — the
    /// provider is the authority on that, and guessing "dead" would throw away
    /// a registration that might still finish.
    expires_unix: u64,
}

impl StoredRegistration {
    /// Whether this handle could still complete a registration.
    ///
    /// `now_unix == 0` means the page could not read a clock, in which case
    /// nothing here is decidable and the handle is given the benefit of the
    /// doubt.
    fn is_live(&self, now_unix: u64) -> bool {
        self.expires_unix == 0 || now_unix == 0 || now_unix < self.expires_unix
    }
}

/// What the page is currently doing, which is also what it renders.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Stage {
    /// Before hydration, and while the invitation is being redeemed. The
    /// server-rendered state, so it must be the one that says nothing about
    /// whether a token is valid — the server has not seen one.
    Opening,
    /// The invitation was redeemed: enrol the second factor, choose a password.
    Enrolling {
        /// What the redemption revealed.
        start: RegistrationStart,
        /// Whether this browser refused to keep the handle, so a refresh would
        /// end the registration rather than resume it.
        at_risk: bool,
    },
    /// A refresh resumed a registration whose secret has already been shown.
    /// The handle survived; the URI deliberately did not.
    Resumed {
        /// The account being registered, so the form still says whose it is.
        username: String,
        /// The handle that finishes it.
        handle: String,
        /// Unix seconds after which that handle is dead, or zero if unknown.
        expires_unix: u64,
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
        /// Whether the invitation was actually spent by this attempt.
        ///
        /// False for a failure that never reached the provider, where the
        /// invitation is untouched and the link is still worth retrying. The
        /// two must not read alike: "somebody else opened your link" sends a
        /// registrant to their administrator to report a compromise, and a
        /// network blip is not one.
        spent: bool,
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
                Stage::Enrolling { start, at_risk } => {
                    view! {
                        <Enrol
                            start=start
                            at_risk=at_risk
                            stage=stage
                            busy=busy
                            message=message
                        />
                    }
                        .into_any()
                }
                Stage::Resumed { username, handle, expires_unix } => {
                    view! {
                        <Finish
                            username=username
                            handle=handle
                            uri=None
                            deadline=expires_unix
                            at_risk=false
                            stage=stage
                            busy=busy
                            message=message
                        />
                    }
                        .into_any()
                }
                Stage::Done { username } => view! { <Done username=username /> }.into_any(),
                Stage::Failed { message, spent } => {
                    view! { <Failed message=message spent=spent /> }.into_any()
                }
            }}
        </div>
    }
}

/// What opening the page should do, given what the tab remembers and what the
/// link carries.
///
/// A pure function so the precedence is testable without a browser — the three
/// inputs meet in exactly one place, and getting the order wrong strands
/// somebody holding a perfectly good invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Opening {
    /// Finish the registration this tab already started.
    Resume(StoredRegistration),
    /// Redeem this token.
    Redeem(String),
    /// Neither: there is nothing here to work with.
    NothingToDo,
}

/// Decide between a remembered registration and a token in the link.
///
/// A *live* remembered registration wins: the token that produced it is already
/// spent, so re-presenting it would be refused — correct behaviour producing
/// the wrong outcome for the person in front of it.
///
/// A remembered registration whose handle window has closed loses to a token,
/// and this is the case that matters. Without it a dead handle shadows every
/// later invitation opened in the same tab: the window lapses, the admin
/// re-mints, the registrant opens the new link in the tab already sitting on
/// this page — and the dead handle answers first, so the new token is never
/// even read. The admin then sees a second untouched invitation and concludes
/// the link is not arriving. The only escape was closing the tab, and nothing
/// on screen said so.
fn decide_opening(
    stored: Option<StoredRegistration>,
    token: Option<String>,
    now_unix: u64,
) -> Opening {
    match (stored, token) {
        (Some(stored), token) if stored.is_live(now_unix) => {
            debug_assert!(token.is_some() || stored.is_live(now_unix));
            Opening::Resume(stored)
        }
        (_, Some(token)) => Opening::Redeem(token),
        // Dead, and there is no token to prefer over it. Resuming anyway
        // reaches the provider's own "no longer valid" wording, which says
        // more than this page could.
        (Some(stored), None) => Opening::Resume(stored),
        (None, None) => Opening::NothingToDo,
    }
}

/// Read the fragment, resume or redeem, and move `stage` on.
fn open_registration(stage: RwSignal<Stage>) {
    match decide_opening(stored_registration(), token_from_fragment(), now_unix()) {
        Opening::Resume(stored) => stage.set(Stage::Resumed {
            username: stored.username,
            handle: stored.handle,
            expires_unix: stored.expires_unix,
        }),
        Opening::Redeem(token) => redeem(token, stage),
        Opening::NothingToDo => stage.set(Stage::Failed {
            message: "This page needs an invitation link. Ask whoever invited you for one — the \
                      link carries the invitation after a '#'."
                .to_string(),
            spent: false,
        }),
    }
}

/// Spend the token and move the page on to enrolment.
fn redeem(token: String, stage: RwSignal<Stage>) {
    leptos::task::spawn_local(async move {
        match crate::api::begin_registration(token).await {
            Ok(start) => {
                // Stored before anything is rendered: the invitation is spent
                // by now, so a page that showed the QR code and *then* failed
                // to keep the handle would leave nothing to recover with.
                let kept = remember_registration(&start);
                // Only now is the token worth discarding. Clearing it before
                // the call meant a transport failure took the token out of the
                // address bar without ever redeeming it — a good invitation
                // lost to a two-second blip, with the provider still showing it
                // as pending and nothing anywhere saying what happened.
                clear_fragment();
                stage.set(Stage::Enrolling {
                    start,
                    // A browser that will not keep the handle is one where a
                    // refresh ends the registration. The person can still
                    // finish, and is the only one who can be told not to
                    // navigate away.
                    at_risk: !kept,
                });
            }
            Err(error) => {
                // The provider refused, or we never reached it. Only the first
                // spends an invitation, and telling somebody their link was
                // "already used" when the node was simply unreachable sends
                // them to an administrator to report a compromise that did not
                // happen.
                let spent = !is_transport_failure(&error);
                if spent {
                    clear_fragment();
                }
                stage.set(Stage::Failed {
                    message: error.to_string(),
                    spent,
                });
            }
        }
    });
}

/// The invitation token from `window.location.hash`.
///
/// Reads and does **not** clear: the token is the only copy of a credential
/// until the provider has answered, and taking it out of the address bar before
/// then turns any transport failure into a lost invitation. [`clear_fragment`]
/// is called once the answer is in.
///
/// `None` on the server (there is no window), and for a `/register` opened with
/// no fragment at all — which is somebody who followed a bare link, and is told
/// so rather than shown a form that cannot work.
#[cfg(feature = "hydrate")]
fn token_from_fragment() -> Option<String> {
    let window = web_sys::window()?;
    let hash = window.location().hash().ok()?;
    let token = hash.trim_start_matches('#').trim().to_string();
    (!token.is_empty()).then_some(token)
}

/// Take the token out of the address bar.
///
/// Called once the invitation has actually been spent — by a redemption or by
/// the provider's refusal of it — and not before: the address bar is read over
/// shoulders and copied into chats, but a token that still has work to do is
/// worth more there than the risk costs.
#[cfg(feature = "hydrate")]
fn clear_fragment() {
    let Some(window) = web_sys::window() else {
        return;
    };
    if let Ok(history) = window.history() {
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some("/register"));
    }
}

/// Server rendering has no address bar.
#[cfg(not(feature = "hydrate"))]
fn clear_fragment() {}

/// The browser's wall clock in Unix seconds, or zero when there is none.
///
/// Zero is "undecidable", not "the epoch": every caller treats it as a reason
/// to defer to the provider rather than to judge a deadline itself.
#[cfg(feature = "hydrate")]
fn now_unix() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Server rendering decides no deadlines.
#[cfg(not(feature = "hydrate"))]
fn now_unix() -> u64 {
    0
}

/// Whether this error means the provider was never reached.
///
/// The distinction decides whether an invitation was spent, so it is made from
/// the transport-level variants rather than by matching on message text: a
/// request that failed to go out, or whose response never came back, cannot
/// have redeemed anything. Anything the provider itself said — including a
/// refusal — is treated as having spent the invitation, which is the safe
/// direction to be wrong in.
#[cfg(feature = "hydrate")]
fn is_transport_failure(error: &ServerFnError) -> bool {
    matches!(
        error,
        ServerFnError::Request(_) | ServerFnError::Response(_) | ServerFnError::Deserialization(_)
    )
}

/// Server rendering never calls this.
#[cfg(not(feature = "hydrate"))]
fn is_transport_failure(_error: &ServerFnError) -> bool {
    false
}

/// No fragment exists on the server, which is the whole point of putting the
/// token in one.
#[cfg(not(feature = "hydrate"))]
fn token_from_fragment() -> Option<String> {
    None
}

/// The registration this tab is part-way through, if any.
///
/// The handle is the load-bearing value; the username is decoration and the
/// deadline is advisory, so neither may veto a resume. Gating on all three —
/// which the `?` chain used to do — meant a browser that wrote one key and
/// refused the next discarded a perfectly usable handle.
#[cfg(feature = "hydrate")]
fn stored_registration() -> Option<StoredRegistration> {
    let storage = web_sys::window()?.session_storage().ok()??;
    let handle = storage.get_item(HANDLE_KEY).ok()??;
    if handle.is_empty() {
        return None;
    }
    Some(StoredRegistration {
        username: storage
            .get_item(USERNAME_KEY)
            .ok()
            .flatten()
            .unwrap_or_else(|| "your account".to_string()),
        handle,
        expires_unix: storage
            .get_item(EXPIRES_KEY)
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    })
}

/// Nothing is stored during server rendering.
#[cfg(not(feature = "hydrate"))]
fn stored_registration() -> Option<StoredRegistration> {
    None
}

/// Keep the handle so a refresh resumes rather than stranding the registration,
/// reporting whether the browser actually took it.
///
/// The answer matters and used to be discarded. By the time this is called the
/// invitation is spent and the TOTP secret has been shown for the only time it
/// ever will be, so a browser that silently refuses the write — Safari's
/// private mode hands out a live `sessionStorage` whose every `setItem` throws
/// on a zero quota, and this flow is often run on a phone — leaves a
/// registration that ends at the next refresh with nothing to recover from.
/// The person in front of it is the only one who can be told not to navigate
/// away.
#[cfg(feature = "hydrate")]
fn remember_registration(start: &RegistrationStart) -> bool {
    let Some(Ok(Some(storage))) = web_sys::window().map(|w| w.session_storage()) else {
        // Storage denied outright (a locked-down browser, some private modes).
        return false;
    };
    // The handle alone decides the answer: without it there is nothing to
    // resume, while the other two only make a resumed page friendlier.
    let kept = storage.set_item(HANDLE_KEY, &start.handle).is_ok();
    let _ = storage.set_item(USERNAME_KEY, &start.username);
    let _ = storage.set_item(EXPIRES_KEY, &start.handle_expires_unix.to_string());
    kept
}

/// Server rendering keeps nothing.
#[cfg(not(feature = "hydrate"))]
fn remember_registration(_start: &RegistrationStart) -> bool {
    false
}

/// Drop the stored handle: the registration finished, or is beyond finishing.
#[cfg(feature = "hydrate")]
fn forget_registration() {
    let Some(Ok(Some(storage))) = web_sys::window().map(|w| w.session_storage()) else {
        return;
    };
    let _ = storage.remove_item(HANDLE_KEY);
    let _ = storage.remove_item(USERNAME_KEY);
    let _ = storage.remove_item(EXPIRES_KEY);
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
    /// Whether this browser refused to keep the handle.
    at_risk: bool,
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
    let deadline = start.handle_expires_unix;
    view! {
        <Finish
            username=username
            handle=handle
            uri=Some(uri)
            deadline=deadline
            at_risk=at_risk
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
    /// Unix seconds after which the handle is dead, or zero if unknown.
    deadline: u64,
    /// Whether this browser refused to keep the handle, so a refresh ends the
    /// registration rather than resuming it.
    at_risk: bool,
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
    // `None` until the button is pressed; then what the browser actually did.
    let copied = RwSignal::new(Option::<bool>::None);

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
                Err(error) => {
                    // A handle past its own deadline is not retryable, and
                    // leaving it in storage is what let a dead registration
                    // shadow the next invitation opened in this tab. Judged by
                    // the deadline rather than by the provider's wording: the
                    // message is prose meant for a person, and matching on it
                    // would break the day it is reworded.
                    let expired = deadline != 0 && now_unix() >= deadline;
                    if expired {
                        forget_registration();
                    }
                    message.set(Some(error.to_string()));
                }
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
                // The window exists whether or not it is shown, and the page's
                // own instruction is to go and do something on another device.
                // Blowing a deadline nobody mentioned is the ordinary outcome,
                // not the exceptional one.
                {(deadline != 0)
                    .then(|| {
                        view! {
                            <p class="wf-panel-sub">
                                "Finish by "
                                <strong class="wf-mono">
                                    {crate::format::timestamp(deadline)}
                                </strong>
                                ". After that this invitation has to be minted again."
                            </p>
                        }
                    })}
            </div>

            {at_risk
                .then(|| {
                    view! {
                        <p class="wf-login-error">
                            "This browser will not let the page save your progress. Finish here without refreshing or closing the tab — this invitation cannot be started again."
                        </p>
                    }
                })}

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
                                    // The answer is reported, never assumed:
                                    // `copy` returns false for a refusal, and
                                    // a registrant who believes a copy that did
                                    // not happen pastes the previous clipboard
                                    // into their authenticator and loses a
                                    // secret shown once. There is no QR code
                                    // here, so on a desktop this button is the
                                    // only practical route to a phone.
                                    copied.set(Some(crate::clipboard::copy(&uri)));
                                }
                            >
                                {move || match copied.get() {
                                    Some(true) => "Copied",
                                    Some(false) => "Could not copy — select it and copy by hand",
                                    None => "Copy setup link",
                                }}
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
    /// Whether the invitation was actually spent by this attempt.
    spent: bool,
) -> impl IntoView {
    view! {
        <div class="wf-panel wf-login">
            <div class="wf-panel-head">
                <h2 class="wf-panel-title">
                    {if spent { "This invitation cannot be used" } else { "Could not reach the node" }}
                </h2>
                <p class="wf-panel-sub">{message}</p>
                // Two different things to say, and saying the wrong one has a
                // cost in each direction. "Somebody else opened your link"
                // sends a registrant to their administrator to report a
                // compromise; telling somebody whose invitation really was
                // spent to "try again" leaves them retrying a dead link.
                <p class="wf-panel-sub">
                    {if spent {
                        "An invitation is good once and expires. If somebody else opened your link, it is already spent — tell whoever invited you, and ask for a new one."
                    } else {
                        "Your invitation has not been used. Open the same link again in a moment — if it keeps failing, tell whoever invited you that the node is not answering."
                    }}
                </p>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::Opening;
    use super::StoredRegistration;
    use super::decide_opening;

    /// A registration in progress, as `sessionStorage` would hand it back.
    fn stored(expires_unix: u64) -> StoredRegistration {
        StoredRegistration {
            username: "rowan".to_string(),
            handle: "HANDLE".to_string(),
            expires_unix,
        }
    }

    /// A live registration in progress beats a token, because the token that
    /// produced it is already spent and re-presenting it would be refused.
    #[test]
    fn a_live_registration_resumes_rather_than_re_redeeming() {
        assert_eq!(
            decide_opening(Some(stored(2_000)), Some("TOKEN".to_string()), 1_000),
            Opening::Resume(stored(2_000))
        );
    }

    /// A registration whose handle window has closed loses to a token.
    ///
    /// This is the case that strands people. Without it the dead handle answers
    /// first and the new token is never read — so the invitation an admin
    /// re-minted in response to the *first* failure is not spent either, the
    /// panel shows it untouched, and it reads as a delivery problem. The only
    /// escape was closing the tab, which nothing on screen suggested.
    #[test]
    fn a_dead_registration_does_not_shadow_a_fresh_token() {
        assert_eq!(
            decide_opening(Some(stored(1_000)), Some("TOKEN".to_string()), 2_000),
            Opening::Redeem("TOKEN".to_string())
        );
    }

    /// A dead handle with no token still resumes, so the provider's own wording
    /// explains it rather than this page guessing.
    #[test]
    fn a_dead_registration_with_no_token_still_resumes() {
        assert_eq!(
            decide_opening(Some(stored(1_000)), None, 2_000),
            Opening::Resume(stored(1_000))
        );
    }

    /// A handle stored without a deadline — written by a build that did not
    /// record one — is given the benefit of the doubt rather than discarded.
    #[test]
    fn a_handle_with_no_recorded_deadline_is_treated_as_live() {
        assert_eq!(
            decide_opening(Some(stored(0)), Some("TOKEN".to_string()), 2_000),
            Opening::Resume(stored(0))
        );
    }

    /// A page that cannot read a clock defers to the provider instead of
    /// declaring a handle dead on a guess.
    #[test]
    fn an_unreadable_clock_does_not_condemn_a_handle() {
        assert_eq!(
            decide_opening(Some(stored(1_000)), Some("TOKEN".to_string()), 0),
            Opening::Resume(stored(1_000))
        );
    }

    /// Nothing stored and nothing in the link is the bare-link case.
    #[test]
    fn nothing_stored_and_no_token_is_nothing_to_do() {
        assert_eq!(decide_opening(None, None, 1_000), Opening::NothingToDo);
    }

    /// A token with nothing stored is the ordinary first visit.
    #[test]
    fn a_token_with_nothing_stored_is_redeemed() {
        assert_eq!(
            decide_opening(None, Some("TOKEN".to_string()), 1_000),
            Opening::Redeem("TOKEN".to_string())
        );
    }

    /// The rule that hides the dashboard behind the sign-in form must not hide
    /// *this* page, which reuses the sign-in page's layout class.
    ///
    /// `.wf-app:has(.wf-login-page) .wf-shell` asks whether `.wf-app` contains
    /// a `.wf-login-page` anywhere — and then hides `.wf-shell`. For the
    /// sign-in form that is a sibling of the shell, which is the case it was
    /// written for. This page puts one *inside* the shell, so the same rule
    /// hides the element containing the very thing it matched on: a blank page,
    /// with the markup all present, correct, and painted nowhere. A
    /// lower-specificity `.wf-shell-bare { display: block }` does not undo it —
    /// one class loses to three.
    #[test]
    fn the_stylesheet_does_not_hide_the_bare_shell() {
        const CSS: &str = include_str!("../../style/main.css");

        // Matched with the whitespace squeezed out, not byte-for-byte: a
        // `nix fmt` reflow of the stylesheet must not fail a test whose message
        // is about a security-adjacent rendering bug.
        let squeezed: String = CSS.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            squeezed.contains(".wf-app:has(.wf-login-page) .wf-shell:not(.wf-shell-bare) {"),
            "the sign-in form's hiding rule no longer spares the registration page's bare shell"
        );
    }
}
