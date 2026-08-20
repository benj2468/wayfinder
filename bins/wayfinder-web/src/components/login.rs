//! The login form: the only thing a dashboard in login mode renders for a
//! browser that has no session.
//!
//! It collects three fields and posts them to one server function. Everything
//! that matters happens on the other side of that call — the keypair, the
//! exchange with the provider, the certificate, the cookie — because the
//! browser holds no key here any more than it does anywhere else in this crate.
//!
//! # Why it says so little when it fails
//!
//! "Those credentials were not accepted" is the whole of it, for every reason:
//! unknown account, wrong password, wrong code, locked, disabled. That is not
//! this component being unhelpful, it is the provider's answer being one
//! answer — anything more specific is an oracle for guessing at, reachable by
//! anyone who can load this page.
//!
//! # The second way in, and why it is a field rather than a second form
//!
//! Below the authenticator code is the other route: a `.wfauth` credential
//! file, downloaded from a dashboard while the certificate authority was
//! reachable and handed back here when it is not. The provider is not consulted
//! at all — the file already holds a certificate it signed — so this is the
//! sign-in that still works in an offline deployment, which is the whole reason
//! it exists.
//!
//! It is the fourth field of the *same* form, under one "Sign in", because from
//! where the person is standing there is one question — "let me in" — and two
//! ways to answer it. Two forms with two buttons would make them choose a
//! mechanism before they have chosen anything, and would leave the button they
//! did not use sitting there looking broken. So the button is live once
//! *either* answer is complete, and [`credential_route`] decides which one the
//! submit takes.
//!
//! Its refusals are the opposite of the password form's: specific, and named.
//! There is no account to enumerate here, because the person is holding *their
//! own file*, so the reticence above would buy nothing and cost them the one
//! fact that says what to do — "this credential expired on the 3rd" is a
//! download away from being fixed, and "the node did not accept it" is not.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::dashboard::use_dashboard;
use crate::components::logo::Logo;
use crate::session::LoginResult;
use crate::session::ViewerResource;

/// What a chosen credential file is, once the browser has read it: the name to
/// show and the text to send.
///
/// A pair rather than two signals, so "a file is chosen" is one fact the button
/// can be enabled from. Two could disagree, and the disagreement would be a
/// button that submits the previous file's contents under this one's name.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ChosenFile {
    /// The file's name, shown so the person can see which one they picked.
    name: String,
    /// The file's contents, sent verbatim. Never parsed in the browser.
    text: String,
}

/// Which of the two sign-ins a submit performs, given what has been filled in.
///
/// A named function rather than an `if` inside the submit handler, because it
/// is the same question the button's enabled state asks — and the two answering
/// it separately is how a form ends up with a live button that submits nothing.
///
/// The file wins when both are present. Choosing a file is the deliberate act:
/// a browser's password manager fills the two fields above without being asked,
/// so "there is a password in the box" is weak evidence of intent where "this
/// person went and found a file" is not.
fn credential_route(username: &str, password: &str, has_file: bool) -> Option<Route> {
    if has_file {
        Some(Route::File)
    } else if !username.trim().is_empty() && !password.is_empty() {
        Some(Route::Password)
    } else {
        None
    }
}

/// Which sign-in a submit will perform; see [`credential_route`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Route {
    /// The user name, password and code, exchanged at the provider.
    Password,
    /// The chosen `.wfauth` file, which needs no provider.
    File,
}

/// The login form.
#[component]
pub fn Login(
    /// The viewer question, re-asked once a login succeeds — which is what
    /// swaps this form for the dashboard.
    viewer: ViewerResource,
) -> impl IntoView {
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let totp = RwSignal::new(String::new());
    // A login is a round trip to a *second* host (the provider), so it is the
    // one action in this dashboard slow enough that a second press is likely.
    let busy = RwSignal::new(false);
    let message = RwSignal::new(Option::<String>::None);

    // The credential file, once the browser has read one. `None` until then,
    // and one of the two things that makes the button live.
    let chosen = RwSignal::new(Option::<ChosenFile>::None);

    // What this form would do if submitted now, and therefore whether the
    // button is live at all. A memo so the button and the submit handler read
    // the *same* answer rather than each deciding for themselves.
    let route = Memo::new(move |_| {
        credential_route(
            &username.get(),
            &password.get(),
            chosen.with(Option::is_some),
        )
    });

    let choose = move |ev: leptos::ev::Event| {
        message.set(None);
        crate::filepicker::read_chosen_file(&ev, move |read| match read {
            Ok((name, text)) => chosen.set(Some(ChosenFile { name, text })),
            Err(error) => {
                chosen.set(None);
                message.set(Some(error));
            }
        });
    };

    let submit = move |ev: SubmitEvent| {
        // The browser's own navigation would post the form to this page and
        // lose the whole reactive runtime with it.
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        let Some(route) = route.get_untracked() else {
            return;
        };
        busy.set(true);
        message.set(None);
        leptos::task::spawn_local(async move {
            let result = match route {
                Route::Password => {
                    crate::api::login(
                        username.get_untracked(),
                        password.get_untracked(),
                        totp.get_untracked(),
                    )
                    .await
                }
                // The file is taken out of the signal on the way in, not left
                // behind: it is a private key, and there is no reason for it to
                // sit in the page's memory once it has been used.
                Route::File => match chosen.try_update(Option::take).flatten() {
                    Some(file) => crate::api::login_with_bundle(file.text).await,
                    None => return,
                },
            };
            busy.set(false);
            // Cleared whatever the outcome: a password left in a signal is a
            // password left in the page's memory for as long as the tab is open.
            password.set(String::new());
            totp.set(String::new());
            match result {
                Ok(LoginResult::LoggedIn(_)) => viewer.refetch(),
                Ok(LoginResult::Denied) => {
                    message.set(Some("Those credentials were not accepted.".to_string()));
                }
                Err(error) => message.set(Some(error.to_string())),
            }
        });
    };

    // The node this dashboard is pointed at, from the shared dashboard state —
    // which fetches it once at startup and does not need a session to do it.
    // Worth showing here and not only past the sign-in: several of these
    // dashboards run side by side, one per node, and they are otherwise
    // identical pages on adjacent ports.
    let node = use_dashboard().label;

    view! {
        <div class="wf-login-page">
            <div class="wf-login-mark">
                <span class="wf-brand">
                    <Logo />
                    "Wayfinder"
                </span>
                <span class="wf-login-node wf-mono">{move || node.get()}</span>
            </div>
            <form class="wf-panel wf-login" on:submit=submit>
                <div class="wf-panel-head">
                    <h2 class="wf-panel-title">"Sign in"</h2>
                    <p class="wf-panel-sub">
                        "Your account is held by this mesh's certificate authority, not by the node. Signing in obtains a certificate that expires on its own."
                    </p>
                </div>

                <label class="wf-login-field">
                    <span class="wf-field-label">"User name"</span>
                    <input
                        class="wf-input"
                        type="text"
                        autocomplete="username"
                        autofocus
                        prop:value=move || username.get()
                        on:input=move |ev| username.set(event_target_value(&ev))
                    />
                </label>

                <label class="wf-login-field">
                    <span class="wf-field-label">"Password"</span>
                    <input
                        class="wf-input"
                        type="password"
                        autocomplete="current-password"
                        prop:value=move || password.get()
                        on:input=move |ev| password.set(event_target_value(&ev))
                    />
                </label>

                <label class="wf-login-field">
                    <span class="wf-field-label">"Authenticator code"</span>
                    <input
                        class="wf-input wf-mono"
                        type="text"
                        inputmode="numeric"
                        autocomplete="one-time-code"
                        prop:value=move || totp.get()
                        on:input=move |ev| totp.set(event_target_value(&ev))
                    />
                    <span class="wf-panel-sub">
                        "Leave empty if this account has no second factor."
                    </span>
                </label>

                <label class="wf-login-field wf-login-alt">
                    <span class="wf-field-label">"Or a credential file"</span>
                    <input
                        class="wf-input wf-file-input"
                        type="file"
                        accept=format!(".{}", crate::bundle::BUNDLE_EXTENSION)
                        on:change=choose
                    />
                    <span class="wf-panel-sub">
                        {move || match chosen.get() {
                            Some(file) => {
                                format!("{} will be used instead of a password.", file.name)
                            }
                            None => {
                                "A .wfauth file downloaded from a dashboard signs you in without \
                                 reaching the certificate authority — which is what to use when \
                                 this deployment cannot reach it."
                                    .to_string()
                            }
                        }}
                    </span>
                </label>

                // Live only once one of the two answers is complete, so the
                // button is never a thing to press and find out.
                <button
                    class="wf-button wf-button-primary"
                    type="submit"
                    disabled=move || busy.get() || route.get().is_none()
                >
                    {move || if busy.get() { "Signing in…" } else { "Sign in" }}
                </button>

                {move || {
                    message
                        .get()
                        .map(|text| {
                            view! {
                                <p class="wf-login-error" role="alert">
                                    {text}
                                </p>
                            }
                        })
                }}
            </form>

        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The button is live for exactly the states a submit can act on, because
    /// the button and the submit read the same function. A rule that lived in
    /// two places would drift into a live button that does nothing — the
    /// failure a form makes worst, since the person has no way to tell it apart
    /// from a sign-in that silently failed.
    #[test]
    fn the_button_is_live_for_exactly_what_a_submit_can_do() {
        // Nothing filled in at all.
        assert_eq!(credential_route("", "", false), None);
        // Half a password sign-in is not a sign-in.
        assert_eq!(credential_route("ops", "", false), None);
        assert_eq!(credential_route("", "secret", false), None);
        // A name that is only spaces is not a name; the field looks filled and
        // the provider would refuse it.
        assert_eq!(credential_route("   ", "secret", false), None);

        assert_eq!(
            credential_route("ops", "secret", false),
            Some(Route::Password)
        );
        // A file alone is a complete answer — that is the whole point of it.
        assert_eq!(credential_route("", "", true), Some(Route::File));
    }

    /// With both filled in, the file wins.
    ///
    /// A password manager fills the two fields above without being asked, so a
    /// password in the box is weak evidence of intent; going and finding a file
    /// is not. Getting this backwards would send an offline deployment's viewer
    /// to a provider that is not there, with their file sitting unused in the
    /// form.
    #[test]
    fn a_chosen_file_wins_over_a_filled_in_password() {
        assert_eq!(credential_route("ops", "secret", true), Some(Route::File));
    }

    /// The stylesheet, not the app, is what hides the dashboard behind this
    /// form — so the rule is pinned here, where deleting it would otherwise
    /// leave a signed-out browser looking at a dashboard.
    ///
    /// It cannot be a reactive class instead: that would mean reading the
    /// session resource outside a `<Suspense>`, which is a hydration mismatch,
    /// and a hydration mismatch in this crate is a wasm panic that leaves the
    /// page looking right and answering nothing.
    #[test]
    fn the_stylesheet_hides_the_shell_behind_this_form() {
        const CSS: &str = include_str!("../../style/main.css");

        assert!(
            CSS.contains(".wf-app:has(.wf-login-page) .wf-shell {\n  display: none;\n}"),
            "the rule that hides the dashboard behind the sign-in form is gone"
        );
    }
}
