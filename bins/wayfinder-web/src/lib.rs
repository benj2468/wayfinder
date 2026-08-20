//! A browser dashboard for a running Wayfinder node.
//!
//! The same operational picture `wayfinder-tui` shows in a terminal, served over
//! HTTP so it can be reached without an SSH session — and, in time, by people
//! who should not have to learn a TUI to use a mesh.
//!
//! # Why this is server-rendered
//!
//! The management API is reached with [`wayfinder_client::Client`], which
//! depends on tokio's network stack, `tokio-rustls` and `tokio-serial`. None of
//! those build for `wasm32-unknown-unknown`, so the browser cannot speak the
//! protocol itself even in principle. Instead this crate is built twice:
//!
//! - with `--features ssr` into an axum server that holds the node connection
//!   and the mesh identity, and
//! - with `--features hydrate` into a wasm bundle that renders and takes over
//!   the markup the server produced.
//!
//! The browser reaches the node only through `#[server]` functions, and never
//! holds a key. `cargo-leptos` drives both builds; see the
//! `[[workspace.metadata.leptos]]` block in the root `Cargo.toml`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
// `view!` nests one type per element, and the app root now nests a `Suspense`
// over a three-way branch over the whole dashboard — deep enough that rustc's
// default query depth gives out while computing the layout of the future that
// renders it. A limit, not a workaround: the types are finite and this is what
// the compiler asks for by name.
#![recursion_limit = "256"]

pub mod api;
// The `.wfauth` credential file. The bundle's *shape* — its extension and the
// path it downloads from — is named by the browser too, in the sign-in form's
// file filter and the header's download link; everything that touches a key is
// gated within the module, so neither `serde_json` nor the auth crate reaches
// the wasm bundle.
pub mod bundle;
// Browser-only in effect (the `ssr` build compiles a stub that copies nothing),
// but not gated: the click handlers that call it are compiled into both builds.
pub mod clipboard;
pub mod components;
// Browser-only in effect, and not gated for the same reason `clipboard` is not:
// the `on:change` handler that calls it is compiled into both builds.
pub mod filepicker;
pub mod format;
pub mod state;

#[cfg(feature = "ssr")]
pub mod conn;
// The outcome and target types cross the wire, so the browser needs them; the
// request itself is server-side and gated within the module.
pub mod enroll;
#[cfg(feature = "mock-node")]
pub mod mock;
#[cfg(feature = "ssr")]
pub mod server;
// The viewer and session types cross the wire, so the browser needs them; the
// store, the credential modes and the cookie mechanics are server-side and
// gated within the module.
pub mod session;
// The snapshot type crosses the wire, so the browser needs it too; only its
// `build_snapshot` fetcher is server-side, and that is gated within the module.
pub mod snapshot;

use leptos::prelude::*;
use leptos_meta::MetaTags;
use leptos_meta::Stylesheet;
use leptos_meta::Title;
use leptos_meta::provide_meta_context;
use leptos_router::StaticSegment;
use leptos_router::components::A;
use leptos_router::components::Route;
use leptos_router::components::Router;
use leptos_router::components::Routes;

use crate::components::dashboard::Dashboard;
use crate::components::dashboard::provide_dashboard;
use crate::components::link_quality::LinkQuality;
use crate::components::links::Links;
use crate::components::login::Login;
use crate::components::logo::Logo;
use crate::components::logs::Logs;
use crate::components::metrics::Metrics;
use crate::components::overview::Overview;
use crate::components::provider::Provider;
use crate::components::routing::Routing;
use crate::components::security::Security;
use crate::session::Viewer;
use crate::session::ViewerResource;

/// The document shell the server renders around [`App`].
///
/// Emits the hydration scripts that let the wasm bundle adopt this markup, so
/// the same component tree that produced the HTML continues running in the
/// browser rather than being re-created.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                // Served by this crate's own route rather than the static-file
                // fallback, so it resolves even when `site-root` is unpopulated.
                <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
                <AutoReload options=options.clone() />
                <HydrationScripts options />
                <MetaTags />
            </head>
            <body>
                <App />
            </body>
        </html>
    }
}

/// One entry in the dashboard's top-level navigation: its route path and the
/// label shown in the tab bar.
///
/// Mirrors `wayfinder_tui::app::Tab` for the seven views the two dashboards
/// share, in the same order, so they stay comparable when reading one against
/// the other. "Provider" is the one this dashboard has and the TUI does not:
/// it is a page of forms — accounts, an enrollment policy — rather than a view
/// of the mesh, and the TUI's Security tab already carries the parts of it that
/// are worth watching.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TabDef {
    /// Route path, relative to the site root. `""` is the index route.
    pub path: &'static str,
    /// Label shown in the tab bar.
    pub title: &'static str,
}

/// The dashboard's tabs, in display order.
pub const TABS: [TabDef; 8] = [
    TabDef {
        path: "",
        title: "Overview",
    },
    TabDef {
        path: "routing",
        title: "Routing",
    },
    TabDef {
        path: "link-quality",
        title: "Link Quality",
    },
    TabDef {
        path: "links",
        title: "Links",
    },
    TabDef {
        path: "metrics",
        title: "Metrics",
    },
    TabDef {
        path: "security",
        title: "Security",
    },
    TabDef {
        path: "provider",
        title: "Provider",
    },
    TabDef {
        path: "logs",
        title: "Logs",
    },
];

/// The application root: who is looking, and therefore what they get.
///
/// # Why the dashboard is hidden rather than not rendered
///
/// `<Routes>` has to be in the view tree unconditionally. `generate_route_list`
/// discovers this app's routes by rendering it once at startup, with no request
/// and so no session — so a `<Routes>` behind "is anyone signed in?" is a
/// `<Routes>` that discovers nothing, and every tab but the index answers 404.
/// It fails at startup, everywhere, for a reason that looks nothing like its
/// cause.
///
/// So the chrome and the tabs are rendered and *hidden*, and the sign-in form is
/// rendered over the top. Nothing is leaked by that: no tab fetches anything of
/// its own, the polling loop does not run while signed out, and what is hidden
/// is the empty state every tab starts in.
///
/// The hiding is done in the stylesheet — `.wf-app:has(.wf-login-page)
/// .wf-shell` — rather than by a reactive class here, and that is not a style
/// preference. Every read of the viewer resource has to happen inside a
/// `<Suspense>`, or leptos renders one thing on the server and another on
/// hydration; a class *attribute* on the shell cannot be inside one. In this
/// crate a hydration mismatch is not a cosmetic bug, it is a wasm panic that
/// leaves a perfect-looking page answering nothing. So the one thing that
/// reads the resource is the sign-in form's own presence, and CSS follows it.
///
/// The viewer is a *blocking* resource: it resolves on the server before the
/// page is written, so the first paint is already the right one. A non-blocking
/// one would paint the dashboard and swap the login form in a moment later,
/// which is both a flash of the wrong thing and an invitation to click it.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    let viewer: ViewerResource =
        Resource::new_blocking(|| (), |()| async move { crate::api::session_state().await });
    // In context so a poll that is refused for want of a session can force the
    // question to be asked again — an expiring session then takes the browser
    // to the login form instead of into a stream of failures.
    provide_context(viewer);
    let dash = provide_dashboard();

    view! {
        <Stylesheet id="leptos" href="/pkg/wayfinder-web.css" />
        <Title text="Wayfinder" />

        <Router>
            <div class="wf-app">
                <div class="wf-shell">
                    <Header dash=dash />
                    <TabBar viewer=viewer dash=dash />
                    <StatusStrip dash=dash />
                    <main class="wf-main">
                        <Routes fallback=|| view! { <p class="wf-empty">"Not found."</p> }>
                            <Route path=StaticSegment("") view=Overview />
                            <Route path=StaticSegment("routing") view=Routing />
                            <Route path=StaticSegment("link-quality") view=LinkQuality />
                            <Route path=StaticSegment("links") view=Links />
                            <Route path=StaticSegment("metrics") view=Metrics />
                            <Route path=StaticSegment("security") view=Security />
                            <Route path=StaticSegment("provider") view=Provider />
                            <Route path=StaticSegment("logs") view=Logs />
                        </Routes>
                    </main>
                </div>
                <Suspense>
                    {move || {
                        matches!(viewer.get(), Some(Ok(Viewer::LoggedOut)))
                            .then(|| view! { <Login viewer=viewer /> })
                    }}
                </Suspense>
            </div>
        </Router>
    }
}

/// The page header: product mark, the node being viewed, a live/stale dot, and
/// — in login mode — who is signed in and how to stop being.
#[component]
fn Header(
    /// Shared dashboard state.
    dash: Dashboard,
) -> impl IntoView {
    view! {
        <header class="wf-header">
            <span class="wf-brand">
                <Logo />
                "Wayfinder"
            </span>
            <span class="wf-header-node wf-mono">{move || dash.label.get()}</span>
            <ViewerStrip />
            <span class="wf-header-status">
                <span
                    class="wf-dot"
                    class:wf-dot-live=move || dash.connected.get()
                    class:wf-dot-stale=move || !dash.connected.get()
                />
                {move || {
                    if dash.connected.get() {
                        "Live".to_string()
                    } else if dash.has_data() {
                        "Reconnecting".to_string()
                    } else {
                        "Connecting".to_string()
                    }
                }}
            </span>
        </header>
    }
}

/// Who is signed in: the name in the header, and everything else behind it.
///
/// The header carries the *name* and nothing else — it is the one fact a person
/// glances at to check they are who they think they are. What the session is
/// (its capability, when it stops working) and what to do about it (sign out)
/// are details, and details in a header are noise between the node label and
/// the liveness dot. They live in a card that opens on hover or focus.
///
/// Opened by CSS rather than by a signal, so there is no open/closed state to
/// get wrong and no reactive read of the session resource outside a
/// `<Suspense>`. `:focus-within` is what makes it reachable without a pointer:
/// tab to the name and the card opens, which is also what a touch tap does.
///
/// Renders nothing in static-credential mode: there is no session to name and
/// nothing to sign out of, and a "signed in as nobody" strip would only invite
/// the question. What that mode *is* said about is said at startup, in the
/// process log, where the operator who chose it is looking.
#[component]
fn ViewerStrip() -> impl IntoView {
    let viewer = use_context::<ViewerResource>();
    let sign_out = move |_| {
        leptos::task::spawn_local(async move {
            // The refresh happens either way: a sign-out that failed still has
            // to be reflected, and the next question the page asks is the one
            // that finds out.
            let _ = crate::api::logout().await;
            if let Some(viewer) = viewer {
                viewer.refetch();
            }
        });
    };

    // Inside a `<Suspense>`, like every other read of this resource: reading it
    // anywhere else is a hydration mismatch waiting to happen, and a hydration
    // mismatch in this crate is a page that renders perfectly and answers
    // nothing (see the panic hook below).
    view! {
        <Suspense>
            {move || {
                let Some(Ok(Viewer::LoggedIn(info))) = viewer.map(|v| v.get())? else {
                    return None;
                };
                Some(
                    view! {
                        <div class="wf-header-user">
                            <button class="wf-user-trigger" aria-haspopup="true">
                                {info.username}
                                <span class="wf-user-caret" aria-hidden="true">
                                    "▾"
                                </span>
                            </button>
                            // No "signed in as" row: the name is the thing
                            // that opened this card and is an inch above it.
                            <div class="wf-user-card">
                                <div class="wf-field">
                                    <span class="wf-field-label">"Access"</span>
                                    <span class="wf-field-value">{info.capability}</span>
                                </div>
                                <div class="wf-field">
                                    <span class="wf-field-label">"Session ends"</span>
                                    <span class="wf-field-value wf-mono">
                                        {crate::format::timestamp(info.expires_unix)}
                                    </span>
                                </div>
                                // A plain link, not a click handler: the
                                // browser does downloads properly on its own,
                                // and going through wasm would mean this stops
                                // working on the page whose hydration failed —
                                // which is exactly the page somebody is trying
                                // to rescue a credential off. `download` is
                                // also what tells the router to keep its hands
                                // off the click; the server names the file.
                                <a
                                    class="wf-button wf-user-download"
                                    href=crate::bundle::DOWNLOAD_PATH
                                    download
                                    rel="external"
                                >
                                    "Download credential"
                                </a>
                                <p class="wf-user-note">
                                    "Signs you in without the certificate authority, until the time above. It is a key — keep it where you keep passwords."
                                </p>
                                <button class="wf-button wf-user-signout" on:click=sign_out>
                                    "Sign out"
                                </button>
                            </div>
                        </div>
                    },
                )
            }}
        </Suspense>
    }
}

/// The banner shown when polling is failing.
///
/// Deliberately says the data is old rather than hiding it: someone diagnosing a
/// mesh is often looking at exactly the node that just went away, and the last
/// values before it did are the most useful thing on the screen.
#[component]
fn StatusStrip(
    /// Shared dashboard state.
    dash: Dashboard,
) -> impl IntoView {
    view! {
        {move || {
            dash.error
                .get()
                .map(|error| {
                    let showing_stale = dash.has_data();
                    view! {
                        <div class="wf-banner" role="status">
                            <span class="wf-banner-title">
                                {if showing_stale {
                                    "Lost contact with the node — the values below are the last received."
                                } else {
                                    "Cannot reach the node."
                                }}
                            </span>
                            <span class="wf-banner-detail wf-mono">{error}</span>
                        </div>
                    }
                })
        }}
    }
}

/// The top-level navigation. Each tab is a real link to a real route, so the
/// browser's back button and a copied URL both work — two things a terminal
/// dashboard cannot offer, and the first thing a non-technical user reaches for.
#[component]
fn TabBar(viewer: ViewerResource, dash: Dashboard) -> impl IntoView {
    let security = move || {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.security.clone()))
    };

    let enrollment = Memo::new(move |_| security().and_then(|s| s.enrollment));

    view! {
        <nav class="wf-tabs">
            {move || {
                // 1. Read the resource reactively using .get() or .with()
                let current_viewer = viewer.get();
                let enrollment = enrollment.get();

                TABS
                    .iter()
                    .filter(|tab| {
                        match tab.path {
                            "provider" => enrollment.is_some(),
                            _ => true,
                        }
                    })
                    .filter(|tab| {
                        // 2. Check permissions safely against the reactive data
                        current_viewer
                            .as_ref()
                            .and_then(|res| res.as_ref().ok())
                            .map(|v| v.can_view(tab))
                            .unwrap_or_default()
                    })
                    .map(|tab| {
                        view! {
                            <A href=format!("/{}", tab.path) attr:class="wf-tab">
                                {tab.title}
                            </A>
                        }
                    })
                    .collect_view()
            }}
        </nav>
    }
}

/// Stand-in for a tab that has not been built yet.
#[component]
fn Placeholder() -> impl IntoView {
    view! {
        <section class="wf-panel">
            <p class="wf-empty">"This tab is not built yet."</p>
        </section>
    }
}

/// The wasm entry point: hand the server-rendered body to the reactive runtime.
///
/// Called by the glue `cargo-leptos` generates; not invoked from Rust.
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    install_panic_hook();
    leptos::mount::hydrate_body(App);
}

/// Element id of the banner [`report_panic`] paints, so a second panic does not
/// stack a second copy of it.
#[cfg(feature = "hydrate")]
const PANIC_BANNER_ID: &str = "wf-panic-banner";

/// Install the panic hook: a readable console trace *and* a banner on the page.
///
/// A wasm panic aborts, taking the whole reactive runtime with it, and the DOM
/// it leaves behind is the fully rendered page — so the failure is invisible.
/// The tab bar is the cruelest part: its links are hydrated before anything
/// below them, so they still intercept a click and then navigate nowhere. The
/// page looks perfect and answers nothing.
///
/// The hook is the only place that can speak, since it runs before the abort,
/// so it says so on the page rather than only in a console nobody has open.
#[cfg(feature = "hydrate")]
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        // The default is `unreachable executed`, which says nothing about where
        // it came from; this keeps the real message and stack for the console.
        console_error_panic_hook::hook(info);
        report_panic();
    }));
}

/// Paint the "this page is dead" banner over the top of the document.
///
/// Styled inline rather than from the stylesheet, and built with bare DOM calls
/// rather than a `view!`: by the time this runs the reactive runtime may be
/// half-torn-down, and the most likely reason to be here at all is that this
/// page and its assets came from different builds — which is exactly when a
/// class name is not to be relied on.
///
/// Every step is fallible and every failure is silently accepted: this is the
/// last thing that runs before an abort, and a panic *inside the panic hook*
/// would replace a legible failure with an unintelligible one.
#[cfg(feature = "hydrate")]
fn report_panic() {
    let Some(document) = leptos::web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    if document.get_element_by_id(PANIC_BANNER_ID).is_some() {
        return;
    }
    let (Some(body), Ok(banner)) = (document.body(), document.create_element("div")) else {
        return;
    };

    banner.set_id(PANIC_BANNER_ID);
    let _ = banner.set_attribute(
        "style",
        "position:fixed;inset:0 0 auto 0;z-index:1000;padding:12px 20px;\
         background:#7f1d1d;color:#fff;font:14px/1.5 system-ui,sans-serif",
    );
    // The reload advice is not boilerplate: the failure this most often follows
    // is a browser pairing freshly rendered markup with a cached bundle from an
    // earlier build, and a cache-bypassing reload is the one action that fixes
    // it from the reader's side.
    banner.set_text_content(Some(
        "This dashboard stopped running, so nothing on this page is updating and the tabs \
         will not respond. Reload the page — and if it happens again, reload with the cache \
         bypassed (Ctrl-Shift-R, or Cmd-Shift-R on a Mac), which is the usual fix when the \
         page and the dashboard come from different builds.",
    ));

    let _ = body.insert_before(&banner, body.first_child().as_ref());
}
