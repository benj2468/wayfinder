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

pub mod api;
pub mod components;
pub mod format;
pub mod state;

#[cfg(feature = "ssr")]
pub mod conn;
#[cfg(feature = "mock-node")]
pub mod mock;
#[cfg(feature = "ssr")]
pub mod server;
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
use crate::components::logo::Logo;
use crate::components::logs::Logs;
use crate::components::metrics::Metrics;
use crate::components::overview::Overview;
use crate::components::routing::Routing;
use crate::components::security::Security;

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
/// Mirrors `wayfinder_tui::app::Tab`, so the two dashboards present the same
/// seven views in the same order and stay comparable when reading one against
/// the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TabDef {
    /// Route path, relative to the site root. `""` is the index route.
    pub path: &'static str,
    /// Label shown in the tab bar.
    pub title: &'static str,
}

/// The dashboard's tabs, in display order.
pub const TABS: [TabDef; 7] = [
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
        path: "logs",
        title: "Logs",
    },
];

/// The application root: the persistent chrome (header, tab bar, status strip)
/// wrapped around whichever tab the current route selects.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    let dash = provide_dashboard();

    view! {
        <Stylesheet id="leptos" href="/pkg/wayfinder-web.css" />
        <Title text="Wayfinder" />

        <Router>
            <div class="wf-app">
                <Header dash=dash />
                <TabBar />
                <StatusStrip dash=dash />
                <main class="wf-main">
                    <Routes fallback=|| view! { <p class="wf-empty">"Not found."</p> }>
                        <Route path=StaticSegment("") view=Overview />
                        <Route path=StaticSegment("routing") view=Routing />
                        <Route path=StaticSegment("link-quality") view=LinkQuality />
                        <Route path=StaticSegment("links") view=Links />
                        <Route path=StaticSegment("metrics") view=Metrics />
                        <Route path=StaticSegment("security") view=Security />
                        <Route path=StaticSegment("logs") view=Logs />
                    </Routes>
                </main>
            </div>
        </Router>
    }
}

/// The page header: product mark, the node being viewed, and a live/stale dot.
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
fn TabBar() -> impl IntoView {
    view! {
        <nav class="wf-tabs">
            {TABS
                .iter()
                .map(|tab| {
                    view! {
                        <A href=format!("/{}", tab.path) attr:class="wf-tab">
                            {tab.title}
                        </A>
                    }
                })
                .collect_view()}
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
    // Turn a wasm panic into a readable console trace instead of the default
    // `unreachable executed`, which says nothing about where it came from.
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
