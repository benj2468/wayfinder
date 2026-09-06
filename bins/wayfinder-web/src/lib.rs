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
// Browser-only in effect (the `ssr` build compiles a stub that answers zero),
// and not gated for the same reason `clipboard` is not: the click handlers
// that call it are compiled into both builds.
pub mod clock;
pub mod components;
// Browser-only in effect, and not gated for the same reason `clipboard` is not:
// the `on:change` handler that calls it is compiled into both builds.
pub mod filepicker;
pub mod format;
/// The invitation flow's view models: what an administrator sees of the
/// invitations they have minted, and what the person redeeming one sees.
pub mod invite;
pub mod qr;
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
#[cfg(feature = "ssr")]
pub mod shutdown;
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
use leptos_router::hooks::use_location;

use crate::components::alarms::AlarmStrip;
use crate::components::dashboard::Dashboard;
use crate::components::dashboard::provide_dashboard;
use crate::components::link_quality::LinkQuality;
use crate::components::links::Links;
use crate::components::login::Login;
use crate::components::logo::Logo;
use crate::components::logs::Logs;
use crate::components::metrics::Metrics;
use crate::components::overview::Overview;
use crate::components::provider::accounts::Accounts;
use crate::components::provider::enrollment::Enrollment;
use crate::components::provider::members::Members;
use crate::components::provider::requests::Requests;
use crate::components::provider::vpn::Vpn;
use crate::components::register::Register;
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

/// One of the dashboard's two top-level views.
///
/// A node can be doing two jobs at once, and they are not the same job. Almost
/// every node only routes: it carries frames, keeps a routing table, and an
/// operator watches the seven views in [`ROUTER_TABS`] to see whether the mesh
/// is working. A handful of nodes are *also* the mesh's certificate authority,
/// and that job is about other nodes — who is admitted, who is ejected, and who
/// holds an account that decides either.
///
/// Those two used to share one tab bar, which put "is this link any good?" and
/// "admit this node to the mesh" at the same rank and one click apart. They are
/// separated here because they have different audiences: the router scope is
/// generally available, and the provider scope is an administrator's, whole and
/// entire (see [`Viewer::can_view`]).
///
/// The scope of the page is not held in a signal. It is read back off the URL
/// by [`Scope::of_path`], so a copied link, a bookmark and the back button all
/// land in the scope they were taken from — which a signal could not do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// The node as a router: what it can reach, over which links, how well.
    Router,
    /// The node as the mesh's certificate authority: who may join, who has been
    /// ejected, and the accounts that decide.
    Provider,
}

impl Scope {
    /// The first path segment every provider route sits under.
    ///
    /// One prefix is the whole basis of [`Scope::of_path`]; a provider route
    /// parked outside it would render its panels under the router's tab bar.
    pub const PROVIDER_PREFIX: &'static str = "provider";

    /// The label the scope switch draws.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Scope::Router => "Router",
            Scope::Provider => "Provider",
        }
    }

    /// Where the scope switch sends a viewer entering this scope: its first
    /// tab.
    #[must_use]
    pub const fn home(self) -> &'static str {
        match self {
            Scope::Router => "/",
            Scope::Provider => "/provider",
        }
    }

    /// This scope's tabs, in display order.
    #[must_use]
    pub const fn tabs(self) -> &'static [TabDef] {
        match self {
            Scope::Router => &ROUTER_TABS,
            Scope::Provider => &PROVIDER_TABS,
        }
    }

    /// Which scope a pathname belongs to.
    ///
    /// Matched on the first path segment rather than with `starts_with`, which
    /// would put `/providers` — or any later route that merely begins with the
    /// word — into the administrator's scope and silently swap the tab bar for
    /// one nobody may use. Anything unrecognised is the router scope, which is
    /// the safe direction to be wrong in: the 404 view then renders under the
    /// generally-available tab bar rather than an administrator's.
    #[must_use]
    pub fn of_path(pathname: &str) -> Self {
        match pathname.trim_start_matches('/').split('/').next() {
            Some(Self::PROVIDER_PREFIX) => Scope::Provider,
            _ => Scope::Router,
        }
    }
}

/// One entry in a scope's tab bar: its route path, its label, and the scope it
/// belongs to.
///
/// [`ROUTER_TABS`] mirrors `wayfinder_tui::app::Tab`, in the same order, so the
/// two dashboards stay comparable when reading one against the other. The TUI
/// has no equivalent of [`PROVIDER_TABS`]: those are pages of forms rather than
/// views of the mesh, and the TUI's Security tab already carries the parts of
/// them worth watching.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TabDef {
    /// Route path, relative to the site root. `""` is the index route.
    pub path: &'static str,
    /// Label shown in the tab bar.
    pub title: &'static str,
    /// Which scope's tab bar this appears in, and — through
    /// [`Viewer::can_view`] — who may see it at all.
    ///
    /// Held on the tab rather than derived from its path, so the capability
    /// check is one `match` on two variants instead of an arm per route. A tab
    /// declared without a scope does not compile; one that forgot to ask for a
    /// capability check would simply be readable by everyone.
    pub scope: Scope,
}

/// The router scope's tabs, in display order. Generally available.
pub const ROUTER_TABS: [TabDef; 7] = [
    TabDef {
        path: "",
        title: "Overview",
        scope: Scope::Router,
    },
    TabDef {
        path: "routing",
        title: "Routing",
        scope: Scope::Router,
    },
    TabDef {
        path: "link-quality",
        title: "Link Quality",
        scope: Scope::Router,
    },
    TabDef {
        path: "links",
        title: "Links",
        scope: Scope::Router,
    },
    TabDef {
        path: "metrics",
        title: "Metrics",
        scope: Scope::Router,
    },
    TabDef {
        path: "security",
        title: "Security",
        scope: Scope::Router,
    },
    TabDef {
        path: "logs",
        title: "Logs",
        scope: Scope::Router,
    },
];

/// The provider scope's tabs, in display order. Administrators only.
///
/// Ordered by how often an operator has a reason to be there: the queue of
/// nodes waiting on a decision leads, and the accounts that make those
/// decisions — changed perhaps twice in the life of a mesh — come last.
pub const PROVIDER_TABS: [TabDef; 5] = [
    TabDef {
        path: Scope::PROVIDER_PREFIX,
        title: "Requests",
        scope: Scope::Provider,
    },
    TabDef {
        path: "provider/members",
        title: "Members",
        scope: Scope::Provider,
    },
    TabDef {
        path: "provider/enrollment",
        title: "Enrollment",
        scope: Scope::Provider,
    },
    TabDef {
        path: "provider/accounts",
        title: "Accounts",
        scope: Scope::Provider,
    },
    TabDef {
        path: VPN_TAB_PATH,
        title: "VPN",
        scope: Scope::Provider,
    },
];

/// The VPN tab's route, named so the tab bar can drop it on a provider that
/// coordinates no tunnel without matching on a title.
const VPN_TAB_PATH: &str = "provider/vpn";

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
/// .wf-shell:not(.wf-shell-bare)` — rather than by a reactive class here, and
/// that is not a style preference. (The `:not()` is `/register`'s exemption:
/// that page reuses `.wf-login-page` for its layout and renders inside the
/// shell, so without it the rule hides the registration page from itself.) Every read of the viewer resource has to happen inside a
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
            <RegistrationAware viewer=viewer dash=dash />
        </Router>
    }
}

/// The page's outer frame, minus everything a registrant has no business
/// seeing.
///
/// Split out of [`App`] purely because it needs a router *context* to ask which
/// route is being rendered, and `use_location` is only available inside
/// `<Router>`.
///
/// `/register` is the one route that renders with the shell's chrome
/// suppressed — inside `.wf-shell` like every other route, since `<Routes>` is
/// unconditional, but with the header, tab bar and status strip skipped and the
/// bare-shell class set. Two things follow, and the second is the load-bearing
/// one:
///
/// * The header, tab bar and status strip are chrome for somebody looking at a
///   node. A person creating an account is not, and giving them a dashboard's
///   navigation to look at is misleading about what they are doing here.
/// * **The sign-in overlay must not cover it.** That overlay is gated on
///   [`Viewer::LoggedOut`], which is precisely what a registrant is — so
///   without this exclusion the registration page would render correctly,
///   underneath a sign-in form, for exactly the audience it exists for.
///
/// What is *not* conditional is `<Routes>` itself, and that is deliberate:
/// `generate_route_list` walks this component once at startup with no request,
/// so a `<Routes>` behind any condition registers nothing and every route but
/// the index answers 404. See this crate's `CLAUDE.md`.
#[component]
fn RegistrationAware(
    /// The viewer question the sign-in overlay hangs on.
    viewer: ViewerResource,
    /// Shared dashboard state.
    dash: Dashboard,
) -> impl IntoView {
    let location = use_location();
    // Derived from the router's own path, which the server knows when it
    // renders and the browser knows when it hydrates — so both halves agree,
    // and hydration does not desynchronise. Anything less deterministic here
    // would be a wasm panic, not a cosmetic bug.
    let registering = move || location.pathname.get().trim_end_matches('/') == "/register";

    view! {
        <div class="wf-app">
            <div class="wf-shell" class:wf-shell-bare=registering>
                <Show when=move || !registering() fallback=|| ()>
                    <Header dash=dash />
                    <TabBar viewer=viewer dash=dash />
                    <StatusStrip dash=dash />
                </Show>
                <main class="wf-main">
                    <Routes fallback=|| view! { <p class="wf-empty">"Not found."</p> }>
                        <Route path=StaticSegment("") view=Overview />
                        <Route path=StaticSegment("routing") view=Routing />
                        <Route path=StaticSegment("link-quality") view=LinkQuality />
                        <Route path=StaticSegment("links") view=Links />
                        <Route path=StaticSegment("metrics") view=Metrics />
                        <Route path=StaticSegment("security") view=Security />
                        <Route path=StaticSegment("logs") view=Logs />
                        // The provider scope. Flat routes under a shared
                        // first segment rather than a nested `<Routes>`:
                        // the two scopes share the whole chrome above and
                        // differ only in which tabs the one bar draws, so
                        // there is no nested outlet for a nested router to
                        // render into.
                        <Route path=StaticSegment("provider") view=Requests />
                        <Route
                            path=(StaticSegment("provider"), StaticSegment("members"))
                            view=Members
                        />
                        <Route
                            path=(StaticSegment("provider"), StaticSegment("enrollment"))
                            view=Enrollment
                        />
                        <Route
                            path=(StaticSegment("provider"), StaticSegment("accounts"))
                            view=Accounts
                        />
                        <Route path=(StaticSegment("provider"), StaticSegment("vpn")) view=Vpn />
                        // In neither scope, and rendered without the chrome
                        // above: whoever opens this has no account yet, so a
                        // tab bar for either scope would be navigation to
                        // pages they cannot reach.
                        <Route path=StaticSegment("register") view=Register />
                    </Routes>
                </main>
            </div>
            <Suspense>
                {move || {
                    (!registering() && matches!(viewer.get(), Some(Ok(Viewer::LoggedOut))))
                        .then(|| view! { <Login viewer=viewer /> })
                }}
            </Suspense>
        </div>
    }
}

/// The page header: product mark, what the node says is wrong, a live/stale
/// dot, and — in login mode — who is signed in and how to stop being.
///
/// The alarm strip and the liveness dot are deliberately adjacent, and answer
/// the two halves of one question. The dot says whether this page is still in
/// touch with the node; the strip says what the node reports about itself. Read
/// apart, either is misleading — "all systems normal" from a snapshot ten
/// minutes stale is the worst thing this page could say.
///
/// It names no node, and that is a deliberate subtraction. The only thing this
/// process knows to name one by is the address it dials, which is a fact about
/// this dashboard's reach rather than about the node: co-locate the two — the
/// certificate authority does — and the header reads `127.0.0.1:7700`, which
/// identifies nothing and invites the reading that the mesh is loopback. That
/// address is still shown, on the Overview tab, under the name of what it
/// actually is. A header that named the node would need the node to say its
/// own name over the management API, which nothing does today.
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
            <ScopeSwitch dash=dash />
            <AlarmStrip dash=dash />
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

/// The switch between the two scopes, drawn only for someone both of them
/// apply to.
///
/// Two conditions, and each removes it for a different reason. A node that
/// reports no enrollment policy is not a certificate authority, so the provider
/// scope is about a job it does not have — the overwhelming majority of nodes.
/// A viewer who may not administer is refused every call those tabs make, so
/// the scope is about a job that is not theirs. Either way the switch is absent
/// entirely, and the dashboard is the seven router views it always was: a
/// control that is drawn and then leads to a refusal is the same broken promise
/// as a button that fails when pressed.
///
/// # Why the count is here
///
/// Putting the provider scope behind a switch makes it less discoverable, and
/// the one thing in it that is genuinely time-sensitive is a node waiting to be
/// let in — which nobody would think to go and look for. The count rides the
/// switch so an administrator working in the router scope still learns of it,
/// which is the discoverability the old flat tab bar had for free.
///
/// The `<Suspense>` is not decoration: reading the viewer resource outside one
/// in `hydrate` mode is the hydration hazard [`App`] describes, which in this
/// crate is a wasm panic rather than a cosmetic reflow. Inside one, the
/// *blocking* resource is already resolved by the time the browser has the
/// page, so the first paint carries the right switch and hydration agrees.
#[component]
fn ScopeSwitch(
    /// Shared dashboard state.
    dash: Dashboard,
) -> impl IntoView {
    let viewer = use_context::<ViewerResource>();
    let location = use_location();
    let scope = Memo::new(move |_| Scope::of_path(&location.pathname.get()));

    // Whether the node issues certificates at all — the same fact the provider
    // tabs gate themselves on, read from the same field of the same poll.
    let is_authority = Memo::new(move |_| {
        dash.snapshot
            .with(|s| s.as_ref().and_then(|s| s.security.as_ref()?.enrollment))
            .is_some()
    });
    let waiting = Memo::new(move |_| {
        dash.snapshot.with(|s| {
            s.as_ref()
                .and_then(|s| s.pending_csrs.as_ref())
                .map_or(0, |csrs| csrs.pending.len())
        })
    });

    view! {
        <Suspense>
            {move || {
                let may_administer = viewer
                    .and_then(|viewer| viewer.get())
                    .and_then(Result::ok)
                    .is_some_and(|viewer| viewer.can_administer());
                if !may_administer || !is_authority.get() {
                    return None;
                }
                Some(
                    view! {
                        <nav class="wf-scope" aria-label="Which of this node's two jobs to look at">
                            {[Scope::Router, Scope::Provider]
                                .into_iter()
                                .map(|target| {
                                    let current = move || scope.get() == target;
                                    view! {
                                        // A plain anchor, not an `<A>`: the
                                        // link is current for a whole scope
                                        // rather than for the one route it
                                        // points at, which is not what `<A>`'s
                                        // own `aria-current` means. The router
                                        // still intercepts the click, so this
                                        // navigates client-side either way.
                                        <a
                                            class="wf-scope-item"
                                            class:wf-scope-provider=target == Scope::Provider
                                            href=target.home()
                                            aria-current=move || current().then_some("page")
                                        >
                                            {target.title()}
                                            {move || {
                                                (target == Scope::Provider && waiting.get() > 0)
                                                    .then(|| {
                                                        view! {
                                                            <span
                                                                class="wf-scope-count"
                                                                title="Nodes waiting to be admitted"
                                                            >
                                                                {waiting.get()}
                                                            </span>
                                                        }
                                                    })
                                            }}
                                        </a>
                                    }
                                })
                                .collect_view()}
                        </nav>
                    },
                )
            }}
        </Suspense>
    }
}

/// Who is signed in: the name in the header, and everything else behind it.
///
/// The header carries the *name* and nothing else — it is the one fact a person
/// glances at to check they are who they think they are. What the session is
/// (its capability, when it stops working) and what to do about it (sign out)
/// are details, and details in a header are noise between the alarm strip and
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

/// The current scope's tab bar. Each tab is a real link to a real route, so
/// the browser's back button and a copied URL both work — two things a terminal
/// dashboard cannot offer, and the first thing a non-technical user reaches
/// for.
///
/// Which tabs those are follows the URL, through [`Scope::of_path`], rather
/// than a signal the switch writes. A signal would be one more thing that can
/// disagree with the address bar, and it would disagree exactly when someone
/// arrived by a pasted link.
///
/// A tab is still drawn only if the viewer may look at it. That is now one
/// question about the scope rather than one per path
/// ([`Viewer::can_view`]), and it stays here as well as on the switch because
/// a URL can be pasted: the switch is the discoverable way in, not the only
/// one.
///
/// The `<Suspense>` is not decoration — see [`ScopeSwitch`] for why reading the
/// viewer resource outside one is a wasm panic in this crate.
#[component]
fn TabBar(viewer: ViewerResource, dash: Dashboard) -> impl IntoView {
    let location = use_location();
    let scope = Memo::new(move |_| Scope::of_path(&location.pathname.get()));

    // Absent on a provider that coordinates no tunnel, which is every
    // deployment reaching the mesh over radio alone. `vpn_peers` is `None` for
    // that and for a node that is not a provider at all; both mean there is no
    // tunnel to administer, and neither is an empty list of peers.
    let has_tunnel = Memo::new(move |_| {
        dash.snapshot
            .with(|s| s.as_ref().is_some_and(|s| s.vpn_peers.is_some()))
    });

    view! {
        <nav class="wf-tabs">
            <Suspense>
                {move || {
                    let current_viewer = viewer.get();
                    let has_tunnel = has_tunnel.get();

                    scope
                        .get()
                        .tabs()
                        .iter()
                        .filter(|tab| tab.path != VPN_TAB_PATH || has_tunnel)
                        .filter(|tab| {
                            current_viewer
                                .as_ref()
                                .and_then(|res| res.as_ref().ok())
                                .map(|v| v.can_view(tab))
                                .unwrap_or_default()
                        })
                        .map(|tab| {
                            view! {
                                // `exact`, because the provider scope has a
                                // two-segment route under a one-segment one:
                                // without it `/provider` reads as current on
                                // every tab beneath it and two tabs light up
                                // at once.
                                <A href=format!("/{}", tab.path) attr:class="wf-tab" exact=true>
                                    {tab.title}
                                </A>
                            }
                        })
                        .collect_view()
                }}
            </Suspense>
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every tab knows which scope it is in, and the two tables agree with it.
    ///
    /// The tables are what the tab bar draws and what [`Viewer::can_view`]
    /// judges, and they are consulted separately. A provider tab that had
    /// wandered into the router table would be drawn for everyone *and* pass
    /// the capability check, because both of those read the field rather than
    /// the table it came from.
    #[test]
    fn each_table_holds_only_its_own_scope() {
        for tab in &ROUTER_TABS {
            assert_eq!(tab.scope, Scope::Router, "{} is a router tab", tab.title);
        }
        for tab in &PROVIDER_TABS {
            assert_eq!(
                tab.scope,
                Scope::Provider,
                "{} is a provider tab",
                tab.title
            );
        }
    }

    /// Provider tabs live under one prefix, which is the whole basis of
    /// [`Scope::of_path`].
    ///
    /// The scope of the page being viewed is read back off the URL rather than
    /// held in a signal — a copied link has to land in the right scope, and a
    /// signal cannot be in the URL. A provider route parked outside the prefix
    /// would render its panels under the router's tab bar.
    #[test]
    fn every_provider_route_lives_under_the_provider_prefix() {
        for tab in &PROVIDER_TABS {
            assert!(
                tab.path == Scope::PROVIDER_PREFIX
                    || tab
                        .path
                        .starts_with(&format!("{}/", Scope::PROVIDER_PREFIX)),
                "{} is at {:?}, outside the prefix",
                tab.title,
                tab.path
            );
        }
    }

    /// No two tabs claim the same route.
    ///
    /// Two `<Route>`s on one path resolve to whichever leptos matched first,
    /// so the loser is a tab in the bar that navigates to somebody else's page
    /// — with a 200 and no error anywhere.
    #[test]
    fn no_two_tabs_share_a_route() {
        let mut seen = Vec::new();
        for tab in ROUTER_TABS.iter().chain(PROVIDER_TABS.iter()) {
            assert!(!seen.contains(&tab.path), "{:?} is claimed twice", tab.path);
            seen.push(tab.path);
        }
    }

    /// Each tab's own route resolves back to the scope it declares.
    ///
    /// The round trip is the property that matters: the tab bar picks its tabs
    /// by [`Scope::of_path`] on the current URL, so a tab whose path resolves
    /// elsewhere is one that removes its own tab bar the moment it is clicked.
    #[test]
    fn a_tab_route_resolves_to_the_scope_it_declares() {
        for tab in ROUTER_TABS.iter().chain(PROVIDER_TABS.iter()) {
            assert_eq!(
                Scope::of_path(&format!("/{}", tab.path)),
                tab.scope,
                "{} at {:?}",
                tab.title,
                tab.path
            );
        }
    }

    /// The router scope is what an unrecognised path falls back to.
    ///
    /// The fallback direction is the safe one: an unknown path renders the 404
    /// view under the generally-available tab bar. Falling back to the provider
    /// scope would draw an administrator's tab bar around it.
    #[test]
    fn an_unknown_path_is_in_the_router_scope() {
        assert_eq!(Scope::of_path("/"), Scope::Router);
        assert_eq!(Scope::of_path("/nothing-here"), Scope::Router);
    }

    /// The prefix matches at a segment boundary, not as a string prefix.
    ///
    /// `starts_with("/provider")` would put `/providers` — or any future route
    /// that merely begins with the word — into the administrator's scope, and
    /// the failure is a tab bar that silently swaps for one nobody may use.
    #[test]
    fn a_path_that_merely_begins_with_provider_is_not_in_that_scope() {
        assert_eq!(Scope::of_path("/providers"), Scope::Router);
        assert_eq!(Scope::of_path("/provider-notes"), Scope::Router);
        assert_eq!(Scope::of_path("/provider"), Scope::Provider);
        assert_eq!(Scope::of_path("/provider/members"), Scope::Provider);
    }
}
