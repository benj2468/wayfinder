//! Assembly of the axum router the dashboard is served from.
//!
//! Split out of `main.rs` so the wiring can be driven by `tests/http.rs`
//! without a socket or a process. The wiring is worth testing on its own: the
//! node connection has to be provided on *both* router arms, and getting that
//! wrong yields a dashboard that renders perfectly and fails every poll.

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::CACHE_CONTROL;
use axum::http::header::CONTENT_TYPE;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use leptos::config::LeptosOptions;
use leptos::prelude::provide_context;
use leptos_axum::LeptosRoutes;
use leptos_axum::generate_route_list;
use leptos_axum::handle_server_fns_with_context;

use crate::App;
use crate::components::logo::FAVICON_SVG;
use crate::conn::NodeConnection;
use crate::shell;

/// Build the dashboard router: the wasm/CSS bundle, server-function endpoints,
/// the server-rendered page routes, and a static-file fallback.
///
/// `conn` is handed to both the server-function route and the page routes,
/// because a page rendered on the server runs the same resources the browser
/// would and so calls the same server functions.
pub fn build_router(options: LeptosOptions, conn: Arc<NodeConnection>) -> Router {
    let provide_conn = move || provide_context(Arc::clone(&conn));

    // The build artifacts get their own service rather than riding the
    // fallback, purely so revalidating them is cheap: leptos's file handler
    // ignores `If-Modified-Since` and answers with the whole body, which under
    // the `no-cache` policy below would re-send a multi-megabyte wasm file on
    // every page view. `ServeDir` answers `304`.
    let bundle = tower_http::services::ServeDir::new(
        std::path::Path::new(options.site_root.as_ref()).join(options.site_pkg_dir.as_ref()),
    );

    Router::new()
        .nest_service("/pkg", bundle)
        // Compiled in rather than served off disk: the static-file fallback
        // reads `site-root`, which only `cargo leptos` populates, so a plain
        // `cargo build` of the `ssr` binary would 404 its own icon.
        .route("/favicon.svg", get(favicon))
        .route(
            "/api/{*fn_name}",
            post({
                let provide = provide_conn.clone();
                move |req| handle_server_fns_with_context(provide.clone(), req)
            })
            .get({
                let provide = provide_conn.clone();
                move |req| handle_server_fns_with_context(provide.clone(), req)
            }),
        )
        .leptos_routes_with_context(&options, generate_route_list(App), provide_conn, {
            let options = options.clone();
            move || shell(options.clone())
        })
        .fallback(leptos_axum::file_and_error_handler(shell))
        .layer(axum::middleware::from_fn(revalidate))
        .with_state(options)
}

/// Require a browser to revalidate anything that does not ask to be cached.
///
/// # Why this is not a micro-optimisation in reverse
///
/// The server-rendered markup and the wasm bundle that hydrates it are two
/// halves of *one build*. Hydration is a walk over the markup the server wrote,
/// so halves from different builds do not merely look wrong — the walk
/// desynchronises and panics partway through, and by then the tab bar has its
/// click handlers. Every tab then swallows its click and navigates nowhere: a
/// dashboard that looks completely normal and is entirely dead.
///
/// Nothing else stops the two halves drifting apart. The bundle URL is
/// build-independent (`/pkg/wayfinder-web.wasm` — cargo-leptos emits no content
/// hash), the static-file handler declares no freshness, so a browser invents
/// one from the file's age, and Chrome's plain reload deliberately does not
/// revalidate subresources. Rebuild the dashboard under a tab someone already
/// has open, have them press reload, and they get today's markup with
/// yesterday's bundle.
///
/// `no-cache` is the narrow fix: the body may still be cached — the wasm bundle
/// is megabytes — but it may not be *reused* without asking, and the ask is a
/// conditional request `/pkg`'s `ServeDir` answers `304`. (The content-hashed
/// filenames cargo-leptos can emit would remove the need for the ask entirely,
/// at the price of a third `LEPTOS_*` variable every deployment has to set
/// correctly — see this crate's CLAUDE.md on what that costs.)
///
/// Set with `or_insert` rather than unconditionally, so a route that has
/// reasoned about its own caching — the favicon, whose content is not tied to a
/// build — keeps what it chose.
async fn revalidate(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .entry(CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-cache"));
    response
}

/// Serve the site icon.
///
/// A day of caching: the mark changes about never, and the request is otherwise
/// repeated on every cold tab.
async fn favicon() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "image/svg+xml"),
            (CACHE_CONTROL, "public, max-age=86400"),
        ],
        FAVICON_SVG,
    )
}
