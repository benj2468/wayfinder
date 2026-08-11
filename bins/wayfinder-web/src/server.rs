//! Assembly of the axum router the dashboard is served from.
//!
//! Split out of `main.rs` so the wiring can be driven by `tests/http.rs`
//! without a socket or a process. The wiring is worth testing on its own: the
//! node connection has to be provided on *both* router arms, and getting that
//! wrong yields a dashboard that renders perfectly and fails every poll.

use std::sync::Arc;

use axum::Router;
use axum::routing::post;
use leptos::config::LeptosOptions;
use leptos::prelude::provide_context;
use leptos_axum::LeptosRoutes;
use leptos_axum::generate_route_list;
use leptos_axum::handle_server_fns_with_context;

use crate::App;
use crate::conn::NodeConnection;
use crate::shell;

/// Build the dashboard router: server-function endpoints, the server-rendered
/// page routes, and a static-file fallback for the wasm/CSS bundle.
///
/// `conn` is handed to both the server-function route and the page routes,
/// because a page rendered on the server runs the same resources the browser
/// would and so calls the same server functions.
pub fn build_router(options: LeptosOptions, conn: Arc<NodeConnection>) -> Router {
    let provide_conn = move || provide_context(Arc::clone(&conn));

    Router::new()
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
        .with_state(options)
}
