//! Assembly of the axum router the dashboard is served from.
//!
//! Split out of `main.rs` so the wiring can be driven by `tests/http.rs`
//! without a socket or a process. The wiring is worth testing on its own: the
//! node connection has to be provided on *both* router arms, and getting that
//! wrong yields a dashboard that renders perfectly and fails every poll.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::http::header::CONTENT_TYPE;
use axum::http::header::HOST;
use axum::http::header::ORIGIN;
use axum::middleware::Next;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use leptos::config::LeptosOptions;
use leptos::prelude::provide_context;
use leptos_axum::LeptosRoutes;
use leptos_axum::generate_route_list;
use leptos_axum::handle_server_fns_with_context;
use tracing::warn;

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
///
/// `hosts` is the set of names this dashboard answers to; see [`HostPolicy`]
/// for why a dashboard with no login of its own has to care.
pub fn build_router(
    options: LeptosOptions,
    conn: Arc<NodeConnection>,
    hosts: HostPolicy,
) -> Router {
    let provide_conn = move || provide_context(Arc::clone(&conn));
    let hosts = Arc::new(hosts);

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
        // `POST` only. No server function uses a GET encoding, so a GET arm
        // would be unreachable today — and a CSRF amplifier the moment one did,
        // because a GET endpoint is forgeable from an `<img>` tag with no
        // script at all.
        //
        // This is a catch-all *behind* the per-function routes:
        // `leptos_routes_with_context` below registers every `#[server]`
        // function at its own exact path and method, and an exact path wins
        // over a wildcard. Which is why the same-origin gate is a router-wide
        // layer rather than a layer on this route — a layer here would never
        // see a real server-function call.
        .route(
            "/api/{*fn_name}",
            post({
                let provide = provide_conn.clone();
                move |req| handle_server_fns_with_context(provide.clone(), req)
            }),
        )
        .leptos_routes_with_context(&options, generate_route_list(App), provide_conn, {
            let options = options.clone();
            move || shell(options.clone())
        })
        .fallback(leptos_axum::file_and_error_handler(shell))
        .layer(from_fn(revalidate))
        .layer(from_fn({
            let hosts = Arc::clone(&hosts);
            move |request: Request, next: Next| {
                let hosts = Arc::clone(&hosts);
                async move { same_origin_only(&hosts, request, next).await }
            }
        }))
        .layer(from_fn({
            let hosts = Arc::clone(&hosts);
            move |request: Request, next: Next| {
                let hosts = Arc::clone(&hosts);
                async move { known_host_only(&hosts, request, next).await }
            }
        }))
        .with_state(options)
}

/// The host names this dashboard answers to.
///
/// # Why a name check, on a dashboard with no login
///
/// The bind address is not the boundary an operator thinks it is. A page on
/// any site can point a DNS name it controls at `127.0.0.1`, wait for the
/// browser's cache to expire, and then be *same-origin* with a loopback-bound
/// dashboard — reading every panel and driving every mutation on it. The only
/// thing that attack cannot do is produce a `Host` header the operator ever
/// chose, so refusing an unrecognised name is what closes it.
///
/// The default set is the loopback names plus the `--listen` address; anything
/// else — the name a reverse proxy fronts this with — is stated by the operator
/// with `--allowed-host`.
///
/// # Ports are not compared
///
/// A published container port (`-p 8081:8080`) and a proxy on 443 both change
/// the port the browser names while the deployment is unchanged, so comparing
/// it would turn ordinary port mapping into a mystery `403`. Nothing is lost:
/// rebinding is an attack on the *name*, and a hostile page served from another
/// port of a name in this set is refused by the cross-site check instead, which
/// compares full origins the way the browser does.
#[derive(Debug, Clone)]
pub struct HostPolicy {
    /// Lowercase host names, with no port and no brackets around an IPv6
    /// literal — the normalised form [`host_name`] produces.
    names: BTreeSet<String>,
}

impl HostPolicy {
    /// The default allowlist for a dashboard bound to `listen`: the loopback
    /// names, plus the bind address itself when it names one interface.
    ///
    /// A wildcard bind (`0.0.0.0`) names no interface, so it contributes
    /// nothing: a deployment that reaches the dashboard by any other name has
    /// to say which, through [`HostPolicy::allow`].
    #[must_use]
    pub fn for_listen(listen: SocketAddr) -> Self {
        let mut names: BTreeSet<String> = ["localhost", "127.0.0.1", "::1"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let ip = listen.ip();
        if !ip.is_unspecified() {
            names.insert(ip.to_string().to_ascii_lowercase());
        }
        Self { names }
    }

    /// Add the names an operator gave (`--allowed-host`), for the reverse proxy
    /// any non-loopback deployment is supposed to sit behind.
    #[must_use]
    pub fn allow<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for host in hosts {
            self.names
                .insert(host_name(host.as_ref()).to_ascii_lowercase());
        }
        self
    }

    /// Whether `authority` — a `Host` header, an HTTP/2 `:authority`, or the
    /// host part of an `Origin` — names this dashboard.
    fn admits(&self, authority: &str) -> bool {
        self.names
            .contains(&host_name(authority).to_ascii_lowercase())
    }
}

/// The host part of an authority: no port, and no brackets around an IPv6
/// literal.
///
/// The brackets are what keep an IPv6 literal's own colons from reading as a
/// port separator (`[::1]:8080`), so they have to be handled before the split.
fn host_name(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match authority.split_once(':') {
        Some((host, _port)) => host,
        None => authority,
    }
}

/// The host of an `Origin` header, or `None` if it is not one this dashboard
/// could have served.
///
/// A serialised origin is `scheme://host[:port]`; the opaque origin a sandboxed
/// frame or a `data:` document sends is the literal `null`, which has no `://`
/// and so lands in `None` — refused, which is what an opaque origin deserves.
fn origin_host(origin: &str) -> Option<&str> {
    let (scheme, rest) = origin.split_once("://")?;
    (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        .then(|| host_name(rest))
}

/// Refuse a request naming a host this dashboard does not answer to.
///
/// Applied to the whole router rather than the server-function route alone: a
/// rebound name that can load a page can read every panel rendered onto it.
///
/// A request with neither a `Host` header nor an HTTP/2 `:authority` is served.
/// That is not a browser — HTTP/1.1 has required `Host` since 1999 — and a
/// client that is not a browser carries no ambient credentials for the attack
/// this check exists to stop.
async fn known_host_only(hosts: &HostPolicy, request: Request, next: Next) -> Response {
    let refused = request
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
        })
        .filter(|authority| !hosts.admits(authority))
        .map(str::to_owned);

    if let Some(authority) = refused {
        warn!(host = %authority, "drop: request host is not in the allowlist");
        return forbidden("this dashboard does not answer to that host");
    }

    next.run(request).await
}

/// Refuse a server-function call that a page on another origin drove.
///
/// `#[server]` defaults to a form encoding, which is a CORS *simple request*:
/// the browser sends it cross-origin with no preflight, so nothing asks this
/// side for permission first, and `server_fn` carries no token of its own.
/// Without this, any page an operator visits can revoke a node, rewrite the
/// enrollment policy, or hand the node's identity to another mesh.
///
/// Two independent checks, because neither is universal. `Sec-Fetch-Site` is
/// the browser's own account of where the request came from and cannot be
/// forged from script, but no browser older than 2019 sends it; `Origin` is
/// older and broader but absent on some same-origin requests. Either one being
/// wrong is a refusal; both being absent is served, since a client that sends
/// neither is not a browser and has no session for a forgery to borrow.
///
/// `same-site` is refused alongside `cross-site`: a sibling port or subdomain
/// is a different origin, and on a developer's machine it is the likelier of
/// the two.
async fn same_origin_only(hosts: &HostPolicy, request: Request, next: Next) -> Response {
    if !is_guarded(&request) {
        return next.run(request).await;
    }

    let headers = request.headers();

    let site = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok());
    if let Some(site) = site
        && !matches!(site, "same-origin" | "none")
    {
        warn!(%site, "drop: cross-site request to a guarded route");
        return forbidden("cross-site requests are not accepted");
    }

    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| !origin_host(origin).is_some_and(|host| hosts.admits(host)))
        .map(str::to_owned);
    if let Some(origin) = origin {
        warn!(%origin, "drop: request to a guarded route from a foreign origin");
        return forbidden("cross-site requests are not accepted");
    }

    next.run(request).await
}

/// The path prefix `#[server]` publishes its functions under. Every mutation
/// this dashboard can perform is one `POST` beneath it.
const SERVER_FN_PREFIX: &str = "/api/";

/// Whether a request has to prove it came from this dashboard's own page.
///
/// Two overlapping rules rather than one, because either alone leaves a gap. A
/// request under [`SERVER_FN_PREFIX`] is a server-function call whatever its
/// method, which covers a future function that chooses a GET encoding — the
/// forgeable-from-an-`<img>`-tag case. Anything with an unsafe method is
/// guarded whatever its path, which covers a route that moves out from under
/// the prefix.
///
/// What is left unguarded is a plain read of a page, and it has to be: a link
/// to this dashboard from a wiki or a chat window is a cross-site navigation,
/// and refusing those would break the ordinary way anyone opens it.
fn is_guarded(request: &Request) -> bool {
    !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) || request.uri().path().starts_with(SERVER_FN_PREFIX)
}

/// A refusal that says what was wrong with the request but nothing about the
/// node behind it.
fn forbidden(detail: &'static str) -> Response {
    (StatusCode::FORBIDDEN, detail).into_response()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The listen address's own port is not what a browser necessarily names —
    /// a published container port or a proxy changes it — so only the name is
    /// compared.
    #[test]
    fn a_host_is_matched_by_name_alone() {
        let hosts = HostPolicy::for_listen("127.0.0.1:8080".parse().unwrap());

        assert!(hosts.admits("127.0.0.1"));
        assert!(hosts.admits("127.0.0.1:8080"));
        assert!(hosts.admits("127.0.0.1:9999"));
        assert!(hosts.admits("localhost:8080"));
        assert!(!hosts.admits("wayfinder.example"));
    }

    /// A name is a name whatever its case: `Host` is not case-sensitive, and a
    /// rebinding attack would happily spell one in mixed case.
    #[test]
    fn a_host_is_matched_case_insensitively() {
        let hosts =
            HostPolicy::for_listen("127.0.0.1:8080".parse().unwrap()).allow(["Wayfinder.Example"]);

        assert!(hosts.admits("WAYFINDER.example"));
        assert!(hosts.admits("LocalHost:8080"));
    }

    /// An IPv6 literal's brackets are what keep its own colons from reading as
    /// a port separator, so they come off before the split, not after.
    #[test]
    fn an_ipv6_literal_keeps_its_address_and_loses_its_brackets() {
        let hosts = HostPolicy::for_listen("[::1]:8080".parse().unwrap());

        assert!(hosts.admits("[::1]:8080"));
        assert!(hosts.admits("[::1]"));
        assert_eq!(host_name("[2001:db8::1]:8080"), "2001:db8::1");
    }

    /// A bind address that names one interface joins the allowlist, since that
    /// is the name the operator will type.
    #[test]
    fn a_specific_bind_address_admits_itself() {
        let hosts = HostPolicy::for_listen("192.168.1.5:8080".parse().unwrap());

        assert!(hosts.admits("192.168.1.5:8080"));
        assert!(hosts.admits("localhost:8080"));
    }

    /// A wildcard bind names no interface, so it contributes nothing: reaching
    /// such a deployment by any name but loopback has to be stated.
    #[test]
    fn a_wildcard_bind_admits_only_loopback_and_what_it_was_told() {
        let hosts = HostPolicy::for_listen("0.0.0.0:8080".parse().unwrap());

        assert!(hosts.admits("127.0.0.1:8080"));
        assert!(!hosts.admits("0.0.0.0:8080"));
        assert!(!hosts.admits("192.168.1.5:8080"));

        let hosts = hosts.allow(["wayfinder.example"]);
        assert!(hosts.admits("wayfinder.example"));
    }

    /// An origin is a scheme and a host; anything else — the opaque `null` a
    /// sandboxed frame sends, or a scheme this dashboard could not have served
    /// from — has no host to match and is refused.
    #[test]
    fn only_an_http_origin_yields_a_host() {
        assert_eq!(origin_host("http://localhost:8080"), Some("localhost"));
        assert_eq!(
            origin_host("https://wayfinder.example"),
            Some("wayfinder.example")
        );
        assert_eq!(origin_host("HTTP://[::1]:8080"), Some("::1"));
        assert_eq!(origin_host("null"), None);
        assert_eq!(origin_host("file://"), None);
    }
}
