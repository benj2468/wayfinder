//! The dashboard's own login, end to end over HTTP.
//!
//! `tests/http.rs` proves the browser-facing wiring of a dashboard that already
//! holds a credential. This proves the half that decides *whether it holds one*:
//! a login exchanges a username and password at the provider for a session
//! certificate, the session id comes back in a cookie, and the node then accepts
//! the connection that certificate authenticates.
//!
//! Every step is real — a real management-TLS handshake against a real
//! `wayfinder-server` listener, a real `CertAuthority` minting a real
//! certificate, and the node verifying it against a real trust anchor. The
//! failure this catches is the one that cannot be caught anywhere else: a
//! session that logs in successfully and then cannot use what it was given.
//!
//! The `.wfauth` credential file is exercised the same way and for the same
//! reason. Its unit tests (`src/bundle.rs`) prove the file round-trips; only a
//! test that carries a real certificate from a real download into a real
//! sign-in and then polls a real node can prove the credential inside it still
//! works — and only one pointed at a *dead provider* can prove the thing the
//! whole feature claims, which is that signing in that way needs no provider at
//! all.

#![cfg(feature = "mock-node")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header::SET_COOKIE;
use http_body_util::BodyExt;
use tower::ServiceExt;
use wayfinder_protos::wayfinder::v1alpha::UserAccount;
use wayfinder_web::mock::MOCK_ADMIN_USER;
use wayfinder_web::mock::MOCK_PASSWORD;
use wayfinder_web::mock::MOCK_VIEWER_USER;
use wayfinder_web::session::LoginResult;
use wayfinder_web::session::SESSION_COOKIE;
use wayfinder_web::session::Viewer;
use wayfinder_web::snapshot::NodeSnapshot;

/// GET a route the way a browser following a link does, with an optional
/// session cookie.
///
/// The credential download is not a server function — it is a plain `GET`
/// behind an `<a download>` — so it needs its own way in rather than [`call`].
async fn get(app: &axum::Router, path: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut request = Request::get(path).header("sec-fetch-site", "same-origin");
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("{SESSION_COOKIE}={cookie}"));
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// Sign in with a password and return the session cookie it set.
async fn sign_in(app: &axum::Router, username: &str) -> String {
    let response = call(
        app,
        "login",
        &format!("username={username}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    session_cookie(&response).0
}

/// Download the credential file for a session, returning the `Content-Disposition`
/// it arrived with and the file's text.
async fn download_credential(app: &axum::Router, cookie: &str) -> (String, String) {
    let response = get(app, wayfinder_web::bundle::DOWNLOAD_PATH, Some(cookie)).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a signed-in session can download its own credential"
    );
    let disposition = response
        .headers()
        .get(axum::http::header::CONTENT_DISPOSITION)
        .expect("a download names the file it is")
        .to_str()
        .unwrap()
        .to_string();
    let cache = response
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .expect("a private key says how it may be cached")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        cache.contains("no-store"),
        "a private key must not be written to a browser's disk cache: {cache}"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (disposition, String::from_utf8(body.to_vec()).unwrap())
}

/// POST a server function the way the browser does, with an optional session
/// cookie.
async fn call(
    app: &axum::Router,
    endpoint: &str,
    form: &str,
    cookie: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::post(format!("/api/{endpoint}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json");
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("{SESSION_COOKIE}={cookie}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(form.to_string())).unwrap())
        .await
        .unwrap()
}

/// Decode a server function's JSON answer.
async fn json<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "server function failed: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).expect("the response is what the browser will decode")
}

/// The session id a `Set-Cookie` carries, plus the attributes it was set with.
fn session_cookie(response: &axum::response::Response) -> (String, String) {
    let header = response
        .headers()
        .get(SET_COOKIE)
        .expect("a successful login sets the session cookie")
        .to_str()
        .unwrap()
        .to_string();
    let value = header
        .split(';')
        .next()
        .unwrap()
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .expect("the cookie is the session cookie")
        .to_string();
    (value, header)
}

/// The whole path: log in, get a cookie, poll the node with it.
///
/// The last step is the one that matters. Everything before it could be right
/// while the certificate the provider issued is one the node will not accept —
/// a mesh id, a validity window or a key binding off by one — and the symptom
/// would be a dashboard that logs in cleanly and then reports the node as
/// unreachable.
#[tokio::test]
async fn a_login_yields_a_session_the_node_accepts() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_ADMIN_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    let (id, attributes) = session_cookie(&response);

    // The cookie is not reachable from script and does not ride a cross-site
    // request: the two attributes that make it a session credential rather than
    // a token any page can borrow.
    assert!(attributes.contains("HttpOnly"), "{attributes}");
    assert!(attributes.contains("SameSite=Strict"), "{attributes}");
    assert!(attributes.contains("Path=/"), "{attributes}");

    let outcome: LoginResult = json(response).await;
    let LoginResult::LoggedIn(info) = outcome else {
        panic!("the admin account's own password is accepted: {outcome:?}");
    };
    assert_eq!(info.username, MOCK_ADMIN_USER);
    assert_eq!(
        info.capability, "administrator",
        "an admin account's session says what it may do, in words"
    );
    assert!(
        info.admin,
        "and says it in a form the dashboard can branch on, not only in words"
    );

    // What the session is *for*: the node answers a poll made with it.
    let snapshot: NodeSnapshot = json(call(&app, "snapshot", "since_seq=0", Some(&id)).await).await;
    assert_eq!(snapshot.routing.entries.len(), 1);

    // And the dashboard knows who is looking at it.
    let viewer: Viewer = json(call(&app, "session", "", Some(&id)).await).await;
    assert_eq!(viewer, Viewer::LoggedIn(info));
}

/// Without a session, login mode reaches no node at all — which is the whole
/// point of it: the process-wide credential that anyone reaching the port
/// inherited is gone.
#[tokio::test]
async fn no_session_reaches_no_node() {
    let app = common::login_router().await;

    let viewer: Viewer = json(call(&app, "session", "", None).await).await;
    assert_eq!(viewer, Viewer::LoggedOut);

    let response = call(&app, "snapshot", "since_seq=0", None).await;
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "a poll with no session cannot succeed"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains(wayfinder_web::session::NEEDS_LOGIN),
        "the failure says to log in rather than blaming the node: {text}"
    );

    // A session id nobody issued is no session either.
    let viewer: Viewer = json(call(&app, "session", "", Some(&"a".repeat(64))).await).await;
    assert_eq!(viewer, Viewer::LoggedOut);
}

/// A wrong password is an *answer*, not an error: the provider says no, the
/// dashboard renders that, and no cookie is set.
///
/// It is also one answer for every reason — the node never learns whether the
/// account exists — so this asserts on the shape of the refusal and not on any
/// detail in it.
#[tokio::test]
async fn a_wrong_password_is_refused_without_a_session() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_ADMIN_USER}&password=not-the-password&totp_code="),
        None,
    )
    .await;
    assert!(
        response.headers().get(SET_COOKIE).is_none(),
        "a refused login sets no cookie"
    );
    let outcome: LoginResult = json(response).await;
    assert_eq!(outcome, LoginResult::Denied);

    // An account that does not exist is refused identically.
    let outcome: LoginResult = json(
        call(
            &app,
            "login",
            &format!("username=nobody&password={MOCK_PASSWORD}&totp_code="),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(outcome, LoginResult::Denied);
}

/// Logging out ends the session on the server, not just in the browser.
///
/// Expiring the cookie alone would leave a live, admin-capable connection in
/// the store for whoever kept a copy of the id.
#[tokio::test]
async fn logging_out_ends_the_session_on_the_server() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_ADMIN_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    let (id, _) = session_cookie(&response);

    let response = call(&app, "logout", "", Some(&id)).await;
    let cleared = response
        .headers()
        .get(SET_COOKIE)
        .expect("logging out clears the cookie")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        cleared.contains("Max-Age=0"),
        "the cookie is expired, not merely replaced: {cleared}"
    );

    let viewer: Viewer = json(call(&app, "session", "", Some(&id)).await).await;
    assert_eq!(
        viewer,
        Viewer::LoggedOut,
        "the id is dead even when it is presented again"
    );
}

/// A viewer account's session may read the node and may not change it.
///
/// The read-only tier is a signed bit on the certificate the provider issues
/// and a request allowlist at the node, with nothing in this crate in between —
/// so this is the only place the two ends are checked against each other.
#[tokio::test]
async fn a_viewer_session_can_poll_and_cannot_mutate() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_VIEWER_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    let (id, _) = session_cookie(&response);
    let outcome: LoginResult = json(response).await;
    let LoginResult::LoggedIn(info) = outcome else {
        panic!("the viewer account's password is accepted: {outcome:?}");
    };
    assert_eq!(
        info.capability, "read-only",
        "a viewer account's session says what it may do, in words"
    );
    assert!(
        !info.admin,
        "and the dashboard is told, so it offers no control the node would refuse"
    );

    let snapshot: NodeSnapshot = json(call(&app, "snapshot", "since_seq=0", Some(&id)).await).await;
    assert_eq!(snapshot.routing.entries.len(), 1);

    let response = call(
        &app,
        "set_link_gate",
        "iface_idx=0&gate=TxOgm&value=false",
        Some(&id),
    )
    .await;
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "a viewer's session cannot flip a gate"
    );
}

/// The page a signed-out browser gets is the sign-in form, with the dashboard
/// rendered but hidden — and every tab route still discovered.
///
/// Both halves matter and they pull against each other. `<Routes>` has to be in
/// the view tree unconditionally, because `generate_route_list` walks the app
/// once at startup with no session to discover them; hiding the shell is how
/// that is reconciled with not showing a dashboard to someone who has not
/// signed in. Put the gate around `<Routes>` instead and every tab but the
/// index answers 404, at startup, for both modes at once.
#[tokio::test]
async fn a_signed_out_page_is_the_sign_in_form_over_a_hidden_dashboard() {
    let app = common::login_router().await;

    for path in ["/", "/routing", "/security"] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path} is served");

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("wf-login-page"),
            "{path} renders the sign-in form"
        );
        assert!(
            html.contains("wf-shell"),
            "{path} still renders the shell, which is what the stylesheet hides"
        );
        assert!(
            !html.contains("Not found."),
            "{path} is still a real route: {html:.400}"
        );
    }
}

/// An administrator's session can read the account roster and add to it; the
/// account it creates is one the provider will then sign in.
///
/// The last step is what makes this more than a wire test: an account that
/// lists correctly and cannot be signed in as is an account the operator will
/// only find out about from somebody else's failed sign-in.
#[tokio::test]
async fn an_admin_session_lists_and_creates_accounts() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_ADMIN_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    let (id, _) = session_cookie(&response);

    let users: Vec<UserAccount> = json(call(&app, "list_users", "", Some(&id)).await).await;
    let names: Vec<&str> = users.iter().map(|u| u.username.as_str()).collect();
    assert!(
        names.contains(&MOCK_ADMIN_USER) && names.contains(&MOCK_VIEWER_USER),
        "the roster is the store's, not a canned one: {names:?}"
    );
    assert!(
        users
            .iter()
            .any(|u| u.username == MOCK_ADMIN_USER && u.admin),
        "and says which of them may administer the mesh: {users:?}"
    );

    // Created without a second factor, so the enrolment URI comes back empty —
    // which is the one case where nothing is lost by not showing it.
    let uri: String = json(
        call(
            &app,
            "create_user",
            "username=fieldop&password=a-long-enough-password&admin=false\
             &session_ttl_secs=900&no_totp=true",
            Some(&id),
        )
        .await,
    )
    .await;
    assert!(uri.is_empty(), "no second factor, no URI to enrol: {uri:?}");

    let users: Vec<UserAccount> = json(call(&app, "list_users", "", Some(&id)).await).await;
    let created = users
        .iter()
        .find(|u| u.username == "fieldop")
        .expect("the new account is in the roster");
    assert!(!created.admin, "created read-only, as asked");
    assert_eq!(created.session_ttl_secs, 900);
    assert!(!created.totp_enrolled);

    // The account is real: it signs in, and the session it gets is read-only.
    let response = call(
        &app,
        "login",
        "username=fieldop&password=a-long-enough-password&totp_code=",
        None,
    )
    .await;
    let outcome: LoginResult = json(response).await;
    let LoginResult::LoggedIn(info) = outcome else {
        panic!("the account just created signs in: {outcome:?}");
    };
    assert_eq!(info.capability, "read-only");
}

/// A read-only session may not read the roster and may not add to it.
///
/// Both refusals come from the node's `permits` allowlist rather than from
/// anything in this crate, which is exactly why they are worth asserting from
/// this end: the dashboard offers the Provider tab to whoever is signed in, and
/// what stops a viewer using it is the node.
#[tokio::test]
async fn a_viewer_session_cannot_read_or_create_accounts() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_VIEWER_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    let (id, _) = session_cookie(&response);

    for (endpoint, form) in [
        ("list_users", ""),
        (
            "create_user",
            "username=sneaky&password=another-password&admin=true\
             &session_ttl_secs=0&no_totp=true",
        ),
        ("remove_user", &format!("username={MOCK_VIEWER_USER}")),
    ] {
        let response = call(&app, endpoint, form, Some(&id)).await;
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "{endpoint} must be refused to a read-only session"
        );
    }
}

/// A name already taken is an error the operator can act on, not a silent
/// replacement of the account that has it.
#[tokio::test]
async fn creating_an_account_twice_is_refused() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_ADMIN_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    let (id, _) = session_cookie(&response);

    let response = call(
        &app,
        "create_user",
        &format!(
            "username={MOCK_ADMIN_USER}&password=a-different-password&admin=true\
             &session_ttl_secs=0&no_totp=true"
        ),
        Some(&id),
    )
    .await;
    assert_ne!(response.status(), StatusCode::OK, "a duplicate is refused");

    // And the account that already had the name still has its own password.
    let outcome: LoginResult = json(
        call(
            &app,
            "login",
            &format!("username={MOCK_ADMIN_USER}&password={MOCK_PASSWORD}&totp_code="),
            None,
        )
        .await,
    )
    .await;
    assert!(matches!(outcome, LoginResult::LoggedIn(_)));
}

/// Removing an account is the other half of administering the roster, and it
/// takes effect where it matters: the account it names can no longer sign in.
///
/// A roster that shrinks is not proof on its own — a store that dropped the row
/// and kept the credential would pass that and fail here.
#[tokio::test]
async fn an_admin_session_removes_an_account() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_ADMIN_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    let (id, _) = session_cookie(&response);

    // The viewer can sign in to begin with, so what changes below is the
    // removal and not something that was never true.
    let outcome: LoginResult = json(
        call(
            &app,
            "login",
            &format!("username={MOCK_VIEWER_USER}&password={MOCK_PASSWORD}&totp_code="),
            None,
        )
        .await,
    )
    .await;
    assert!(matches!(outcome, LoginResult::LoggedIn(_)));

    let response = call(
        &app,
        "remove_user",
        &format!("username={MOCK_VIEWER_USER}"),
        Some(&id),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the removal is accepted");

    let users: Vec<UserAccount> = json(call(&app, "list_users", "", Some(&id)).await).await;
    assert!(
        !users.iter().any(|u| u.username == MOCK_VIEWER_USER),
        "the account is off the roster: {users:?}"
    );

    let outcome: LoginResult = json(
        call(
            &app,
            "login",
            &format!("username={MOCK_VIEWER_USER}&password={MOCK_PASSWORD}&totp_code="),
            None,
        )
        .await,
    )
    .await;
    assert!(
        matches!(outcome, LoginResult::Denied),
        "and the credential it had goes with it"
    );
}

/// The mock provider has exactly one administrator, which makes it the shape
/// this refusal exists for: removing it would leave a mesh nobody can
/// administer over the network, recoverable only with a shell on the provider
/// host.
#[tokio::test]
async fn removing_the_last_administrator_is_refused() {
    let app = common::login_router().await;

    let response = call(
        &app,
        "login",
        &format!("username={MOCK_ADMIN_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    let (id, _) = session_cookie(&response);

    let response = call(
        &app,
        "remove_user",
        &format!("username={MOCK_ADMIN_USER}"),
        Some(&id),
    )
    .await;
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "the last administrator is not removable over the API"
    );

    // And the session that tried it still works, because the account still does.
    let users: Vec<UserAccount> = json(call(&app, "list_users", "", Some(&id)).await).await;
    assert!(
        users
            .iter()
            .any(|u| u.username == MOCK_ADMIN_USER && u.admin),
        "the administrator is still on file: {users:?}"
    );
}

/// The whole credential-file path: sign in with a password, download the file,
/// sign in again with nothing but that file, and poll the node with what it
/// produced.
///
/// The last step is the one that matters, and it is the same reason
/// `a_login_yields_a_session_the_node_accepts` ends where it does. Everything
/// before it could be right while the credential the file carries is one the
/// node will not accept — a seed and certificate that came apart in the hex, a
/// certificate truncated by a serialiser — and the symptom would be a dashboard
/// that signs in off a file and then reports the node as unreachable.
#[tokio::test]
async fn a_downloaded_credential_signs_back_in_and_reaches_the_node() {
    let app = common::login_router().await;
    let cookie = sign_in(&app, MOCK_ADMIN_USER).await;

    let (disposition, file) = download_credential(&app, &cookie).await;
    assert!(
        disposition.starts_with(&format!("attachment; filename=\"{MOCK_ADMIN_USER}-")),
        "the file is named for the account it belongs to: {disposition}"
    );
    assert!(
        disposition.ends_with(".wfauth\""),
        "and carries the extension the sign-in form filters on: {disposition}"
    );

    // Signed in with the file alone: no password, no code, and — crucially —
    // no cookie from the session that produced it.
    let response = call(
        &app,
        "login_bundle",
        &format!("bundle={}", urlencoded(&file)),
        None,
    )
    .await;
    let (offline_id, attributes) = session_cookie(&response);
    assert!(attributes.contains("HttpOnly"), "{attributes}");
    assert!(attributes.contains("SameSite=Strict"), "{attributes}");

    let outcome: LoginResult = json(response).await;
    let LoginResult::LoggedIn(info) = outcome else {
        panic!("a credential this dashboard issued is one it accepts back: {outcome:?}");
    };
    assert_eq!(info.username, MOCK_ADMIN_USER);
    assert_eq!(
        info.capability, "administrator",
        "the capability is recomputed from the certificate's signed flags"
    );

    // What the session is *for*: the node answers a poll made with it.
    let snapshot: NodeSnapshot =
        json(call(&app, "snapshot", "since_seq=0", Some(&offline_id)).await).await;
    assert_eq!(snapshot.routing.entries.len(), 1);

    // Two independent sessions, not one re-used: the file did not adopt the
    // session it came from, and ending that one leaves this one alone.
    assert_ne!(offline_id, cookie);
    let response = call(&app, "logout", "", Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let viewer: Viewer = json(call(&app, "session", "", Some(&offline_id)).await).await;
    assert_eq!(viewer, Viewer::LoggedIn(info));
}

/// The claim the whole feature rests on: a credential file signs in with the
/// certificate authority **unreachable**.
///
/// Pointed at a provider address nothing is listening on, so a password sign-in
/// genuinely cannot work — which is what makes the file sign-in that follows
/// mean something. Without this, every other test here would pass with a
/// `login_with_bundle` that quietly asked the provider anyway.
#[tokio::test]
async fn a_credential_file_signs_in_with_the_provider_unreachable() {
    // The file is minted while the provider is up.
    let online = common::login_router().await;
    let cookie = sign_in(&online, MOCK_VIEWER_USER).await;
    let (_, file) = download_credential(&online, &cookie).await;

    // A second dashboard onto the same node, whose provider is a dead address.
    let offline = common::login_router_with_dead_provider().await;

    // The password route is genuinely shut, and not merely slow: a provider
    // that cannot be reached is an error rather than a `Denied`, so this is
    // asserted on the response and not decoded as an outcome.
    let response = call(
        &offline,
        "login",
        &format!("username={MOCK_VIEWER_USER}&password={MOCK_PASSWORD}&totp_code="),
        None,
    )
    .await;
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "a password sign-in cannot succeed against a provider that is not there"
    );
    assert!(
        response.headers().get(SET_COOKIE).is_none(),
        "and opens no session"
    );

    let response = call(
        &offline,
        "login_bundle",
        &format!("bundle={}", urlencoded(&file)),
        None,
    )
    .await;
    let (id, _) = session_cookie(&response);
    let outcome: LoginResult = json(response).await;
    let LoginResult::LoggedIn(info) = outcome else {
        panic!("the credential file needs no provider: {outcome:?}");
    };
    assert_eq!(info.capability, "read-only");

    let snapshot: NodeSnapshot =
        json(call(&offline, "snapshot", "since_seq=0", Some(&id)).await).await;
    assert_eq!(
        snapshot.routing.entries.len(),
        1,
        "and the session it produced reaches the node"
    );
}

/// The credential is handed only to the session it belongs to.
///
/// There is no id in the URL to change, so the whole of the access control is
/// "which session does this cookie name" — which is exactly why it is worth a
/// test of its own: a route that forgot to look would serve the first session
/// in the map to anybody, and nothing else here would notice.
#[tokio::test]
async fn a_credential_is_not_served_without_the_session_it_belongs_to() {
    let app = common::login_router().await;
    // A live session exists, so "there is nothing to serve" is not the reason
    // the requests below fail.
    let cookie = sign_in(&app, MOCK_ADMIN_USER).await;

    for (label, presented) in [
        ("no cookie at all", None),
        ("a session id nobody issued", Some("a".repeat(64))),
    ] {
        let response = get(
            &app,
            wayfinder_web::bundle::DOWNLOAD_PATH,
            presented.as_deref(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "the credential download is refused to {label}"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&body).contains(wayfinder_web::session::NEEDS_LOGIN),
            "and says to sign in rather than blaming the node"
        );
    }

    // The session that does hold one still gets it, so the refusals above are
    // about the credential presented and not about the route being broken.
    let (_, file) = download_credential(&app, &cookie).await;
    assert!(file.contains("\"version\""), "{file:.200}");
}

/// A credential file is only worth what the node makes of it, and this is the
/// proof: flip a bit anywhere in the certificate and the sign-in fails.
///
/// The dashboard holds no trust anchor and cannot check the mesh root's
/// signature itself — in login mode it holds no mesh identity at all — so the
/// refusal has to come from the node. Which means a sign-in that skipped asking
/// the node would pass every other test here and fail this one.
#[tokio::test]
async fn a_tampered_credential_is_refused_by_the_node() {
    let app = common::login_router().await;
    let cookie = sign_in(&app, MOCK_VIEWER_USER).await;
    let (_, file) = download_credential(&app, &cookie).await;

    // The `flags` byte, which is where a forger would go: the second byte of
    // the certificate, and the one that says "administrator". It is inside the
    // signed body, so changing it breaks the mesh root's signature.
    let bundle: serde_json::Value = serde_json::from_str(&file).unwrap();
    let cert = bundle["cert"].as_str().unwrap();
    let forged = format!("{}01{}", &cert[..2], &cert[4..]);
    assert_ne!(forged, cert, "the flags byte actually changed");
    let mut bundle = bundle;
    bundle["cert"] = serde_json::Value::String(forged);
    let file = serde_json::to_string(&bundle).unwrap();

    let response = call(
        &app,
        "login_bundle",
        &format!("bundle={}", urlencoded(&file)),
        None,
    )
    .await;
    assert!(
        response.headers().get(SET_COOKIE).is_none(),
        "a forged credential opens no session"
    );
    assert_ne!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("did not accept this credential"),
        "the refusal names the node as the party that refused: {text}"
    );
}

/// A file that is not a credential, or is one that has run out, is refused with
/// its reason.
///
/// The opposite of the password form's deliberate silence, and deliberately so:
/// the person is holding their own file, so there is no account to enumerate
/// and nothing an attacker learns — while "this expired" is the difference
/// between downloading a new one and filing a bug.
#[tokio::test]
async fn a_file_that_is_not_a_usable_credential_says_why() {
    let app = common::login_router().await;
    let cookie = sign_in(&app, MOCK_ADMIN_USER).await;
    let (_, file) = download_credential(&app, &cookie).await;

    // Not a bundle at all.
    let response = call(&app, "login_bundle", "bundle=hello", None).await;
    assert_ne!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("not a Wayfinder credential bundle"),
        "{}",
        String::from_utf8_lossy(&body)
    );

    // A bundle whose certificate does not belong to the key beside it — which
    // is what pasting somebody else's certificate into your own file produces.
    let mut bundle: serde_json::Value = serde_json::from_str(&file).unwrap();
    bundle["seed"] = serde_json::Value::String("11".repeat(32));
    let response = call(
        &app,
        "login_bundle",
        &format!("bundle={}", urlencoded(&bundle.to_string())),
        None,
    )
    .await;
    assert_ne!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("does not belong to the key"),
        "{}",
        String::from_utf8_lossy(&body)
    );
}

/// The sign-in page offers the file route, in the one form, filtered to the
/// extension the download actually produces.
///
/// A markup test because the two ends are named in different files: an `accept`
/// filter that disagrees with the downloaded name is a file picker that greys
/// out the file it just made, which nothing else here would catch.
#[tokio::test]
async fn the_sign_in_page_offers_the_credential_file_route() {
    let app = common::login_router().await;

    let response = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&body);

    assert!(html.contains("Or a credential file"), "{html:.600}");
    assert!(
        html.contains(&format!(
            "accept=\".{}\"",
            wayfinder_web::bundle::BUNDLE_EXTENSION
        )),
        "the picker filters on the extension the download produces"
    );
    // One form and one submit: the file is a fourth field, not a second way in
    // with a button of its own.
    assert_eq!(
        html.matches("type=\"submit\"").count(),
        1,
        "the sign-in page has exactly one submit button"
    );
}

/// Percent-encode a file's text for the form encoding `#[server]` uses.
///
/// Written out rather than pulled from a crate: the bundle is JSON — braces,
/// quotes, newlines and hex — and this is the one place in the test suite that
/// has to survive them.
fn urlencoded(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
