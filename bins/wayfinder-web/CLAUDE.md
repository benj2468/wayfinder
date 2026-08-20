# bins/wayfinder-web

A browser dashboard for a running node: the seven views `wayfinder-tui` shows in
a terminal, reachable over HTTP, plus a **Provider** tab the TUI has no
equivalent for. Built with Leptos in SSR mode — an axum server plus a wasm
hydration bundle, compiled from this one crate.

## The constraint that shapes everything

`wayfinder-client` depends on tokio's network stack, `tokio-rustls` and
`tokio-serial`. **None of those build for `wasm32-unknown-unknown`**, so the
browser cannot speak the management protocol even in principle. The server holds
the connection and the mesh identity; the browser reaches the node only through
`#[server]` functions and never holds a key.

This is also why picoserve or any `no_std` HTTP server is not an option here:
Leptos SSR has integrations for axum and actix only, and its renderer is not
`no_std` regardless. An embedded node is reached by pointing this dashboard at
its serial management port (`--serial`), not by having the board serve HTTP.

## Two builds from one crate

`cargo-leptos` compiles this crate twice, driven by `[[workspace.metadata.leptos]]`
in the **root** `Cargo.toml`:

| Feature | Target | Produces |
|---|---|---|
| `ssr` | host | the axum server binary |
| `hydrate` | `wasm32-unknown-unknown` | the bundle that adopts the server's markup |

**`default` is deliberately empty.** A plain `cargo build --workspace` then
compiles a stub (`main` is `#[cfg(feature = "ssr")]`-gated) rather than failing,
which keeps the root workspace green. The corollary is that a workspace build
proves nothing about this crate — hence the `build:web` CI job.

Anything server-side must be behind `#[cfg(feature = "ssr")]` (`conn`, `server`,
`mock`, and `build_snapshot`). The wasm build is the check that this holds:
it drops every server dependency, so a misplaced `cfg` fails there and nowhere
else.

### Version pins that move together

`wasm-bindgen` refuses to run when the CLI generating the JS glue differs from
the crate compiled into the wasm. Three places carry the same version and must
be bumped as one:

- `wasm-bindgen = "=0.2.126"` in this crate's `Cargo.toml`
- `wasm-bindgen-cli_0_2_126` in the repo's `flake.nix` devShell
- `wasm-bindgen-cli@0.2.126` in `containers/testenv.Dockerfile`

## Layout

- `conn.rs` (ssr) — one `Client` behind a mutex, connected lazily and dropped on
  any failure so the next poll reconnects. The TUI's policy. `run` takes the
  whole client for one exchange, so a ten-RPC poll costs one lock.
- `snapshot.rs` — `NodeSnapshot`, the bundle every tab reads, plus its fetcher.
  Carries the generated proto types directly; there is no parallel DTO layer.
- `session.rs` — who is looking and what credential that gets them: the two
  `Access` modes, the session store (one `NodeConnection` per signed-in viewer),
  and the cookie mechanics. The shared `Viewer`/`SessionInfo`/`LoginResult`
  types cross the wire; everything else is `ssr`-gated within the module.
- `bundle.rs` — the `.wfauth` credential file: a session's seed and certificate
  as JSON, plus the checks a file gets on the way back in. Only its two
  constants (the extension, the download path) are ungated — the browser names
  both and looks inside neither.
- `api.rs` — the `#[server]` functions, thin wrappers over the above. Every one
  sets `endpoint` explicitly; the derived paths carry a rename-sensitive hash.
  `connection()` is where the two modes converge: static hands back the
  process's connection, login resolves the cookie to a session's own.
- `state.rs` — what accumulates across polls (log scrollback, throughput trend).
- `format.rs` — every display conversion, so none of them live in a `view!`
  macro where they cannot be tested.
- `components/` — the tabs. Pure functions of the dashboard state. `security.rs`
  is about *this node*: who it believes it is, who it believes its neighbours
  are, what it refuses to do without a certificate. `provider.rs` is about the
  node's other job, which most nodes do not have at all — deciding who else gets
  in: the accounts, the enrollment policy, what a joining node must be told, and
  the queue of nodes waiting. The one exception to "pure function of the state"
  is `logo.rs`: the mark, drawn inline so the ink can follow the theme, and the
  favicon `server.rs` serves from its own route. It carries a second copy of the
  geometry in `assets/logo/`, pinned to it by unit tests — see that directory's
  README before replacing the logo.
- `clipboard.rs` — the one copy-to-clipboard path, browser-side only.
- `filepicker.rs` — the one read-a-chosen-file path, browser-side only, for the
  sign-in form's credential file. Reads bytes and judges nothing.
- `mock.rs` (`mock-node` feature) — a canned node, for tests and for
  `examples/mock_node.rs`.

## Working on it without hardware

```bash
cargo run -p wayfinder-web --features mock-node --example mock_node
# then, in another shell, run the command it prints
```

The mock is the *real* `wayfinder-server` TLS listener over canned data, so the
handshake, framing and dispatch are all genuine.

## Shipping it

`containers/Dockerfile`'s `web` target is the only image assembled from two
build stages, because the two builds above have different architectures: the
`builder` stage cross-compiles the axum server for the image's real arch, and a
separate `site` stage runs `cargo leptos build --release --frontend-only` to
produce the wasm/JS/CSS bundle, which is arch-independent.

**Outside `cargo leptos`, the binary finds its assets only through the
environment**, and `LEPTOS_OUTPUT_NAME` is needed twice over:

- **At runtime**, `get_configuration(None)` reads `LEPTOS_OUTPUT_NAME`,
  `LEPTOS_SITE_ROOT` and `LEPTOS_SITE_PKG_DIR` and consults nothing else — there
  is no `Cargo.toml` to fall back on in a container.
- **At compile time**, `leptos` reads the same variable through
  `std::option_env!`. Unset, it bakes in the plain `wasm-bindgen` file layout and
  asks the browser for `<name>_bg.wasm`, which cargo-leptos never emits (it
  renames the file to `<name>.wasm`).

Either mistake fails the same silent way: the server starts, serves correct
server-rendered markup, and 404s the wasm that would have made the page
interactive — a dashboard that looks right and never updates. `cargo leptos`
exports both for its own builds, so only a *plain* `cargo build` of the `ssr`
binary has to do it by hand. The container does, in `ENV` on both stages; any
other deployment path has to as well.

### The two halves must come from one build

Server-rendered markup and the wasm that hydrates it are halves of the same
build, and hydration is a *walk* over the markup — so halves from different
builds do not merely look wrong, the walk desynchronises and panics partway
through. By then the tab bar has its click handlers, so every tab swallows its
click and goes nowhere: a dashboard that looks completely normal and is entirely
dead. `server.rs` therefore serves everything `cache-control: no-cache`
(revalidate, not re-download) — nothing else prevents the drift, since the
bundle URL carries no content hash and Chrome's plain reload does not
revalidate subresources. The favicon opts out with its own header; anything else
that wants a cache must do the same, deliberately.

`/pkg` gets its own `ServeDir` rather than riding leptos's static-file fallback,
only because that fallback ignores `If-Modified-Since` — under `no-cache` it
would re-send the whole wasm bundle on every page view instead of a `304`.

cargo-leptos's `hash-files` would make the drift *impossible* rather than merely
detectable, by putting a content hash in the bundle filenames. It is off: the
server then needs `LEPTOS_HASH_FILES` as well, and getting that wrong fails the
same silent way as the two variables above — hashed files on disk, unhashed URLs
in the markup, a page that renders and never wakes up. Revisit if the
revalidation round trip ever costs more than that risk.

`hydrate()` installs a panic hook that paints a banner saying the page is dead
and to reload. It is the only thing that can speak — a wasm panic aborts — and
without it this whole failure mode is invisible.

## Conventions

- **Formatting goes in `format.rs`, never inline in a `view!`.** Macro bodies
  are not unit testable, and these conversions are exactly the ones worth
  testing.
- **Plain language leads, jargon follows.** "94%" with `TQ 240` beneath, not the
  other way round. Non-technical users are the point of this crate.
- **An empty state says why it is empty.** "No neighbours yet" and "waiting for
  the node" render identically as a blank table and mean different things.
- **The node is the authority.** Mutations apply optimistically and the next poll
  confirms them; a change that did not take must visibly snap back.
- **Losing the node is a state, not an error.** Keep the last snapshot on screen
  under a banner rather than blanking the tabs.
- `#[server]` generates a request struct whose fields carry no docs, so each one
  needs `#[allow(missing_docs, reason = "…")]` — scoped to the function, the way
  `wayfinder-protos` quarantines the same lint over its prost bindings.

## Testing

```bash
cargo test -p wayfinder-web --features mock-node     # all of the below
```

- `format.rs` / `state.rs` / `chart.rs` unit tests — the pure conversions.
- `tests/snapshot.rs` — a poll against a real TLS listener. Catches an RPC wired
  into the wrong snapshot field, which compiles.
- `tests/http.rs` — the router in-process via `tower`'s `oneshot`. Catches the
  connection being provided on only one of the two router arms, which renders a
  perfect dashboard that fails every poll.
- `tests/render.rs` — each tab rendered to markup from a seeded dashboard.
  Catches a tab reading the wrong field or inverting an emptiness check, which
  every other test above would pass.
- `tests/session.rs` — a real sign-in against a mock node that is its own
  certificate authority: password in, cookie out, and the node accepting the
  connection that certificate authenticates. Catches the failure nothing else
  can — a login that succeeds and hands back a credential the node refuses.
  Also the whole `.wfauth` round trip: download, sign back in with the file
  alone, poll the node with what it produced. One of those tests runs against a
  **dead provider address** (`common::login_router_with_dead_provider`), and it
  is the only thing that proves the feature's actual claim — a bundle sign-in
  that quietly asked the provider anyway would pass every other test here.

## Charts

Read the `dataviz` skill before touching `components/chart.rs`. The two series
hues are categorical slots 1 and 2, validated for colour-blind separation
against **both** the light and dark surfaces; re-run
`scripts/validate_palette.js` if either changes. One axis only — both series are
bytes per second — and the scale stays anchored at zero.

## Security posture

**Two credential modes, chosen once at startup by `--provider`** (`session.rs`,
and §8.3 of `docs/design/06-management-api-authentication.md`):

- **Login mode** (`--provider <addr>`) — the process holds *no* credential. A
  viewer signs in, the provider issues a short-lived session certificate bound
  to a keypair this process generates for them, and that session is what reaches
  the node. No session, no node access. The session id lives in an `HttpOnly;
  SameSite=Strict` cookie; the browser never holds a key, here as everywhere
  else in this crate.
- **Static mode** (`--identity`/`--cert`, or `--serial`) — one credential for
  the whole process, shared by everyone who can reach the port. Kept
  deliberately, because two deployments have no login available and no other way
  in: an **un-enrolled node**, which has no user store to sign in to and admits
  only a client proving the node's own key, and an **embedded node over
  `--serial`**, which has no authentication at all. It warns at startup about
  exactly what it is.

Neither mode terminates TLS, so the bind address is still a boundary: loopback
by default, a reverse proxy's job to expose, and a password crossing a
non-loopback bind crosses it in the clear unless something else is terminating
TLS in front.

**A signed-in viewer can download their credential as a file** (`bundle.rs`,
the `/api/auth_bundle` route in `server.rs`, and `api::login_with_bundle`). It
exists because §8.3's offline case had no answer short of running the dashboard
in static mode: a session survives losing the provider, but the session store is
in memory, so restarting the dashboard locked everyone out until the certificate
authority came back. The file is that session's own seed and certificate, and
handing it back to the sign-in form rebuilds a session with **no contact with
the provider at all**. Five things govern it:

- **This is the one place the browser holds a key, deliberately.** Everywhere
  else in this crate the rule is absolute; here the whole point is giving the
  *person* their credential so it can outlive the process that minted it. The
  file is not encrypted — that would need a second secret they have to keep
  anyway — and it expires exactly when the session it came from does, which is
  why the expiry is in the *filename* rather than only inside the file.
- **It is a plain `GET` behind an `<a download>`, not a `#[server]` function.**
  Browsers do downloads properly: the response names the file and nothing passes
  through wasm — so it still works on a page whose hydration panicked, which is
  exactly the page somebody is trying to rescue a credential off. `download` on
  the anchor is also what makes `leptos_router` keep its hands off the click.
  The route sits under `/api/` so `is_guarded` covers it, and `SameSite=Strict`
  means a cross-site navigation carries no cookie and so resolves to no session.
- **It is served only to the session it belongs to.** There is no id in the URL,
  so the whole of the access control is which session the cookie names.
  `Access::export` answers `None` in **static mode, always**: that credential
  belongs to the process, and serving it would turn "can load this page" into
  "holds the mesh's admin key, portably, forever".
- **A bundle sign-in asks the node before it calls the session real.** This
  process holds no trust anchor — in login mode it holds no mesh identity at all
  — so it *cannot* check the mesh root's signature. It checks what it can (the
  certificate belongs to the key beside it, the window contains now) and then
  proves the rest by using it, with one `GetNodeInfo` on the node's read-only
  tier. Skip that round trip and a forged or revoked file yields a dashboard
  that looks signed in, names a capability, and fails every poll — which reads
  as "the node is down".
- **Its refusals are specific, unlike the password form's.** The reticence there
  exists because a password refusal is an oracle anyone who can load the page
  may query. A credential file is the person's *own*: there is no account to
  enumerate, and "this expired on the 3rd" is the difference between downloading
  a new one and filing a bug.

**`<Routes>` must stay unconditional in `App`.** `generate_route_list` walks the
app once at startup, with no request and so no session, to discover the routes
to register — so a `<Routes>` behind "is anyone signed in?" registers nothing and
every tab but the index answers 404, in both modes, from the first boot. That is
why a signed-out page renders the whole shell and *hides* it (`wf-shell-hidden`,
`display: none`, which takes it out of the tab order and the accessibility tree
too) with the sign-in form over the top, rather than not rendering it. Nothing
leaks by that: no tab fetches anything of its own, and the polling loop does not
run while signed out. `tests/session.rs` pins both halves.

**The bind address alone does not make it unreachable, which is why
`server.rs` carries two gates** (`HostPolicy`, and the `known_host_only` /
`same_origin_only` layers):

- **A host allowlist**, because a page on any site can point a DNS name it
  controls at `127.0.0.1` and become same-origin with a loopback-bound
  dashboard. The `Host` it sends is the one part of that it cannot choose, so a
  name that is neither loopback, nor `--listen`'s own address, nor one an
  operator named with `--allowed-host`, is refused. Ports are not compared —
  a published container port and a proxy on 443 both change the port while the
  deployment is unchanged.
- **A same-origin check on anything that mutates**, because `#[server]`
  defaults to a form encoding, which is a CORS *simple request*: the browser
  sends it cross-origin with no preflight and `server_fn` checks nothing
  itself. `Sec-Fetch-Site` and `Origin` are checked independently and each is
  only checked when present; a request carrying neither is not a browser and
  has no session for a forgery to borrow. `SameSite=Strict` on the session
  cookie closes the same hole from the other end in login mode — the browser
  does not attach the cookie to a cross-site request at all — but the layer
  stays, because static mode has no cookie to protect.

**Both are router-wide layers, and they have to be.**
`leptos_routes_with_context` registers every `#[server]` function at its own
exact path and method, and an exact route wins over the `/api/{*fn_name}`
wildcard this crate declares — so a layer attached to that wildcard route never
sees a real server-function call. It compiles, the tests that only assert a
`200` still pass, and the gate is simply never invoked.

Neither gate is a substitute for signing in; both stop the deployment being
remotely administrable by anyone who can get an operator to open a tab.

**The Security tab enrolls the node**, too: its "Join a mesh" panel asks a
provider to certify the node and installs what comes back (`enroll.rs`, and
`api::request_enrollment`). Three things about it are worth knowing before
changing it:

- **It certifies the node's existing identity, and never handles a key.** The
  CSR names the keys and MAC the node reports, and the certificate is installed
  against the seed the node keeps (`Client::install_cert` — a `SetAuth` with an
  empty seed). Minting a fresh keypair here, as the offline `wayfinderctl
  enroll` does, would change the node's MAC — read once at startup — leaving it
  signing frames under a certificate its peers cannot attribute to it until
  someone restarts it.
- **The connection to the provider is anonymous by design.** A throwaway key,
  no certificate: a node with nothing to present is exactly what is asking. The
  provider admits it for enrollment alone (`wayfinder_server::authz`), and
  decides on its token and its operator's approval.
- **A held request is polled, not pushed.** Re-submitting an identical CSR is
  how a certificate is collected after approval, so the panel simply asks again
  on a timer while it waits.

**The Provider tab is the other end of that exchange**, and it shows what a
joining node must be told — the provider's address, the key that pins it, and
the enrollment token. Two rules govern that panel:

- **The token is fetched, never polled.** `GetSecurityStatus` reports only
  `enrollment_token_set`; the value comes back from `reveal_enrollment_token`
  when the operator presses "Show token". Who may read it has not changed — an
  admin or the node itself, the same clients that may replace or clear the token
  through `SetConfig`, so disclosure confers nothing they did not already have.
  What changed is *how often*: on the poll, the secret crossed the wire once a
  second into the browser and into anything that formats the snapshot, for the
  sake of a value an operator reads perhaps twice in the life of a mesh. Do not
  put it back on the snapshot to save a round trip.
- **Shown, masked and copied are three different things.** The key is
  abbreviated and the token masked outright, while the copy button carries each
  in full. A dashboard gets read over a shoulder and screenshotted into chats;
  the value that leaves it should leave through the clipboard, deliberately.
  `clipboard.rs` explains why the copy goes through the deprecated
  `execCommand` rather than `navigator.clipboard` (the modern API is undefined
  over plain HTTP, which is how this dashboard is usually reached, and a
  `wasm-bindgen` call that throws aborts the page).

**A panel holding operator input must not be rebuilt by a poll.** `snapshot` is
replaced once a second, so a `move ||` closure over it constructs a *fresh*
component every second — and a component's `signal(String::new())` fields are
re-created empty, wiping whatever was half-typed and taking the focus with it.
The Security tab's "Join a mesh" panel and the Provider tab's enrollment-policy
and join-details panels are therefore driven from `Memo`s over the narrowest
projection they need (`security::membership_of`, and the Provider tab's
`enrollment`/`join_details`), since a memo only notifies when its own value
changes. Widening one of those projections to something that moves on its own —
a node list, a timestamp — silently restores the bug, which no markup test can
see; `membership_ignores_everything_that_changes_on_its_own` is what guards it.

**The Provider tab administers the mesh's accounts**, which is the surface with
the longest reach on this dashboard: an account here mints certificates the
whole mesh honours. Four things govern it:

- **The roster is fetched, not polled.** It changes when somebody creates or
  removes an account and at no other time, so `Users` holds a `Resource` it
  refetches after its own mutations rather than putting the account list on the
  once-a-second snapshot. That is also what keeps the create form from being
  rebuilt mid-keystroke — the same failure the memoised panels above avoid.
- **The first account cannot be created here.** Creating one over the API needs
  the credential it creates, so `wayfinderctl user add` on the provider host
  remains the only way to bootstrap. What this tab adds is every account after
  that, and it is a real widening: an admin session can now mint another
  account. The trade is stated in the proto (`CreateUserRequest`) — an admin can
  already revoke nodes and rewrite the enrollment policy, so it grants no new
  class of power, but it does put the user store on the network.
- **The enrolment URI is shown once.** A TOTP secret is not recoverable from the
  authority, so the panel holds the `otpauth://` URI on screen until dismissed,
  says plainly that it will not be shown again, and offers it through the
  clipboard rather than only as text on a screen someone else can see.
- **The node refuses to strand itself, and the dashboard does not second-guess
  it.** `MeshAuthority::remove_user` rejects removing the last account that can
  still administer the mesh — both it and `CreateUser` need a full management
  grant, so an authority with no enabled administrator has a user store that no
  dashboard can change again. The *inherent* `CertAuthority::remove_user` has no
  such guard on purpose: it is what `wayfinderctl user remove` calls on the
  provider host, and it is the recovery path that refusal points at. The tab
  shows the refusal as an error rather than pre-computing "is this the last
  admin?" in the browser, per "the node is the authority" above.

**The Security and Provider tabs write, not just read**, and that raises the
stakes of the paragraph above. Whoever can reach this port can turn the node's
fail-closed gate on or off, flip lazy cert distribution (a flag-day,
wire-incompatible change for the whole mesh), and — on a certificate authority
— change the enrollment policy, including clearing the enrollment token so any
node in range may join. Those changes **persist** on a node configured with a
`runtime_state_path`, so they outlast the browser tab, the dashboard process,
and the node's next restart.

**In login mode this is now scoped**, which it was not when these controls were
added. Every one of them needs a full management grant, so a viewer account
reaches none of them — `authz::permits` is the closed allowlist that decides,
and `tests/session.rs` pins both halves of it (an admin lists and creates
accounts; a viewer is refused the same calls).

**In static mode it is not**, and that has not changed: one credential serves
everyone who can reach the port, so treat reachability as equivalent to whatever
that identity carries — root on the mesh, when it is an admin certificate. The
mitigations there are the ones they always were: do not expose the port, and a
confirmation dialog on each change that cannot be casually walked back.
