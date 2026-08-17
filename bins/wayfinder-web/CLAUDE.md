# bins/wayfinder-web

A browser dashboard for a running node: the same seven views `wayfinder-tui`
shows in a terminal, reachable over HTTP. Built with Leptos in SSR mode — an
axum server plus a wasm hydration bundle, compiled from this one crate.

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
- `api.rs` — the `#[server]` functions, thin wrappers over the above. Every one
  sets `endpoint` explicitly; the derived paths carry a rename-sensitive hash.
- `state.rs` — what accumulates across polls (log scrollback, throughput trend).
- `format.rs` — every display conversion, so none of them live in a `view!`
  macro where they cannot be tested.
- `components/` — the tabs. Pure functions of the dashboard state.
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

## Charts

Read the `dataviz` skill before touching `components/chart.rs`. The two series
hues are categorical slots 1 and 2, validated for colour-blind separation
against **both** the light and dark surfaces; re-run
`scripts/validate_palette.js` if either changes. One axis only — both series are
bytes per second — and the scale stays anchored at zero.

## Security posture

No authentication of its own. It binds loopback by default and warns on any
other bind. The server process holds the mesh identity, so anyone who can reach
the port has whatever access that identity carries; exposing it is a
reverse-proxy's job. A session layer is a later, separable change — do not
quietly widen the bind default in the meantime.

**The Security tab now writes, not just reads**, and that raises the stakes of
the paragraph above. Whoever can reach this port can turn the node's
fail-closed gate on or off, flip lazy cert distribution (a flag-day,
wire-incompatible change for the whole mesh), and — on a certificate authority
— change the enrollment policy, including clearing the enrollment token so any
node in range may join. Those changes **persist** on a node configured with a
`runtime_state_path`, so they outlast the browser tab, the dashboard process,
and the node's next restart.

This was a deliberate call rather than an oversight: `revoke_node` was already
exposed here with no authentication, so the port was already a full-privilege
surface, and gating only the new controls would have implied a boundary that
does not exist. The mitigation is the same one as before — do not expose the
port — plus a confirmation dialog on each change that cannot be casually walked
back. Adding the session layer would let all of this be scoped properly; until
then, treat reachability of this port as equivalent to root on the mesh.
