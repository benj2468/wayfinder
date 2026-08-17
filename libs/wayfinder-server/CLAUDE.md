# libs/wayfinder-server

The management-API server. Three layers in one crate, split by feature so an
embedded node links only what it can run.

| Layer | Feature | Files |
|---|---|---|
| `RouterAdapter` — projects a borrowed `CentralRouter` onto `WayfinderDataProvider` | always (`no_std` + `alloc`) | `adapter.rs`, `provider.rs`, `authz.rs`, `settings.rs` (trait half) |
| host transports — authenticated TLS over TCP, plus an in-process channel | `std` (default) | `transport.rs`, `tls.rs`, `authority.rs`, `persistence.rs`, `settings.rs` (`SettingsFile`) |
| embedded transport — length-delimited frames over `embedded-io-async` | `embedded` | `framing.rs`, `embedded.rs` |

`std` and `embedded` are mutually exclusive in practice — a target picks one.
The embedded node reuses the *adapter*, not the transport.

Entry points for the host transport are `bind_tcp_server` (bind the listener),
`serve_tls_server` (accept + handshake + serve), `serve_authenticated_stream`
(one already-accepted stream), and `run_channel_server` (in-process). There is
no Unix-datagram or UDP listener — earlier docs referenced `run_unix_server` /
`run_udp_server`, which no longer exist.

## The query channel, and why the router is never shared

`QueryTx`/`QueryRx` (and their `embassy-sync` twins `EmbeddedQueryTx`/`Rx`)
exist so the router is owned by exactly one task. Listener tasks accept
connections concurrently, but they do not touch `CentralRouter` — they forward a
request over the channel and await a oneshot reply. The driver's event loop
services it between frames.

This is the constraint to respect when adding anything here: **nothing outside
the driver loop may hold a `&mut CentralRouter`.** If a new feature seems to
need one, it needs a new request kind, not a lock.

## `RouterAdapter` and the eleven const generics

`RouterAdapter` is generic over `CentralRouter`'s eleven capacity parameters, so
`adapter.rs` spells them out three times (~40 lines of pure boilerplate). This
is a known wart, not a pattern to imitate — see the root `CLAUDE.md` capacity
notes. If you are adding a method, copy the existing generic header verbatim
rather than inventing a shorter one.

The adapter borrows the router (`&'a mut`) and evaluates time-varying metrics at
a caller-supplied `now`, the same monotonic instant the driver stamps on
received frames. Don't call `Instant::now()` inside it — a metric read at a
different clock than the frames it describes is how throughput graphs go
subtly wrong.

## Authentication vs. authorization

Deliberately separated, and the boundary matters:

- **Authentication** is at the transport (`tls.rs`): rustls with **raw public
  keys** (RFC 7250, no X.509) — the client proves possession of its Ed25519
  mesh identity in the handshake. The TLS verifier deliberately checks *only*
  key possession; it does not decide who you are.
- **Authorization** is `authz.rs`: a pure decision over already-verified inputs
  (`decide_access` → `MgmtAccess`), with no transport and no crypto, so the
  policy is unit-testable standalone and identical across transports.

Two grant paths: `GrantedAdmin` (a verified, non-revoked admin cert bound to the
handshake key) and `GrantedBootstrap` (the node is un-enrolled and the client
proved possession of the node's *own* key — how you configure a fresh node).

**The decision is per-connection, not per-request.** Once admitted, a client may
invoke every request kind. Denials return a deliberately generic
`"authentication denied"` over the wire while the precise reason stays in a
local `warn!` — an unauthenticated peer must not get an oracle distinguishing
wrong-key / revoked / expired / not-admin.

## Provider mode (the CA)

A node in provider mode answers enrollment (`GetTrustAnchor`, `SubmitCsr`,
`RevokeNode`) by delegating to the `MeshAuthority` trait (`provider.rs`). The
trait is byte-oriented on purpose so it stays `no_std + alloc`; the concrete
`CertAuthority` holding the mesh root key is `std`-only (`authority.rs`) and is
injected into `RouterAdapter` by the host driver.

`persistence.rs` snapshots the issued-cert log and held CSRs so the
impersonation guard, revocations, and pending approvals survive a restart. Two
things about it:

- The on-disk schema is JSON with an explicit `CURRENT_STATE_VERSION`, kept
  **independent of the protobuf wire format** so the two evolve separately.
- Mutation goes through `wayfinder_storage::Persisted` — mutate, persist, roll
  back in memory if the persist failed. Do not add ad-hoc `persist()` calls
  alongside a direct field write; that ordering is the whole point of the type.

## Persisting a runtime security setting

Two stores, split by *what owns the thing*, not by convenience:

- **The enrollment policy** rides the CA snapshot (`persistence.rs`), next to
  the certificates it governs. `CertAuthority::set_enrollment_policy` records
  the override, then re-runs `apply_policy_overrides` — the same overlay a
  restart performs, so the live path and the restart path cannot drift apart.
- **Everything node-wide** (the fail-closed gate, lazy cert distribution, an
  identity installed by `SetAuth`) goes to `settings.rs`, injected into
  `RouterAdapter` via `.with_settings(...)` by the host driver, exactly as the
  CA is.

Both stores hold **overrides**, never values: `None` means "the operator never
changed this", so the startup config still governs it and deleting the state
file returns the node wholly to its YAML. A field that stored the effective
value instead would freeze the config out permanently after one edit.

Two rules for anything added here:

- **Persist before applying.** A change that could not be recorded must not be
  running: the request fails and the node keeps its previous state. Applying
  first would leave a setting live that the next restart silently discards,
  which is precisely the failure this exists to prevent.
- **Per-interface knobs stay in memory.** Trickle bounds and participation
  gates are keyed by an index into the startup config's link list, so a stored
  override would re-point at a different link the moment an operator reorders
  one. `set_config` deliberately does not persist them.
