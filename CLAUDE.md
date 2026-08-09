# CLAUDE.md

Guidance for Claude Code when working in this repository.

> **Context note.** This root file holds only always-true rules and an
> orientation map. Deep, area-specific detail lives in per-crate `CLAUDE.md`
> files that load on demand when you work in that crate (see the map below).
> Procedures live in skills — reach for `tdd`, `mr`, `mr-review`, `add-metric`
> when the task matches.

## Project Overview

A research project implementing BATMAN-adv (Better Approach To Mobile Adhoc
Networking) mesh routing for embedded systems and multi-radio edge links (LoRa,
IEEE 802.15.4). It's a Cargo workspace of `no_std`-friendly core libraries,
host-side driver/server/tooling crates, and a runnable node.

The core routing engine is `#![no_std]` and heap-free (`heapless`), so the
*same* routing code runs on a bare-metal MCU and on a Linux gateway. Host
concerns (tokio event loop, sockets, TAP bridging, the management API server,
TUI/CLI clients) live in separate `std` crates layered on top.

## Building and Testing

```bash
cargo build                       # whole workspace (add --release for optimized)
cargo build -p batman             # a single package
cargo test --workspace            # all tests
cargo test -p wayfinder           # one package
cargo test test_ogm_forwarding    # one test by name
cargo test -- --nocapture         # with output visible
```

Run binaries:

```bash
cargo run -p wayfinder-tap -- --config <config.yaml>  # a mesh node (TAP + UDP links + mgmt API)
cargo run -p wayfinder-tui -- <addr>                  # terminal dashboard vs a node's mgmt API
cargo run -p wayfinder-ctl -- <subcommand>            # CLI mgmt client / offline cert tooling
```

**Formatting:** run `nix fmt` (the repo's `treefmt` config, Rust and everything
else) before committing; the pre-commit hook also runs it. Prefer it over
`cargo fmt`.

The `libs/wayfinder-shark` Wireshark dissector is tested with pytest
(`libs/wayfinder-shark/tests/`), which drives `tshark` against the Lua
dissector — outside the Cargo test harness.

**Crates outside the root workspace don't run under a root `cargo
nextest run --workspace`/`cargo test --workspace`** — each needs its own
invocation from its own directory:

- `libs/wayfinder-py` — a separate `[workspace]` (needs a linkable libpython;
  must not leak into the main host build). Host-testable: `cd libs/wayfinder-py
  && cargo nextest run`. Wired into CI's `test:run:python` job, alongside pytest.
- `bins/wayfinder-nrf52840`, `bins/wayfinder-nrf52840-dongle`,
  `bins/wayfinder-stm32f411` — separate `[workspace]`s, `no_std`/`no_main`
  firmware binaries with `test = false`; a host test harness can't link against
  them at all. Their logic is exercised indirectly through the `libs/*` crates
  they wire together (tested in the root workspace) plus CI's `build:embedded`
  job (cross-compile + clippy for the real target). Only real/simulated
  hardware-in-the-loop (e.g. `defmt-test` + `probe-rs`) could add genuine test
  coverage here — not set up in this repo.
- `libs/wayfinder-nrf` — the nRF board-support crate the two nRF firmwares
  share. Not a workspace member (it depends on `nrf-softdevice`, which only
  links for a real embedded target) and not its own `[workspace]` either — a
  root-level `exclude`, pulled in by path from each board. Covered by the same
  `build:embedded` job, through the boards that consume it.
- `libs/*/fuzz` (`wayfinder`, `batman`, `wayfinder-auth`, `ieee802154`) —
  `cargo-fuzz` targets, not unit tests; run explicitly with `cargo fuzz run`,
  not part of any `nextest` invocation.

## Always-on rules

### Model selection

Match the model to the phase of work:

- **Planning / design** — use **Opus** (`claude-opus-4-8`). Architecture,
  decomposing a task, weighing trade-offs, drafting an implementation plan.
- **Coding / implementation** — use **Sonnet** (`claude-sonnet-5`). Writing the
  code once the plan is settled: the fast, high-volume phase.
- **Reviewing** — use **Opus** again. Second-opinion diff review (`mr-review`),
  security-sensitive changes, judging whether a design holds up.

Switch with `/model` (or hand a phase to a sub-agent with the matching `model`).
The rule of thumb: Opus opens and closes a task (plan, then review); Sonnet does
the build in between.

### Documentation

Every public API **must have documentation**.

- **Rust** — every `pub` item (function, struct, trait, enum, field, associated
  type, constant) needs a `///` doc comment explaining what it does and any
  invariants/constraints. Trait methods are documented on the trait definition;
  impls may add notes but don't replace trait-level docs.
- **Protobuf** — every message, field, `oneof`, enum, and enum value in
  `libs/wayfinder-protos/protos/` needs a `//` comment. The `buf lint`
  `COMMENTS` rule enforces this; run `buf lint` from `libs/wayfinder-protos/`.

Good doc comments explain the *why* and non-obvious constraints (valid ranges,
encoding formats, error conditions). They don't restate the name.

### Test-first development

This project is developed **test-first**: write the failing test that specifies
the desired API/outcome, confirm it's red, then implement the minimum to make it
green, then refactor. Do not pair an implementation diff with its failing test
in the same change unless explicitly asked — the failing test is its own
reviewable checkpoint. All non-trivial logic needs unit tests in a `#[cfg(test)]`
module (data-structure invariants, protocol state machines, edge cases:
empty/single/at-capacity). **Invoke the `tdd` skill** before writing
implementation code — it carries the workflow and this repo's test conventions
(`u8` for generic containers, a `mac(n)` helper for concrete `Mac` tests,
`assert_invariants()` for stateful structures).

### Logging

Logging is via [`tracing`] — never `log`, `println!`, or `eprintln!`. Pick the
level by **who the record is for**, not by how interesting it felt:

- **`error!`** — a failure an operator must act on, originating in *this* node
  (invalid config, violated invariant, permanently lost resource). Not reachable
  by arbitrary peer input; not once-per-hot-loop-iteration. A handled-and-retried
  I/O error is `warn!`, not `error!`.
- **`warn!`** — unexpected but handled, worth operator attention (capacity
  eviction, security-relevant drop, a torn-down errored stream). Never reachable
  by arbitrary remote input on a hot path.
- **`info!`** — lifecycle/topology events an observer wants (startup, listeners
  bound, auth enabled, node discovered/revoked). Not per-frame, never a payload,
  never a secret. If it can repeat per packet, it isn't `info!`.
- **`debug!`** — developer-facing state transitions (config dump, connection
  open/close, route-table/auth-state changes, evictions). Off in normal
  operation.
- **`trace!`** — per-frame/packet flow; the bulk of the logs. Two hard rules:
  (1) **never log payload bytes** — no `pretty_hex` of a frame, no `{:?}` of a
  struct embedding a payload slice; log metadata only (src, dst, protocol,
  lengths, seqno, TTL). (2) **Always structured fields** with a short static
  message — `trace!(?src, ?dst, payload_len = n, "rx frame")`. Drops use a
  `"drop: <reason>"` message.

Carry shared per-frame context in a span (`trace_span!("handle_frame", ?src, …)`)
rather than repeating it. Import a module's macros and call them bare; don't mix
bare and fully-qualified `tracing::` calls in one file. Parse failures of
remotely-supplied frames are `trace!`, not `warn!` — a malformed packet must not
flood the logs.

**Logs are readable over the management API.** `libs/wayfinder-log` installs the
subscribers on every target and feeds two things: a text sink (RTT on a board,
the console on a host) and a bounded record ring that `GetLogs` serves. That
ring is how a node with no debug probe attached — an nRF52840 dongle, or any
board whose cable is out — has observable logs at all. `SetLogLevel` changes the
runtime filter across *every* sink at once; its grammar is a `RUST_LOG` subset
(`info,batman=trace`), with prefixes matching at module boundaries so
`wayfinder=trace` does not sweep in every `wayfinder_*` crate.

Two rules follow, and both are the kind that fail silently:

- **Never set a `max_level_*` Cargo feature** on `log` or `tracing`, anywhere in
  the workspace. Those compile records out, so no runtime filter can bring them
  back and `SetLogLevel trace` becomes a lie.
- **A `Subscriber`/`Layer` here must override `register_callsite` to return
  `Interest::sometimes()`.** The default caches an always/never verdict per
  callsite forever, which freezes every already-hit log line at its startup
  verbosity — the busiest lines being exactly the ones that freeze first.

[`tracing`]: https://docs.rs/tracing

### Metrics are first-class

A mesh node sits underneath applications that can't otherwise see the network
they run on. Surfacing the router's internal state is how an app *infers what the
mesh is doing* and adapts. For every feature ask "could an operator or an app on
top of the mesh want to observe this?" Two invariants when adding one:

- **State lives in `CentralRouter` (the `no_std` core), never only in the
  driver** — an embedded node has no `wayfinder-driver`/tokio loop, so a
  driver-only metric wouldn't exist on hardware. The driver may *feed* the router
  (e.g. `record_tx`), but counters/estimators and their accessors belong to the
  router.
- **Prefer bounded here-and-now signals over unbounded totals** — a time-decayed
  EWMA *rate* (`RateEstimator`) or a current-vs-capacity gauge (`TableOccupancy`)
  over a monotonic count, evaluated at request time.

**Invoke the `add-metric` skill** to wire one end to end (proto → service →
`RouterAdapter` → client → TUI Metrics tab → smoke test).

### Merge requests

Ships through GitLab MRs (`git.haganah.net`), not direct pushes to `main`. The
**MR title must follow Conventional Commits** (`type(scope): summary`, lowercase
imperative summary ≤100 chars) — the `lint:mr-title` CI job enforces it on the
title. **Invoke the `mr` skill** to run the checks, draft the title/description,
and create it with `glab`; **`mr-review`** for the second-opinion review a
complex MR needs.

## Architecture map

The workspace splits into the `no_std` routing core, radio drivers, host-side
(`std`/tokio) crates, and runnable binaries. Crates marked → have a per-crate
`CLAUDE.md` with the deep detail.

**Core routing (`no_std`)**
- **libs/interfaces** → core abstractions: `Mac`, `LinkFrame`, `RoutingAction`,
  the `MeshRoutingEngine`/`MeshIdentifier` traits, `LinkMetrics`.
- **libs/batman** → BATMAN-adv engine: OGM/unicast/broadcast/mcast logic, TVLVs,
  the `Trickle` emission timer, originator/membership tables.
- **libs/wayfinder** → `CentralRouter` orchestration: protocol demux, `LinkT`,
  multicast egress, `OgmAuth`, per-link Trickle config, observability.

**Radio drivers (`no_std`)** — each → has a driver-authoring guide:
- **libs/rylr998** — REYAX RYLR998/498 LoRa AT-command driver + `LinkT`.
- **libs/ieee802154** — hardware-agnostic 802.15.4 framing (`encode`/`decode`).
- **libs/at86rf233** — SPI driver for the AT86RF233 transceiver.
- **libs/nrf-ieee802154** — `LinkT` adapter for the nRF52840 built-in radio.
- **libs/blue** → `LinkT` adapters for connectionless BLE advertising
  broadcast, in two interoperating backends sharing one wire format:
  `NrfBleLink` (nRF52840 via `nrf-softdevice`, `no_std` — mutually exclusive
  with `nrf-ieee802154` at the RADIO peripheral) and `StdBleLink` (a Linux
  host via BlueZ/`bluer`, used by `bins/wayfinder-tap`).
- **libs/wayfinder-link-utils** — shared small-MTU fragmentation/reassembly
  for `LinkT` drivers whose medium caps payload well below
  `MAX_LINK_FRAME_LEN` (used by `rylr998`, `blue`).

**Identity & management API**
- **libs/wayfinder-auth** → crypto identity/membership. A mesh is optionally
  segregated by a per-mesh trust anchor (root key); a node belongs iff it holds a
  `MembershipCert` signed by that root (Ed25519 pubkey ↔ MAC ↔ mesh). `no_std`
  core does verification + X25519 agreement; the `std`-gated `Authority` is the
  CA. Payloads are never encrypted — authenticity + segregation only.
- **libs/wayfinder-protos** → management API protobuf (`prost`, package
  `wayfinder.v1alpha`); `service.rs` defines `WayfinderDataProvider`. `buf lint`
  runs here; the `serde` feature is used by the CLI.
- **libs/wayfinder-server** → the mgmt-API server: `RouterAdapter` (`no_std`+
  `alloc`, projects a borrowed `CentralRouter`), the `std` authenticated
  TLS-over-TCP transport (`bind_tcp_server`/`serve_tls_server` +
  `QueryTx`/`QueryRx`), the `embedded` framing/`serve` loop, and `authority.rs`
  (the CA in provider mode; embedded nodes never link this).
- **libs/wayfinder-tls-mgmt** — the shared mgmt-TLS bridge between the mesh
  Ed25519 identity and rustls **raw public keys** (RFC 7250, no X.509):
  `certified_key_from_seed`, `verify_raw_key_signature`. Depended on by both
  `wayfinder-server` and `wayfinder-client` so neither has to depend on the
  other.
- **libs/wayfinder-client** — reusable API client: the same prost envelope with
  4-byte BE length-delimited framing, over authenticated TLS (`connect_tls`) or
  a serial port (`connect_serial`, for an embedded node's mgmt port). Shared by
  TUI and CLI.
- **libs/wayfinder-storage** — the durable-store abstraction both the host CA
  and the embedded node persist through. `DurableStore` is one guarantee —
  replace a blob so a reader never sees a torn old/new mix, even across a crash
  mid-write — over media with different atomicity primitives: a `std`
  `FileStore` (atomic `rename`) and a `flash` `FlashStore` (A/B two-page
  ping-pong). `Persisted` owns the mutate → persist → roll-back-on-failure
  ordering, so callers never write ad-hoc `persist()` calls. Blob *contents*
  (encoding, versioning, migration) stay the caller's concern.
- **libs/wayfinder-log** — the logging plumbing every target shares: the runtime
  `RUST_LOG`-style filter, the bounded record ring behind `GetLogs`, and the line
  formatter. Two facades on top — the RTT subscriber/logger for `target_os =
  "none"`, and a `tracing-subscriber` layer stack (`subscriber` feature) for a
  host node.

**Drivers — one behavior, three loops**

The planning logic (received frame → outgoing frames, due OGMs, due keepalives)
lives once in `wayfinder-driver-core`; each shell wraps it in a different event
loop. **A behavior change almost always belongs in the core, not a shell.**

- **libs/wayfinder-driver-core** — the shared, synchronous, allocation-free
  planning logic. A shell's event loop has three arms and each maps to one
  call: `handle_link_result` (a link produced a `recv` result),
  `poll_due_all` (the periodic timer fired) and `plan_dispatch` (a staged
  frame is ready to go out). The first two plan frames into an
  `OutgoingFrame` borrowing the caller's scratchpad and hand it to a
  `MeshSink` the shell implements (`Vec` on host, `heapless::Vec` on
  embedded); the third returns a `DispatchPlan`. No async, no interfaces, no
  I/O.
- **libs/wayfinder-driver** → the `std`/tokio shell: a `select!` loop, plus the
  concrete socket carriers a Linux node runs on. Transport-agnostic — host
  device and mesh interfaces are `FrameIo` carriers, so the same loop runs
  against real sockets and in-process test channels. `snoop.rs`
  (`McastSnooper`) snoops IPv4 IGMP to learn joined groups. Loop/transports
  gated behind the default `tokio` feature.
- **libs/wayfinder-embedded-driver** — the `no_std`, HAL-agnostic shell: a
  plain `async fn` loop the board's executor drives, racing each link's `recv`
  against the OGM timer with `embassy_futures::select`, staging into a fixed
  `heapless` buffer. No vendor HAL and no concrete time driver — a board
  supplies the `LinkT`s and a `Clock`. Optional `mgmt` feature adds the
  management-API arm (`run_with_mgmt`). Also owns node-identity persistence
  (`identity.rs`) over `wayfinder-storage`.
- **libs/wayfinder-tick-driver** — a synchronous, non-blocking shell for a
  caller that drives its own clock: no `LinkT` at all, interfaces are plain
  queues (`push_rx` → `tick` → `poll_egress`/`poll_local`). For tick-based
  simulation (a Python-driven physics sim) rather than a live node.

The transmit side is shared the same way: `plan_dispatch` makes the whole
decision (auth-tagging, egress resolution, split-horizon, the per-link transmit
gate) and returns *how much to send* plus *which interfaces*. Each shell only
does the I/O for the interfaces in that plan — a `LinkT::send` on embedded, a
`DynLinkT` send on the host, a queue push in the tick driver.

**Host node & tooling**
- **libs/wayfinder-test** → `Switch` simulator + `TestRouter` harness for
  multi-node integration tests over mpsc (no hardware). Wraps the *production*
  tokio `Driver`, but drives it via the deterministic `poll_due` /
  `process_pending` API — `run`/`run_once` and the `select!` arms have no
  direct coverage.
- **libs/rylr998-sim** — an in-process AT-command simulator standing in for a
  real RYLR998/498 module, so a real `RylrClient` is drivable without
  hardware. `RylrSimulator` speaks the AT protocol over a
  `tokio::io::DuplexStream`; `LoraSwitch` fans `AT+SEND` between several
  simulators the way LoRa's shared broadcast medium would (filtering by network
  id/frequency/mode, applying per-link signal quality). Its own crate rather
  than a `#[cfg(test)]` module or feature on `rylr998`, so the `no_std`-first
  driver never carries tokio test scaffolding in its dependency graph.
- **libs/wayfinder-shark** — `tshark` Lua dissector for on-air BATMAN frames +
  pytest tests.
- **bins/wayfinder-tap** — the runnable node: assembles TAP + UDP links + mgmt-API
  listeners from YAML and hands them to a `wayfinder-driver::Driver`.
- **bins/wayfinder-tui** — `ratatui` dashboard (routing, link quality, OGM
  schedule, throughput/metrics, security tabs).
- **bins/wayfinder-ctl** (`wayfinderctl`) — CLI mgmt client (query commands) +
  offline `cert` tooling + online `enroll`.
- **bins/rylr998-cli** — a small host CLI for driving a RYLR998/498 module over
  a real serial port, for bringing up and debugging a LoRa link outside a full
  node. Split lib (`rylr998_cli::run_command`) + thin `clap` binary on purpose,
  so the command logic is testable against `rylr998-sim` while `main.rs` owns
  the only real-hardware bit.

**Bare-metal boards** (each binary its own `[workspace]`; see "Crates outside
the root workspace" above)
- **libs/wayfinder-nrf** → nRF52840 board support: the panic/HardFault
  handling, stack painting, FICR identity, `MeshLink` enum, USB management
  port, capacity profile and `node::run` bring-up sequence both nRF boards
  share. A board binary is then only its pins, flash layout and `memory.x`.
- **bins/wayfinder-nrf52840** — the DK (PCA10056).
- **bins/wayfinder-nrf52840-dongle** — the dongle (PCA10059): no probe, no
  LFXO, less flash. Logs are readable only over the USB management port.
- **bins/wayfinder-stm32f411** — NUCLEO-F411RE, a LoRa-only relay on a
  non-Nordic Cortex-M: the proof the driver is HAL-portable.

## Key design patterns

- **Zero-copy parsing** — `zerocopy` for packet handling without allocations;
  wire structs derive `FromBytes`/`IntoBytes`/`Immutable`/`KnownLayout`.
- **Async I/O** — `embedded-io-async`; `LinkT` is a native `async fn` trait
  (static dispatch on embedded), dynamic-dispatched via `dynosaur`'s `DynLinkT`
  on the host.
- **Trait-based abstraction** — routing engines (`MeshRoutingEngine`), mesh links
  (`LinkT`), and driver transports (`FrameIo`) are all traits.
- **No-std compatibility** — the core uses `heapless` fixed-capacity collections;
  host concerns live in `std`-gated crates/features.

## Edition note

Many crates use `edition = "2024"`, not yet stable as of the knowledge cutoff. Be
aware of edition compatibility when editing `Cargo.toml` files.
