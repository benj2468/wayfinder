# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a research project implementing BATMAN-adv (Better Approach To Mobile Adhoc Networking) mesh routing for embedded systems and multi-radio edge links (LoRa, IEEE 802.15.4). The project is a Cargo workspace of `no_std`-friendly core libraries, host-side driver/server/tooling crates, and a runnable node.

The core routing engine is `#![no_std]` and heap-free (`heapless`), so the *same* routing code runs on a bare-metal MCU and on a Linux gateway. Host concerns (tokio event loop, sockets, TAP bridging, the management API server, TUI/CLI clients) live in separate `std` crates layered on top.

## Building and Testing

### Build Commands
```bash
# Build the entire workspace
cargo build

# Build a specific package
cargo build -p batman
cargo build -p wayfinder
cargo build -p wayfinder-driver
cargo build -p rylr998
cargo build -p interfaces

# Build with release optimizations
cargo build --release
```

### Formatting

Format all code with `nix fmt` (runs the repo's `treefmt` config across the
tree — Rust and everything else). Do this before committing; the pre-commit
hook also runs it. Prefer `nix fmt` over `cargo fmt`.

### Testing Commands
```bash
# Run all tests in the workspace
cargo test --workspace

# Run tests for a specific package
cargo test -p wayfinder
cargo test -p batman
cargo test -p wayfinder-auth

# Run a specific test by name
cargo test test_ogm_forwarding

# Run tests with output visible
cargo test -- --nocapture
```

The Wireshark dissector in `libs/wayfinder-shark` is tested with pytest
(`libs/wayfinder-shark/tests/`), which drives `tshark` against the Lua
dissector — outside the Cargo test harness.

### Running Binaries
```bash
# Run a mesh node from a YAML config (TAP bridge + UDP links + management API)
cargo run -p wayfinder-tap -- --config <config.yaml>

# The terminal dashboard against a running node's management API
cargo run -p wayfinder-tui -- <addr>

# The command-line management client / offline cert tooling
cargo run -p wayfinder-ctl -- <subcommand>
```

### Documentation Requirement

Every public API **must have documentation**.  This applies to:

**Rust** — every `pub` item (function, struct, trait, enum, field, associated type, constant) must have a `///` doc comment explaining what it does and any invariants or constraints.  Trait methods must be documented on the trait definition; implementations may add implementation-specific notes but do not replace trait-level docs.

**Protobuf** — every message, field, `oneof`, enum, and enum value in `libs/wayfinder-protos/protos/` must have a `//` comment.  The `buf lint` rule `COMMENTS` is enabled in `buf.yaml` and enforces this; run `buf lint` from `libs/wayfinder-protos/` to check.

Good doc comments explain the *why* and any non-obvious constraints (valid ranges, encoding formats, error conditions).  They do not restate the name.

### Test-Driven Development

This project is developed **test-first**.  When adding new behaviour or changing existing behaviour:

1.  Write the test first, expressing the desired API and outcome.  Place it in the appropriate `#[cfg(test)]` module (or integration-test crate) and run it to confirm it fails — either at compile time (because the API doesn't exist yet) or at runtime (because the behaviour isn't implemented yet).  That "red" state is the specification.
2.  Implement the minimum needed to turn the test green.
3.  Refactor with the test as the safety net.

Do not pair an implementation diff with the failing test in the same change unless explicitly asked.  The failing test is its own checkpoint — it captures the intent so it can be reviewed independently of the implementation.

### Unit Testing Requirement

All non-trivial logic **must be accompanied by unit tests** in a `#[cfg(test)]` module at the bottom of the source file.  This includes — but is not limited to:

- Data structures with internal invariants (LRU caches, routing tables, free-slot stacks)
- Protocol state machines and routing algorithms
- Edge cases: empty collections, single-element collections, at-capacity/eviction behavior

For the generic container tests (`IdentTable`, `LinkQualityTable`, `Switch`), use `u8` as the identifier type (it implements `MeshIdentifier`).  For engine/router/wire tests, which are concrete over `Mac`, use a `fn mac(n: u8) -> Mac { Mac([0,0,0,0,0,n]) }` helper to build node addresses from compact literals.  When a data structure has non-trivial invariants, add an `assert_invariants()` helper (gated behind `#[cfg(test)]`) and call it after each operation in the relevant tests.

## Architecture

### Workspace Structure

The workspace splits into the `no_std` routing core, radio drivers, host-side
crates (`std`, tokio), and runnable binaries.

#### Core routing (`no_std`)

**libs/interfaces** — Core abstractions shared by every layer:
- `MeshRoutingEngine` trait: routing protocol behaviour (`handle_rx`, `produce_periodic_broadcast`)
- `Mac`: the node-address type — a `#[repr(transparent)]` newtype over `[u8; 6]` (a MAC address) with `is_multicast`/`is_broadcast` (I/G bit), `from_ipv4_multicast`, `BROADCAST`, and `From<[u8;6]>`. The protocol/engine/router layers are concrete over `Mac`.
- `MeshIdentifier` trait: retained only as the type constraint for the still-generic *container* types (`IdentTable`, `LinkQualityTable`, `Switch`); implemented for `u8` (used by their unit tests) and `Mac`.
- `LinkFrame` / `LinkFrameData` / `LinkFrameDataMut`: zero-copy link-layer frame with src/dst (`Mac`)/protocol/payload
- `RoutingAction` enum: returned by routing engines (`Consumed`, `ForwardTo`, `DeliverLocal`, `DeliverLocalAndForward`)
- `LinkMetrics` (per-frame RSSI/SNR) and `LinkError`

**libs/batman** — BATMAN-adv routing protocol implementation:
- `BatmanEngine<MAX_ORIGINATORS>`: core routing engine with originator table, broadcast dedup table, and multicast membership tables (`local_mcast` / `mcast_members`)
- `BatmanOgmPacket`: Originator Messages (OGM) for topology discovery. Matches batman-adv's `batadv_ogm_packet` layout (`flags`, `reserved`, big-endian `tvlv_len`) and can carry a variable-length TVLV tail after the fixed header.
- `BatmanTvlvHdr` + `find_tvlv`: Type-Version-Length-Value records carried in the OGM tail; `BATADV_TVLV_MCAST` announces the originator's joined multicast groups. The router adds `Cert` / `OgmSig` TVLVs for authentication; the engine preserves unknown TVLVs verbatim when re-flooding.
- `BatmanUnicastPacket`: unicast data packets with TTL and destination
- `BatmanMcastPacket`: selectively-forwarded multicast copy (one per interested listener), routed toward `dest` like a unicast
- `BatmanBroadcastPacket`: TTL-limited, seqno-deduplicated flooded broadcasts (e.g. ARP)
- `Trickle` (`trickle.rs`): a Trickle-style adaptive OGM emission timer (after RFC 6206). The interval doubles from `i_min` toward `i_max` while the topology is stable and snaps back to `i_min` on any inconsistency (new originator, changed next hop, lost route, membership change) — near-silence in steady state, fast reconvergence on change.
- `set_local_mcast_groups` / `mcast_listeners`: manage local memberships (announced in OGMs) and query learned `(group → originators)` memberships
- Implements `MeshRoutingEngine`; uses heapless data structures for embedded compatibility
- Protocol constants: `ETH_P_BATMAN` (0x4305), `BATADV_IV_OGM` (0x01), `BATADV_BCAST` (0x02), `BATADV_UNICAST` (0x03), `BATADV_MCAST` (0x04), `BATADV_TVLV_MCAST` (0x06)

**libs/wayfinder** — Central router orchestration (`no_std`; `std` feature enables `DynLinkT`):
- `CentralRouter`: wraps the BATMAN engine plus an ident table and a per-(neighbor, interface) link-quality table, and owns the observability counters/estimators
- `LinkT` (`link.rs`): the single mesh-interface trait the router/driver speaks to — a native `async fn` trait usable in a `no_std` executor by static dispatch. The `std` driver dynamic-dispatches over `DynLinkT` (a `dynosaur`-generated `dyn`-compatible wrapper, gated behind `std`). Yields a `Received` frame-with-metrics.
- `DEFAULT_BATMAN_ETHER_TYPE`: 0x4305; `MCAST_FANOUT`: 16
- `handle_frame` / `handle_frame_with_metrics`: process a received `LinkFrame`, fold in metrics, return any outgoing frame
- `poll`: drive periodic (Trickle-paced) OGM broadcasts
- `handle_local`: wrap application/host data destined for a mesh node in a BATMAN unicast
- `mcast_plan` / `mcast_targets` / `handle_local_mcast`: multicast egress. `mcast_plan` returns `McastPlan::Unicast` when 1..=`MCAST_FANOUT` listeners are known (else `Flood`); `mcast_targets` is a no-alloc borrowing iterator of those listeners; `handle_local_mcast` wraps a frame as a `BATADV_MCAST` packet to one listener. `set_local_mcast_groups` feeds locally-snooped memberships to the engine.
- `get_egress_interface` / `resolve_route`: choose the egress interface for a destination (metric-driven), the latter without mutating state
- `auth.rs` (`OgmAuth`): opt-in OGM authentication, kept in the router (not the engine) so the engine stays crypto-free. `augment_ogm` appends the originator's membership cert + Ed25519 signature TVLVs; `verify_ogm` gates an incoming OGM against the mesh trust anchor *before* it reaches the engine. Also caches neighbor keys for pairwise data-plane tags.
- `config.rs`: per-link Trickle bounds (`i_min_ms`/`i_max_ms`) so a fast LAN link and a slow LoRa link back off on different schedules
- Observability lives here (see Metrics section): `RateEstimator` throughput EWMAs, `TableOccupancy` gauges — served identically on embedded and host deployments

#### Radio drivers (`no_std`)

**libs/rylr998** — REYAX RYLR998/RYLR498 LoRa module driver: `RylrClient<S>` async AT-command interface (`set_mode`, `set_rf_frequency`, `set_parameters`, `send_data`, `listen_for_packet` with RSSI/SNR), plus a `LinkT` mesh-interface adapter. Treats LoRa as a shared broadcast medium (mesh filters on the embedded `Mac`).

**libs/ieee802154** — Hardware-agnostic IEEE 802.15.4 framing: `encode`/`decode` wrap/unwrap a `LinkFrame` in a minimal 802.15.4 MAC header (broadcast PAN/address, no security/ack). No opinion about the radio chip; the mesh filters on the embedded `Mac`. `MAX_FRAME_LEN` = 125.

**libs/at86rf233** — SPI driver for the Atmel/Microchip AT86RF233 802.15.4 transceiver, exposed as a `LinkT`. Generic over `embedded-hal-async` `SpiDevice`/`Wait` + `embedded-hal` `OutputPin` (interrupt + reset GPIOs). Runs the chip in basic mode (no hardware auto-ACK/CSMA-CA); on-air framing delegated to `ieee802154`.

**libs/nrf-ieee802154** — `LinkT` adapter for the nRF52840's built-in 802.15.4 radio (`embassy-nrf`). Adapts `ieee802154::encode`/`decode` to the radio's `Packet` buffer; the caller constructs the `Radio` from the real peripheral.

#### Identity & management API

**libs/wayfinder-auth** — Cryptographic identity and mesh membership. A mesh is optionally segregated by a per-mesh trust anchor (root key); a node belongs only if it holds a `MembershipCert` signed by that root, binding `Ed25519 pubkey ↔ node MAC ↔ mesh`. `no_std` core does verification + X25519 key agreement (`pairwise_tag`/`pairwise_key`, used by the router on embedded nodes); the `std`-gated `Authority` is the CA (root-key custody, issuing, revocation) run by an enrollment portal. Payloads are never encrypted — wayfinder provides authenticity and segregation only; confidentiality is left to L3.

**libs/wayfinder-protos** — Management API (`prost`/protobuf, package `wayfinder.v1alpha`): request/response envelopes (`WayfinderRequest`/`WayfinderResponse`) for node info, routing table, link-quality table, OGM schedule, throughput, aggregate node metrics, security status, route resolution, and the certificate-authority flow (trust anchor, submit CSR, revoke, list certs). `service.rs` defines the `WayfinderDataProvider` trait and dispatch. `buf lint` runs from this crate; the `serde` feature is used by the CLI.

**libs/wayfinder-server** — The management-API server. Two layers:
- `RouterAdapter` (`no_std` + `alloc`): projects a borrowed `CentralRouter` through the `WayfinderDataProvider` trait; takes the router's monotonic `now` so time-varying metrics are evaluated at request time.
- transport layer (`std` feature): per-transport listener loops (`run_tcp_server`/`run_unix_server`/`run_udp_server` over tokio net) and the `QueryTx`/`QueryRx` channel that forwards queries to the single-threaded router loop so the router is never shared across tasks.
- `authority.rs` (`std`): the concrete CA in provider mode — holds the mesh root key and issues/revokes member certs in response to enrollment requests. Embedded nodes never link this.

**libs/wayfinder-client** — Reusable client for the management API, speaking the prost envelope over TCP (4-byte big-endian length-delimited framing, matching `run_tcp_server`) or Unix datagram (one prost message per datagram). Shared by the TUI and CLI so wire framing lives in one place.

#### Host driver & node

**libs/wayfinder-driver** — The `std`/`tokio` driver that owns the router event loop, deliberately transport-agnostic: the host device and every mesh interface are `FrameIo` carriers (`transport.rs`), so the *same* loop runs against real sockets in production and in-process channels in tests. `Driver::run`/`run_once` is the free-running `select!` loop; `Driver::poll` + `process_pending` is deterministic stepping for tests. `snoop.rs` (`McastSnooper`) snoops IPv4 IGMP (v1/v2/v3; MLD not yet) off the host link to learn joined multicast groups. The transport-agnostic surface (`FrameIo`, `McastSnooper`) is always available; the tokio loop, `tokio::net` transports, and link builders are gated behind the default `tokio` feature.

**libs/wayfinder-test** — Test-only harness: a `Switch` simulator and `TestRouter` wrapper for multi-node integration tests over `tokio` mpsc channels (no hardware).

**libs/wayfinder-shark** — A Wireshark/`tshark` Lua dissector (`wayfinder.lua`) for the on-air BATMAN frames, with pytest tests (`tests/`) that drive `tshark` against it.

**bins/wayfinder-tap** — The runnable node. Bridges a host TAP device onto the mesh, carries mesh links over UDP, and exposes the management API. All the routing event loop lives in `wayfinder-driver`; this binary only assembles the concrete transports (a kernel TAP via `tun-rs`, UDP links) and the management-API listeners from the YAML config, then hands them to a `Driver` and runs it.

**bins/wayfinder-tui** — A `ratatui` terminal dashboard against a running node's management API (via `wayfinder-client`): tabs for routing, link quality, OGM schedule, throughput/metrics, and mesh security. `lib.rs`/`ui.rs` split out so rendering + snapshot logic is integration-tested.

**bins/wayfinder-ctl** (`wayfinderctl`) — A command-line management client. Two families: **query** commands (`node-info`, `routes`, `link-quality`, `metrics`, `security`, `resolve`) open a `wayfinder-client::Client` to a node; **`cert`** commands run offline, minting the seed/certificate/trust-anchor files a node loads to join an authenticated mesh, plus an online `enroll` (generate keypair → submit CSR → write returned cert + trust anchor).

### Key Design Patterns

**Zero-copy parsing**: uses `zerocopy` for packet handling without allocations. Wire-format structs derive `FromBytes`, `IntoBytes`, `Immutable`, `KnownLayout`.

**Async I/O**: built on `embedded-io-async`. `LinkT` is a native `async fn` trait so embedded links are driven by static dispatch; the host driver dynamic-dispatches over the `dynosaur`-generated `DynLinkT`.

**Trait-based abstraction**: routing engines (`MeshRoutingEngine`), mesh links (`LinkT`), and driver transports (`FrameIo`) are all traits, enabling protocol/hardware/transport flexibility.

**No-std compatibility**: the routing core uses `heapless` fixed-capacity collections; host concerns live in `std`-gated crates or features.

## Important Implementation Details

### BATMAN Routing Logic

The BATMAN engine maintains an originator table tracking:
- `neighbor_ident`: the destination node
- `best_next_hop`: immediate neighbor to forward packets to
- `max_tq`: Transmission Quality metric (0-255)
- `paths`: up to 4 alternate paths via different neighbors

OGM processing (`handle_rx`, `BATADV_IV_OGM` arm in libs/batman/src/engine.rs):
1. Drops own OGMs (loop prevention)
2. Creates or updates originator record
3. Computes path quality (TQ -= 10 per hop)
4. Selects best path based on highest TQ
5. Folds the OGM's multicast TVLV into `mcast_members` (authoritative per originator, so dropped groups are pruned)
6. Forwards OGM with decremented TTL and updated prev_sender, preserving the TVLV tail verbatim

When authentication is enabled, the router's `OgmAuth::verify_ogm` runs *before* the engine sees an incoming OGM (rejecting unsigned/forged/foreign OGMs) and `augment_ogm` appends the cert + signature TVLVs *after* the engine builds one; the engine itself is unchanged.

Multicast forwarding (`handle_rx`, `BATADV_MCAST` arm + `CentralRouter`):
1. Each node announces its locally-joined groups in its OGM's `BATADV_TVLV_MCAST` tail; receivers record `(group → originator)` in `mcast_members`.
2. To send a multicast frame, `CentralRouter::mcast_plan` chooses `Unicast` (1..=`MCAST_FANOUT` known listeners) or `Flood`. For unicast, the executor sends one `BATADV_MCAST` copy per listener via `handle_local_mcast`.
3. A `BATADV_MCAST` packet routes like a unicast: delivered locally when `dest` is self, else forwarded toward the next hop with TTL decremented.

Broadcast flooding (`handle_rx`, `BATADV_BCAST` arm):
1. Drops own broadcasts (loop prevention)
2. Deduplicates on `(orig, seqno)` via the engine's `broadcast_seqno` table — duplicates/stale are dropped
3. If TTL expired, returns `DeliverLocal` (deliver, no re-flood)
4. Otherwise writes a re-flood (TTL-1, inner frame preserved) into the reply buffer and returns `DeliverLocalAndForward(BROADCAST)`. The caller delivers the inner frame locally *and* forwards the re-flood.

Unicast forwarding (`handle_rx`, `BATADV_UNICAST` arm):
1. Checks if packet is for local node (DeliverLocal)
2. Validates TTL > 1
3. Looks up next hop in originator table
4. Returns ForwardTo action with immediate neighbor address

### Link Layer Frame Format

All frames use the `LinkFrame` structure (libs/interfaces/src/frame.rs):
- `src: Mac` — source identifier (added by link layer)
- `dst: Mac` — destination identifier (or `Mac::BROADCAST`)
- `protocol: u16` — EtherType-style protocol identifier
- `payload: [u8]` — variable-length payload

### Protocol Multiplexing

The CentralRouter demuxes by protocol field (`handle_frame_with_metrics` in libs/wayfinder/src/lib.rs):
- `0x4305` (DEFAULT_BATMAN_ETHER_TYPE): routes to BATMAN engine
- `0x88B5`: reserved for experimental protocols
- Other values are dropped

## Metrics and Observability

**Metrics are a first-class part of this system, not an afterthought.** A mesh
node sits underneath applications that cannot otherwise see the network they run
on — link quality, topology size, route stability, congestion, capacity
pressure. Surfacing the router's internal state through the management API is
how an application developer *infers what the underlying mesh is doing* and
adapts to it (e.g. backing off when throughput collapses, or preferring a
different peer when a path is flapping). Treat "could an operator or an app on
top of the mesh want to observe this?" as a design question for every feature,
and expose the answer through `wayfinder-protos` / `wayfinder-server` and the
`wayfinder-tui` Metrics tab.

Principles for adding a metric:

- **State lives in `CentralRouter` (the `no_std` core), never only in the
  host-side driver.** An embedded node drives the router directly with no
  `wayfinder-driver`/tokio loop, so any metric kept only in the driver would not
  exist on hardware. The driver may *feed* the router (e.g. calling `record_tx`
  after a physical send), but the counters/estimators and their accessors belong
  to the router so every deployment serves the same data through the same API.
- **Prefer bounded, here-and-now signals over unbounded totals.** Throughput is
  modelled as a time-decayed EWMA *rate* (`RateEstimator`, bytes/sec and
  frames/sec per interface/direction) rather than a cumulative counter, so a
  long-lived node reports a stable, directly-usable value. Reach for the same
  pattern (or a current-vs-capacity gauge like `TableOccupancy`) before adding a
  monotonic count.
- **Time-varying metrics are evaluated at request time.** `RouterAdapter::new`
  takes the router's monotonic `now` so rates and uptime reflect the instant the
  query is served, and an idle interface reads as a decaying — not stale — rate.
- **Wire it end to end**: a `Get*Request`/response pair in
  `protos/wayfinder/v1alpha/wayfinder.proto` (every message/field documented —
  `buf lint` enforces it), an intermediate `*Data` type plus
  `WayfinderDataProvider` method and handler arm in `wayfinder-protos::service`,
  the projection in `RouterAdapter`, a client method in `wayfinder-client`, and a
  row/panel on the TUI Metrics tab. The `wayfinder-tui` smoke test exercises the
  whole path over a real TCP server — extend it.

## Logging

Logging is via [`tracing`].  Every crate uses the `tracing` facade — never
`log`, `println!`, or `eprintln!` for diagnostics.  Pick the level by **who the
record is for**, not by how interesting the event felt while writing it:

- **`error!`** — a failure an operator must act on, originating in *this* node
  (config invalid, an invariant violated, a resource permanently lost).  Must
  not be reachable by arbitrary peer input and must not fire once per iteration
  of a hot loop.  A handled-and-retried I/O error is a `warn!`, not an `error!`.
- **`warn!`** — something unexpected but handled, worth an operator's attention
  (capacity eviction, a security-relevant drop, a stream that errored and was
  torn down).  Never reachable by arbitrary remote input on a hot path — a peer
  must not be able to drive `warn!` volume.
- **`info!`** — lifecycle and topology events an observer *wants*: startup,
  listeners bound, auth enabled, a node discovered or revoked.  Not per-frame,
  never a payload, never a secret (no full config/key/token dumps — those go to
  `debug!`).  If it can repeat per packet, it is not `info!`.
- **`debug!`** — developer-facing state transitions: config dump, connection
  open/close, route-table or auth-state changes, capacity evictions.  Strictly
  for debugging; off in normal operation.
- **`trace!`** — per-frame / per-packet flow; expected to be the bulk of the
  logs.  Two hard rules: (1) **never log payload bytes** — no `pretty_hex` of a
  frame, no `{:?}` of a struct that embeds a payload slice (e.g. `RxOutcome`).
  Log metadata only: src, dst, protocol, lengths, seqno, TTL.  (2) **Always use
  structured fields** with a short, static message — `trace!(?src, ?dst,
  payload_len = n, "rx frame")`, not `trace!("rx src={:?} ...", src)`.  Drops use
  a `"drop: <reason>"` message.

Carry shared per-frame context in a span (`trace_span!("handle_frame", ?src,
…)`) rather than repeating it in every event.  Import the macros a module uses
(`use tracing::{debug, info, trace};`) and call them bare; don't mix bare and
fully-qualified `tracing::` calls within one file.  Parse failures of
remotely-supplied frames are `trace!`, not `warn!` — a malformed packet from any
peer must not be able to flood the logs.

[`tracing`]: https://docs.rs/tracing

## Merge Requests

This project ships through GitLab merge requests (`git.haganah.net`), not direct
pushes to `main`.

**The MR title MUST follow Conventional Commits** — `type(scope): summary`. The
`lint:mr-title` CI job (in `.gitlab-ci.yml`) pipes the MR title through
`commitlint` and fails the pipeline if it doesn't conform. Note it checks the
*MR title*, not individual commit messages.

- **Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `chore`, `revert`.
- **Scope** (optional but encouraged): the crate or area, e.g. `metrics`,
  `batman`, `tui`, `driver`, `auth`.
- **Summary**: lowercase, imperative, no trailing period, ≤100 chars.
- Example: `feat(metrics): add throughput and node metrics to the management API`
- A non-compliant title like `Add throughput metrics` (no type, sentence-case)
  will fail the lint.

**Description**: use the template at
`.gitlab/merge_request_templates/Default.md` — Summary, What's included, Key
design decisions, Testing, Deferred/follow-ups. Explain the *why* and the
trade-offs; a reviewer should be able to judge the design from the description
alone. State test results honestly.

**Constructing an MR**:

1. Branch off `origin/main` (not whatever local `main` happens to be) so the MR
   diff is exactly your change and unrelated local commits don't ride along.
2. Keep the branch focused — one logical change per MR.
3. Run the workspace checks locally first: `cargo test --workspace`, `nix fmt`,
   `cargo clippy --workspace`, and `buf lint` (from `libs/wayfinder-protos/`) if
   protos changed — these all run in CI and will block the MR otherwise.
4. Create it with `glab` (authenticated to `git.haganah.net`):

```bash
glab mr create \
  --source-branch <branch> --target-branch main \
  --title "feat(scope): imperative lowercase summary" \
  --description "$(cat <<'EOF'
## Summary
...
EOF
)"
```

`glab`'s API calls need a personal access token configured for
`git.haganah.net` (in `~/.config/glab-cli/config.yml`); the SSH agent only
authenticates `git push`/`pull`, not the MR-creation API.

5. **For a sufficiently complex MR** (non-trivial logic, security-sensitive code,
   a new wire format, multi-crate changes), once it is pushed, spawn a sub-agent
   to give it a second-opinion review — a fresh reviewer that reads the diff
   (`git diff origin/main...<branch>`) and reports prioritized findings. Address
   the findings (or justify why not) before requesting human review. Trivial MRs
   (small fixes, doc tweaks, mechanical refactors) don't need this.

## Common Development Patterns

### Adding a new routing protocol

1. Implement the `MeshRoutingEngine` trait in a new library
2. Add a protocol constant (EtherType) to identify your protocol
3. Update the `CentralRouter::handle_frame_with_metrics` match statement to handle your protocol
4. Create wire-format packet structs with zerocopy derives

### Implementing a physical radio driver

1. Implement the `LinkT` trait (in `libs/wayfinder/src/link.rs`) for your device
2. Serialize the `LinkFrame` and send via hardware; parse received bytes back into a `LinkFrame` plus `LinkMetrics`
3. Reuse `ieee802154::encode`/`decode` for 802.15.4 radios (see `at86rf233` / `nrf-ieee802154`); handle broadcast addressing appropriately for your medium

### Testing with a simulated mesh

Use the `TestRouter` wrapper from `libs/wayfinder-test`, which pairs a
`CentralRouter` with one mpsc egress channel per interface and serialises
outgoing frames automatically:
```rust
let (tx_a, mut rx_a) = mpsc::channel(64);
let mut router = TestRouter::new(Mac([0,0,0,0,0,1]), vec![tx_a]);
router.poll(now).await;            // drive periodic OGMs
router.receive(0, &raw).await;     // feed a received wire frame
router.send_local(Mac([0,0,0,0,0,2]), payload).await?; // inject local data toward node 2
```
For multi-node scenarios, connect several `TestRouter`s through a `Switch`.

## Edition Note

Many crates use `edition = "2024"`, which is not yet stable as of the knowledge cutoff. When modifying Cargo.toml files, be aware of edition compatibility.
