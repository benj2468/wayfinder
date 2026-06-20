# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a research project implementing BATMAN-adv (Better Approach To Mobile Adhoc Networking) mesh routing for embedded systems and LoRa radio communication. The project is structured as a Cargo workspace with multiple libraries focusing on different aspects of mesh networking.

## Building and Testing

### Build Commands
```bash
# Build the entire workspace
cargo build

# Build a specific package
cargo build -p batman
cargo build -p wayfinder
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
cargo test

# Run tests for a specific package
cargo test -p wayfinder
cargo test -p batman

# Run a specific test by name
cargo test test_ogm_forwarding

# Run tests with output visible
cargo test -- --nocapture
```

### Running Binaries
```bash
# Run the tun binary
cargo run --bin tun
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

The workspace is organized into several libraries plus one binary:

**libs/interfaces** - Core abstractions and traits for the mesh networking system:
- `MeshRoutingEngine` trait: Defines routing protocol behavior (handle_rx, produce_periodic_broadcast)
- `EmbeddedMeshLink` trait: Abstracts physical layer communication; `receive` reports per-frame `LinkMetrics` (RSSI/SNR)
- `Mac`: the node-address type — a `#[repr(transparent)]` newtype over `[u8; 6]` (a MAC address) with `is_multicast`/`is_broadcast` (I/G bit), `from_ipv4_multicast`, `BROADCAST`, and `From<[u8;6]>`. The protocol/engine/router layers are concrete over `Mac`.
- `MeshIdentifier` trait: retained only as the type constraint for the still-generic *container* types (`IdentTable`, `LinkQualityTable`, `Switch`); implemented for `u8` (used by their unit tests) and `Mac`.
- `LinkFrame`: Zero-copy link-layer frame structure with src/dst (`Mac`)/protocol/payload
- `RoutingAction` enum: Returned by routing engines (Consumed, ForwardTo, DeliverLocal, DeliverLocalAndForward)

**libs/batman** - BATMAN-adv routing protocol implementation:
- `BatmanEngine<MAX_ORIGINATORS>`: Core routing engine with originator table, broadcast dedup table, and multicast membership tables (`local_mcast` / `mcast_members`)
- `BatmanOgmPacket`: Originator Messages (OGM) for topology discovery. Matches batman-adv's `batadv_ogm_packet` layout (`flags`, `reserved`, big-endian `tvlv_len`) and can carry a variable-length TVLV tail after the fixed header.
- `BatmanTvlvHdr` + `find_tvlv`: Type-Version-Length-Value records carried in the OGM tail; `BATADV_TVLV_MCAST` announces the originator's joined multicast groups (group MACs back-to-back).
- `BatmanUnicastPacket`: Unicast data packets with TTL and destination
- `BatmanMcastPacket`: Selectively-forwarded multicast copy (one per interested listener), routed toward `dest` like a unicast
- `BatmanBroadcastPacket`: TTL-limited, seqno-deduplicated flooded broadcasts (e.g. ARP)
- `set_local_mcast_groups` / `mcast_listeners`: manage local memberships (announced in OGMs) and query learned `(group → originators)` memberships
- Implements `MeshRoutingEngine` trait
- Uses heapless data structures for embedded compatibility
- Protocol constants: `ETH_P_BATMAN` (0x4305), `BATADV_IV_OGM` (0x01), `BATADV_BCAST` (0x02), `BATADV_UNICAST` (0x03), `BATADV_MCAST` (0x04), `BATADV_TVLV_MCAST` (0x06)

**libs/wayfinder** - Central router orchestration (`no_std`):
- `CentralRouter`: Wraps the BATMAN engine plus an ident table and a per-(neighbor, interface) link-quality table
- `DEFAULT_BATMAN_ETHER_TYPE`: 0x4305
- `handle_frame` / `handle_frame_with_metrics`: Process a received `LinkFrame`, fold in metrics, return any outgoing frame
- `poll`: Drive periodic OGM broadcasts
- `handle_local`: Wrap application/host data destined for a mesh node in a BATMAN unicast
- `mcast_plan` / `mcast_targets` / `handle_local_mcast`: multicast egress. `mcast_plan` returns `McastPlan::Unicast` when 1..=`MCAST_FANOUT` listeners are known (else `Flood`); `mcast_targets` is a no-alloc borrowing iterator of those listeners; `handle_local_mcast` wraps a frame as a `BATADV_MCAST` packet to one listener. `set_local_mcast_groups` feeds locally-snooped memberships to the engine.
- `get_egress_interface` / `resolve_route`: Choose the egress interface for a destination (metric-driven), the latter without mutating state
- Protocol demultiplexing based on `LinkFrame` protocol field

**libs/wayfinder-protos** - Management API (`prost`/protobuf, package `wayfinder.v1alpha`): request/response envelopes for querying node info, the routing table, the link-quality table, and route resolution. `buf lint` runs from this crate.

**libs/wayfinder-server** - The management-API server. Two layers: `RouterAdapter` (`no_std` + `alloc`) projects a borrowed `CentralRouter` through the `WayfinderDataProvider` trait; the transport layer (gated behind the `std` feature) provides the per-transport listener loops (`run_tcp_server`/`run_unix_server`/`run_udp_server` over tokio net) and the `QueryTx`/`QueryRx` channel that forwards queries to the single-threaded router loop. The `std` feature pulls in tokio, tokio-util, futures, bytes, anyhow, and `prost/std`.

**libs/wayfinder-test** - Test-only harness: a `Switch` simulator and `TestRouter` wrapper for multi-node integration tests over `tokio` mpsc channels (no hardware).

**bins/wayfinder-tap** - The runnable node: bridges a TAP device (`Layer::L2`) onto the mesh, carries links over UDP/Unix sockets, and exposes the management API (via `wayfinder-server`) over TCP/Unix/UDP. The event loop snoops IGMP off the TAP (`McastSnooper` in `snoop.rs`, IPv4 IGMP v1/v2/v3; MLD not yet) to learn the host's joined multicast groups and announce them via `set_local_mcast_groups`; a host multicast frame is then sent as per-listener `BATADV_MCAST` copies (or flooded as fallback).

**libs/rylr998** - REYAX RYLR998/RYLR498 LoRa module driver:
- `RylrClient<S>`: Async AT command interface for LoRa modules
- Configuration methods: set_mode, set_rf_frequency, set_parameters (spreading factor, bandwidth, coding rate)
- `send_data()`: Transmit up to 240 bytes to target address
- `listen_for_packet()`: Async receive with RSSI/SNR metrics
- Supports network IDs, encryption passwords, RF output power configuration

### Key Design Patterns

**Zero-copy parsing**: Uses `zerocopy` crate for efficient packet handling without allocations. All wire format structs derive `FromBytes`, `IntoBytes`, `Immutable`, `KnownLayout`.

**Async I/O**: Built on `embedded-io-async` for async operations. Physical links implement `AsyncRead + AsyncWrite`.

**Trait-based abstraction**: Routing engines and physical links are abstracted via traits, enabling protocol/hardware flexibility.

**No-std compatibility**: BATMAN engine uses `heapless::Vec` for fixed-capacity collections suitable for embedded systems.

**Test infrastructure**: `libs/wayfinder-test` provides a `Switch` simulator and `TestRouter` wrapper (over `tokio` mpsc channels) for testing multi-node scenarios without hardware.

## Important Implementation Details

### BATMAN Routing Logic

The BATMAN engine maintains an originator table tracking:
- `neighbor_ident`: The destination node
- `best_next_hop`: Immediate neighbor to forward packets to
- `max_tq`: Transmission Quality metric (0-255)
- `paths`: Up to 4 alternate paths via different neighbors

OGM processing (`handle_rx`, `BATADV_IV_OGM` arm in libs/batman/src/engine.rs):
1. Drops own OGMs (loop prevention)
2. Creates or updates originator record
3. Computes path quality (TQ -= 10 per hop)
4. Selects best path based on highest TQ
5. Folds the OGM's multicast TVLV into `mcast_members` (authoritative per originator, so dropped groups are pruned)
6. Forwards OGM with decremented TTL and updated prev_sender, preserving the TVLV tail verbatim

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
- `src: Mac` - Source identifier (added by link layer)
- `dst: Mac` - Destination identifier (or `Mac::BROADCAST`)
- `protocol: u16` - EtherType-style protocol identifier
- `payload: [u8]` - Variable-length payload

### Protocol Multiplexing

The CentralRouter demuxes by protocol field (`handle_frame_with_metrics` in libs/wayfinder/src/lib.rs):
- `0x4305` (DEFAULT_BATMAN_ETHER_TYPE): Routes to BATMAN engine
- `0x88B5`: Reserved for experimental protocols
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
  the projection in `RouterAdapter`, a client method, and a row/panel on the TUI
  Metrics tab. The `wayfinder-tui` smoke test exercises the whole path over a
  real TCP server — extend it.

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
  `batman`, `tui`, `driver`.
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

## Common Development Patterns

### Adding a new routing protocol

1. Implement the `MeshRoutingEngine` trait in a new library
2. Add protocol constant (EtherType) to identify your protocol
3. Update the `CentralRouter::handle_frame_with_metrics` match statement to handle your protocol
4. Create wire format packet structs with zerocopy derives

### Implementing a physical radio driver

1. Implement the `EmbeddedMeshLink` trait
2. `transmit()`: Serialize LinkFrameData and send via hardware
3. `receive()`: Read from hardware, parse into LinkFrame
4. Handle broadcast addresses appropriately for your medium

### Testing with simulated mesh

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

Some packages use `edition = "2024"` which is not yet stable as of the knowledge cutoff. When modifying Cargo.toml files, be aware of edition compatibility.
