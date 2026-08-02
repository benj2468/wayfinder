# libs/wayfinder

Central router orchestration. `no_std`; the `std` feature enables `DynLinkT`.

## Types

- `CentralRouter` — wraps the BATMAN engine plus an ident table and a
  per-(neighbor, interface) link-quality table, and owns the observability
  counters/estimators.
- `LinkT` (`link.rs`) — the single mesh-interface trait the router/driver speaks
  to: a native `async fn` trait usable in a `no_std` executor by static
  dispatch. The `std` driver dynamic-dispatches over `DynLinkT` (a
  `dynosaur`-generated `dyn`-compatible wrapper, gated behind `std`). Yields a
  `Received` frame-with-metrics.
- `DEFAULT_BATMAN_ETHER_TYPE`: 0x4305; `MCAST_FANOUT`: 16.
- `handle_frame` / `handle_frame_with_metrics` — process a received `LinkFrame`,
  fold in metrics, return any outgoing frame.
- `poll` — drive periodic (Trickle-paced) OGM broadcasts.
- `handle_local` — wrap application/host data destined for a mesh node in a
  BATMAN unicast.
- `mcast_plan` / `mcast_targets` / `handle_local_mcast` — multicast egress.
  `mcast_plan` returns `McastPlan::Unicast` when 1..=`MCAST_FANOUT` listeners are
  known (else `Flood`); `mcast_targets` is a no-alloc borrowing iterator of those
  listeners; `handle_local_mcast` wraps a frame as a `BATADV_MCAST` packet to one
  listener. `set_local_mcast_groups` feeds locally-snooped memberships to the
  engine.
- `get_egress_interface` / `resolve_route` — choose the egress interface for a
  destination (metric-driven), the latter without mutating state.
- `auth.rs` (`OgmAuth`) — opt-in OGM authentication, kept in the router (not the
  engine) so the engine stays crypto-free. `augment_ogm` appends the
  originator's membership cert + Ed25519 signature TVLVs; `verify_ogm` gates an
  incoming OGM against the mesh trust anchor *before* it reaches the engine. Also
  caches neighbor keys for pairwise data-plane tags.

  `OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS,
  MAX_PENDING_REPLIES>` is const-generic over its table sizes; all four default
  to the module constants of the same name. The neighbour cache dominates the
  footprint (`NeighborKeys` is 272 B, ×64 at host capacity), so a constrained
  node picks a smaller profile: `OgmAuth<8, 4, 2, 2>` is 3,808 bytes against the
  host profile's 25,000.

  **Capacity never reaches the wire** — a host-profile and a tiny-profile node
  interoperate unchanged; `profiles_do_not_change_the_wire_format` pins this.

  `new` lives in its own impl on the fully-defaulted type, *not* on the generic
  impl: a struct's default const parameters do not drive inference in expression
  position, so a generic `OgmAuth::new` would make every call site name its
  capacities (`E0284`). A profile-specific node calls `with_capacities` instead.
  Apply the same pattern to any future constructor here.
- `config.rs` — per-link Trickle bounds (`i_min_ms`/`i_max_ms`) so a fast LAN
  link and a slow LoRa link back off on different schedules.
- Observability: `RateEstimator` throughput EWMAs, `TableOccupancy` gauges —
  served identically on embedded and host deployments. See the Metrics guidance
  in the root `CLAUDE.md` and the `add-metric` skill.

## Protocol multiplexing

`CentralRouter` demuxes by protocol field (`handle_frame_with_metrics` in
`src/lib.rs`):

- `0x4305` (`DEFAULT_BATMAN_ETHER_TYPE`) — routes to the BATMAN engine.
- `0x88B5` — reserved for experimental protocols.
- Other values are dropped.

## Adding a new routing protocol

1. Implement the `MeshRoutingEngine` trait (from `libs/interfaces`) in a new
   library.
2. Add a protocol constant (EtherType) to identify your protocol.
3. Update the `CentralRouter::handle_frame_with_metrics` match statement to
   handle it.
4. Create wire-format packet structs with `zerocopy` derives.

## Fuzzing

`fuzz/` is a `cargo-fuzz` project, kept as its own independent Cargo
workspace (standard cargo-fuzz layout) rather than a member of the root
workspace, so its `libfuzzer-sys`/nightly-only dependencies never touch the
main build. Run from inside `libs/wayfinder/fuzz/`:

```bash
cargo fuzz run verify_ogm corpus/verify_ogm seeds/verify_ogm
```

The first directory is libFuzzer's mutable working corpus (create it once
with `mkdir -p corpus/verify_ogm`; everything under `corpus/` is gitignored,
ephemeral, and safe to delete). The second, `seeds/verify_ogm/`, is a
**tracked**, read-only seed directory — libFuzzer only reads from directories
after the first, so a curated valid input there survives forever without
being polluted by the fuzzer's own finds. `seeds/verify_ogm/seed_valid_ogm`
is one fully valid, real-signed OGM (built once via the existing
`member`/`bare_ogm`/`augment_ogm` test helpers in `src/auth.rs`, then copied
out); it roughly doubles code coverage over an empty-corpus run, since
mutations near a structurally valid cert/signature reach much deeper into
`verify_ogm` than random bytes ever will on their own.

- `verify_ogm` — fuzzes `OgmAuth::verify_ogm`, the gate an incoming OGM must
  clear before it reaches the routing engine (TVLV scan → cert parse → trust-
  anchor + signature verification). The harness builds a real `Authority`
  once (lazily, `std::sync::OnceLock`) to get a valid trust anchor, but
  constructs a fresh `OgmAuth` per input so a crash stays reproducible from
  the input alone, independent of fuzzing history.
- To add another target: `cargo fuzz add <name>` from `fuzz/`, then add a
  `seeds/<name>/` directory if a valid-structured seed would meaningfully
  help (it isn't required to get started).
