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
- `router_ops.rs` (`RouterOps`, `OgmAuthOps`) — `CentralRouter`'s **driver
  surface with the eleven capacities erased**, so code that merely *drives* a
  router writes `R: RouterOps` instead of re-declaring eleven const arguments
  and re-applying them to the router type. Implemented once, blanket, for every
  profile.

  Reach for it in any new generic function that takes a router. Before it,
  `wayfinder-embedded-driver`'s `dispatch` named fifteen generic parameters to
  express four real ones; its `Driver` struct named fourteen.

  Three things worth knowing:

  - **`INTERFACES` is deliberately *not* erased**, exposed as an associated
    const. It is part of the contract with a driver — holding more links than
    the router can schedule leaves the node silently mute on the surplus link
    (`configure_interface_ogm` no-ops past the bound), so
    `wayfinder-embedded-driver` asserts `N <= R::INTERFACES` at compile time.
  - **Auth is reached through the `Auth` associated type**, bounded by
    `OgmAuthOps`, because `OgmAuth` is itself const-generic over four more
    capacities. `dyn` is not an option — `revoked_macs` returns an
    `impl Iterator` and there is no allocator here to box one.
  - **Scope is the driver surface, not everything.** The read-only
    observability accessors the management API projects are *not* on the trait:
    `wayfinder-server`'s `RouterAdapter` already projects those onto
    `WayfinderDataProvider`, and duplicating ~25 of them here would create a
    second near-copy to keep in step. `RouterAdapter` (and the one
    `#[cfg(feature = "mgmt")]` impl in `wayfinder-embedded-driver` that feeds
    it) therefore still spell the capacities out.
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

## Receive path

`handle_frame_with_metrics` owns only what every protocol shares — the
fail-closed `auth_locked` gate, the unconditional ingress accounting
(`account_ingress`: link quality + rx rate, deliberately before any demux so a
frame the upper layers drop still counts), and the demux itself. Everything
BATMAN-specific is in `handle_batman_frame`, in the order the wire demands:

1. **Receive gate** — `LinkFeatures` `rx_ogm`/`rx_data` for this interface.
   Cert-control packets are never gated; the auth control plane must keep
   flowing.
2. **`authenticate_inbound`** → `InboundVerdict` — the pre-engine control-plane
   gate (OGM against the trust anchor, keep-alive against the sender's cached
   cert), plus the Trickle reset a newly-folded revocation triggers.
3. **`batman.handle_rx`** — the engine call, writing any outgoing frame into
   the `reply` scratchpad.
4. **Action dispatch** — `on_consumed` / `on_deliver_local` / inline
   forward-verbatim, with `engine_reply_frame` doing the trim-to-incoming-size
   both re-flood arms need.

The one non-obvious shape here is **`InboundVerdict` carrying no borrow**. Its
`NeedCert` arm names the originator and fingerprint to fetch and leaves
building the request to `build_cert_request_frame`; if the verdict borrowed
`tx_buf` to carry a ready-made `CertReq`, the accept path could no longer use
that same buffer for the engine's reply. Keep any future gate decision-only for
the same reason — it is the same rule `driver_core::plan_dispatch` follows.

The two lazy-cert control packets terminate in the node's own auth state and
never reach the host TAP: a `CertReply` is ingested, a `CertReq` is answered by
`answer_cert_request` (immediately when a route back exists and it fits) or
parked for `flush_parked_cert_reply` to flush opportunistically after a later
OGM from the requester reconfirms the route.

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
