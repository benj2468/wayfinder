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
