# libs/wayfinder-driver

The `std`/tokio host driver: the router event loop plus the concrete socket
carriers a Linux node runs on. This is what `bins/wayfinder-tap` assembles.

The loop is transport-agnostic — the host device and every mesh interface are
`FrameIo` carriers — so the *same* loop runs against real sockets in production
and in-process channels under `libs/wayfinder-test`.

## One driver, three shells

Read this before assuming logic lives here. The planning logic (received frame →
outgoing frames, due OGMs, due keepalives) is **not** in this crate; it is
`libs/wayfinder-driver-core`, shared with two other shells:

| Shell | Loop | Used by |
|---|---|---|
| `wayfinder-driver` (here) | tokio `select!` | host nodes, `wayfinder-test` |
| `wayfinder-embedded-driver` | `embassy_futures::select` | nRF/STM32 firmware |
| `wayfinder-tick-driver` | synchronous `tick()`, plain queues | `wayfinder-py` / sim |

"One behavior, N loops." A behavior change almost always belongs in
`driver-core`, not here.

The whole transmit-side *decision* — auth-tagging, egress resolution, the
per-link transmit gate — is `driver_core::plan_dispatch`.
`dispatch` in `driver.rs` only does the I/O: reserve the auth trailer, call the
planner, then transmit `plan.payload()` on each interface in `plan.targets()`.

**So a change to *what* goes out belongs in `plan_dispatch`, not here.** This
logic used to be written out in all three shells, which made a correctness
invariant something you could fix in one and silently leave broken in two.

`Egress::Auto` floods **every** interface, the ingress one included — there is
no interface-level split-horizon, and re-introducing one black-holes any
multi-access link whose neighbors cannot hear each other. Its doc comment in
`wayfinder-driver-core` is the canonical statement of why.

## Two ways to drive it

- `run` / `run_once` — the free-running `select!` loop used in production: awaits
  whichever comes first (mesh frame, host frame, management query, periodic
  timer).
- `poll_due` / `poll_due_keepalive` / `process_pending` — deterministic
  stepping. **This is what the entire integration suite uses**; `run_once` and
  the `select!` arms have no direct test coverage. Worth knowing before you
  change the loop and see green tests.

## `FrameIo` vs `LinkT` — the two-layer carrier model

- `FrameIo` (`transport.rs`) is a dumb message-oriented byte pipe: one
  `recv`/`send` moves exactly one whole frame. A TAP device, a `UnixDatagram`, a
  connected `UdpSocket`, an mpsc channel are all this shape.
- `LinkT` is one *mesh interface*. A point-to-point carrier gets `LinkT` free
  via the blanket `Link` adapter, which ignores the destination and frames
  `[dst][src][protocol][payload]` onto the pipe.
- A **multi-access or self-routing** carrier (UDP multicast, raw L2, a radio
  that does its own addressing) implements `LinkT` directly, because "ignore the
  destination" is wrong for it.

That last distinction is the one to get right when adding a carrier: if the
medium has more than one reachable peer, `Link` is not your adapter. `wire.rs`
holds the single bounds-checked writer for the Ethernet-shaped header so every
such carrier stamps identical bytes.

Carriers available: `build_udp_link` / `build_udp_multi_link` / `UdpMultiLink`
(`net.rs`), `build_raw_ip_link` / `build_raw_l2_link` / `RawL2Link` (`raw.rs`),
`build_rylr998_link` (`rylr998.rs`), `build_ble_link` (`blue.rs`),
`build_iroh_link` / `IrohLink` (`iroh.rs`).

`IrohLink` is the internet carrier: BATMAN frames as QUIC datagrams over
[iroh](https://docs.iroh.computer), dialed by the node's own Ed25519 identity
key instead of an IP address, so it reaches a CGNAT'd peer without a tunnel
daemon or a coordination server. It is structurally `UdpMultiLink` with an
`EndpointId` where that link keeps a `SocketAddr` — the same learn-from-received
-frames peer table with the same bound and TTL — and two differences worth
knowing before changing it:

- **A broadcast fans out over the live *connection* set, not the peer table.**
  A bootstrapped connection has taught us nothing yet, so a table-driven
  fan-out would never send it the first OGM, the peer would never reply, and
  nothing would ever be learned. The table is for unicast resolution only.
- **`send` never dials.** A QUIC handshake plus a hole punch is far longer than
  the driver's event loop can be held, so an unconnected destination gets a
  deduped background dial and a dropped frame; Trickle's next emission uses the
  connection. See `docs/design/18-iroh-mesh-links.md` §3.5.
- **Revocation reaches the transport through `AuthView`, not through `LinkT`.**
  `peers.rs` publishes `Mac → key` plus a *stale* set (revoked ∪ superseded)
  and a generation counter; `IrohLink::reconcile` closes any connection whose
  key went stale, and `recv` races the watch so an idle link reacts too. Without
  it revocation stopped at the router: the engine refused a revoked peer's
  frames while the carrier held the socket open and kept it in the broadcast
  fan-out set.

  A revocation names a **MAC, not a key**, and the router evicts the cached
  certificate as it ingests one — so `AuthView` remembers the last key each MAC
  was known by. That memory is what makes a revoked connection closable at all.

  The same mechanism is what rotates a re-keyed peer (including the CA) without
  touching config, but only while the node is *connected* when the rotation
  happens. A node offline across a rotation restarts with an empty view and a
  stale `bootstrap_peers`; recovering needs the key out of band.

It cannot ever run on a board — iroh is `std`-only, and an MCU has no IP stack
and no NAT to traverse (design 18 §2). Host-only, like the BlueZ and raw-L2
carriers, and gated the same way: the constructor exists unconditionally and
fails with a stated reason, so a config naming an iroh link is a startup error
rather than a compile error.

## Features

`tokio` (default) gates the event loop, the concrete `tokio::net` transports and
the link builders; without it the crate is just `FrameIo` + `McastSnooper`.
`ble` is split out of `tokio`/`std` deliberately so a consumer can take the
`Driver` without dragging in BlueZ/D-Bus — note the `blue?/std` (optional-dep)
syntax in `Cargo.toml`, which is what keeps `std` alone from pulling it.

`iroh` is split out for the same reason and goes further: it is **not in
`default`**, because it pulls 112 crates (quinn/noq, hickory-resolver,
portmapper) that core work should not pay for. `bins/wayfinder-tap` turns it on,
so a real node and a workspace build both cover it — but
`cargo check -p wayfinder-driver` alone does *not* compile `iroh.rs`'s
implementation. Use `--features iroh` when changing it.

## Re-exports are the public seam

This crate re-exports `LinkT`/`DynLinkT`/`Received` (from `wayfinder`) and the
whole management-server wiring (`QueryTx`/`QueryRx`, `bind_tcp_server`,
`serve_tls_server`, `AuthSnapshot*`, from `wayfinder-server`) so a node
assembling itself depends on *this* crate only. Keep new wiring re-exported here
rather than making `wayfinder-tap` take a direct dependency.

## Reconnection

`ReconnectingRylr998Link` reopens the serial port and re-issues the
`AT+ADDRESS`/`AT+NETWORKID`/`AT+PARAMETER` sequence after an `Io` error, so an
unplugged or power-cycled LoRa module recovers without restarting the node. A
new hot-pluggable carrier should follow the same shape.

## Snooping

`snoop.rs` (`McastSnooper`) watches the host link's IGMP membership
reports/leaves to learn which IPv4 groups the host wants, so the router
announces only those to the mesh. IPv4 IGMP v1/v2/v3 only — **IPv6 MLD is not
snooped**, so an IPv6 multicast app will not be discovered this way.
