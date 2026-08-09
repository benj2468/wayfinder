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

The whole transmit-side *decision* — auth-tagging, egress resolution,
split-horizon, the per-link transmit gate — is `driver_core::plan_dispatch`.
`dispatch` in `driver.rs` only does the I/O: reserve the auth trailer, call the
planner, then transmit `buf[..send_len]` on each interface in `plan.targets`.

**So a change to *what* goes out belongs in `plan_dispatch`, not here.** This
logic used to be written out in all three shells, which made split-horizon — a
correctness invariant — something you could fix in one and silently leave broken
in two.

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
`build_rylr998_link` (`rylr998.rs`), `build_ble_link` (`blue.rs`).

## Features

`tokio` (default) gates the event loop, the concrete `tokio::net` transports and
the link builders; without it the crate is just `FrameIo` + `McastSnooper`.
`ble` is split out of `tokio`/`std` deliberately so a consumer can take the
`Driver` without dragging in BlueZ/D-Bus — note the `blue?/std` (optional-dep)
syntax in `Cargo.toml`, which is what keeps `std` alone from pulling it.

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
