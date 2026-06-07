# Wayfinder mesh simulation (docker-compose)

A throwaway three-node mesh you can stand up locally to watch BATMAN routing
converge and inspect it with the `wayfinder-tui` dashboard.

## Topology

```
  node1 ──(link_ab)── node2 ──(link_bc)── node3
 10.0.0.1            10.0.0.2            10.0.0.3
```

`link_ab` and `link_bc` are two **separate** docker bridge networks, each its
own isolated L2 segment carrying raw mesh frames (EtherType `0xfafa`). node2 is
the only container on both segments, so node1 and node3 cannot hear each other
directly — traffic between them is forwarded by node2's BATMAN engine. That
two-hop path is exactly what the TUI shows.

## How it works

* `sim.Dockerfile` builds `wayfinder-tap` **and** `wayfinder-tui` onto a
  `debian-slim` base (the production `Dockerfile` is distroless and tap-only).
* The image's entrypoint generates the node config at start: it discovers every
  `eth*` NIC docker attached and emits one `RawL2` link per NIC, so the
  topology is defined purely by the compose network wiring — no hard-coded
  interface names. It also enables the management API on TCP `0.0.0.0:7700`.
* Each node creates a kernel TAP (`wayfinder0`) for host-facing traffic; its MAC
  becomes the node's mesh identifier. This needs `NET_ADMIN` + `/dev/net/tun`,
  and the `AF_PACKET` RawL2 sockets need `NET_RAW` — both granted in the compose
  file.

## Run it

```bash
# Build images and start the three nodes.
docker compose up --build -d

# Give the OGMs a few seconds to propagate, then open the dashboard on a node.
docker compose exec node1 wayfinder-tui
docker compose exec node2 wayfinder-tui
docker compose exec node3 wayfinder-tui

# Watch routing/OGM activity in the logs.
docker compose logs -f node2

# Tear it all down (also removes the two networks).
docker compose down
```

In the TUI, the **Routing Table** tab is the interesting one:

* **node2** sees node1 and node3 as direct (1-hop) originators.
* **node1** sees node2 directly and node3 via node2 (next-hop = node2's MAC).
* **node3** sees node2 directly and node1 via node2.

Use the number keys (`1`/`2`/`3`) or `←/→` to switch tabs, `↑/↓` to select an
originator and see its per-neighbor path breakdown, and `q` to quit.

## Notes

* The TUI defaults to `127.0.0.1:7700`, which is where each node's server
  listens inside its container, so `docker compose exec <node> wayfinder-tui`
  just works with no arguments.
* `RUST_LOG` is set to `info` per node; bump it (e.g. `RUST_LOG=debug`) in
  `docker-compose.yml` for more detail.
