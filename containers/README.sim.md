# Wayfinder mesh simulation (docker-compose)

A throwaway multi-node mesh you can stand up locally to watch BATMAN routing
converge and inspect it with the `wayfinder-tui` dashboard.

## Topology

The default is a **4-node diamond bolted onto a 5-node complete-graph mesh**,
joined by a single link (`d4 ⇄ m1`):

```
        d2                 m2───m3
       /  \               /│ ╳ │\
   d1 ┤    ├ d4 ──── m1 ──┤ ╳   ╳ ├ (every m_i ⇄ m_j)
       \  /               \│ ╳ │/
        d3                 m4───m5
   diamond (2 disjoint     K5 mesh (10 links,
   2-hop paths d1⇒d4)      every pair direct)
```

* The **diamond** (`d1..d4`) gives two disjoint 2-hop paths between `d1` and
  `d4`, so you can watch failover when a path is cut.
* The **mesh** (`m1..m5`) is a complete graph K5 — every pair of mesh nodes is
  joined by its own point-to-point link, so each is a distinct interface the
  router paces independently.
* `d4 ⇄ m1` is the **only** bridge between the two clusters, so traffic from the
  diamond into the deep mesh (e.g. `d1 → m5`) must cross the diamond, hop the
  bridge, then route through the mesh — a multi-hop path the TUI visualises.

Every docker network is a **separate** bridge — its own isolated L2 segment
carrying raw mesh frames (EtherType `0x4305`). A node hears only the nodes it
shares a segment with; everything else is reached by BATMAN forwarding.

## Editing the topology

The topology is **generated** by [`sim/topology.py`](../sim/topology.py) — the
sim image derives each node's config from the NICs docker attaches, so the
compose wiring *is* the topology. Edit `build_links()` (or the helpers
`diamond`, `complete_graph`, `path`, `shared_lan`) and re-run; nothing else
changes.

```bash
python sim/topology.py graph             # ASCII adjacency summary
python sim/topology.py print             # the generated compose YAML
python sim/topology.py up                # write ephemeral file + compose up --build -d
python sim/topology.py logs d1 m5        # follow specific nodes
python sim/topology.py down              # tear it down (removes networks)
python sim/topology.py write             # refresh the committed docker-compose.yml
```

`up`/`down`/`logs` operate on an ephemeral, gitignored file
(`.sim-compose.gen.yml`) under the fixed project name `wayfinder-sim`. The
committed `docker-compose.yml` is a snapshot of the default topology, so plain
`docker compose up --build -d` works too.

## Stress-testing the flood path

`blast` floods broadcast traffic from one node into a **running** stack, to see
how the mesh and the application hold up under a storm of flooded frames. It
`docker compose exec`s `ping` at the subnet broadcast address, so every frame
goes to the all-ones MAC and the router floods it out *every* mesh interface
(the `BATADV_BCAST` path). Egress is pinned to the host TAP with `ping -I
wayfinder0`, so the traffic enters the mesh through the node — it never leaks
straight onto the `eth*` segment NICs.

```bash
python sim/topology.py up                                  # stack must be up first
python sim/topology.py blast m1 --rate 200 --size 1000 --duration 30
python sim/topology.py blast d1 --rate 0 --size 1400       # --rate 0 = flood as fast as possible
python sim/topology.py blast                               # first node, 100 fps × 1000 B for 10 s
```

* `--rate` is frames/second (`0` uses `ping -f` to flood as fast as the kernel
  accepts); `--size` is the **total IP packet size** in bytes; `--duration` is
  how long to run (`0` runs until you Ctrl-C).
* The origin `NODE` defaults to the first node in the topology; pass any node
  name to blast from there instead.
* Watch the fallout in another terminal: `python sim/topology.py logs` for OGM/
  forwarding churn, or `docker exec -it wf-<node> wayfinder-tui` to see whether
  routing stays converged under load.

A link with **2 members** is a point-to-point segment; a link with **more**
members is a single shared LAN where everyone hears everyone (swap
`complete_graph("m", 5)` for `shared_lan([...])` if you want the mesh on one
wire instead of 10).

## How it works

* `sim.Dockerfile` builds `wayfinder-tap` **and** `wayfinder-tui` onto a
  `debian-slim` base (the production `Dockerfile` is distroless and tap-only).
* The image's entrypoint generates the node config at start: it discovers every
  `eth*` NIC docker attached and emits one `RawL2` link per NIC. It also enables
  the management API on TCP `0.0.0.0:7700`.
* Per-link **OGM backoff** (the adaptive Trickle interval) defaults to 1 s → 64 s.
  Set `OGM_I_MIN_MS` / `OGM_I_MAX_MS` on a node (via `build_nodes()` in the
  script, or `environment:` in compose) to pin that node's bounds on every link —
  e.g. a slow-radio node that should chatter less.
* Each node creates a kernel TAP (`wayfinder0`) for host-facing traffic; its MAC
  becomes the node's mesh identifier. This needs `NET_ADMIN` + `/dev/net/tun`,
  and the `AF_PACKET` RawL2 sockets need `NET_RAW` — both granted in the compose
  file.

## Inspecting it

Containers are named `wf-<node>`, so these work whichever way the stack was
started (the script uses the project name `wayfinder-sim`):

```bash
docker exec -it wf-d1 wayfinder-tui       # d1's routing tree (reaches the mesh via d4→m1)
docker exec -it wf-m3 wayfinder-tui       # a mesh node: m1,m2,m4,m5 direct; diamond multi-hop
python sim/topology.py logs d4            # the bridge node: watch OGM/route activity
```

In the TUI, the **Routing Table** tab is the interesting one: direct (1-hop)
originators versus those reached via a next-hop neighbor. Use the number keys or
`←/→` to switch tabs, `↑/↓` to select an originator and see its per-neighbor path
breakdown, and `q` to quit. The TUI defaults to `127.0.0.1:7700`, which each
node's server listens on, so `docker exec -it wf-<node> wayfinder-tui` just
works with no arguments.
