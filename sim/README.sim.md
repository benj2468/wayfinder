# Wayfinder mesh simulation (docker-compose)

A throwaway multi-node mesh you can stand up locally to watch BATMAN routing
converge and inspect it with the `wayfinder-tui` dashboard.

For a physics-driven, single-process simulation instead of real containers
and sockets — e.g. modeling a moving node's radio link quality as a function
of distance and watching BATMAN's next-hop selection react — see
[`sim/scenarios/`](./scenarios/), built on the `wayfinder-sim` package in
[`sim/src/wayfinder_sim/`](./src/wayfinder_sim/): a small SimPy-scheduled
harness that drives real `wayfinder-py` `PyDriver`s (the PyO3 binding over
the tick-based mesh driver) against Python-side `Mobility`/`Channel` models,
so a scenario only has to describe topology, channel tuning, and what to
record — not tick/delivery bookkeeping.

`wayfinder-sim` is a uv workspace member and a dependency of the root
`wayfinder-dev` project, so a plain `uv sync` installs it (editable) and
`import wayfinder_sim` resolves from anywhere — no `PYTHONPATH`, no
`sys.path` insert at the top of a scenario. The `sim` dependency group adds
only its `plot` extra (matplotlib), which the charts need and a headless
sweep does not.

```bash
uv sync --group sim
uv run --group sim python sim/scenarios/drone_relay.py
```

### Writing a scenario

A scenario builds a `Node`/`Link` topology (via `wayfinder_sim.topology`'s
`pair`/`path`/`complete_graph`/`shared_lan`/`diamond`/`star`, mirroring
`scripts/topology.py`'s docker-topology vocabulary), wires it into a
`Simulation`, registers what to record, and runs it:

```python
from wayfinder_sim.channel import FreeSpacePathLoss
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.topology import pair

nodes = [Node("a"), Node("b")]
links = [pair("a", "b", FreeSpacePathLoss())]
sim = Simulation(nodes, links, seed=0)
sim.record("route", lambda s: s.route_via("a", "b"))

rec = sim.run(until_s=10.0)
print(rec.transitions("route"))
```

Scenarios stay plain scripts rather than package modules — each is runnable
on its own, and `wayfinder-ml generate` takes one by path.

See `sim/scenarios/drone_relay.py` for a full example (mobility, multiple
channels, a switch summary, and a chart via `wayfinder_sim.plotting`), and
`sim/tests/` for the engine's own pure-logic + integration tests
(`uv run pytest sim/tests/`).

### Terrain

`wayfinder_sim.terrain` makes the ground a first-class part of the model, so
connectivity stops being a pure function of distance. A `Terrain` answers
"how high is the ground at (x, y)?" — either analytically (`MountainRange`, a
base elevation plus a sum of `GaussianPeak`s) or from gridded data
(`Heightmap`, bilinearly interpolated, the shape a real DEM arrives in).

Everything else builds on that:

* `elevation_profile` / `has_line_of_sight` sample the ground under the
  straight line between two nodes.
* `max_fresnel_parameter` reduces that profile to the single worst
  obstruction, as the dimensionless `v` a diffraction model consumes.
* `channel.TerrainMasked` wraps any RSSI-reporting radio (`FreeSpacePathLoss`)
  and subtracts the resulting knife-edge diffraction loss
  (`channel.knife_edge_loss_db`, ITU-R P.526). A node in one valley then
  cannot hear a node in the next one however strong its radio, while the same
  node at altitude — or a relay on the ridge between them — hears both.
* `TerrainFollowing` flies a route's *ground track* at a fixed height above
  ground rather than a fixed altitude, so a drone's absolute height, and what
  it can see over, rises and falls with the terrain.
* `peak_sites` / `valley_sites` pick summit or valley-floor locations to put
  infrastructure on — the natural thing to sweep.

Terrain geometry is memoized per endpoint pair, so a scenario's fixed
infrastructure costs one profile evaluation for a whole run no matter how
many frames cross it.

### Measuring connectivity

`wayfinder_sim.connectivity` turns a recorded signal into the numbers a
coverage study reports. `Simulation.reachable(node, targets)` is the probe —
the set form of `route_via`, answering "is this node in touch with anything"
rather than "which link does it forward on" — and `connectivity_stats` reduces
that column to a connected share plus the individual outage windows.

Both halves matter: "94% connected" is the same number whether the missing 6%
was one four-minute blackout or a hundred half-second flickers, so
`ConnectivityStats` carries `outages`, `longest_outage_s` and `outage_count`
alongside `connected_fraction`.

```python
from wayfinder_sim.connectivity import connectivity_stats

sim.record("reachable", lambda s: s.reachable("drone", ground_stations))
rec = sim.run(until_s=300)

stats = connectivity_stats(rec, "reachable")
print(f"{stats.connected_fraction:.1%}, worst gap {stats.longest_outage_s:.0f}s")
```

### Interactive output

Static PNGs are the default, but terrain is the case where a fixed camera
hides the answer — which ridge blocks a link depends entirely on the angle
you look from. Three ways to get a rotatable view, in increasing order of
what they cost:

1. **A native window, no extra dependency.** matplotlib's GUI backends are
   already interactive: drag a 3D axes to orbit it. `sim/scenarios/mountain_relay.py
   --show` does exactly this, and any scenario can by calling `plt.show()`.
2. **A browser, no extra dependency.** `MPLBACKEND=webagg` serves the same
   figure to `localhost` — useful when there's no GUI session to open a
   window in.
3. **A self-contained HTML file** (the `interactive` extra, plotly).
   `wayfinder_sim.interactive.terrain_scene` builds a rotatable, hoverable
   scene of the terrain with node tracks and sites on it, and `write_html`
   bundles the runtime into the page so it opens offline by double-click and
   can be sent to someone with no Python at all.

```python
from wayfinder_sim.interactive import terrain_scene, write_html

scene = terrain_scene(terrain, bounds, tracks={"Drone": positions}, sites=relays)
write_html(scene, Path("scene.html"))
```

Heights are drawn with a vertical exaggeration (`VERTICAL_EXAGGERATION`) —
real terrain is far wider than it is tall, and a true-to-scale box renders as
a flat plate. Read heights off the axis, not off the picture.

### Sweep reports

`wayfinder_sim.report` collects a whole sweep into one self-contained page:
a ranked outcome list first, then every run with the parameters that produced
it and the charts it produced. It exists because a sweep's actual question —
which setting won, and what did the losers look like? — is the one thing a
directory of PNGs and a wall of console output makes hardest to answer.

```python
from wayfinder_sim.report import ImagePanel, RunReport, ScenePanel, write_sweep_report

runs = [
    RunReport(
        label=result.param,
        params={"relays": 3},
        metrics={"outages": stats.outage_count},
        headline=stats.connected_fraction,      # what the ranking sorts on
        panels=[ImagePanel(png_path, caption="Coverage"), ScenePanel(scene)],
    )
    for result in sweep_results
]
write_sweep_report(Path("report.html"), "Placement sweep", runs)
```

Images are embedded as data URIs and plotly scenes stay live and rotatable
inside the page, with one shared copy of the runtime. `ImagePanel` needs
nothing beyond the standard library; `ScenePanel` needs the `interactive`
extra. Leave `headline` unset for a sweep with no single winner and the page
drops the ranking rather than inventing one.

### Terrain scenario

`sim/scenarios/mountain_relay.py` puts all of the above together: a drone
transits an 8 x 6 km range at 80 m above ground while three relays — each
with its own satellite backhaul, so reaching *any* of them counts as
connected — sit on summits, on the valley floor, or a mix. The same flight is
re-run against each siting, and the sweep reports how much of the transit had
a route.

```bash
uv run --group sim python sim/scenarios/mountain_relay.py
uv run --group sim python sim/scenarios/mountain_relay.py --show   # rotatable window
```

It writes per-placement coverage maps and timelines, a comparison chart, a
terrain cross-section explaining the worst outage, a rotatable scene per
placement, and `mountain_relay_report.html` tying the whole sweep together.

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

The topology is **generated** by [`scripts/topology.py`](../scripts/topology.py) — the
sim image derives each node's config from the NICs docker attaches, so the
compose wiring *is* the topology. Edit `build_links()` (or the helpers
`diamond`, `complete_graph`, `path`, `shared_lan`) and re-run; nothing else
changes.

```bash
python scripts/topology.py graph             # ASCII adjacency summary
python scripts/topology.py print             # the generated compose YAML
python scripts/topology.py up                # write ephemeral file + compose up --build -d
python scripts/topology.py logs d1 m5        # follow specific nodes
python scripts/topology.py down              # tear it down (removes networks)
python scripts/topology.py write             # refresh the committed docker-compose.yml
```

`up`/`down`/`logs` operate on an ephemeral, gitignored file
(`.sim-compose.gen.yml`) under the fixed project name `wayfinder-sim`.

> **`write` with no path targets `docker-compose.yml`, which is no longer a
> topology snapshot.** That file is now the *deployment* compose (release images
> from `containers/Dockerfile`), so `topology.py write` with no argument
> overwrites it with a simulation topology. Pass an explicit path.

## Dashboards

Every node gets its own `wayfinder-web` container beside it, published on
loopback: `8080` for the first node in the topology, `8081` for the second, and
so on. `up` prints the table, and `graph` repeats it per node.

```bash
cargo build --workspace     # the nodes
cargo leptos build          # the dashboard — see below, a plain build is not enough
python scripts/topology.py up
# → dashboards:
#     d1     http://127.0.0.1:8080
#     d2     http://127.0.0.1:8081
#     …
```

`wayfinder-web` is the one binary a plain `cargo build` does **not** produce
usably: the crate's default feature set is deliberately empty, so it compiles to
a stub, and the wasm half that makes the page interactive is not built at all.
`cargo leptos build` produces both. Skip it and the container says so at startup
rather than serving a dashboard that silently never updates.

The dashboards authenticate with a shared **operator** identity minted alongside
the node certificates — an enrolled node refuses any management connection that
cannot present a certificate carrying the admin capability, so a node's own
member cert is deliberately not enough.

## Identity, and what this sim does not exercise

`scripts/topology.py` mints the mesh root, one plain **member** certificate per
node, and one **admin** operator certificate on the host *before* the stack
starts. Each node mounts only its own at `/secrets` and is a mesh member from
its first instant — which also makes its MAC (derived from that seed)
reproducible across runs.

Nothing enrols at runtime. An earlier version had each node generate a key at
startup and enroll against the provider over the management API; once that API
required an authenticated TLS handshake, that stopped being possible — a node
with no certificate cannot open the connection it would use to request one. So
**online enrollment and the CSR-approval flow are not exercised here**, even
though the provider still serves those RPCs for a CSR submitted by hand
(`--require-approval` still gates those).

## Stress-testing the flood path

`blast` floods broadcast traffic from one node into a **running** stack, to see
how the mesh and the application hold up under a storm of flooded frames. It
`docker compose exec`s `ping` at the subnet broadcast address, so every frame
goes to the all-ones MAC and the router floods it out *every* mesh interface
(the `BatmanPacketType::Bcast` path). Egress is pinned to the host TAP with `ping -I
wayfinder0`, so the traffic enters the mesh through the node — it never leaks
straight onto the `eth*` segment NICs.

```bash
python scripts/topology.py up                                  # stack must be up first
python scripts/topology.py blast m1 --rate 200 --size 1000 --duration 30
python scripts/topology.py blast d1 --rate 0 --size 1400       # --rate 0 = flood as fast as possible
python scripts/topology.py blast                               # first node, 100 fps × 1000 B for 10 s
```

* `--rate` is frames/second (`0` uses `ping -f` to flood as fast as the kernel
  accepts); `--size` is the **total IP packet size** in bytes; `--duration` is
  how long to run (`0` runs until you Ctrl-C).
* The origin `NODE` defaults to the first node in the topology; pass any node
  name to blast from there instead.
* Watch the fallout in another terminal: `python scripts/topology.py logs` for OGM/
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
python scripts/topology.py logs d4            # the bridge node: watch OGM/route activity
```

In the TUI, the **Routing Table** tab is the interesting one: direct (1-hop)
originators versus those reached via a next-hop neighbor. Use the number keys or
`←/→` to switch tabs, `↑/↓` to select an originator and see its per-neighbor path
breakdown, and `q` to quit. The TUI defaults to `127.0.0.1:7700`, which each
node's server listens on, so `docker exec -it wf-<node> wayfinder-tui` just
works with no arguments.
