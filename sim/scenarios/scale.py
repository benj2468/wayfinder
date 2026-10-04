"""Scale: what happens as the mesh grows from a couple of dozen radios to a
few hundred?

Square grids of N radios, 450 m apart on one shared 2.4 GHz channel, HQ in a
corner — the field grid of `failover.py`, made bigger. Every node streams to
HQ and HQ streams back to every node, so reachability is measured in both
directions by delivered traffic, not by reading routing tables.

Three things grow with N, and the scenario measures each:

- **Convergence.** How long after power-on until every node has a route to
  HQ — the time a freshly deployed network takes to be usable.
- **Control traffic.** Every node relays every other node's advert once per
  round, so each node's share of the flood grows linearly with N, and the
  channel's total with N². That cost is paid whether or not any data moves.
- **The originator table.** A router remembers a bounded number of other
  nodes. The default capacity profile — what the simulator, the tests and a
  small gateway build — holds 128 (`wayfinder::default`); the `host` profile a
  server-class node builds holds 4,096.

**The edge is a cliff, not a slope.** Below 128 nodes everything scales as
expected. Past it, a default-profile router must evict an originator to admit
one, the evicted one is heard again within a round, and re-learning it counts
as a topology change — which resets Trickle. With every router evicting and
re-learning continuously, every Trickle timer is pinned at `i_min`, the advert
rate jumps to `N²/(0.75·i_min)`, and the channel collapses in both
directions. (Beyond ~150 nodes the storm is large enough that the simulation
itself runs out of memory, which is why the sweep stops there.) So the
default profile is a hard ceiling to size under, not a soft one to drift
past; a larger mesh needs the host profile on every node — and arguably the
router should not treat re-learning an evicted originator as an
inconsistency at all.

Run: `uv run --group sim python sim/scenarios/scale.py [--export DIR]`
"""

from __future__ import annotations

import argparse
import math
import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim.channel import FreeSpacePathLoss
from wayfinder_sim.mobility import Static, Vec3
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.showcase import Chart, Headline, Series, Showcase, write_showcase
from wayfinder_sim.topology import shared_lan

HQ = "hq"
SPACING_M = 450.0
TRICKLE = (1000, 10_000)
"""A calmer schedule than the 200/2000 ms default: at a few hundred nodes the
N² advert flood at the default rate is more than a 2.4 GHz channel is worth
simulating, and more than a deployment of that size would run."""
SIZES = (25, 49, 81, 100, 121, 128, 132, 144)
WARMUP_S = 60.0
MEASURE_S = 60.0
STREAM_HZ = 0.5
TABLE_CAPACITY = 128
HOST_TABLE_CAPACITY = 4096
SEED = 0


def build_simulation(n: int, seed: int = SEED) -> tuple[Simulation, list[str]]:
    side = math.ceil(math.sqrt(n))
    names = [HQ] + [f"n{i}" for i in range(1, n)]
    nodes = [
        Node(
            name,
            mobility=Static(Vec3((i % side) * SPACING_M, (i // side) * SPACING_M, 2.0)),
            trickle=TRICKLE,
        )
        for i, name in enumerate(names)
    ]
    radio = FreeSpacePathLoss(
        tx_power_dbm=24.0, max_range_m=700.0, delivery_steepness=1.0
    )
    return Simulation(nodes, shared_lan(names, radio), seed=seed), names


@dataclass(frozen=True)
class ScaleRun:
    nodes: int
    converged_s: float | None
    """Seconds from power-on until every node held a route to HQ."""
    to_hq: float
    """Share of node → HQ packets delivered in the window."""
    from_hq: float
    """Share of HQ → node packets delivered in the window."""
    hq_reaches: float
    """Share of nodes HQ held a route to at the end."""
    frames_per_node_s: float
    channel_frames_s: float
    hq_table: int
    median_table: int
    mean_hops: float
    max_hops: int


def run_size(n: int, seed: int = SEED) -> ScaleRun:
    sim, names = build_simulation(n, seed)
    others = names[1:]
    to_hq = [
        sim.stream(m, HQ, rate_hz=STREAM_HZ, start_s=WARMUP_S, duration_s=MEASURE_S)
        for m in others
    ]
    from_hq = [
        sim.stream(HQ, m, rate_hz=STREAM_HZ, start_s=WARMUP_S, duration_s=MEASURE_S)
        for m in others
    ]
    sim.record("all_to_hq", lambda s: all(s.has_route(m, HQ) for m in others))
    rec = sim.run(until_s=WARMUP_S, sample_interval_ms=500)
    converged = next(
        (t for t, ok in zip(rec.times_s, rec.column("all_to_hq")) if ok), None
    )
    frames_before = sum(sim.tx_frames(m) for m in names)
    sim.run(until_s=WARMUP_S + MEASURE_S + 2.0, sample_interval_ms=5000)
    frames = sum(sim.tx_frames(m) for m in names) - frames_before

    def ratio(flows) -> float:
        sent = sum(len(f.sent) for f in flows)
        return sum(len(f.received) for f in flows) / sent if sent else 0.0

    hops = [len(p) - 1 for m in others if (p := sim.route_path(m, HQ)) is not None]
    tables = sorted(sim.driver(m).originator_occupancy()[0] for m in names)
    return ScaleRun(
        nodes=n,
        converged_s=converged,
        to_hq=ratio(to_hq),
        from_hq=ratio(from_hq),
        hq_reaches=sum(sim.has_route(HQ, m) for m in others) / len(others),
        frames_per_node_s=frames / (n * MEASURE_S),
        channel_frames_s=frames / MEASURE_S,
        hq_table=sim.driver(HQ).originator_occupancy()[0],
        median_table=tables[len(tables) // 2],
        mean_hops=statistics.mean(hops) if hops else 0.0,
        max_hops=max(hops) if hops else 0,
    )


def print_summary(runs: Sequence[ScaleRun]) -> None:
    print(
        f"Scale — square grids, {SPACING_M:.0f} m spacing, adverts {TRICKLE[0]}–{TRICKLE[1]} ms"
    )
    print(
        "  nodes  converged  →HQ     HQ→     HQ routes to  frames/s/node  HQ table  hops (mean/max)"
    )
    for r in runs:
        conv = "never" if r.converged_s is None else f"{r.converged_s:.1f} s"
        print(
            f"  {r.nodes:>5}  {conv:>9}  {r.to_hq:>6.1%}  {r.from_hq:>6.1%}  {r.hq_reaches:>11.1%}"
            f"  {r.frames_per_node_s:>13.1f}  {r.hq_table:>4}/{TABLE_CAPACITY}  {r.mean_hops:.1f}/{r.max_hops}"
        )


def showcase(runs: Sequence[ScaleRun]) -> Showcase:
    ns = [r.nodes for r in runs]
    fits = [r for r in runs if r.nodes - 1 <= TABLE_CAPACITY]
    over = [r for r in runs if r.nodes - 1 > TABLE_CAPACITY]
    edge = max(fits, key=lambda r: r.nodes)
    past = min(over, key=lambda r: r.nodes) if over else None
    worst = min(over, key=lambda r: r.to_hq) if over else None
    return Showcase(
        slug="scale",
        title="Growing the mesh",
        category="capacity",
        scenario="sim/scenarios/scale.py",
        question="Does it scale, and where is the edge?",
        headlines=[
            Headline(
                f"{edge.nodes}",
                "nodes on the default router profile, at full delivery",
                f"{edge.to_hq:.0%} to HQ, {edge.from_hq:.0%} back; ready {edge.converged_s or 0:.0f} s after power-on",
            ),
            Headline(
                f"{worst.to_hq:.0%}" if worst else "–",
                f"delivered past the edge ({worst.nodes} nodes)"
                if worst
                else "past the edge",
                "a full routing table triggers an advert storm",
            ),
            Headline(
                f"{past.frames_per_node_s / edge.frames_per_node_s:.0f}x"
                if past
                else "–",
                "jump in control traffic one step past the edge",
                f"{edge.frames_per_node_s:.0f} → {past.frames_per_node_s:.0f} frames/s per node"
                if past
                else "",
            ),
        ],
        summary=(
            f"Square grids from {ns[0]} to {ns[-1]} radios, every node streaming to HQ and HQ streaming "
            f"back. Up to {edge.nodes} nodes the mesh scales as it should: delivery stays at "
            f"{min(r.to_hq for r in fits):.0%} or better both ways, every node has a route to HQ within "
            f"{max(r.converged_s or 0 for r in fits):.0f} s of power-on, and each node's control traffic "
            f"grows in step with the mesh. The default router profile remembers {TABLE_CAPACITY} other "
            f"nodes, and past that the mesh doesn't degrade gracefully. Routers start evicting nodes and "
            f"hearing them again a moment later. Each re-learned node counts as a topology change and "
            f"resets every router to its fastest advertising rate, so control traffic "
            + (
                f"jumps {past.frames_per_node_s / edge.frames_per_node_s:.0f}x and delivery falls to "
                f"{worst.to_hq:.0%}. "
                if past and worst
                else ". "
            )
            + f"The default profile is therefore a hard ceiling. A larger mesh needs the host profile "
            f"({HOST_TABLE_CAPACITY:,} nodes) on every router, and the storm itself is worth fixing in the "
            f"router."
        ),
        method=(
            f"The real wayfinder router (default capacity profile) on square grids, {SPACING_M:.0f} m apart, "
            "one shared 2.4 GHz channel at 24 dBm with a 700 m range. Adverts run on a "
            f"{TRICKLE[0] / 1000:g}–{TRICKLE[1] / 1000:g} s schedule. After {WARMUP_S:.0f} s of warm-up, "
            f"every node streams to HQ and HQ to every node at {STREAM_HZ:g} packets/s for "
            f"{MEASURE_S:.0f} s. Reachability is delivered packets; convergence is the first instant every "
            "node held a route to HQ, sampled every 0.5 s."
        ),
        charts=[
            Chart(
                title="Traffic delivered, both directions",
                x_label="nodes in the mesh",
                y_label="delivery ratio",
                series=[
                    Series("node → HQ", ns, [r.to_hq for r in runs]),
                    Series("HQ → node", ns, [r.from_hq for r in runs]),
                ],
                y_range=(0.0, 1.0),
                caption=f"Both directions collapse once the mesh outgrows the default router's {TABLE_CAPACITY}-entry table.",
            ),
            Chart(
                title="Who the gateway remembers",
                x_label="nodes in the mesh",
                y_label="originators in HQ's table",
                series=[
                    Series("HQ's table", ns, [float(r.hq_table) for r in runs]),
                    Series("every other node", ns, [float(r.nodes - 1) for r in runs]),
                ],
            ),
            Chart(
                title="Control traffic per node",
                x_label="nodes in the mesh",
                y_label="frames / s / node",
                series=[
                    Series(
                        "adverts relayed and sent",
                        ns,
                        [r.frames_per_node_s for r in runs],
                    )
                ],
                caption="Linear per node below the edge; past it, eviction churn pins every router at its fastest advert rate.",
            ),
            Chart(
                title="Time to a usable mesh",
                x_label="nodes in the mesh",
                y_label="seconds from power-on",
                series=[
                    Series(
                        "every node has a route to HQ",
                        ns,
                        [r.converged_s for r in runs],
                    )
                ],
            ),
        ],
        table=[
            [
                "nodes",
                "converged (s)",
                "→HQ",
                "HQ→",
                "HQ table",
                "frames/s/node",
                "max hops",
            ]
        ]
        + [
            [
                r.nodes,
                r.converged_s,
                round(r.to_hq, 3),
                round(r.from_hq, 3),
                r.hq_table,
                round(r.frames_per_node_s, 1),
                r.max_hops,
            ]
            for r in runs
        ],
        params={
            "sizes": list(SIZES),
            "spacing_m": SPACING_M,
            "trickle_ms": list(TRICKLE),
            "table_capacity": TABLE_CAPACITY,
            "stream_hz": STREAM_HZ,
        },
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument(
        "--export", type=Path, help="write showcase JSON into this directory"
    )
    parser.add_argument("--quick", action="store_true", help="up to 100 nodes")
    args = parser.parse_args(argv)
    wf.init_tracing()

    sizes = [n for n in SIZES if n <= 100] if args.quick else list(SIZES)
    runs = []
    for n in sizes:
        runs.append(run_size(n))
        print_summary(runs[-1:])
    print_summary(runs)
    if args.export:
        print(f"wrote {write_showcase(showcase(runs), args.export)}")


if __name__ == "__main__":
    main()
