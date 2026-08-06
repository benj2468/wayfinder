"""Drone relay scenario: two ground control stations linked by fiber, and a
drone flying between them reachable from each by radio.

Topology::

    GCSA ===fiber=== GCSB
      \\              /
       \\radio   radio/
        \\          /
          \\      /
            Drone

Radio link quality is derived from real 3D distance via a free-space
path-loss model (`wayfinder_sim.channel.FreeSpacePathLoss`), fed into wayfinder as
each frame's `quality` metric. wayfinder's BATMAN engine clamps a received
OGM's transmission quality (TQ) by that per-hop value
(`ogm.tq.saturating_sub(10).min(local_quality)` — see
`libs/batman/src/engine.rs`), so degrading radio quality directly drives
next-hop selection: this script demonstrates GCSA's best route to the drone
switching from "direct radio" to "via GCSB" (fiber + GCSB's own radio) as the
drone flies past the midpoint, and back again on the return leg.

This is a `wayfinder_sim` scenario: it only describes topology, channel tuning,
the flight path, and what to record — the tick/delivery loop that drives the
real `wayfinder_py` router lives in `wayfinder_sim.scenario.Simulation`.

Run: `uv run --group sim python sim/scenarios/drone_relay.py`
"""

from __future__ import annotations

from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim.channel import FreeSpacePathLoss, PerfectWire
from wayfinder_sim.mobility import Static, Vec3, Waypoints
from wayfinder_sim.node import Node
from wayfinder_sim.recorder import Recorder
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.topology import pair

# matplotlib (and `wayfinder_sim.plotting` with it) is imported inside `plot` rather
# than here, so importing this module costs nothing but the topology. That is
# what lets a headless consumer — `wayfinder-ml generate`, which wants only
# `build_simulation` — load the scenario without a plotting stack installed.

GCS_SEPARATION_M = 1000.0
ALTITUDE_M = 50.0
SPEED_M_S = 10.0
TRICKLE_MS = (200, 2000)  # (i_min_ms, i_max_ms) — fast enough to track the flight

DURATION_S = 2 * (GCS_SEPARATION_M / SPEED_M_S)
"""One full out-and-back leg: the scenario's natural length, and what
`wayfinder-ml generate` runs an episode for when not told otherwise."""

# The two route names `route_via("gcsa", "drone")` can resolve to, and how
# the switch summary/chart legend should describe each.
ROUTE_DIRECT = "gcsa-drone"
ROUTE_VIA_GCSB = "gcsa-gcsb"
ROUTE_LABELS = {
    ROUTE_DIRECT: "Direct radio (GCSA→Drone)",
    ROUTE_VIA_GCSB: "Via GCSB (fiber + radio)",
}


def build_simulation(seed: int = 0) -> Simulation:
    """Wire the three-node topology and register the signals worth
    recording as the drone flies its out-and-back leg."""
    flight = Waypoints(
        (Vec3(0, 0, ALTITUDE_M), Vec3(GCS_SEPARATION_M, 0, ALTITUDE_M)),
        speed_m_s=SPEED_M_S,
        loop="pingpong",
    )
    nodes = [
        Node("gcsa", mobility=Static(Vec3(0, 0, 0)), trickle=TRICKLE_MS),
        Node("gcsb", mobility=Static(Vec3(GCS_SEPARATION_M, 0, 0)), trickle=TRICKLE_MS),
        Node("drone", mobility=flight, trickle=TRICKLE_MS),
    ]
    radio = FreeSpacePathLoss()
    links = [
        pair("gcsa", "gcsb", PerfectWire()),  # fiber: perfect, always-connected
        pair("gcsa", "drone", radio),
        pair("gcsb", "drone", radio),
    ]

    sim = Simulation(nodes, links, seed=seed)
    sim.record("distance_a", lambda s: s.distance("drone", "gcsa"))
    sim.record("distance_b", lambda s: s.distance("drone", "gcsb"))
    sim.record("rssi_a", lambda s: s.sample_channel("drone", "gcsa").metrics.rssi_dbm)
    sim.record("rssi_b", lambda s: s.sample_channel("drone", "gcsb").metrics.rssi_dbm)
    sim.record("route", lambda s: s.route_via("gcsa", "drone"))
    return sim


def print_switch_summary(rec: Recorder) -> None:
    print("GCSA -> Drone next-hop changes:")
    dist_a = rec.column("distance_a")
    dist_b = rec.column("distance_b")
    for t_s, route in rec.transitions("route"):
        idx = rec.times_s.index(t_s)
        print(
            f"  t={t_s:7.1f}s  drone at {dist_a[idx]:6.0f}m from A, "
            f"{dist_b[idx]:6.0f}m from B  ->  {ROUTE_LABELS.get(route, route)}"
        )


def plot(rec: Recorder, out_path: Path) -> None:
    import matplotlib.pyplot as plt

    from wayfinder_sim.plotting import PALETTE, state_band, style_axes

    t = rec.times_s

    fig, (ax_dist, ax_rssi, ax_route) = plt.subplots(
        3,
        1,
        figsize=(10, 8),
        sharex=True,
        height_ratios=[1, 1, 0.4],
        facecolor=PALETTE.surface,
    )
    style_axes((ax_dist, ax_rssi, ax_route))

    ax_dist.plot(
        t,
        rec.column("distance_a"),
        color=PALETTE.series[0],
        linewidth=2,
        label="Distance to GCSA",
    )
    ax_dist.plot(
        t,
        rec.column("distance_b"),
        color=PALETTE.series[1],
        linewidth=2,
        label="Distance to GCSB",
    )
    ax_dist.set_ylabel("Distance (m)", color=PALETTE.ink_secondary, fontsize=10)
    ax_dist.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper right"
    )

    ax_rssi.plot(
        t,
        rec.column("rssi_a"),
        color=PALETTE.series[0],
        linewidth=2,
        label="RSSI to GCSA",
    )
    ax_rssi.plot(
        t,
        rec.column("rssi_b"),
        color=PALETTE.series[1],
        linewidth=2,
        label="RSSI to GCSB",
    )
    ax_rssi.set_ylabel("RSSI (dBm)", color=PALETTE.ink_secondary, fontsize=10)
    ax_rssi.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper right"
    )

    # Next-hop state timeline: a categorical identity encoding (which path is
    # current), not a magnitude — filled bands rather than a numeric y-axis.
    state_band(ax_route, t, rec.column("route"), labels=ROUTE_LABELS)
    ax_route.set_xlabel("Time (s)", color=PALETTE.ink_secondary, fontsize=10)
    ax_route.set_ylabel(
        "GCSA→Drone\nnext hop", color=PALETTE.ink_secondary, fontsize=10
    )
    ax_route.legend(
        frameon=False,
        labelcolor=PALETTE.ink_secondary,
        fontsize=9,
        loc="upper right",
        ncol=2,
    )

    fig.suptitle(
        "Drone relay: GCSA→Drone next hop tracks whichever ground station has the stronger radio link",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    print(f"Chart written to {out_path}")


def main() -> None:
    wf.init_tracing()  # quiet by default; set RUST_LOG to see mesh internals

    sim = build_simulation()
    rec = sim.run(until_s=DURATION_S, sample_interval_ms=50)

    print_switch_summary(rec)
    plot(rec, Path(__file__).parent / "output" / "drone_relay.png")


if __name__ == "__main__":
    main()
