"""Satellite relay scenario: a low-altitude drone with a short-range ground
radio, kept in contact — intermittently — by a satellite on a real orbital
pass rather than a fixed overhead escort.

Topology::

    GCSA
      |  \\
      |   \\ sat-radio
    ground  \\
     radio   Sat (orbiting)
      |      /
      |  sat-radio
      | /
     Low

`ground_radio` (`wayfinder_sim.channel.FreeSpacePathLoss` with a hard
`max_range_m` cutoff) models the low drone's small telemetry radio: past a
fixed range there's no signal at all, not just a weak one — so as the low
drone flies away from GCSA, it goes out of contact once it's far enough
away. `sat_radio` (a bigger link budget than the ground radio, tuned via
`sat_tx_power_dbm` below — "like Starlink") links the satellite to both
GCSA and the low drone; unlike the earlier version of this scenario, the
satellite now flies `wayfinder_sim.mobility.Orbit` — a real circular pass around a
point off to the side of the flight line — so its distance to both GCSA and
the low drone varies over the orbit period instead of staying fixed. That
makes the relay itself intermittent: GCSA's route to the low drone can go
direct (close by), via satellite (far away, satellite currently in a good
position), or resolve to no route at all (far away, satellite currently on
the far side of its orbit) — a state this scenario never produced with a
satellite that stayed in constant lockstep overhead.

`run_power_sweep` re-runs the scenario across a range of satellite transmit
powers, each producing its own pair of charts plus one summary chart of how
the first handoff distance shifts with power.

Run: `uv run --group sim python sim/scenarios/satellite_relay.py`
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Sequence

import wayfinder_py as wf
from wayfinder_sim.channel import FreeSpacePathLoss
from wayfinder_sim.mobility import Orbit, Static, Vec3, Waypoints
from wayfinder_sim.node import Node
from wayfinder_sim.recorder import Recorder
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.sweep import SweepResult, run_sweep
from wayfinder_sim.topology import pair

# matplotlib (and `wayfinder_sim.plotting` with it) is imported inside each plotting
# function rather than here, so importing this module costs nothing but the
# topology. That is what lets a headless consumer — `wayfinder-ml generate`,
# which wants only `build_simulation` — load the scenario without a plotting
# stack installed.

GCSA_POSITION = Vec3(0, 0, 0)
FLIGHT_RANGE_M = 2000.0  # how far out the low drone flies before turning back
LOW_ALTITUDE_M = 30.0  # the low drone's cruise altitude
SPEED_M_S = 20.0  # the low drone's flight speed

# The satellite's orbit: centered off to the side of the flight line (not on
# GCSA or on the flight line itself — centering an orbit exactly on a point
# of interest makes that point's distance to the orbiter *constant*, which
# defeats the purpose), with a radius large enough relative to altitude that
# horizontal excursion — not just altitude — meaningfully drives distance.
ORBIT_CENTER = Vec3(1000.0, 3000.0, 0.0)
ORBIT_RADIUS_M = 4000.0
ORBIT_ALTITUDE_M = 2500.0
ORBIT_PERIOD_S = 120.0

GROUND_RADIO_MAX_RANGE_M = 700.0  # the low drone's telemetry radio's hard range limit
TRICKLE_MS = (200, 2000)  # (i_min_ms, i_max_ms) — fast enough to track the flight
# The ground link's keep-alive cadence: OGM-interval staleness alone gives
# this link a MAX_MISSED_OGMS(6) x up-to-i_max(2000ms) = ~12s grace period
# after it physically dies (the low drone flying past GROUND_RADIO_MAX_RANGE_M)
# before the route is even eligible to fail over — at SPEED_M_S=20, that's
# ~200m+ of flight with a dead direct link still "active". A keep-alive at
# the Trickle floor (matching i_min) with MAX_MISSED_KEEPALIVES(3) shrinks
# that grace to ~3 x 200ms = 600ms (~12m of flight) instead.
GROUND_RADIO_KEEPALIVE_MS = TRICKLE_MS[0]
DEFAULT_SAT_TX_POWER_DBM = 30.0  # shows the richest story: 3 distinct dropout windows
SAT_TX_POWER_SWEEP_DBM = (10.0, 15.0, 20.0, 25.0, 30.0, 35.0, 40.0, 45.0, 50.0, 55.0)

# The two route names `route_via("gcsa", "low")` can resolve to, and how the
# switch summary/chart legend should describe each.
ROUTE_DIRECT = "gcsa-low"
ROUTE_VIA_SAT = "gcsa-sat"
ROUTE_LABELS = {
    ROUTE_DIRECT: "Direct ground radio (GCSA→Low)",
    ROUTE_VIA_SAT: "Via satellite (GCSA→Sat→Low)",
}


def flight_duration_s() -> float:
    return 2 * (FLIGHT_RANGE_M / SPEED_M_S)  # out to max range, then back


DURATION_S = flight_duration_s()
"""One full out-and-back leg: the scenario's natural length, and what
`wayfinder-ml generate` runs an episode for when not told otherwise."""


def build_simulation(
    seed: int = 0, sat_tx_power_dbm: float = DEFAULT_SAT_TX_POWER_DBM
) -> Simulation:
    """Wire the three-node topology and register the signals worth recording
    as the low drone flies its out-and-back leg and the satellite orbits
    independently."""
    track = (GCSA_POSITION, dataclasses.replace(GCSA_POSITION, x=FLIGHT_RANGE_M))
    low_flight = Waypoints(
        tuple(dataclasses.replace(p, z=LOW_ALTITUDE_M) for p in track),
        speed_m_s=SPEED_M_S,
        loop="pingpong",
    )
    sat_flight = Orbit(
        center=ORBIT_CENTER,
        radius_m=ORBIT_RADIUS_M,
        altitude_m=ORBIT_ALTITUDE_M,
        period_s=ORBIT_PERIOD_S,
    )
    nodes = [
        Node("gcsa", mobility=Static(GCSA_POSITION), trickle=TRICKLE_MS),
        Node("low", mobility=low_flight, trickle=TRICKLE_MS),
        Node("sat", mobility=sat_flight, trickle=TRICKLE_MS),
    ]

    # The low drone's small telemetry radio: a hard maximum range — past it,
    # no signal at all — plus, below that, a normal RSSI-driven quality
    # gradient. `tx_power_dbm` is nudged up from the default (which put the
    # quality/TQ crossover at ~100m, absurdly early relative to the 700m
    # cutoff) but deliberately not so high that quality saturates across the
    # *whole* range (which would make the hard cutoff the only thing that
    # ever matters, flattening `run_power_sweep`'s result into a single
    # point) — the gradient across most of the range is what lets a
    # stronger satellite link win sooner, which is the whole point of the
    # sweep below.
    ground_radio = FreeSpacePathLoss(
        max_range_m=GROUND_RADIO_MAX_RANGE_M, tx_power_dbm=24.0
    )
    # The satellite's radio: no hard range cap ("like Starlink" — link budget
    # is the limit, not a fixed cutoff), but distance now varies a lot more
    # than in the fixed-overhead version of this scenario (the orbit swings
    # from ~2600m to ~7600m from either ground point), so `tx_power_dbm`
    # matters even more here — see `run_power_sweep`.
    sat_radio = FreeSpacePathLoss(tx_power_dbm=sat_tx_power_dbm)

    links = [
        # Keep-alive armed on the ground link specifically: it's the one
        # with a hard range cutoff (a real "the link just died," not just a
        # degraded one), so it's the one that benefits from faster-than-OGM
        # liveness detection.
        pair(
            "gcsa",
            "low",
            ground_radio,
            tx_keepalive_interval_ms=GROUND_RADIO_KEEPALIVE_MS,
        ),
        pair("gcsa", "sat", sat_radio),
        pair("low", "sat", sat_radio),  # the low drone's satellite uplink
    ]

    sim = Simulation(nodes, links, seed=seed)
    sim.record("distance_gcsa", lambda s: s.distance("low", "gcsa"))
    sim.record("distance_sat", lambda s: s.distance("low", "sat"))
    sim.record("low_pos", lambda s: s.position("low"))
    sim.record("sat_pos", lambda s: s.position("sat"))
    sim.record("route", lambda s: s.route_via("gcsa", "low"))
    return sim


def print_switch_summary(rec: Recorder) -> None:
    print("GCSA -> Low-drone next-hop changes:")
    dist_a = rec.column("distance_gcsa")

    events: list[tuple[float, str]] = []
    for t_s, route in rec.transitions("route"):
        idx = rec.times_s.index(t_s)
        events.append(
            (
                t_s,
                f"t={t_s:7.1f}s  low drone at {dist_a[idx]:6.0f}m from A  ->  {ROUTE_LABELS.get(route, route)}",
            )
        )
    for start_s, end_s in dropout_windows_s(rec):
        # A dropout can resume to the *same* route it had before (e.g. a
        # brief gap while still via satellite either side), which
        # `Recorder.transitions` has no record of at all — so this can't be
        # folded into the loop above; it's a genuinely separate signal.
        events.append(
            (
                start_s,
                f"t={start_s:7.1f}s..{end_s:7.1f}s  NO ROUTE (satellite out of position)",
            )
        )

    for _, message in sorted(events, key=lambda e: e[0]):
        print(f"  {message}")


def dropout_windows_s(rec: Recorder) -> list[tuple[float, float]]:
    """`(start_s, end_s)` for each contiguous stretch where GCSA has no
    route to the low drone at all — the low drone out of ground-radio range
    *and* the satellite currently on the far side of its orbit. Distinct from
    `Recorder.transitions`, which skips `None` samples entirely (by design,
    for switch-summary purposes) and so would never surface this."""
    routes = rec.column("route")
    times = rec.times_s
    windows: list[tuple[float, float]] = []
    start: float | None = None
    for t_s, route in zip(times, routes):
        if route is None:
            if start is None:
                start = t_s
        elif start is not None:
            windows.append((start, t_s))
            start = None
    if start is not None:
        windows.append((start, times[-1]))
    return windows


def handoff_distance_m(rec: Recorder) -> float | None:
    """Distance from GCSA at the moment the route first hands off away from
    direct ground radio — i.e. the *second* entry in `route`'s transitions,
    the first being the initial direct-radio resolution near t=0 — or `None`
    if it never handed off at all within the recorded run."""
    transitions = rec.transitions("route")
    if len(transitions) < 2:
        return None
    handoff_t_s, _ = transitions[1]
    idx = rec.times_s.index(handoff_t_s)
    return rec.column("distance_gcsa")[idx]


def run_power_sweep(
    tx_powers_dbm: Sequence[float] = SAT_TX_POWER_SWEEP_DBM,
) -> list[SweepResult[float]]:
    """Re-run the scenario once per satellite `tx_power_dbm`, everything
    else held fixed."""
    return run_sweep(
        lambda power: build_simulation(sat_tx_power_dbm=power),
        tx_powers_dbm,
        until_s=flight_duration_s(),
        sample_interval_ms=50,
    )


def print_sweep_summary(results: Sequence[SweepResult[float]]) -> None:
    print("Satellite tx power -> handoff distance from GCSA:")
    for r in results:
        distance = handoff_distance_m(r.recorder)
        distance_str = f"{distance:6.0f}m" if distance is not None else "  never"
        print(f"  {r.param:5.1f} dBm  ->  {distance_str}")


def plot(rec: Recorder, out_path: Path) -> None:
    import matplotlib.pyplot as plt

    from wayfinder_sim.plotting import PALETTE, state_band, style_axes

    t = rec.times_s

    fig, (ax_dist, ax_route) = plt.subplots(
        2,
        1,
        figsize=(10, 6.5),
        sharex=True,
        height_ratios=[1, 0.4],
        facecolor=PALETTE.surface,
    )
    style_axes((ax_dist, ax_route))

    ax_dist.plot(
        t,
        rec.column("distance_gcsa"),
        color=PALETTE.series[0],
        linewidth=2,
        label="Distance to GCSA",
    )
    ax_dist.plot(
        t,
        rec.column("distance_sat"),
        color=PALETTE.series[2],
        linewidth=2,
        label="Distance to satellite",
    )
    ax_dist.axhline(
        GROUND_RADIO_MAX_RANGE_M,
        color=PALETTE.ink_muted,
        linewidth=1,
        linestyle="--",
        label="Ground radio max range",
    )
    ax_dist.set_ylabel("Distance (m)", color=PALETTE.ink_secondary, fontsize=10)
    ax_dist.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper right"
    )

    # Next-hop state timeline: a categorical identity encoding (which path is
    # current), not a magnitude — filled bands rather than a numeric y-axis.
    state_band(ax_route, t, rec.column("route"), labels=ROUTE_LABELS)
    ax_route.set_xlabel("Time (s)", color=PALETTE.ink_secondary, fontsize=10)
    ax_route.set_ylabel("GCSA→Low\nnext hop", color=PALETTE.ink_secondary, fontsize=10)
    ax_route.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper right"
    )

    fig.suptitle(
        "Satellite relay: the satellite is only a usable relay during its orbital "
        "pass — gaps in the band below are total dropouts, not just a slow handoff",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Chart written to {out_path}")


def plot_3d(rec: Recorder, out_path: Path) -> None:
    """A 3D render of every entity's position over the course of the flight:
    GCSA fixed on the ground, the low drone's straight out-and-back track,
    and the satellite's orbital loop off to the side."""
    import matplotlib.pyplot as plt

    from wayfinder_sim.plotting import PALETTE, point_3d, style_axes_3d, trajectory_3d

    fig = plt.figure(figsize=(9, 8), facecolor=PALETTE.surface)
    ax = fig.add_subplot(projection="3d")
    style_axes_3d(ax)

    point_3d(
        ax, GCSA_POSITION, color=PALETTE.series[0], label="GCSA", marker="^", size=120
    )
    trajectory_3d(ax, rec.column("low_pos"), color=PALETTE.series[1], label="Low drone")
    trajectory_3d(
        ax, rec.column("sat_pos"), color=PALETTE.series[2], label="Satellite drone"
    )

    ax.set_xlabel("x (m)")
    ax.set_ylabel("y (m)")
    ax.set_zlabel("altitude (m)")
    ax.legend(frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9)
    fig.suptitle(
        "Satellite relay: entity positions over the flight",
        color=PALETTE.ink_primary,
        fontsize=12,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"3D render written to {out_path}")


def plot_sweep(results: Sequence[SweepResult[float]], out_path: Path) -> None:
    """How the handoff distance shifts as satellite `tx_power_dbm` varies —
    the visual case for "higher power fails over sooner."""
    import matplotlib.pyplot as plt

    from wayfinder_sim.plotting import PALETTE, style_axes

    powers = [r.param for r in results]
    handoffs = [handoff_distance_m(r.recorder) for r in results]
    # NaN (not None) so matplotlib draws a real gap rather than erroring, for
    # any power that never handed off within the recorded run.
    handoffs_plot = [float("nan") if d is None else d for d in handoffs]

    fig, ax = plt.subplots(figsize=(8, 5.5), facecolor=PALETTE.surface)
    style_axes((ax,))

    ax.plot(powers, handoffs_plot, color=PALETTE.series[0], linewidth=2, marker="o")
    ax.axhline(
        GROUND_RADIO_MAX_RANGE_M,
        color=PALETTE.ink_muted,
        linewidth=1,
        linestyle="--",
        label="Ground radio max range",
    )
    ax.set_xlabel("Satellite tx power (dBm)", color=PALETTE.ink_secondary, fontsize=10)
    ax.set_ylabel(
        "Handoff distance from GCSA (m)", color=PALETTE.ink_secondary, fontsize=10
    )
    ax.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper right"
    )

    never_powers = [r.param for r in results if handoff_distance_m(r.recorder) is None]
    if never_powers:
        note = (
            f"No route at all at {', '.join(f'{p:g}' for p in never_powers)} dBm — "
            "satellite link never reliable enough to be learned as a route"
        )
        ax.text(
            0.02,
            0.02,
            note,
            transform=ax.transAxes,
            fontsize=8,
            color=PALETTE.ink_muted,
            va="bottom",
            ha="left",
        )
    fig.suptitle(
        "Higher satellite tx power wins the route sooner (shorter handoff distance)",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Sweep chart written to {out_path}")


def main() -> None:
    wf.init_tracing()  # quiet by default; set RUST_LOG to see mesh internals

    sweep_results = run_power_sweep()
    for i, r in enumerate(sweep_results):
        rec = r.recorder
        print_switch_summary(rec)
        plot(rec, Path(__file__).parent / "output" / f"satellite_relay_{i}.png")
        plot_3d(rec, Path(__file__).parent / "output" / f"satellite_relay_3d_{i}.png")

    print_sweep_summary(sweep_results)
    plot_sweep(
        sweep_results,
        Path(__file__).parent / "output" / "satellite_relay_power_sweep.png",
    )


if __name__ == "__main__":
    main()
