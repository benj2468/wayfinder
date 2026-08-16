r"""Satellite relay scenario: a long-haul aircraft and a ground gateway, joined
— when the sky cooperates — through a Starlink-like LEO constellation with
inter-satellite links, rather than through one satellite on a toy circle.

Topology::

        sat00 --- sat01 --- sat02          a closed ISL ring: every satellite
          |                     |          relays for its two neighbours
        sat05 --- sat04 --- sat03
          .                     .
          .  Ku-band user links, 25 deg elevation mask
          .                     .
        GCSA  ................  Aircraft   (9,000 km apart at the far end)
          \____________________/
           ground radio, 700 m hard cutoff

Four things make this different from a satellite parked overhead:

**The orbit is real.** `wayfinder_sim.mobility.EarthOrbit` puts the satellites on
circular orbits about the planet, rendered into the scene's ENU frame. The
period is not a free parameter — Kepler's third law fixes it at ~109 minutes
for this shell — and half an orbit later a satellite is on the far side of the
Earth, not still hovering at constant altitude.

**The horizon blocks.** `wayfinder_sim.channel.EarthOccluded` refuses any path that
passes through the planet, and masks a user link below `MIN_ELEVATION_DEG` —
the angle below which a real terminal stops tracking. That, not the link
budget, is what makes contact intermittent here: a satellite that has set.

**The link budget closes.** A Starlink user terminal is ~66.7 dBm EIRP into a
~35 dBi array; over ~1,200 km that lands comfortably inside the receiver's
usable window, so a visible satellite is a *good* link rather than a marginal
one. The intermittency is geometric, and no amount of extra transmit power
buys any of it back — which is why this scenario sweeps constellation shape
rather than power.

**The mesh has to carry traffic.** Consecutive satellites are ~7,900 km apart
over the ground and a footprint is ~1,700 km across, so the aircraft and the
gateway only end up under *different* satellites once they are thousands of
kilometres apart. That is what the 9,000 km leg is for: past that point the
route stops being ground-satellite-ground and starts crossing the ring.

`run_constellation_sweep` re-runs the flight across constellation geometries.
The result worth reading is that six satellites in one plane beat six split
across two or three: only an in-plane ring closes here, so splitting them
breaks the very links the long-haul route depends on.

Run: `uv run --group sim python sim/scenarios/satellite_relay.py`
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import wayfinder_py as wf
from wayfinder_sim.channel import EarthOccluded, FreeSpacePathLoss
from wayfinder_sim.connectivity import ConnectivityStats, connectivity_stats
from wayfinder_sim.mobility import EarthOrbit, GreatCircle, Static, Vec3
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

# --- the shell ---------------------------------------------------------------

ALTITUDE_M = 1_200_000.0
"""The shell. Sets the period (~109 min), the footprint, and — the binding
constraint here — whether a plane's satellites can see each other at all.

OneWeb's altitude, and the one Starlink originally filed for, rather than
Starlink's eventual 550 km. The choice is forced by geometry, not taste. Two
satellites in a plane can only work an inter-satellite link if the chord
between them clears the planet, which caps their angular separation at
`2*acos(R_earth/r)`: 46 degrees at 550 km, so a ring needs at least *eight*
satellites before it can close. `wf.MAX_INTERFACES` caps the ground station
at seven satellite links, so a 550 km ring could never close in this sim and
every ISL in it would be decoration. At 1200 km the limit relaxes to 65
degrees — six satellites per plane, which fits.
"""

MIN_ELEVATION_DEG = 25.0
"""How high a satellite must be before a user terminal will work it.

Starlink's own mask. Well above the geometric horizon: lower down the slant
range through the atmosphere is long, the array is at the edge of its scan,
and neighbouring satellites interfere. It is this number, far more than the
link budget, that decides how much of the time a ground site is served.
"""

ORBIT_PERIOD_S = EarthOrbit(altitude_m=ALTITUDE_M).period_s

# --- radios ------------------------------------------------------------------

KU_BAND_HZ = 12.0e9
"""Ku-band, where Starlink's user links live."""

UT_EIRP_DBM = 66.7
"""A Starlink user terminal's EIRP — ~36.7 dBW, i.e. a couple of watts into a
~34 dBi phased array."""

SAT_RX_GAIN_DBI = 35.0
"""Receive gain at the other end of a user link.

Carried separately from `UT_EIRP_DBM` because it is what actually closes the
link: over 550 km the path loss is ~169 dB, and no plausible transmit power
covers that without the antennas. Folding it into the EIRP would leave a
"transmit power" that means nothing physical.
"""

ISL_EIRP_DBM = 80.0
ISL_RX_GAIN_DBI = 45.0
ISL_MAX_RANGE_M = 8_000_000.0
"""The inter-satellite links, the thing that makes the constellation a mesh
rather than a set of independent bent pipes.

Starlink's are optical, and this sim has no optical model — so they are
modelled as a very high-gain RF link with a hard acquisition range. What
matters for routing is reproduced faithfully: within range and with the
planet out of the way they close reliably, and beyond it they do not close at
all.

The range is sized to the shell: neighbours in a six-satellite ring at
`ALTITUDE_M` are ~7,600 km apart, so anything under that would leave the ring
permanently broken.
"""

GROUND_RADIO_MAX_RANGE_M = 700.0
"""The drone's own telemetry radio: a hard cutoff, not a fading edge. It is
what makes the drone reliant on the constellation within the first minute of
the flight."""

TRICKLE_MS = (2000, 10000)
"""OGM cadence. Slow by terrestrial standards and deliberately so: this is a
space segment, and the events that matter here play out over minutes."""

GROUND_RADIO_KEEPALIVE_MS = 500

# --- the constellation -------------------------------------------------------

DEFAULT_PLANES = 1
DEFAULT_PER_PLANE = 6
"""One closed ring of six — the only six-satellite shell whose
inter-satellite links all close at this altitude, and correspondingly the one
that serves the long-haul route best. See `CONSTELLATION_SWEEP`."""

PLANE_HEADING_DEG = 20.0
PLANE_HEADING_SPREAD_DEG = 55.0
PLANE_OFFSET_M = 150_000.0
"""How the planes differ from one another: each is rotated
`PLANE_HEADING_SPREAD_DEG` further round in ground-track bearing and passes
`PLANE_OFFSET_M` further to the side of the ground station. Planes that
differed only in phase would be one plane.
"""

CONSTELLATION_SWEEP = ((1, 1), (1, 2), (1, 3), (2, 2), (1, 6), (2, 3), (3, 2))
"""`(planes, per_plane)` geometries to compare.

Deliberately includes three different shapes of six satellites — 1x6, 2x3 and
3x2 — because the interesting question is not only how many you launch but how
you arrange them. Visibility from a single ground site barely notices the
difference; the end-to-end route notices a great deal, because only a plane
with enough satellites in it has a ring whose links clear the planet.
"""

# A node has at most `wf.MAX_INTERFACES` links, and the ground station carries
# one per satellite plus the drone — so the sweep cannot ask for a shell it
# could not physically wire up.
MAX_SATELLITES = wf.MAX_INTERFACES - 1

# --- the flight --------------------------------------------------------------

GCSA_POSITION = Vec3(0, 0, 0)

FLIGHT_RANGE_M = 9_000_000.0
LOW_ALTITUDE_M = 10_000.0
SPEED_M_S = 250.0
FLIGHT_HEADING_DEG = PLANE_HEADING_DEG
"""A long-haul airliner on a satellite terminal, not a quadcopter — and the
distances are what make the mesh do any work.

Consecutive satellites in a six-satellite ring are ~7,900 km apart over the
ground while a footprint is only ~1,700 km across, so two terminals are only
under *different* satellites once they are thousands of kilometres apart.
Below that they always share one, the route is always ground-satellite-ground,
and every inter-satellite link is decoration. A 9,000 km leg is what puts the
aircraft under a different satellite from the gateway and forces traffic to
cross the shell — which is exactly Starlink's aviation case.

The bearing follows `PLANE_HEADING_DEG` for the same reason an airline route
and an orbital track are both great circles: flown across the constellation's
corridor instead of along it, the aircraft simply leaves coverage and there is
nothing to observe.
"""

DURATION_S = 5 * ORBIT_PERIOD_S
"""Five revolutions — about nine hours, a long-haul leg.

Sized by the aircraft, not the orbit: at `SPEED_M_S` this is how long it takes
to get far enough from the gateway to be under a different satellite, which is
when the ISLs start carrying traffic. Shorter runs show the pass pattern but
never exercise the mesh."""

ROUTE_DIRECT = "gcsa-low"


def satellite_names(planes: int, per_plane: int) -> tuple[str, ...]:
    """Every satellite in a `planes` x `per_plane` shell, plane-major.

    No hyphens in the names: a `Link` is named by joining its endpoints with
    one, and the timeline code splits on it to recover them.
    """
    return tuple(f"sat{p}{i}" for p in range(planes) for i in range(per_plane))


def constellation(planes: int, per_plane: int) -> dict[str, EarthOrbit]:
    """The shell as one orbit per satellite.

    Satellites in a plane share a ground track and differ only in phase,
    evenly spread round the orbit — which is what makes them a ring passing
    overhead in succession rather than a formation arriving together.

    Phase is staggered *between* planes as well, by a fraction of the in-plane
    spacing, the way a Walker constellation does it. Without that every plane
    reaches closest approach at the same instant and the extra planes buy a
    ground site nothing at all: their satellites rise and set together with
    the ones it already had.
    """
    if planes < 1 or per_plane < 1:
        raise ValueError(
            f"need at least one plane and one satellite per plane, got {planes}x{per_plane}"
        )
    if planes * per_plane > MAX_SATELLITES:
        raise ValueError(
            f"{planes}x{per_plane} satellites exceeds the {MAX_SATELLITES} a ground "
            f"station can carry interfaces for (wf.MAX_INTERFACES={wf.MAX_INTERFACES})"
        )
    return {
        f"sat{p}{i}": EarthOrbit(
            altitude_m=ALTITUDE_M,
            heading_deg=PLANE_HEADING_DEG + PLANE_HEADING_SPREAD_DEG * p,
            ground_offset_m=PLANE_OFFSET_M * p,
            phase_s=-ORBIT_PERIOD_S * (i / per_plane + p / (planes * per_plane)),
        )
        for p in range(planes)
        for i in range(per_plane)
    }


def _isl_pairs(planes: int, per_plane: int) -> list[tuple[str, str]]:
    """Which satellites are wired to which — a ring within each plane, plus a
    rung to the neighbouring plane, the "web" a real constellation forms.

    A ring of two is one link, not two: the pair would otherwise be joined to
    each other twice.
    """
    pairs: list[tuple[str, str]] = []
    for p in range(planes):
        ring = [f"sat{p}{i}" for i in range(per_plane)]
        span = len(ring) if len(ring) > 2 else len(ring) - 1
        pairs += [(ring[i], ring[(i + 1) % len(ring)]) for i in range(span)]
        if p:
            prev = [f"sat{p - 1}{i}" for i in range(per_plane)]
            pairs += list(zip(prev, ring))
    return pairs


def build_simulation(
    seed: int = 0,
    planes: int = DEFAULT_PLANES,
    per_plane: int = DEFAULT_PER_PLANE,
) -> Simulation:
    """Wire the constellation, the ground station and the drone, and register
    the signals worth recording as the drone flies and the shell turns."""
    sats = constellation(planes, per_plane)

    user_link = EarthOccluded(
        FreeSpacePathLoss(
            freq_hz=KU_BAND_HZ,
            tx_power_dbm=UT_EIRP_DBM,
            rx_gain_dbi=SAT_RX_GAIN_DBI,
        ),
        min_elevation_deg=MIN_ELEVATION_DEG,
    )
    # No elevation mask between satellites: the only question up there is
    # whether the planet is in the way.
    isl = EarthOccluded(
        FreeSpacePathLoss(
            freq_hz=KU_BAND_HZ,
            tx_power_dbm=ISL_EIRP_DBM,
            rx_gain_dbi=ISL_RX_GAIN_DBI,
            max_range_m=ISL_MAX_RANGE_M,
        )
    )
    ground_radio = FreeSpacePathLoss(
        max_range_m=GROUND_RADIO_MAX_RANGE_M, tx_power_dbm=24.0
    )

    # `GreatCircle`, not `Waypoints`: a straight line in the ENU tangent plane
    # holds its `z` while the planet curves away, so a 9,000 km leg at a
    # nominal 10 km cruise ends up 4,662 km up — above the shell, seeing
    # satellites no aircraft ever could.
    flight = GreatCircle(
        range_m=FLIGHT_RANGE_M,
        speed_m_s=SPEED_M_S,
        altitude_m=LOW_ALTITUDE_M,
        heading_deg=FLIGHT_HEADING_DEG,
        loop="pingpong",
    )

    nodes = [
        Node("gcsa", mobility=Static(GCSA_POSITION), trickle=TRICKLE_MS),
        Node("low", mobility=flight, trickle=TRICKLE_MS),
        *(
            Node(name, mobility=orbit, trickle=TRICKLE_MS)
            for name, orbit in sats.items()
        ),
    ]

    links = [
        pair(
            "gcsa",
            "low",
            ground_radio,
            tx_keepalive_interval_ms=GROUND_RADIO_KEEPALIVE_MS,
        )
    ]
    # Both ground terminals see the whole shell; which satellite they can
    # actually work is the elevation mask's business, evaluated per frame.
    for name in sats:
        links += [pair("gcsa", name, user_link), pair("low", name, user_link)]
    links += [pair(a, b, isl) for a, b in _isl_pairs(planes, per_plane)]

    sim = Simulation(nodes, links, seed=seed)
    sim.record("route", lambda s: s.route_via("gcsa", "low"))
    sim.record("path", route_path)
    sim.record("positions", lambda s: {n: s.position(n) for n in s.node_names})
    sim.record("visible", lambda s: visible_satellites(s, sats))
    sim.record("live_links", live_links)
    return sim


def route_path(
    sim: Simulation, src: str = "gcsa", dest: str = "low"
) -> tuple[str, ...]:
    """The whole forwarding path from `src` to `dest`, hop by hop, or empty if
    there is none.

    `route_via` names only the *first* hop, which was enough when there was
    one relay and is not enough now: "via the constellation" can mean one
    satellite or four, and which four is the thing worth looking at. Walking
    the next hops is the only way to recover it — each node's egress link
    names its two endpoints, so the far one is the next hop.
    """
    hops = [src]
    current = src
    # A path longer than the node count has to be a loop; bound it there
    # rather than trusting the tables to be consistent mid-convergence.
    for _ in range(len(sim.node_names)):
        if current == dest:
            return tuple(hops)
        link = sim.route_via(current, dest)
        if link is None or link == "*":
            return ()
        a, b = link.split("-")
        current = b if a == current else a
        if current in hops:
            return ()
        hops.append(current)
    return ()


def visible_satellites(sim: Simulation, sats: Sequence[str]) -> tuple[str, ...]:
    """Which satellites the ground station could work right now — above the
    elevation mask, with a link that closes.

    Read off the channel rather than the router: this is the sky, not the
    mesh's opinion of it, and the gap between the two is most of what this
    scenario has to say.
    """
    return tuple(
        name
        for name in sats
        if sim.sample_channel("gcsa", name).delivery_probability > 0.5
    )


LINK_STALE_MS = 6 * TRICKLE_MS[1]
"""How long a hop can go unheard before it stops counting as up — BATMAN's own
budget (`MAX_MISSED_OGMS` emissions at up to `i_max`), so the picture agrees
with the router by construction."""


def live_links(sim: Simulation) -> tuple[str, ...]:
    """Every link both of whose ends have heard the other within
    `LINK_STALE_MS`.

    Recency, not a link-quality reading: quality is an EWMA over frames that
    arrived, so it holds its last value for as long as nothing arrives and a
    satellite that has set still reports the quality it had on the way down.
    Both ends, because a hop only relays if it works both ways — and over a
    pass this short the asymmetry is common.
    """
    names = sim.node_names
    return tuple(
        f"{a}-{b}"
        for i, a in enumerate(names)
        for b in names[i + 1 :]
        if all(
            age is not None and age <= LINK_STALE_MS
            for age in (sim.link_age_ms(a, b), sim.link_age_ms(b, a))
        )
    )


# --- metrics -----------------------------------------------------------------


def stats_for(rec: Recorder) -> ConnectivityStats:
    """How much of the flight GCSA had any route to the drone."""
    return connectivity_stats(rec, "route")


def sky_stats(rec: Recorder) -> tuple[float, float]:
    """`(visible_fraction, reach_fraction)` — how much of the run at least one
    satellite was workable from the gateway, and how much of *that* time the
    aircraft was reachable through the shell.

    The pair, not either alone: together they separate "the gateway had no
    sky" from "the gateway had sky and the far end was still unreachable".
    The second figure is a measure of the constellation's *reach*, not of how
    fast the mesh converges — the gateway having a satellite says nothing
    about whether the aircraft, up to 9,000 km away, has one it can be
    relayed to. It climbs from ~17% to ~45% purely on whether the ring's
    inter-satellite links close, which is the sweep's whole point.

    The first figure is the gateway's sky only, so `connected_fraction` can
    exceed it: the aircraft sometimes works a satellite the gateway cannot
    see, and the ring carries the traffic back.
    """
    visible = rec.column("visible")
    routes = rec.column("route")
    seen = sum(1 for v in visible if v)
    served = sum(1 for v, r in zip(visible, routes) if v and r)
    total = len(rec.times_s)
    return (seen / total if total else 0.0, served / seen if seen else 0.0)


def longest_gap_s(rec: Recorder) -> float:
    """The longest stretch with no route at all — the number that decides
    whether a constellation is usable, rather than the average."""
    return stats_for(rec).longest_outage_s


def max_path_hops(rec: Recorder) -> int:
    """The most hops any route took, so a shell that actually relays through
    its ISLs is distinguishable from one that only ever bent a pipe."""
    return max((len(p) - 1 for p in rec.column("path") if p), default=0)


def run_constellation_sweep(
    geometries: Sequence[tuple[int, int]] = CONSTELLATION_SWEEP,
) -> list[SweepResult[tuple[int, int]]]:
    """Re-run the flight once per `(planes, per_plane)` geometry."""
    return run_sweep(
        lambda geometry: build_simulation(planes=geometry[0], per_plane=geometry[1]),
        geometries,
        until_s=DURATION_S,
        sample_interval_ms=5000,
    )


def geometry_label(geometry: tuple[int, int]) -> str:
    planes, per_plane = geometry
    total = planes * per_plane
    return f"{planes}x{per_plane} ({total} satellite{'' if total == 1 else 's'})"


def print_summary(rec: Recorder, geometry: tuple[int, int]) -> None:
    stats = stats_for(rec)
    visible, reach = sky_stats(rec)
    print(f"{geometry_label(geometry)}:")
    print(f"  gateway can work a sat    {visible:6.1%} of the flight")
    print(f"  ...aircraft reachable     {reach:6.1%} of that time")
    print(f"  GCSA has a route          {stats.connected_fraction:6.1%} of the flight")
    print(f"  longest gap               {longest_gap_s(rec) / 60:6.1f} min")
    print(f"  deepest path              {max_path_hops(rec)} hops")


# --- static charts -----------------------------------------------------------


def plot(rec: Recorder, geometry: tuple[int, int], out_path: Path) -> None:
    """How many satellites were workable over the orbit, against what the mesh
    made of them."""
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, state_band, style_axes

    t_min = [t / 60 for t in rec.times_s]

    fig, (ax_sky, ax_route) = plt.subplots(
        2,
        1,
        figsize=(11, 6.5),
        sharex=True,
        height_ratios=[1, 0.4],
        facecolor=PALETTE.surface,
    )
    style_axes((ax_sky, ax_route))

    ax_sky.fill_between(
        t_min,
        [len(v) for v in rec.column("visible")],
        step="mid",
        color=PALETTE.series[2],
        alpha=0.5,
        label=f"Satellites above {MIN_ELEVATION_DEG:.0f}° from GCSA",
    )
    ax_sky.plot(
        t_min,
        [len(p) - 1 if p else 0 for p in rec.column("path")],
        color=PALETTE.series[0],
        linewidth=1.5,
        label="Hops in the route GCSA is using",
    )
    ax_sky.set_ylabel("Count", color=PALETTE.ink_secondary, fontsize=10)
    ax_sky.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper right"
    )

    # Minutes on both panels: an axis shared between one series in seconds and
    # another in minutes silently plots the two at different scales.
    state_band(
        ax_route,
        t_min,
        ["route" if r else None for r in rec.column("route")],
        labels={"route": "GCSA has a route to the drone"},
    )
    ax_route.set_xlabel("Time (minutes)", color=PALETTE.ink_secondary, fontsize=10)
    ax_route.set_ylabel("Service", color=PALETTE.ink_secondary, fontsize=10)
    # Outside the axes: the band fills its own height, so a legend inside it
    # sits on top of the data it is labelling.
    ax_route.legend(
        frameon=False,
        labelcolor=PALETTE.ink_secondary,
        fontsize=9,
        loc="upper left",
        bbox_to_anchor=(0, -0.35),
    )

    visible, reach = sky_stats(rec)
    fig.suptitle(
        f"Satellite relay, {geometry_label(geometry)} — gateway sky {visible:.0%}, "
        f"aircraft reachable in {reach:.0%} of it\n"
        "Two hops while both ends share a satellite; three once the ring has to "
        "bridge them; nothing in between",
        color=PALETTE.ink_primary,
        fontsize=11,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Chart written to {out_path}")


def plot_3d(rec: Recorder, geometry: tuple[int, int], out_path: Path) -> None:
    """The constellation as it actually flies: whole orbits round the planet,
    with the ground station a speck on the surface.

    One track per *plane*, not per satellite. Satellites sharing a plane trace
    exactly the same circle and differ only in where along it they are, so
    drawing six of them overlays six identical rings and shows five of them
    for nothing; the spacing — which is the whole content — comes from marking
    each satellite's position at a single instant instead.
    """
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, point_3d, style_axes_3d, trajectory_3d

    planes, per_plane = geometry
    fig = plt.figure(figsize=(9, 8), facecolor=PALETTE.surface)
    ax = fig.add_subplot(projection="3d")
    style_axes_3d(ax)

    snapshots = rec.column("positions")
    orbits = constellation(*geometry)
    # One period's worth of samples is one full circle; the run is several.
    per_orbit = max(2, int(ORBIT_PERIOD_S / (rec.times_s[1] - rec.times_s[0])))

    for p in range(planes):
        lead = f"sat{p}0"
        trajectory_3d(
            ax,
            [snap[lead] for snap in snapshots[:per_orbit]],
            color=PALETTE.series[(p % 3) + 1],
            label=f"plane {p} ({per_plane} satellites)",
        )
    for orbit in orbits.values():
        point_3d(ax, orbit.position(0.0), color=PALETTE.ink_muted, marker="o", size=24)

    trajectory_3d(
        ax,
        [snap["low"] for snap in snapshots],
        color=PALETTE.series[0],
        label=f"Aircraft ({FLIGHT_RANGE_M / 1000:.0f} km leg)",
    )
    point_3d(
        ax, GCSA_POSITION, color=PALETTE.series[0], label="GCSA", marker="^", size=120
    )

    ax.set_xlabel("x (m)")
    ax.set_ylabel("y (m)")
    ax.set_zlabel("altitude (m)")
    ax.legend(frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=8)
    fig.suptitle(
        f"Satellite relay, {geometry_label(geometry)}: one revolution of each "
        "plane, with the satellites' spacing marked\n"
        "ENU frame — the plunge below zero is the orbit passing round the far "
        "side of the Earth",
        color=PALETTE.ink_primary,
        fontsize=11,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"3D render written to {out_path}")


def plot_sweep(results: Sequence[SweepResult[tuple[int, int]]], out_path: Path) -> None:
    """What each extra satellite buys, and whether it matters where you put
    it."""
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, style_axes

    labels = [geometry_label(r.param) for r in results]
    connected = [stats_for(r.recorder).connected_fraction for r in results]
    gaps = [longest_gap_s(r.recorder) / 60 for r in results]

    fig, (ax_cov, ax_gap) = plt.subplots(
        2, 1, figsize=(10, 7), sharex=True, facecolor=PALETTE.surface
    )
    style_axes((ax_cov, ax_gap))

    ax_cov.bar(labels, connected, color=PALETTE.series[0])
    ax_cov.set_ylabel(
        "Share of the flight\nwith a route", color=PALETTE.ink_secondary, fontsize=10
    )
    ax_gap.bar(labels, gaps, color=PALETTE.series[5])
    ax_gap.set_ylabel(
        "Longest gap\n(minutes)", color=PALETTE.ink_secondary, fontsize=10
    )
    ax_gap.set_xlabel(
        "Constellation (planes x satellites per plane)",
        color=PALETTE.ink_secondary,
        fontsize=10,
    )
    ax_gap.tick_params(axis="x", labelrotation=20)

    fig.suptitle(
        "Filling the sky: coverage against constellation size and shape — "
        "compare the three six-satellite shells",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Sweep chart written to {out_path}")


# --- interactive output ------------------------------------------------------


def _segments(hops: Sequence[str], at: dict[str, Vec3]) -> list[tuple[Vec3, Vec3]]:
    return [(at[a], at[b]) for a, b in itertools.pairwise(hops)]


def pass_timeline(rec: Recorder, geometry: tuple[int, int]) -> Any:
    """The orbit as a scrubbable time axis: every satellite where it actually
    was, which links were up, and the path GCSA was using drawn through them.

    This is the scenario's whole argument made visible. A static chart says
    the route was up for eleven minutes out of ninety-five; only stepping
    through the geometry shows that the gaps are satellites setting, and that
    the route often arrives minutes into a pass and leaves before the
    satellite does.
    """
    from wayfinder_sim.interactive import Timeline

    snapshots = rec.column("positions")
    paths = rec.column("path")
    visible = rec.column("visible")
    live = rec.column("live_links")
    sats = satellite_names(*geometry)

    captions: list[str] = []
    links: list[list[tuple[Vec3, Vec3]]] = []
    usable: list[list[tuple[Vec3, Vec3]]] = []
    for at, path, in_sky, up in zip(snapshots, paths, visible, live):
        links.append(_segments(path, at))
        usable.append([(at[a], at[b]) for a, b in (n.split("-") for n in up)])
        if path:
            state = f"routed: {' → '.join(path)}"
        elif in_sky:
            state = f"no route — {', '.join(in_sky)} overhead but not yet converged"
        else:
            state = "no route — nothing above the mask"
        captions.append(f"{state} · {len(in_sky)}/{len(sats)} satellites workable")

    return Timeline(
        times_s=rec.times_s,
        positions={name: [snap[name] for snap in snapshots] for name in (*sats, "low")},
        captions=captions,
        links=links,
        usable_links=usable,
    )


REPORT_MAX_FRAMES = 60
"""Frame budget for a scene embedded in the sweep report.

Half the standalone budget, because the report carries one scene per run. A
scrubber's trails cost O(frames^2) — each frame redraws the whole path flown
so far — so halving the frames is most of a 3x saving per scene, and at
orbital timescales 60 steps over nine hours is still finer than anything a
reader resolves by dragging.
"""

TRACK_POINTS = 400
"""How many points a static context track keeps.

The run records thousands of samples per entity, and the track behind the
scrubber is a smooth ring drawn as context — it reads identically at 400
points and costs a fraction as much in the page.
"""


def build_scene(
    rec: Recorder,
    geometry: tuple[int, int],
    *,
    title: bool = True,
    max_frames: int | None = None,
) -> Any:
    """The orbit as a rotatable, scrubbable 3D scene.

    `max_frames` defaults to the renderer's own budget; the report passes a
    smaller one, since it carries a scene per run.
    """
    from wayfinder_sim.interactive import DEFAULT_MAX_FRAMES, track_scene

    snapshots = rec.column("positions")
    stride = max(1, len(snapshots) // TRACK_POINTS)
    stats = stats_for(rec)
    visible, _ = sky_stats(rec)

    return track_scene(
        # The aircraft is a track in its own right, not just a scrubbed
        # marker: its 9,000 km leg out from under the gateway's satellite is
        # half the reason the route changes shape.
        tracks={
            name: [snap[name] for snap in snapshots[::stride]]
            for name in (*satellite_names(*geometry), "low")
        },
        max_frames=DEFAULT_MAX_FRAMES if max_frames is None else max_frames,
        sites={"GCSA": GCSA_POSITION},
        site_label="Ground station",
        timeline=pass_timeline(rec, geometry),
        title=(
            f"Starlink-like relay, {geometry_label(geometry)} at "
            f"{ALTITUDE_M / 1000:.0f} km — a satellite is workable {visible:.0%} of "
            f"the orbit, GCSA has a route {stats.connected_fraction:.0%}"
            "<br><sub>Drag to rotate; scrub the slider to fly one revolution. Faint "
            "grey is a link that is up both ways, dotted orange the path in use. "
            "The tracks dive below the ground plane where the orbit goes round the "
            "back of the Earth.</sub>"
        )
        if title
        else None,
    )


def write_interactive_scene(
    rec: Recorder, geometry: tuple[int, int], out_path: Path
) -> None:
    """Write one revolution out as a self-contained page.

    Needs the `interactive` extra (plotly); skipped with a note when it isn't
    installed, so a plain `--group sim` run still produces everything else.
    """
    try:
        from wayfinder_sim.interactive import write_html
    except ImportError:
        print("plotly not installed — skipping the interactive scene")
        return

    write_html(build_scene(rec, geometry), out_path)
    print(f"Interactive scene written to {out_path}")


def _scene_panel(rec: Recorder, geometry: tuple[int, int]) -> list[Any]:
    """This run's scrubbable scene, behind a disclosure — or nothing at all
    when plotly is missing, so the report still writes with its static charts.

    Collapsed, and that is what makes one per run possible: seven scenes built
    eagerly would claim more WebGL contexts than a browser grants, and the
    ones it dropped would go blank.
    """
    try:
        from wayfinder_sim.report import ScenePanel
    except ImportError:
        return []

    return [
        ScenePanel(
            build_scene(rec, geometry, title=False, max_frames=REPORT_MAX_FRAMES),
            caption=(
                f"Fly the {geometry_label(geometry)} shell — drag to rotate, scrub "
                "the slider to watch satellites rise, carry the route, and set"
            ),
            collapsed=True,
        )
    ]


def write_sweep_report_page(
    results: Sequence[SweepResult[tuple[int, int]]], out_dir: Path
) -> None:
    """Collect the whole sweep into one page, so "how much sky do I have to
    fill" doesn't have to be reassembled from a wall of console output."""
    from wayfinder_sim.report import ImagePanel, RunReport, write_sweep_report

    runs = []
    for i, result in enumerate(results):
        rec = result.recorder
        planes, per_plane = result.param
        stats = stats_for(rec)
        visible, reach = sky_stats(rec)
        runs.append(
            RunReport(
                label=geometry_label(result.param),
                params={
                    "shell": f"{ALTITUDE_M / 1000:.0f} km, {ORBIT_PERIOD_S / 60:.1f} min period",
                    "constellation": f"{planes} plane(s) x {per_plane} satellites",
                    "user link": f"{UT_EIRP_DBM:.0f} dBm EIRP + {SAT_RX_GAIN_DBI:.0f} dBi, Ku-band",
                    "elevation mask": f"{MIN_ELEVATION_DEG:.0f}°",
                    "flight": f"{FLIGHT_RANGE_M / 1000:.0f} km out and back at {SPEED_M_S:.0f} m/s",
                },
                metrics={
                    "gateway sky": f"{visible:.1%} of the flight",
                    "aircraft reachable then": f"{reach:.1%}",
                    "with a route": f"{stats.connected_s / 60:.1f} min of {stats.total_s / 60:.1f} min",
                    "outages": stats.outage_count,
                    "longest gap": f"{longest_gap_s(rec) / 60:.1f} min",
                    "deepest path": f"{max_path_hops(rec)} hops",
                },
                headline=stats.connected_fraction,
                panels=[
                    ImagePanel(
                        out_dir / f"satellite_relay_{i}.png",
                        caption="Satellites workable from GCSA, and what the mesh made of them",
                    ),
                    ImagePanel(
                        out_dir / f"satellite_relay_3d_{i}.png",
                        caption="One revolution of the shell, in the scene's ENU frame",
                    ),
                    *_scene_panel(rec, result.param),
                ],
            )
        )

    summary_panels: list[Any] = [
        ImagePanel(
            out_dir / "satellite_relay_constellation_sweep.png",
            caption="Coverage and worst-case gap against constellation size and shape",
        )
    ]

    out_path = write_sweep_report(
        out_dir / "satellite_relay_report.html",
        "Starlink-like constellation sweep",
        runs,
        subtitle=(
            f"The same {DURATION_S / 60:.0f}-minute flight under "
            f"{len(runs)} constellation geometries at {ALTITUDE_M / 1000:.0f} km. The "
            f"aircraft's own radio dies hard at {GROUND_RADIO_MAX_RANGE_M:.0f} m, so "
            "past the first minute everything depends on what is above the "
            f"{MIN_ELEVATION_DEG:.0f}° mask — and, once it is far enough out, on the "
            "ring being able to relay between two different satellites."
        ),
        headline_label="share of the flight with a route",
        summary_panels=summary_panels,
    )
    print(f"Sweep report written to {out_path}")


def main() -> None:
    wf.init_tracing()  # quiet by default; set RUST_LOG to see mesh internals

    out_dir = Path(__file__).parent / "output"
    results = run_constellation_sweep()
    for i, result in enumerate(results):
        rec = result.recorder
        print_summary(rec, result.param)
        plot(rec, result.param, out_dir / f"satellite_relay_{i}.png")
        plot_3d(rec, result.param, out_dir / f"satellite_relay_3d_{i}.png")

    plot_sweep(results, out_dir / "satellite_relay_constellation_sweep.png")

    default = next(
        (r for r in results if r.param == (DEFAULT_PLANES, DEFAULT_PER_PLANE)),
        results[-1],
    )
    write_interactive_scene(
        default.recorder, default.param, out_dir / "satellite_relay_scene.html"
    )
    write_sweep_report_page(results, out_dir)


if __name__ == "__main__":
    main()
