"""Mountain relay scenario: a drone transits a mountain range at low level
while ground relays — scattered on summits, on the valley floor, or both —
try to keep it in contact.

Every relay has its own satellite backhaul, so a relay is a gateway in its
own right: the drone counts as *connected* whenever it can reach **any**
relay, directly or by hopping through another relay. The question the
scenario answers is therefore not "which route is chosen" but "how much of
the flight had a route at all, and where were the gaps" — and, by re-running
the same flight against different relay placements, "where should the relays
go".

What makes this different from the flat-ground scenarios
(`sim/scenarios/satellite_relay.py`) is that distance stops being the thing
that decides connectivity. Every link here is `wayfinder_sim.channel.TerrainMasked`,
which reduces the ground profile between two nodes to its worst obstruction
and charges the resulting knife-edge diffraction loss against the link
budget. A relay 2 km away behind a ridge is unreachable while one 5 km away
across open valley is fine, so *line of sight*, not range, sets the coverage
— which is exactly why placement is worth sweeping.

The drone flies `wayfinder_sim.terrain.TerrainFollowing`: it holds a fixed
height above the ground rather than a fixed altitude, so its absolute height
— and with it what it can see over — rises and falls with the terrain
beneath it, the way a real low-level transit works.

Topology (N relays, here 3)::

      r1 ──── r2          every relay pair is a link (they can hop
       \\  ╳  /            for each other), and every relay has its
        \\/  \\/             own satellite backhaul, so reaching ANY
        r3 ───┘             of them counts as connected

      drone ⇢ r1, r2, r3   one link per relay; terrain decides which,
                            if any, is actually usable at each instant

Run: `uv run --group sim python sim/scenarios/mountain_relay.py`
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import wayfinder_py as wf
from wayfinder_sim.channel import FreeSpacePathLoss, TerrainMasked
from wayfinder_sim.connectivity import ConnectivityStats, connectivity_stats
from wayfinder_sim.link import Link
from wayfinder_sim.mobility import Static, Vec3, Waypoints
from wayfinder_sim.node import Node
from wayfinder_sim.recorder import Recorder
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.sweep import SweepResult, run_sweep
from wayfinder_sim.terrain import (
    Bounds,
    GaussianPeak,
    MountainRange,
    Terrain,
    TerrainFollowing,
    peak_sites,
    valley_sites,
)
from wayfinder_sim.topology import complete_graph, pair

# matplotlib (and `wayfinder_sim.plotting` with it) is imported inside each
# plotting function rather than here, so importing this module costs nothing
# but the topology — what lets `wayfinder-ml generate` load the scenario
# without a plotting stack installed.

# --- the range ---------------------------------------------------------------

WORLD = Bounds(0.0, 0.0, 8000.0, 6000.0)
"""8 km x 6 km of mountains."""

BASE_ELEVATION_M = 200.0

PEAKS = (
    # The two big massifs either side of the corridor.
    GaussianPeak(x=1500.0, y=1200.0, height_m=1100.0, sigma_m=500.0),
    GaussianPeak(x=4500.0, y=1500.0, height_m=1200.0, sigma_m=600.0),
    GaussianPeak(x=3000.0, y=3800.0, height_m=950.0, sigma_m=550.0),
    GaussianPeak(x=6000.0, y=3600.0, height_m=1000.0, sigma_m=500.0),
    # Smaller knolls *inside* the corridor: these are what break line of
    # sight along the valley itself, so a relay at one end can't simply see
    # the whole route.
    GaussianPeak(x=2200.0, y=2600.0, height_m=700.0, sigma_m=400.0),
    GaussianPeak(x=5200.0, y=2800.0, height_m=800.0, sigma_m=450.0),
    GaussianPeak(x=7000.0, y=1800.0, height_m=900.0, sigma_m=500.0),
)

# --- the flight --------------------------------------------------------------

FLIGHT_TRACK = (
    Vec3(300.0, 2400.0),
    Vec3(1800.0, 3200.0),
    Vec3(3400.0, 2400.0),
    Vec3(4200.0, 3000.0),
    Vec3(5600.0, 1900.0),
    Vec3(7000.0, 2900.0),
    Vec3(7800.0, 2200.0),
)
"""Ground track only — z is supplied by the terrain (see `AGL_M`), so the
waypoints are written as a plan view and the drone climbs and descends with
the ground under it."""

AGL_M = 80.0
"""How high above the ground the drone holds. Low enough that terrain, not
range, dominates its connectivity — the point of the scenario."""

SPEED_M_S = 25.0

# --- the radios --------------------------------------------------------------

FREQ_HZ = 900e6
"""900 MHz rather than 2.4 GHz: the band a long-range drone link actually
uses, and one whose longer wavelength diffracts appreciably around terrain
instead of being blocked outright."""

TX_POWER_DBM = 30.0
MAX_RANGE_M = 6000.0
"""A hard link-budget cutoff on top of the RSSI waterfall, so placement is
answerable to *both* failure modes a real deployment has: too far away, and
behind a mountain."""

MAST_HEIGHT_M = 10.0
"""Antenna height above the ground at a relay site — small, but enough that a
relay standing on a valley floor isn't buried in its own terrain sample."""

TRICKLE_MS = (200, 2000)
KEEPALIVE_MS = 500
"""Keep-alive cadence on every link. Terrain makes links die abruptly (the
drone rounds a spur and the path is simply gone), and OGM staleness alone
would take MAX_MISSED_OGMS x i_max ~ 12 s to notice — at 25 m/s, 300 m of
flight credited to a link that is already dead. Keep-alives cut that to
~3 x 500 ms."""

RELAY_COUNT = 3
SITE_SEPARATION_M = 1500.0
"""Minimum spacing between chosen relay sites, so a placement strategy
returns distinct locations rather than three points on the same summit."""

SAMPLE_INTERVAL_MS = 200
"""Recording cadence, and therefore the resolution of every outage figure."""


def build_terrain() -> MountainRange:
    """The range every run of this scenario flies through — fixed across the
    sweep, so placement is the only thing that varies."""
    return MountainRange(PEAKS, base_elevation_m=BASE_ELEVATION_M)


def flight_duration_s() -> float:
    """One full transit, start to finish."""
    track = Waypoints(FLIGHT_TRACK, speed_m_s=SPEED_M_S, loop="once")
    return track.duration_s()


DURATION_S = flight_duration_s()
"""The scenario's natural length — one transit — and what `wayfinder-ml
generate` runs an episode for when not told otherwise."""


# --- placement strategies ----------------------------------------------------

CORRIDOR = Bounds(300.0, 1500.0, 7800.0, 3800.0)
"""The band the flight track runs through. Valley placements are searched
here rather than over the whole map: the fair comparison to hauling a relay
up a summit is siting one on the valley floor *near the route*, not in
whatever map corner happens to be lowest."""


def summit_placement(terrain: Terrain) -> tuple[Vec3, ...]:
    """On the highest ground available — maximum visibility, hardest to
    install and service."""
    return peak_sites(
        terrain,
        WORLD,
        RELAY_COUNT,
        spacing_m=200.0,
        min_separation_m=SITE_SEPARATION_M,
    )


def valley_placement(terrain: Terrain) -> tuple[Vec3, ...]:
    """On the valley floor along the route — trivial to install, and mostly
    blind past the next spur."""
    return valley_sites(
        terrain,
        CORRIDOR,
        RELAY_COUNT,
        spacing_m=200.0,
        min_separation_m=SITE_SEPARATION_M,
    )


def mixed_placement(terrain: Terrain) -> tuple[Vec3, ...]:
    """One summit relay to cover the corridor broadly, the rest on the valley
    floor — the compromise a real deployment tends to reach."""
    summits = peak_sites(
        terrain, WORLD, 1, spacing_m=200.0, min_separation_m=SITE_SEPARATION_M
    )
    valleys = valley_sites(
        terrain,
        CORRIDOR,
        RELAY_COUNT - len(summits),
        spacing_m=200.0,
        min_separation_m=SITE_SEPARATION_M,
    )
    return (*summits, *valleys)


def single_summit_placement(terrain: Terrain) -> tuple[Vec3, ...]:
    """One relay, on the best summit — the control case for "is a mesh of
    relays buying anything over a single well-sited one?"."""
    return peak_sites(terrain, WORLD, 1, spacing_m=200.0)


PLACEMENTS: dict[str, Callable[[Terrain], tuple[Vec3, ...]]] = {
    "summits": summit_placement,
    "valley floor": valley_placement,
    "mixed": mixed_placement,
    "single summit": single_summit_placement,
}
"""The swept parameter: a named siting strategy -> the sites it picks."""


def relay_name(index: int) -> str:
    """`r1`, `r2`, ... — relays are named by position in the placement."""
    return f"r{index + 1}"


# --- the simulation ----------------------------------------------------------


def build_simulation(seed: int = 0, placement: str = "summits") -> Simulation:
    """Wire the drone and the relays `placement` chooses, and register the
    signals a coverage study reads."""
    if placement not in PLACEMENTS:
        raise ValueError(
            f"unknown placement {placement!r}; expected one of {sorted(PLACEMENTS)}"
        )

    terrain = build_terrain()
    sites = PLACEMENTS[placement](terrain)

    # One radio model, wrapped once: `TerrainMasked` memoizes path geometry
    # per endpoint pair, so sharing the instance across every link lets the
    # relay-to-relay paths — which never move — be computed once for the
    # whole run.
    radio = TerrainMasked(
        FreeSpacePathLoss(
            freq_hz=FREQ_HZ, tx_power_dbm=TX_POWER_DBM, max_range_m=MAX_RANGE_M
        ),
        terrain,
    )

    drone = Node(
        "drone",
        mobility=TerrainFollowing(
            Waypoints(FLIGHT_TRACK, speed_m_s=SPEED_M_S, loop="once"),
            terrain,
            agl_m=AGL_M,
        ),
        trickle=TRICKLE_MS,
    )
    relays = [
        Node(
            relay_name(i),
            mobility=Static(dataclasses.replace(site, z=site.z + MAST_HEIGHT_M)),
            trickle=TRICKLE_MS,
        )
        for i, site in enumerate(sites)
    ]
    names = [relay_name(i) for i in range(len(sites))]

    links: list[Link] = [
        pair("drone", name, radio, tx_keepalive_interval_ms=KEEPALIVE_MS)
        for name in names
    ]
    # Relays hop for each other, so a drone that can only see r3 is still in
    # touch with the whole ground segment.
    links += [
        dataclasses.replace(link, tx_keepalive_interval_ms=KEEPALIVE_MS)
        for link in complete_graph(names, radio)
    ]

    sim = Simulation([drone, *relays], links, seed=seed)
    sim.record("reachable", lambda s: s.reachable("drone", names))
    sim.record("uplink", lambda s: uplink_link(s, names))
    sim.record("drone_pos", lambda s: s.position("drone"))
    sim.record("altitude", lambda s: s.position("drone").z)
    return sim


def uplink_link(sim: Simulation, relays: Sequence[str]) -> str | None:
    """The name of the link the drone currently egresses on to reach the
    ground segment, or `None` when it can reach none of it.

    This is the handoff signal: because the relays mesh with each other, the
    drone reaching `r1` may well be egressing on its link to `r3`, and it's
    the *link* — the neighbour actually carrying the traffic — that a
    coverage chart wants to show changing.
    """
    for relay in relays:
        route = sim.route_via("drone", relay)
        if route is not None:
            return route
    return None


def relay_sites(placement: str, terrain: Terrain) -> dict[str, Vec3]:
    """The sited relay positions — antenna height included, so these are the
    points the channel actually sees — keyed by node name."""
    return {
        relay_name(i): dataclasses.replace(site, z=site.z + MAST_HEIGHT_M)
        for i, site in enumerate(PLACEMENTS[placement](terrain))
    }


# --- running the sweep -------------------------------------------------------


def run_placement_sweep(
    placements: Sequence[str] | None = None, *, seed: int = 0
) -> list[SweepResult[str]]:
    """Fly the identical route against each placement strategy in turn."""
    return run_sweep(
        lambda name: build_simulation(seed=seed, placement=name),
        list(PLACEMENTS) if placements is None else list(placements),
        until_s=DURATION_S,
        sample_interval_ms=SAMPLE_INTERVAL_MS,
    )


def stats_for(rec: Recorder) -> ConnectivityStats:
    """Connectivity over one recorded transit. `reachable` is the signal
    rather than `uplink` because the question is "in touch with the ground
    segment at all", and an empty reachable set is exactly that."""
    return connectivity_stats(rec, "reachable")


def print_connectivity_summary(placement: str, rec: Recorder) -> None:
    stats = stats_for(rec)
    print(f"\n{placement}:")
    print(
        f"  connected {stats.connected_s:6.1f}s of {stats.total_s:6.1f}s "
        f"({stats.connected_fraction:.1%})"
    )
    print(
        f"  {stats.outage_count} outage(s), "
        f"longest {stats.longest_outage_s:.1f}s, "
        f"total dark {stats.disconnected_s:.1f}s"
    )
    for outage in stats.outages:
        print(f"    t={outage.start_s:6.1f}s..{outage.end_s:6.1f}s  no route")

    handoffs = rec.transitions("uplink")
    print(f"  uplink handoffs ({len(handoffs)}):")
    for t_s, link in handoffs:
        print(f"    t={t_s:6.1f}s  -> {link}")


def print_sweep_summary(results: Sequence[SweepResult[str]]) -> None:
    print("\nPlacement -> share of the transit with a route to the ground:")
    for result in results:
        stats = stats_for(result.recorder)
        print(
            f"  {result.param:<15} {stats.connected_fraction:6.1%}  "
            f"({stats.outage_count} outage(s), longest {stats.longest_outage_s:5.1f}s)"
        )


# --- charts ------------------------------------------------------------------


def plot_timeline(placement: str, rec: Recorder, out_path: Path) -> None:
    """The flight as a timeline: how high the drone was, which link carried
    it, and — shaded across both panels — when it had nothing at all."""
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, outage_spans, state_band, style_axes

    stats = stats_for(rec)
    t = rec.times_s

    fig, (ax_alt, ax_link) = plt.subplots(
        2,
        1,
        figsize=(10, 6.5),
        sharex=True,
        height_ratios=[1, 0.45],
        facecolor=PALETTE.surface,
    )
    style_axes((ax_alt, ax_link))

    ax_alt.plot(
        t,
        rec.column("altitude"),
        color=PALETTE.series[0],
        linewidth=2,
        label="Drone altitude (MSL)",
    )
    ax_alt.plot(
        t,
        [z - AGL_M for z in rec.column("altitude")],
        color=PALETTE.ink_muted,
        linewidth=1,
        linestyle="--",
        label="Ground beneath",
    )
    outage_spans(ax_alt, stats.outages)
    ax_alt.set_ylabel("Elevation (m)", color=PALETTE.ink_secondary, fontsize=10)
    ax_alt.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper left"
    )

    # Which link carries the drone is a categorical identity, not a
    # magnitude — filled bands, no numeric y-axis.
    state_band(ax_link, t, rec.column("uplink"))
    outage_spans(ax_link, stats.outages, label=None)
    ax_link.set_xlabel("Time (s)", color=PALETTE.ink_secondary, fontsize=10)
    ax_link.set_ylabel("Drone uplink", color=PALETTE.ink_secondary, fontsize=10)
    ax_link.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper left"
    )

    fig.suptitle(
        f"Mountain transit, relays on {placement}: "
        f"{stats.connected_fraction:.0%} of the flight connected, "
        f"{stats.outage_count} outage(s), longest {stats.longest_outage_s:.0f}s",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Timeline written to {out_path}")


def plot_coverage_map(
    placement: str, rec: Recorder, sites: dict[str, Vec3], out_path: Path
) -> None:
    """Plan view: the range, where the relays sit on it, and the route
    coloured by whether the drone had a link — the chart that turns "80%
    connected" into "connected except behind *that* ridge"."""
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, style_axes, terrain_contour

    stats = stats_for(rec)
    positions = rec.column("drone_pos")
    reachable = rec.column("reachable")

    fig, ax = plt.subplots(figsize=(11, 7.5), facecolor=PALETTE.surface)
    style_axes((ax,))
    contours = terrain_contour(ax, build_terrain(), WORLD)
    colorbar = fig.colorbar(contours, ax=ax, pad=0.02)
    colorbar.set_label("Ground elevation (m)", color=PALETTE.ink_secondary, fontsize=9)
    colorbar.ax.tick_params(colors=PALETTE.ink_muted, labelsize=8)

    ax.plot(
        [p.x for p in positions],
        [p.y for p in positions],
        color=PALETTE.series[0],
        linewidth=2,
        label="Connected",
    )
    # Overplot only the disconnected samples, so the losses read as gaps
    # burned into the same line rather than as a second track to correlate.
    dark_x = [p.x for p, r in zip(positions, reachable) if not r]
    dark_y = [p.y for p, r in zip(positions, reachable) if not r]
    ax.plot(
        dark_x,
        dark_y,
        linestyle="none",
        marker="o",
        markersize=3,
        color=PALETTE.series[5],  # red — loss of service, not a series identity
        label="No route",
    )

    for name, site in sorted(sites.items()):
        ax.plot(
            site.x,
            site.y,
            marker="^",
            markersize=11,
            color=PALETTE.series[3],
            linestyle="none",
        )
        ax.annotate(
            f"{name} ({site.z:.0f}m)",
            (site.x, site.y),
            textcoords="offset points",
            xytext=(10, 6),
            color=PALETTE.ink_primary,
            fontsize=9,
        )
    # One legend entry for the relays, however many there are.
    ax.plot(
        [],
        [],
        marker="^",
        markersize=11,
        color=PALETTE.series[3],
        linestyle="none",
        label="Relay site",
    )

    ax.set_xlabel("x (m)", color=PALETTE.ink_secondary, fontsize=10)
    ax.set_ylabel("y (m)", color=PALETTE.ink_secondary, fontsize=10)
    ax.set_aspect("equal")
    ax.legend(
        frameon=True,
        facecolor=PALETTE.surface,
        edgecolor=PALETTE.axis,
        labelcolor=PALETTE.ink_secondary,
        fontsize=9,
        loc="upper left",
    )
    fig.suptitle(
        f"Coverage along the route, relays on {placement}: "
        f"{stats.connected_fraction:.0%} connected",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Coverage map written to {out_path}")


def flight_timeline(rec: Recorder, sites: dict[str, Vec3]) -> Any:
    """The transit as a scrubbable time axis: where the drone was at each
    sample, which relay was carrying it, and the hop itself drawn between the
    two.

    The hop is what a static track can't show. A line through the mountains
    says where the drone flew; it can't say that at *this* instant the traffic
    was crossing 4 km of open valley to r3 rather than going to the relay
    sitting much closer behind a spur — which is the whole question the
    placement sweep is asking.
    """
    from wayfinder_sim.interactive import Timeline

    positions = rec.column("drone_pos")
    uplinks = rec.column("uplink")
    reachable = rec.column("reachable")

    captions: list[str] = []
    links: list[list[tuple[Vec3, Vec3]]] = []
    for position, uplink, in_reach in zip(positions, uplinks, reachable):
        serving = uplink_site(uplink, sites)
        if serving is None:
            captions.append("no route to the ground segment")
            links.append([])
            continue
        name, site = serving
        captions.append(
            f"uplink {uplink} · {position.distance_to(site) / 1000:.1f} km to {name} "
            f"· in reach: {', '.join(in_reach)}"
        )
        links.append([(position, site)])

    return Timeline(
        times_s=rec.times_s,
        positions={"Drone": positions},
        captions=captions,
        links=links,
    )


def uplink_site(uplink: str | None, sites: dict[str, Vec3]) -> tuple[str, Vec3] | None:
    """The relay on the far end of the drone's current uplink, or `None` when
    it has none. Link names are their endpoints joined with `-`
    (`wayfinder_sim.link.Link.name`), so the far end is whichever endpoint is
    a relay."""
    if uplink is None:
        return None
    for endpoint in uplink.split("-"):
        if endpoint in sites:
            return endpoint, sites[endpoint]
    return None


def write_interactive_scene(
    placement: str, rec: Recorder, sites: dict[str, Vec3], out_path: Path
) -> None:
    """The same scene as `plot_terrain_3d`, but rotatable in a browser and
    scrubbable through the flight — the form that actually answers "which
    ridge was in the way", since that depends on the angle you look from and
    on when you look, and no single static camera is right for either.

    Needs the `interactive` extra (plotly); skipped with a note when it isn't
    installed, so a plain `--group sim` run still produces everything else.
    """
    try:
        from wayfinder_sim.interactive import terrain_scene, write_html
    except ImportError:
        print("plotly not installed — skipping the interactive scene")
        return

    positions = rec.column("drone_pos")
    reachable = rec.column("reachable")
    stats = stats_for(rec)

    figure = terrain_scene(
        build_terrain(),
        WORLD,
        tracks={"Drone track": positions},
        markers={"No route": [p for p, r in zip(positions, reachable) if not r]},
        sites=sites,
        timeline=flight_timeline(rec, sites),
        title=(
            f"Mountain transit, relays on {placement} — "
            f"{stats.connected_fraction:.0%} connected "
            f"(drag to rotate, scroll to zoom, scrub the slider to fly it)"
        ),
    )
    write_html(figure, out_path)
    print(f"Interactive scene written to {out_path}")


def plot_terrain_3d(
    placement: str, sites: dict[str, Vec3], out_path: Path, *, show: bool = False
) -> None:
    """An oblique render of the range and the relay sites on it — the "these
    are real mountains, not a flat map" picture. Deliberately *not* the
    coverage chart: matplotlib draws a 3D line behind a surface it should be
    in front of, so the route lives in `plot_coverage_map` instead."""
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import (
        PALETTE,
        point_3d,
        style_axes_3d,
        terrain_surface_3d,
    )

    fig = plt.figure(figsize=(10, 8), facecolor=PALETTE.surface)
    ax = fig.add_subplot(projection="3d")
    style_axes_3d(ax)
    ax.view_init(elev=42, azim=-118)

    terrain_surface_3d(ax, build_terrain(), WORLD, resolution=80)
    for i, (name, site) in enumerate(sorted(sites.items())):
        point_3d(
            ax,
            site,
            # Relays are one kind of thing, so they share a hue and are told
            # apart by their labels rather than by near-identical ones.
            color=PALETTE.series[5],
            label="Relay site" if i == 0 else None,
            marker="^",
            size=110,
        )
        ax.text(
            site.x, site.y, site.z + 140, name, color=PALETTE.ink_primary, fontsize=9
        )

    ax.set_xlabel("x (m)")
    ax.set_ylabel("y (m)")
    ax.set_zlabel("elevation (m)")
    ax.legend(frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9)
    fig.suptitle(
        f"The range, with relays on {placement}",
        color=PALETTE.ink_primary,
        fontsize=12,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    print(f"3D render written to {out_path}")
    if show:
        # matplotlib's GUI backends are already interactive: this window
        # rotates by dragging, with no extra dependency. It blocks until
        # closed, so it is the last thing the run does.
        print("Showing the 3D figure — drag to rotate, close the window to finish")
        plt.show()
    plt.close(fig)


def plot_worst_outage_profile(
    placement: str, rec: Recorder, sites: dict[str, Vec3], out_path: Path
) -> None:
    """A cross-section of the ground between the drone and its nearest relay
    at the worst moment of the flight — the chart that says *why* the link
    was down, where a timeline can only say that it was."""
    import math

    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, style_axes, terrain_profile

    stats = stats_for(rec)
    if not stats.outages or not sites:
        print(f"No outage to profile for {placement!r} — skipping profile chart")
        return

    worst = max(stats.outages, key=lambda o: o.duration_s)
    midpoint_s = (worst.start_s + worst.end_s) / 2
    idx = min(range(len(rec.times_s)), key=lambda i: abs(rec.times_s[i] - midpoint_s))
    drone_pos = rec.column("drone_pos")[idx]
    nearest_name, nearest_site = min(
        sites.items(), key=lambda kv: drone_pos.distance_to(kv[1])
    )

    fig, ax = plt.subplots(figsize=(10, 5), facecolor=PALETTE.surface)
    style_axes((ax,))
    terrain_profile(ax, build_terrain(), drone_pos, nearest_site, freq_hz=FREQ_HZ)

    ax.set_xlabel(
        f"Distance from drone toward {nearest_name} (m)",
        color=PALETTE.ink_secondary,
        fontsize=10,
    )
    ax.set_ylabel("Elevation (m)", color=PALETTE.ink_secondary, fontsize=10)
    ax.legend(
        frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, loc="upper right"
    )

    separation_m = math.dist(
        (drone_pos.x, drone_pos.y), (nearest_site.x, nearest_site.y)
    )
    fig.suptitle(
        f"Why the link was down ({placement}, t={midpoint_s:.0f}s): "
        f"{nearest_name} is only {separation_m:.0f}m away, but not in sight of it",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Link profile written to {out_path}")


def plot_placement_comparison(
    results: Sequence[SweepResult[str]], out_path: Path
) -> None:
    """The scenario's headline: connected share of the transit, by placement.

    A magnitude comparison across a handful of named categories — so
    horizontal bars, ordered best-first, each labelled directly rather than
    read off a grid.
    """
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, style_axes

    ranked = sorted(
        ((r.param, stats_for(r.recorder)) for r in results),
        key=lambda item: item[1].connected_fraction,
    )
    labels = [name for name, _ in ranked]
    fractions = [stats.connected_fraction for _, stats in ranked]

    fig, ax = plt.subplots(figsize=(9, 5), facecolor=PALETTE.surface)
    style_axes((ax,))

    ax.barh(labels, fractions, color=PALETTE.series[0], height=0.55)
    for y, (name, stats) in enumerate(ranked):
        ax.text(
            stats.connected_fraction + 0.015,
            y,
            f"{stats.connected_fraction:.0%}  "
            f"({stats.outage_count} outage(s), longest {stats.longest_outage_s:.0f}s)",
            va="center",
            color=PALETTE.ink_secondary,
            fontsize=9,
        )

    ax.set_xlim(0, 1.35)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
    ax.set_xlabel(
        "Share of the transit with a route to the ground segment",
        color=PALETTE.ink_secondary,
        fontsize=10,
    )
    ax.grid(axis="y", visible=False)

    fig.suptitle(
        "Where the relays go decides the coverage, not how many there are",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Comparison chart written to {out_path}")


def write_sweep_report_page(
    results: Sequence[SweepResult[str]], terrain: Terrain, out_dir: Path
) -> None:
    """Collect the whole sweep — every placement's parameters, metrics and
    charts — into one page, so the comparison doesn't have to be reassembled
    from a directory of PNGs and a wall of console output."""
    from wayfinder_sim.report import ImagePanel, RunReport, write_sweep_report

    try:
        import wayfinder_sim.interactive  # noqa: F401  (probe for the extra)

        embed_scenes = True
    except ImportError:
        # Without the `interactive` extra the report is still worth writing —
        # it just carries the static charts and drops the rotatable scenes.
        embed_scenes = False

    runs = []
    for result in results:
        placement = result.param
        slug = placement.replace(" ", "_")
        rec = result.recorder
        stats = stats_for(rec)
        sites = relay_sites(placement, terrain)

        panels: list[Any] = [
            ImagePanel(
                out_dir / f"mountain_relay_{slug}.png",
                caption="Coverage along the route — red marks where no relay was reachable",
            ),
            ImagePanel(
                out_dir / f"mountain_relay_timeline_{slug}.png",
                caption="Altitude, serving uplink, and outages over the transit",
            ),
        ]
        if embed_scenes:
            panels.append(_scene_panel(placement, rec, sites))

        runs.append(
            RunReport(
                label=placement,
                params={
                    "relays": len(sites),
                    "sites": ", ".join(
                        f"{name} @ {site.z:.0f}m"
                        for name, site in sorted(sites.items())
                    ),
                    "radio": f"{TX_POWER_DBM:.0f} dBm @ {FREQ_HZ / 1e6:.0f} MHz",
                    "max range": f"{MAX_RANGE_M:.0f} m",
                },
                metrics={
                    "connected": f"{stats.connected_s:.1f} s of {stats.total_s:.1f} s",
                    "outages": stats.outage_count,
                    "longest outage": f"{stats.longest_outage_s:.1f} s",
                    "total dark": f"{stats.disconnected_s:.1f} s",
                    "uplink handoffs": len(rec.transitions("uplink")),
                },
                headline=stats.connected_fraction,
                panels=panels,
            )
        )

    out_path = write_sweep_report(
        out_dir / "mountain_relay_report.html",
        "Mountain relay placement sweep",
        runs,
        subtitle=(
            f"One {DURATION_S:.0f}s low-level transit of the same {WORLD.width_m / 1000:.0f} x "
            f"{WORLD.depth_m / 1000:.0f} km range, flown against {len(runs)} relay sitings. "
            "Every link is terrain-masked, so line of sight — not range — decides "
            "who can hear whom."
        ),
        headline_label="connected share of the transit",
        summary_panels=[
            ImagePanel(
                out_dir / "mountain_relay_placement.png",
                caption="Connected share of the transit, by placement",
            ),
            ImagePanel(
                out_dir / "mountain_relay_profile.png",
                caption="Why the worst placement lost the link: the ground between drone and relay",
            ),
        ],
    )
    print(f"Sweep report written to {out_path}")


def _scene_panel(placement: str, rec: Recorder, sites: dict[str, Vec3]):
    """One rotatable terrain scene, sized for embedding in the report.

    Collapsed: four scenes built eagerly is four WebGL contexts and four
    megabytes of geometry laid out before the reader has asked for any of
    them, on a page whose point is the comparison above.
    """
    from wayfinder_sim.interactive import terrain_scene
    from wayfinder_sim.report import ScenePanel

    positions = rec.column("drone_pos")
    reachable = rec.column("reachable")
    return ScenePanel(
        terrain_scene(
            build_terrain(),
            WORLD,
            tracks={"Drone track": positions},
            markers={"No route": [p for p, r in zip(positions, reachable) if not r]},
            sites=sites,
            timeline=flight_timeline(rec, sites),
        ),
        caption=(
            f"Fly the transit with relays on {placement} — drag to rotate, "
            "scroll to zoom, scrub the slider"
        ),
        collapsed=True,
    )


def main(argv: Sequence[str] | None = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument(
        "--show",
        action="store_true",
        help=(
            "open the 3D render in an interactive matplotlib window (drag to "
            "rotate). Needs a GUI session; the run blocks until you close it."
        ),
    )
    args = parser.parse_args(argv)

    wf.init_tracing()  # quiet by default; set RUST_LOG to see mesh internals

    out_dir = Path(__file__).parent / "output"
    terrain = build_terrain()

    results = run_placement_sweep()
    for result in results:
        placement = result.param
        slug = placement.replace(" ", "_")
        sites = relay_sites(placement, terrain)

        print_connectivity_summary(placement, result.recorder)
        plot_coverage_map(
            placement, result.recorder, sites, out_dir / f"mountain_relay_{slug}.png"
        )
        plot_timeline(
            placement,
            result.recorder,
            out_dir / f"mountain_relay_timeline_{slug}.png",
        )
        write_interactive_scene(
            placement,
            result.recorder,
            sites,
            out_dir / f"mountain_relay_{slug}.html",
        )

    print_sweep_summary(results)
    plot_placement_comparison(results, out_dir / "mountain_relay_placement.png")

    # One oblique render, and one "why was it down" cross-section, off the
    # runs where each is most informative — rather than four near-identical
    # copies of each.
    best = max(results, key=lambda r: stats_for(r.recorder).connected_fraction)
    worst = min(results, key=lambda r: stats_for(r.recorder).connected_fraction)
    plot_worst_outage_profile(
        worst.param,
        worst.recorder,
        relay_sites(worst.param, terrain),
        out_dir / "mountain_relay_profile.png",
    )
    write_sweep_report_page(results, terrain, out_dir)

    # Last, because `--show` blocks on the window until it's closed.
    plot_terrain_3d(
        best.param,
        relay_sites(best.param, terrain),
        out_dir / "mountain_relay_3d.png",
        show=args.show,
    )


if __name__ == "__main__":
    main()
