"""Shared chart chrome for static matplotlib figures.

The palette itself lives in `palette.py` (and is re-exported here, so
existing `from .plotting import PALETTE` imports keep working) — it is shared
with the plotly-backed `interactive` module, and neither renderer should have
to import the other's stack to agree on colors.

Only imported when a scenario actually plots — keeps matplotlib out of the
import graph for pure-logic engine use (see `__init__.py`).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, cast

from matplotlib.axes import Axes
from mpl_toolkits.mplot3d.axes3d import Axes3D

from .connectivity import Outage
from .mobility import Vec3
from .palette import PALETTE, TERRAIN_RAMP, Palette
from .terrain import Bounds, Terrain


def style_axes(axes: Iterable[Axes], palette: Palette = PALETTE) -> None:
    """Apply the shared surface/ink/grid chrome to every axis in `axes`."""
    for ax in axes:
        ax.set_facecolor(palette.surface)
        for spine in ax.spines.values():
            spine.set_color(palette.axis)
        ax.tick_params(colors=palette.ink_muted, labelsize=9)
        ax.grid(True, color=palette.gridline, linewidth=0.8)
        ax.set_axisbelow(True)


def state_band(
    ax: Axes,
    t: Iterable[float],
    states: Iterable[Any],
    *,
    palette: Palette = PALETTE,
    labels: Mapping[Any, str] | None = None,
) -> None:
    """A categorical identity timeline (which state is current, not a
    magnitude) rendered as filled bands rather than a numeric y-axis — e.g.
    `Recorder.column("route")` from a `Simulation.record("route", ...)`
    probe. Each distinct non-`None` value in `states` gets its own band in
    `palette.series` order (first-seen); `None` samples (not yet resolved)
    contribute to no band. `labels` overrides a value's legend text
    (default: `str(value)`)."""
    t = list(t)
    states = list(states)

    seen: dict[Any, int] = {}
    for value in states:
        if value is not None and value not in seen:
            seen[value] = len(seen)

    for value, order in seen.items():
        color = palette.series[order % len(palette.series)]
        band = [1 if s == value else 0 for s in states]
        label = labels[value] if labels and value in labels else str(value)
        ax.fill_between(t, 0, band, step="post", color=color, label=label)

    ax.set_ylim(0, 1)
    ax.set_yticks([])


def style_axes_3d(ax: Axes3D, palette: Palette = PALETTE) -> None:
    """Apply the shared surface/ink chrome to a 3D axes (`projection="3d"`)."""
    ax.set_facecolor(palette.surface)
    for axis in (ax.xaxis, ax.yaxis, ax.zaxis):
        # `.pane`/`.line` are real Axes3D attributes matplotlib adds at
        # runtime; its type stubs still type these as plain 2D Axis. `cast`
        # (rather than a line-pinned `pyright: ignore`) survives reformatting.
        axis3d = cast(Any, axis)
        axis3d.pane.set_facecolor(palette.surface)
        axis3d.pane.set_edgecolor(palette.axis)
        axis3d.line.set_color(palette.axis)
    ax.tick_params(colors=palette.ink_muted, labelsize=8)
    ax.xaxis.label.set_color(palette.ink_secondary)
    ax.yaxis.label.set_color(palette.ink_secondary)
    ax.zaxis.label.set_color(palette.ink_secondary)


def trajectory_3d(
    ax: Axes3D,
    positions: Iterable[Vec3],
    *,
    color: str,
    label: str | None = None,
    linewidth: float = 2.0,
) -> None:
    """A moving node's path through world space — e.g.
    `Recorder.column("low_pos")` from a `Simulation.record("low_pos", lambda
    s: s.position("low"))` probe."""
    positions = list(positions)
    ax.plot(
        [p.x for p in positions],
        [p.y for p in positions],
        [p.z for p in positions],
        color=color,
        linewidth=linewidth,
        label=label,
    )


def point_3d(
    ax: Axes3D,
    position: Vec3,
    *,
    color: str,
    label: str | None = None,
    marker: str = "^",
    size: float = 80.0,
) -> None:
    """A fixed node's position — e.g. static ground infrastructure."""
    # matplotlib's stubs type Axes.scatter's 2D signature (int-only `zs`/`s`)
    # even on Axes3D, where the real 3D override accepts array-likes/floats.
    # `cast` (rather than a line-pinned `pyright: ignore`) survives reformatting.
    cast(Any, ax).scatter(
        [position.x],
        [position.y],
        [position.z],
        color=color,
        label=label,
        marker=marker,
        s=size,
    )  # pyright: ignore[reportArgumentType]


def _terrain_colormap(ramp: Sequence[str] = TERRAIN_RAMP):
    from matplotlib.colors import LinearSegmentedColormap

    return LinearSegmentedColormap.from_list("wayfinder_terrain", list(ramp))


def terrain_surface_3d(
    ax: Axes3D,
    terrain: Terrain,
    bounds: Bounds,
    *,
    resolution: int = 60,
    ramp: Sequence[str] = TERRAIN_RAMP,
    alpha: float = 0.9,
) -> None:
    """The ground itself, as a shaded relief surface under the trajectories.

    `resolution` is the number of samples per axis — this is a picture, not
    the model the channel evaluates against, so it can be far coarser than
    the terrain's real detail without affecting any result.
    """
    if resolution < 2:
        raise ValueError(f"resolution must be at least 2, got {resolution!r}")

    xs = [
        bounds.min_x + bounds.width_m * i / (resolution - 1) for i in range(resolution)
    ]
    ys = [
        bounds.min_y + bounds.depth_m * j / (resolution - 1) for j in range(resolution)
    ]
    # `plot_surface` requires real ndarrays rather than nested sequences.
    # numpy is a hard dependency of matplotlib, so it is always present
    # wherever this module is importable at all (the `plot` extra).
    import numpy as np

    grid_x = np.array([list(xs) for _ in ys])
    grid_y = np.array([[y for _ in xs] for y in ys])
    grid_z = np.array([[terrain.elevation(x, y) for x in xs] for y in ys])

    cast(Any, ax).plot_surface(
        grid_x,
        grid_y,
        grid_z,
        cmap=_terrain_colormap(ramp),
        linewidth=0,
        antialiased=True,
        alpha=alpha,
        rstride=1,
        cstride=1,
    )


def terrain_contour(
    ax: Axes,
    terrain: Terrain,
    bounds: Bounds,
    *,
    resolution: int = 120,
    levels: int = 12,
    ramp: Sequence[str] = TERRAIN_RAMP,
):
    """The ground as a filled contour map, seen from above — the base layer
    for a plan-view coverage chart.

    Preferred over `terrain_surface_3d` whenever the question is *where*
    something happened along a route: a 3D surface renders a track behind the
    peaks it passes (matplotlib composites surfaces and lines by painter's
    order, not by depth), while a plan view never hides it. Returns the
    contour set, so a caller can hang a colorbar off it.
    """
    if resolution < 2:
        raise ValueError(f"resolution must be at least 2, got {resolution!r}")

    xs = [
        bounds.min_x + bounds.width_m * i / (resolution - 1) for i in range(resolution)
    ]
    ys = [
        bounds.min_y + bounds.depth_m * j / (resolution - 1) for j in range(resolution)
    ]
    grid_z = [[terrain.elevation(x, y) for x in xs] for y in ys]

    return ax.contourf(xs, ys, grid_z, levels=levels, cmap=_terrain_colormap(ramp))


def terrain_profile(
    ax: Axes,
    terrain: Terrain,
    a: Vec3,
    b: Vec3,
    *,
    freq_hz: float | None = None,
    samples: int = 128,
    palette: Palette = PALETTE,
    ramp: Sequence[str] = TERRAIN_RAMP,
) -> None:
    """A vertical slice through the ground between two nodes, with the line of
    sight over it — the chart that explains *why* a link works or doesn't,
    where a distance-vs-quality plot can only show that it doesn't.

    Pass `freq_hz` to also draw the first Fresnel zone, whose intrusion (not
    the bare line of sight) is what actually governs diffraction loss.
    """
    from .terrain import elevation_profile, fresnel_radius_m

    profile = elevation_profile(terrain, a, b, samples=samples)
    if not profile:
        return

    total_m = math.dist((a.x, a.y), (b.x, b.y))
    # Endpoints are excluded from the profile by design, but the picture wants
    # the ground and the sight line to run the full span.
    distances = [0.0, *(p.distance_m for p in profile), total_m]
    ground = [
        terrain.elevation(a.x, a.y),
        *(p.position.z for p in profile),
        terrain.elevation(b.x, b.y),
    ]
    line_of_sight = [a.z, *(p.los_z_m for p in profile), b.z]

    ax.fill_between(distances, 0, ground, color=ramp[-2], label="Ground")
    ax.plot(
        distances,
        line_of_sight,
        color=palette.series[0],
        linewidth=2,
        label="Line of sight",
    )

    if freq_hz is not None:
        radii = [
            0.0,
            *(
                fresnel_radius_m(p.distance_m, total_m - p.distance_m, freq_hz)
                for p in profile
            ),
            0.0,
        ]
        ax.fill_between(
            distances,
            [z - r for z, r in zip(line_of_sight, radii)],
            [z + r for z, r in zip(line_of_sight, radii)],
            color=palette.series[0],
            alpha=0.15,
            linewidth=0,
            label="First Fresnel zone",
        )

    ax.set_ylim(bottom=0)


def outage_spans(
    ax: Axes,
    outages: Iterable[Outage],
    *,
    palette: Palette = PALETTE,
    label: str | None = "No route",
) -> None:
    """Shade every connectivity outage across an existing panel, so the gaps
    are read against whatever that panel plots (altitude, distance, quality)
    rather than as a separate timeline the eye has to correlate by hand.

    Only the first span carries `label`, so the legend gets one entry rather
    than one per outage.
    """
    for i, outage in enumerate(outages):
        ax.axvspan(
            outage.start_s,
            outage.end_s,
            color=palette.series[5],  # red — a loss-of-service state, not a series
            alpha=0.18,
            linewidth=0,
            label=label if i == 0 else None,
        )
