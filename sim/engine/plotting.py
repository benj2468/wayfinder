"""Shared chart chrome — palette per the dataviz skill's validated reference
instance (`references/palette.md`): the full 8-hue categorical set (blue,
aqua, yellow, green, violet, red, magenta, orange, in that order), light
chart surface, muted ink for axes/gridlines. Reused verbatim (not
re-derived), since these are the pre-validated default hues (ordered to
maximize the minimum adjacent CVD-safe color distance), not a new brand
palette. Only the first 2 mattered while every scenario's categorical charts
had 2 states; a 3+-state chart (e.g. more than one alternate route) needs
the rest, so all 8 are here up front rather than patched in per scenario.

Only imported when a scenario actually plots — keeps matplotlib out of the
import graph for pure-logic engine use (see `engine/__init__.py`).
"""

from __future__ import annotations

import dataclasses
from typing import Any, Iterable, Mapping, cast

from matplotlib.axes import Axes
from mpl_toolkits.mplot3d.axes3d import Axes3D

from .mobility import Vec3


@dataclasses.dataclass(frozen=True)
class Palette:
    """A small, ordered set of categorical series hues plus the ink/surface
    colors every panel in a chart shares."""

    series: tuple[str, ...]
    surface: str
    ink_primary: str
    ink_secondary: str
    ink_muted: str
    gridline: str
    axis: str


PALETTE = Palette(
    series=(
        "#2a78d6",  # blue
        "#1baf7a",  # aqua
        "#eda100",  # yellow
        "#008300",  # green
        "#4a3aa7",  # violet
        "#e34948",  # red
        "#e87ba4",  # magenta
        "#eb6834",  # orange
    ),
    surface="#fcfcfb",
    ink_primary="#0b0b0b",
    ink_secondary="#52514e",
    ink_muted="#898781",
    gridline="#e1e0d9",
    axis="#c3c2b7",
)


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
