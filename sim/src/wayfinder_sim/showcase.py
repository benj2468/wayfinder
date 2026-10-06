"""The results a scenario publishes to the website, as plain JSON.

`report.py` renders a whole run into one self-contained page for whoever ran
it. This is the other audience: the public results page on wayfndr.dev
(`www/sim/`), which has no build step beyond bundling these files and no
Python, and so cannot take a
matplotlib figure or a `Recorder`. What it takes instead is the *answer* —
a few headline numbers, the prose saying what they mean, and the series
behind each chart — which its own small script draws in the site's palette.

Keeping the contract this narrow is the point. A scenario decides what is
worth showing; the page decides how it looks; neither has to change when the
other does, and a re-run of a scenario is a data refresh, not a site edit.

`schema` is bumped whenever a field changes meaning, so a page reading an
old file can tell rather than mis-draw it.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

__all__ = [
    "SCHEMA_VERSION",
    "Chart",
    "Headline",
    "Heatmap",
    "Marker",
    "Series",
    "Showcase",
    "write_showcase",
]

SCHEMA_VERSION = 1

_DECIMALS = 4
"""Floats are rounded to this many places on export: the page draws them a
few hundred pixels wide, and full float precision would multiply the size of
every data file for digits no one can see."""

SeriesKind = Literal["line", "step", "bar", "scatter"]

CATEGORIES = ("resilience", "security", "range", "planning", "capacity")
"""The page's sections, in the order `lab.js` names them (its `CATEGORY`)."""

_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


@dataclasses.dataclass
class Series:
    """One named sequence of points. `kind` is a drawing hint: `step` for a
    signal that holds its value between samples (delivered / not), `bar` for
    a categorical comparison, `scatter` for samples with no order."""

    name: str
    x: list[Any]
    y: list[float | None]
    kind: SeriesKind = "line"

    def __post_init__(self) -> None:
        if len(self.x) != len(self.y):
            raise ValueError(
                f"series {self.name!r}: {len(self.x)} x values but {len(self.y)} y"
            )


@dataclasses.dataclass
class Marker:
    """A vertical rule on a chart at `x`, labelled — "relay powered off"."""

    x: float
    label: str


@dataclasses.dataclass
class Heatmap:
    """A value per grid cell: `values[row][col]` sits at `(xs[col], ys[row])`.
    `None` marks a cell with no data. `label` names what the colour encodes;
    `value_range` pins the colour scale (a ratio is `(0, 1)`)."""

    xs: list[float]
    ys: list[float]
    values: list[list[float | None]]
    label: str
    value_range: tuple[float, float] | None = None

    def __post_init__(self) -> None:
        if len(self.values) != len(self.ys) or any(
            len(row) != len(self.xs) for row in self.values
        ):
            raise ValueError(
                f"heatmap {self.label!r}: values must be {len(self.ys)} rows of {len(self.xs)}"
            )
        # The page sizes every cell from the first gap on each axis, so the
        # grid must be non-empty and evenly spaced, ascending.
        for name, axis in (("xs", self.xs), ("ys", self.ys)):
            if not axis:
                raise ValueError(f"heatmap {self.label!r}: {name} is empty")
            gaps = [b - a for a, b in itertools.pairwise(axis)]
            if gaps and (min(gaps) <= 0 or max(gaps) - min(gaps) > 1e-6 * max(gaps)):
                raise ValueError(f"heatmap {self.label!r}: {name} must ascend evenly")
        if self.value_range is None and not any(
            v is not None for row in self.values for v in row
        ):
            raise ValueError(f"heatmap {self.label!r}: no values and no value_range")


@dataclasses.dataclass
class Chart:
    """One chart: axes, the series drawn on them, and any event markers.
    `y_range`, when given, pins the y axis (a ratio is always `(0, 1)`)."""

    title: str
    x_label: str
    y_label: str
    series: list[Series]
    markers: list[Marker] = dataclasses.field(default_factory=list)
    y_range: tuple[float, float] | None = None
    caption: str | None = None
    x_log: bool = False
    heatmap: Heatmap | None = None
    """A grid drawn beneath the series — a coverage or interference map —
    with any `series` (tracks, sites) plotted over it."""

    def __post_init__(self) -> None:
        if not self.series and self.heatmap is None:
            raise ValueError(f"chart {self.title!r}: nothing to draw")
        if self.y_range is not None and not self.y_range[0] < self.y_range[1]:
            raise ValueError(f"chart {self.title!r}: y_range {self.y_range} is empty")
        if self.x_log and any(
            isinstance(x, (int, float)) and x <= 0 for s in self.series for x in s.x
        ):
            raise ValueError(f"chart {self.title!r}: a log x axis needs positive x")


@dataclasses.dataclass
class Headline:
    """A number worth putting in large type, with what it counts. `detail`
    is the qualifier a careful reader needs ("median of 9 failures")."""

    value: str
    label: str
    detail: str | None = None


@dataclasses.dataclass
class Showcase:
    """Everything the results page shows for one scenario.

    `slug` names the data file (`<slug>.json`) and the page anchor. `question`
    is the one-sentence question the scenario answers, in a customer's words;
    `summary` is the paragraph answering it. `method` says how the number was
    produced, so a reader can judge it; `params` are the knobs it was produced
    with. `table` is an optional grid (first row the header).
    """

    slug: str
    title: str
    question: str
    headlines: list[Headline]
    summary: str
    charts: list[Chart]
    params: dict[str, Any] = dataclasses.field(default_factory=dict)
    method: str | None = None
    table: list[list[Any]] | None = None
    category: str = "resilience"
    scenario: str | None = None
    """Path of the script that produced this, relative to the repo root."""

    def __post_init__(self) -> None:
        if not _SLUG.fullmatch(self.slug):
            raise ValueError(f"slug {self.slug!r}: lowercase words joined by hyphens")
        if self.category not in CATEGORIES:
            raise ValueError(f"category {self.category!r} is not one of {CATEGORIES}")
        if self.table and any(len(row) != len(self.table[0]) for row in self.table):
            raise ValueError(
                f"{self.slug}: table rows differ in length from the header"
            )


def _rounded(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, _DECIMALS)
    if isinstance(value, dict):
        return {k: _rounded(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_rounded(v) for v in value]
    return value


def showcase_dict(showcase: Showcase) -> dict[str, Any]:
    """`showcase` as the JSON-ready dict `write_showcase` serialises."""
    return {"schema": SCHEMA_VERSION, **_rounded(dataclasses.asdict(showcase))}


def write_showcase(showcase: Showcase, out_dir: Path) -> Path:
    """Write `showcase` to `out_dir/<slug>.json` and return the path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{showcase.slug}.json"
    # allow_nan=False: `Infinity`/`NaN` are not JSON. A result that is not a
    # finite number is a scenario bug to fix, not something to publish.
    path.write_text(
        json.dumps(showcase_dict(showcase), indent=1, allow_nan=False) + "\n"
    )
    return path


def downsample(
    x: Sequence[float], y: Sequence[Any], max_points: int = 600
) -> tuple[list[float], list[Any]]:
    """Thin a long time series to roughly `max_points`, keeping every point
    where the value *changes* first — so a step signal keeps its edges
    exactly, and only flat stretches lose samples."""
    if len(x) <= max_points:
        return list(x), list(y)
    keep = {0, len(x) - 1}
    keep.update(i for i in range(1, len(y)) if y[i] != y[i - 1])
    keep.update(i - 1 for i in list(keep) if i > 0)
    if len(keep) < max_points:
        stride = max(1, len(x) // (max_points - len(keep)))
        keep.update(range(0, len(x), stride))
    idx = sorted(keep)
    return [x[i] for i in idx], [y[i] for i in idx]
