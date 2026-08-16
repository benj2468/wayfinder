"""Ground elevation, and the line-of-sight geometry a radio needs to know
whether a mountain is in the way.

A `Terrain` answers one question — "how high is the ground at (x, y)?" — in
the same ENU world frame `mobility.Vec3` uses (x east, y north, z up, metres).
Everything else here is built on that: sampling the ground profile under the
straight line between two nodes (`elevation_profile`), turning the worst
obstruction on that profile into the dimensionless Fresnel parameter a
diffraction model consumes (`max_fresnel_parameter`), flying a route at a
fixed height above ground rather than a fixed altitude (`TerrainFollowing`),
and picking summit/valley-floor sites to place relays on (`peak_sites`,
`valley_sites`).

This module deliberately stops short of dB: it reports *geometry*, and
`channel.TerrainMasked` turns that geometry into path loss. The split keeps
the terrain half testable against closed-form expectations (a Gaussian
summit's height, the 60%-first-Fresnel-zone rule) without an RF model in the
way.

Earth curvature and atmospheric refraction are not modelled — over the
single-digit-kilometre paths these scenarios cover, both are well under the
error already introduced by a synthetic heightmap.
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from .mobility import Mobility, Vec3

SPEED_OF_LIGHT_M_S = 299_792_458.0
"""Canonical definition for the package: `channel` re-exports it rather than
holding its own, since the Fresnel geometry here and the path-loss model
there must agree on the wavelength they derive from a frequency."""

DEFAULT_PROFILE_SAMPLES = 64
"""Ground samples taken between two endpoints when a caller doesn't say.
Enough to catch a ridge line at the scale these scenarios run at (kilometres
of path against hundreds of metres of summit width) without making a
per-frame channel evaluation expensive."""


@dataclasses.dataclass(frozen=True)
class Bounds:
    """An axis-aligned horizontal extent, in metres, in the world frame."""

    min_x: float
    min_y: float
    max_x: float
    max_y: float

    def __post_init__(self) -> None:
        if self.max_x < self.min_x or self.max_y < self.min_y:
            raise ValueError(
                f"inverted bounds: ({self.min_x}, {self.min_y}) "
                f"is not below-left of ({self.max_x}, {self.max_y})"
            )

    @property
    def width_m(self) -> float:
        """Extent along x (east)."""
        return self.max_x - self.min_x

    @property
    def depth_m(self) -> float:
        """Extent along y (north)."""
        return self.max_y - self.min_y

    @property
    def center(self) -> Vec3:
        """The horizontal midpoint, at z = 0 — bounds carry no elevation."""
        return Vec3((self.min_x + self.max_x) / 2, (self.min_y + self.max_y) / 2, 0.0)


@runtime_checkable
class Terrain(Protocol):
    """Ground elevation as a pure function of horizontal position.

    Like `Mobility.position`, implementations MUST be deterministic and
    side-effect-free: the engine samples them at whatever points a channel
    evaluation lands on, many times per delivered frame, and two calls at the
    same (x, y) must always agree.
    """

    def elevation(self, x: float, y: float) -> float:
        """Height of the ground above the world frame's z = 0, in metres."""
        ...


@dataclasses.dataclass(frozen=True)
class FlatGround:
    """Featureless ground at a constant elevation — the implicit terrain of
    every scenario that doesn't model any, and the control case to compare a
    mountain run against."""

    elevation_m: float = 0.0

    def elevation(self, x: float, y: float) -> float:
        return self.elevation_m


@dataclasses.dataclass(frozen=True)
class GaussianPeak:
    """A single radially-symmetric summit: `height_m` at its centre, falling
    off with a Gaussian of width `sigma_m` (so ~61% of peak height one sigma
    out, ~1% at 3 sigma — read `sigma_m` as "how broad the mountain is")."""

    x: float
    y: float
    height_m: float
    sigma_m: float

    def __post_init__(self) -> None:
        if self.sigma_m <= 0:
            raise ValueError(f"sigma_m must be positive, got {self.sigma_m!r}")

    def contribution(self, x: float, y: float) -> float:
        """This peak's own contribution to the elevation at (x, y)."""
        dx, dy = x - self.x, y - self.y
        return self.height_m * math.exp(-(dx * dx + dy * dy) / (2 * self.sigma_m**2))


@dataclasses.dataclass(frozen=True)
class MountainRange:
    """An analytic terrain: `base_elevation_m` plus the sum of every peak's
    contribution.

    Analytic rather than gridded, so there's no interpolation error between
    what a scenario declares and what the channel sees, and a range is a few
    lines to write. Overlapping peaks add, which is how a ridge is built: a
    line of peaks a sigma or so apart reads as a continuous crest rather than
    separate summits, and the low ground between two ridges is the valley a
    drone flies up.

    For real DEM data, use `Heightmap` instead; to render or search *this*
    terrain, rasterize it with `to_heightmap`.
    """

    peaks: tuple[GaussianPeak, ...] = ()
    base_elevation_m: float = 0.0

    def elevation(self, x: float, y: float) -> float:
        return self.base_elevation_m + sum(p.contribution(x, y) for p in self.peaks)

    def to_heightmap(self, bounds: Bounds, cell_size_m: float) -> Heightmap:
        """Sample this terrain onto a regular grid covering `bounds`.

        The grid always covers `bounds` completely, extending past `max_x` /
        `max_y` when the extent isn't a whole number of cells; on an exact
        multiple the rasterized `Heightmap.bounds` equals `bounds`.
        """
        if cell_size_m <= 0:
            raise ValueError(f"cell_size_m must be positive, got {cell_size_m!r}")
        cols = max(2, math.ceil(bounds.width_m / cell_size_m) + 1)
        rows = max(2, math.ceil(bounds.depth_m / cell_size_m) + 1)
        grid = [
            [
                self.elevation(
                    bounds.min_x + i * cell_size_m, bounds.min_y + j * cell_size_m
                )
                for i in range(cols)
            ]
            for j in range(rows)
        ]
        return Heightmap.from_rows(
            grid,
            cell_size_m=cell_size_m,
            origin_x=bounds.min_x,
            origin_y=bounds.min_y,
        )


@dataclasses.dataclass(frozen=True)
class Heightmap:
    """A regular grid of elevation samples, bilinearly interpolated between
    grid nodes — the shape real DEM data arrives in.

    `heights[j][i]` is the elevation at `(origin_x + i * cell_size_m,
    origin_y + j * cell_size_m)`: rows advance north (+y), columns advance
    east (+x). Queries outside the grid clamp to the nearest edge node rather
    than raising, so a node that strays off the mapped area keeps a defined
    (if flat) ground under it instead of crashing a run mid-flight.
    """

    heights: tuple[tuple[float, ...], ...]
    cell_size_m: float
    origin_x: float = 0.0
    origin_y: float = 0.0

    def __post_init__(self) -> None:
        if self.cell_size_m <= 0:
            raise ValueError(f"cell_size_m must be positive, got {self.cell_size_m!r}")
        if not self.heights or not self.heights[0]:
            raise ValueError("heightmap needs at least one row of at least one column")
        widths = {len(row) for row in self.heights}
        if len(widths) != 1:
            raise ValueError(f"ragged heightmap: rows have lengths {sorted(widths)}")

    @classmethod
    def from_rows(
        cls,
        rows: Sequence[Sequence[float]],
        cell_size_m: float,
        *,
        origin_x: float = 0.0,
        origin_y: float = 0.0,
    ) -> Heightmap:
        """Build from any nested sequence (a list of lists, a loaded DEM),
        copying it into the frozen tuple-of-tuples the dataclass holds."""
        return cls(
            heights=tuple(tuple(float(v) for v in row) for row in rows),
            cell_size_m=cell_size_m,
            origin_x=origin_x,
            origin_y=origin_y,
        )

    @property
    def bounds(self) -> Bounds:
        """The horizontal extent the grid nodes span."""
        return Bounds(
            self.origin_x,
            self.origin_y,
            self.origin_x + (len(self.heights[0]) - 1) * self.cell_size_m,
            self.origin_y + (len(self.heights) - 1) * self.cell_size_m,
        )

    def elevation(self, x: float, y: float) -> float:
        cols, rows = len(self.heights[0]), len(self.heights)
        fx = min(max((x - self.origin_x) / self.cell_size_m, 0.0), cols - 1)
        fy = min(max((y - self.origin_y) / self.cell_size_m, 0.0), rows - 1)

        i0, j0 = math.floor(fx), math.floor(fy)
        i1, j1 = min(i0 + 1, cols - 1), min(j0 + 1, rows - 1)
        tx, ty = fx - i0, fy - j0

        south = self.heights[j0][i0] * (1 - tx) + self.heights[j0][i1] * tx
        north = self.heights[j1][i0] * (1 - tx) + self.heights[j1][i1] * tx
        return south * (1 - ty) + north * ty


@dataclasses.dataclass(frozen=True)
class TerrainFollowing:
    """Fly `base`'s *ground track* at a fixed height above the ground, rather
    than at a fixed altitude.

    Only `base.position`'s x/y are used — its z is ignored entirely — so a
    route can be written as plain waypoints at z = 0 and still clear the
    terrain it crosses. This is how a drone actually transits a mountain
    valley: it holds an altitude relative to what's under it, which means its
    absolute height (and so its line of sight to a relay) rises and falls
    with the ground.
    """

    base: Mobility
    terrain: Terrain
    agl_m: float

    def position(self, t_s: float) -> Vec3:
        p = self.base.position(t_s)
        return Vec3(p.x, p.y, self.terrain.elevation(p.x, p.y) + self.agl_m)


@dataclasses.dataclass(frozen=True)
class ProfilePoint:
    """One sample of the ground under the straight line joining two nodes."""

    distance_m: float
    """Horizontal distance from the first endpoint."""

    position: Vec3
    """The sampled ground point: the track's (x, y), at the terrain's height."""

    los_z_m: float
    """Height of the line of sight itself directly above this point."""

    @property
    def clearance_m(self) -> float:
        """How far the line of sight passes above the ground here — negative
        when the ground is *through* the line, i.e. an obstruction."""
        return self.los_z_m - self.position.z


def elevation_profile(
    terrain: Terrain,
    a: Vec3,
    b: Vec3,
    *,
    samples: int = DEFAULT_PROFILE_SAMPLES,
) -> list[ProfilePoint]:
    """Sample the ground under the line from `a` to `b` at `samples` evenly
    spaced points, strictly between the endpoints.

    The endpoints themselves are excluded: the ground at a node's own
    position is not an obstruction to it (a relay standing on a summit is not
    blocked by that summit), and the Fresnel geometry is singular there.
    Returns `[]` when `a` and `b` share a horizontal position — a purely
    vertical path has no ground track to sample and nothing can be between
    them.
    """
    if samples < 1:
        raise ValueError(f"samples must be at least 1, got {samples!r}")

    ground_distance_m = math.dist((a.x, a.y), (b.x, b.y))
    if ground_distance_m == 0.0:
        return []

    profile: list[ProfilePoint] = []
    for k in range(1, samples + 1):
        frac = k / (samples + 1)
        x = a.x + (b.x - a.x) * frac
        y = a.y + (b.y - a.y) * frac
        profile.append(
            ProfilePoint(
                distance_m=ground_distance_m * frac,
                position=Vec3(x, y, terrain.elevation(x, y)),
                los_z_m=a.z + (b.z - a.z) * frac,
            )
        )
    return profile


def has_line_of_sight(
    terrain: Terrain,
    a: Vec3,
    b: Vec3,
    *,
    samples: int = DEFAULT_PROFILE_SAMPLES,
) -> bool:
    """Whether the ground stays below the straight line joining `a` and `b`.

    Strictly geometric — a path can be clear by this test and still be a poor
    radio link, because grazing an obstruction costs ~6 dB even with positive
    clearance. Use `max_fresnel_parameter` where that matters; this is for
    coverage questions ("can this summit see that valley at all?").
    """
    return all(
        p.clearance_m > 0 for p in elevation_profile(terrain, a, b, samples=samples)
    )


def fresnel_radius_m(d1_m: float, d2_m: float, freq_hz: float) -> float:
    """Radius of the first Fresnel zone at the point `d1_m` along a path
    whose remaining length is `d2_m` — widest at midpath, pinching to zero at
    both endpoints.

    Keeping ~60% of this radius clear of obstructions is the classic test for
    a path that behaves as if it were free-space.
    """
    total_m = d1_m + d2_m
    if total_m <= 0 or d1_m <= 0 or d2_m <= 0:
        return 0.0
    wavelength_m = SPEED_OF_LIGHT_M_S / freq_hz
    return math.sqrt(wavelength_m * d1_m * d2_m / total_m)


def fresnel_parameter(
    clearance_m: float, d1_m: float, d2_m: float, freq_hz: float
) -> float:
    """The dimensionless knife-edge diffraction parameter `v` for an obstacle
    offering `clearance_m` at the point `d1_m` / `d2_m` along a path.

    Sign follows the usual convention, which is the opposite of clearance's:
    positive `v` means the obstacle intrudes into the path (the ground is
    above the line of sight), `v = 0` is exactly grazing, and negative `v` is
    a clear path. `v = -0.6*sqrt(2) ~ -0.85` is the 60%-clearance rule, just
    past the `v = -0.78` point below which diffraction loss vanishes
    entirely.

    Returns `-inf` at a path endpoint, where the Fresnel zone pinches to zero
    and nothing can obstruct.
    """
    radius_m = fresnel_radius_m(d1_m, d2_m, freq_hz)
    if radius_m <= 0:
        return -math.inf
    return -clearance_m * math.sqrt(2.0) / radius_m


def max_fresnel_parameter(
    terrain: Terrain,
    a: Vec3,
    b: Vec3,
    freq_hz: float,
    *,
    samples: int = DEFAULT_PROFILE_SAMPLES,
) -> float:
    """The worst (largest) `fresnel_parameter` anywhere along the path from
    `a` to `b` — the single obstacle a knife-edge model reduces the whole
    terrain profile to.

    Returns `-inf` for a path with no ground track to sample (see
    `elevation_profile`), i.e. "nothing in the way".
    """
    profile = elevation_profile(terrain, a, b, samples=samples)
    if not profile:
        return -math.inf
    total_m = math.dist((a.x, a.y), (b.x, b.y))
    return max(
        fresnel_parameter(p.clearance_m, p.distance_m, total_m - p.distance_m, freq_hz)
        for p in profile
    )


def _extreme_sites(
    terrain: Terrain,
    bounds: Bounds,
    count: int,
    spacing_m: float,
    min_separation_m: float,
    *,
    highest: bool,
) -> tuple[Vec3, ...]:
    if spacing_m <= 0:
        raise ValueError(f"spacing_m must be positive, got {spacing_m!r}")

    cols = math.floor(bounds.width_m / spacing_m) + 1
    rows = math.floor(bounds.depth_m / spacing_m) + 1
    candidates = [
        Vec3(x, y, terrain.elevation(x, y))
        for j in range(rows)
        for i in range(cols)
        for x, y in ((bounds.min_x + i * spacing_m, bounds.min_y + j * spacing_m),)
    ]
    candidates.sort(key=lambda p: p.z, reverse=highest)

    chosen: list[Vec3] = []
    for candidate in candidates:
        if len(chosen) >= count:
            break
        if all(
            math.dist((candidate.x, candidate.y), (c.x, c.y)) >= min_separation_m
            for c in chosen
        ):
            chosen.append(candidate)
    return tuple(chosen)


def peak_sites(
    terrain: Terrain,
    bounds: Bounds,
    count: int,
    *,
    spacing_m: float = 100.0,
    min_separation_m: float = 0.0,
) -> tuple[Vec3, ...]:
    """Up to `count` summit sites within `bounds`, highest first, each
    returned as a `Vec3` carrying the ground elevation as its `z`.

    Sites are picked greedily off a `spacing_m` grid, skipping any candidate
    within `min_separation_m` of one already chosen. That separation is what
    makes the result *distinct summits* rather than several adjacent cells of
    the same one, so set it to roughly a summit's width; the `0.0` default
    imposes no constraint and is only sensible for `count=1`. Fewer than
    `count` sites come back when the separation leaves no room for more.
    """
    return _extreme_sites(
        terrain, bounds, count, spacing_m, min_separation_m, highest=True
    )


def valley_sites(
    terrain: Terrain,
    bounds: Bounds,
    count: int,
    *,
    spacing_m: float = 100.0,
    min_separation_m: float = 0.0,
) -> tuple[Vec3, ...]:
    """Up to `count` valley-floor sites within `bounds`, lowest first — the
    counterpart to `peak_sites`, for placing a relay down where the flying is
    rather than up where the seeing is."""
    return _extreme_sites(
        terrain, bounds, count, spacing_m, min_separation_m, highest=False
    )
