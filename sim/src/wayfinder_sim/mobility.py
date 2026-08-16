"""Node position as a pure function of simulation time.

`Mobility.position(t_s)` MUST be deterministic (no RNG): the engine's
per-node and per-delivery SimPy processes call it at whatever instants their
own events land on, not on a fixed global grid, so two calls at the same
`t_s` must always agree.
"""

from __future__ import annotations

import dataclasses
import math
from typing import Literal, Protocol, runtime_checkable

LoopMode = Literal["once", "pingpong", "cycle"]


@dataclasses.dataclass(frozen=True)
class Vec3:
    """A point in metres, ENU world frame (x east, y north, z up)."""

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0

    def distance_to(self, other: Vec3) -> float:
        return math.dist((self.x, self.y, self.z), (other.x, other.y, other.z))


@runtime_checkable
class Mobility(Protocol):
    """Something that can report a node's world position at any simulation
    time `t_s` (seconds since the scenario started)."""

    def position(self, t_s: float) -> Vec3: ...


@dataclasses.dataclass(frozen=True)
class Static:
    """A node that never moves — the common case for fixed infrastructure
    (ground stations, base stations)."""

    at: Vec3

    def position(self, t_s: float) -> Vec3:
        return self.at


@dataclasses.dataclass(frozen=True)
class Waypoints:
    """Piecewise-linear travel through `points` at a constant `speed_m_s`.

    `loop` controls what happens once the last point is reached:
    - `"once"`: stop there — `position` clamps to the final point forever after.
    - `"pingpong"`: reverse and retrace the route back to the first point,
      then repeat (period `2 * duration_s()`).
    - `"cycle"`: jump back to the first point and repeat the route forward
      (period `duration_s()`).
    """

    points: tuple[Vec3, ...]
    speed_m_s: float
    loop: LoopMode = "pingpong"

    def __post_init__(self) -> None:
        if len(self.points) == 0:
            raise ValueError("Waypoints needs at least one point")
        if self.loop not in ("once", "pingpong", "cycle"):
            raise ValueError(f"unknown loop mode: {self.loop!r}")

    def duration_s(self) -> float:
        """Time to travel the route once, start to end."""
        total_length = sum(
            a.distance_to(b) for a, b in zip(self.points, self.points[1:])
        )
        return total_length / self.speed_m_s

    def _position_along(self, distance_m: float) -> Vec3:
        """The point reached after travelling `distance_m` along the route
        from `points[0]`, clamped to the route's own length."""
        remaining = max(0.0, distance_m)
        for a, b in zip(self.points, self.points[1:]):
            seg_len = a.distance_to(b)
            if remaining <= seg_len or seg_len == 0.0:
                if seg_len == 0.0:
                    continue
                frac = remaining / seg_len
                return Vec3(
                    a.x + (b.x - a.x) * frac,
                    a.y + (b.y - a.y) * frac,
                    a.z + (b.z - a.z) * frac,
                )
            remaining -= seg_len
        return self.points[-1]

    def position(self, t_s: float) -> Vec3:
        if len(self.points) == 1:
            return self.points[0]

        duration = self.duration_s()
        if duration == 0.0:
            return self.points[-1]

        if self.loop == "once":
            return self._position_along(max(0.0, t_s) * self.speed_m_s)

        if self.loop == "cycle":
            t_in_cycle = t_s % duration
            return self._position_along(t_in_cycle * self.speed_m_s)

        # pingpong
        period = 2 * duration
        t_in_cycle = t_s % period
        if t_in_cycle <= duration:
            return self._position_along(t_in_cycle * self.speed_m_s)
        return self._position_along((period - t_in_cycle) * self.speed_m_s)


@dataclasses.dataclass(frozen=True)
class Orbit:
    """Circular motion in the horizontal (x/y) plane around `center`, at a
    fixed height `center.z + altitude_m`, completing one revolution every
    `period_s` — a satellite pass, or any node that circles a fixed point
    rather than shuttling between two.

    `phase_s` shifts the starting angle (added to `t_s` before computing
    the orbital angle), useful for staggering multiple orbiting nodes on
    the same period without them coinciding.
    """

    center: Vec3
    radius_m: float
    altitude_m: float
    period_s: float
    phase_s: float = 0.0

    def __post_init__(self) -> None:
        if self.period_s <= 0:
            raise ValueError(f"period_s must be positive, got {self.period_s!r}")

    def position(self, t_s: float) -> Vec3:
        angle = 2 * math.pi * ((t_s + self.phase_s) % self.period_s) / self.period_s
        return Vec3(
            self.center.x + self.radius_m * math.cos(angle),
            self.center.y + self.radius_m * math.sin(angle),
            self.center.z + self.altitude_m,
        )


EARTH_RADIUS_M = 6_371_000.0
"""Mean Earth radius. The scene frame is ENU with its origin *on* the
surface, so the planet's centre sits at `Vec3(0, 0, -EARTH_RADIUS_M)` — which
is what makes a spherical-Earth horizon test exact in these coordinates
rather than an approximation."""

EARTH_MU_M3_S2 = 3.986_004_418e14
"""Earth's standard gravitational parameter (GM), for Kepler's third law."""


@dataclasses.dataclass(frozen=True)
class EarthOrbit:
    """A circular orbit about the planet, rendered into the scene's ENU frame.

    `Orbit` circles a point in the horizontal plane at fixed altitude, which
    is a fair model of a drone flying a racetrack and a poor one of anything
    in space: it never sets, its period is a free parameter, and it stays the
    same distance above the ground however far it travels. At the few
    kilometres that scenario ran over, none of that mattered. At 550 km it is
    the whole story — a real satellite is over the horizon for most of its
    period, and how long it is *not* is the thing a constellation exists to
    fix.

    The orbit is specified by how its ground track runs past the scene rather
    than by classical elements, because that is the question a link budget
    asks:

    - `altitude_m` sets the shell, and with it the period — Kepler's third
      law, not a free choice.
    - `heading_deg` is the compass bearing of the ground track (0 north,
      90 east) as it passes the scene. Different bearings are different
      orbital planes.
    - `ground_offset_m` is how far to the side of the origin the track
      passes. A satellite whose track runs 400 km away never comes overhead,
      and never gets above a modest elevation angle.
    - `phase_s` shifts where along the track the satellite is at `t_s = 0`.
      Satellites in one plane are this orbit at evenly spaced phases, which
      is what makes them a ring rather than a formation.
    """

    altitude_m: float
    heading_deg: float = 0.0
    ground_offset_m: float = 0.0
    phase_s: float = 0.0

    def __post_init__(self) -> None:
        if self.altitude_m <= 0:
            raise ValueError(f"altitude_m must be positive, got {self.altitude_m!r}")

    @property
    def radius_m(self) -> float:
        """Orbital radius measured from the planet's centre, not the ground."""
        return EARTH_RADIUS_M + self.altitude_m

    @property
    def period_s(self) -> float:
        """One revolution, from Kepler's third law."""
        return 2 * math.pi * math.sqrt(self.radius_m**3 / EARTH_MU_M3_S2)

    def _basis(self) -> tuple[tuple[float, float, float], tuple[float, float, float]]:
        """The orbital plane's two in-plane unit vectors, in ENU axes.

        `u` points at the closest-approach direction (so `t_s = 0` puts the
        satellite nearest the scene) and `v` at the direction of travel
        there, so the ground track runs along `heading_deg`.
        """
        psi = math.radians(self.heading_deg)
        # Angular distance from the origin's zenith to the ground track.
        alpha = self.ground_offset_m / EARTH_RADIUS_M
        # Cross-track horizontal direction (heading rotated 90 degrees), then
        # the plane normal tilted off the zenith by exactly `alpha`.
        cross = (math.cos(psi), -math.sin(psi), 0.0)
        normal = (
            math.cos(alpha) * cross[0],
            math.cos(alpha) * cross[1],
            math.sin(alpha),
        )
        # Closest approach: the zenith direction projected into the plane.
        zenith_in_plane = (
            -normal[2] * normal[0],
            -normal[2] * normal[1],
            1 - normal[2] ** 2,
        )
        norm = math.sqrt(sum(c * c for c in zenith_in_plane))
        u = tuple(c / norm for c in zenith_in_plane)
        v = (
            u[1] * normal[2] - u[2] * normal[1],
            u[2] * normal[0] - u[0] * normal[2],
            u[0] * normal[1] - u[1] * normal[0],
        )
        return u, v  # type: ignore[return-value]

    def position(self, t_s: float) -> Vec3:
        theta = 2 * math.pi * (t_s + self.phase_s) / self.period_s
        u, v = self._basis()
        r = self.radius_m
        cos_t, sin_t = math.cos(theta), math.sin(theta)
        # Earth-centred, then dropped into ENU by moving the origin from the
        # planet's centre up to the surface point the scene is pinned to.
        return Vec3(
            r * (cos_t * u[0] + sin_t * v[0]),
            r * (cos_t * u[1] + sin_t * v[1]),
            r * (cos_t * u[2] + sin_t * v[2]) - EARTH_RADIUS_M,
        )


@dataclasses.dataclass(frozen=True)
class GreatCircle:
    """Travel at a constant altitude above a curved Earth, along a great
    circle on `heading_deg`.

    `Waypoints` interpolates straight lines through the ENU frame, which holds
    `z` fixed while the planet curves away underneath. Over the few kilometres
    a drone scenario flies, the difference is centimetres. Over the thousands
    an airliner flies it is the dominant term: a "10 km" cruise held straight
    for 9,000 km ends up 4,662 km from the ground, above the shell of any LEO
    constellation meant to be serving it, seeing satellites no aircraft could.

    Distances are arcs over the surface, not chords, so `range_m` is directly
    comparable to a satellite's footprint radius.
    """

    range_m: float
    speed_m_s: float
    altitude_m: float = 0.0
    heading_deg: float = 0.0
    loop: LoopMode = "pingpong"

    def __post_init__(self) -> None:
        if self.speed_m_s <= 0:
            raise ValueError(f"speed_m_s must be positive, got {self.speed_m_s!r}")
        if self.range_m <= 0:
            raise ValueError(f"range_m must be positive, got {self.range_m!r}")
        if self.loop not in ("once", "pingpong", "cycle"):
            raise ValueError(f"unknown loop mode {self.loop!r}")

    def duration_s(self) -> float:
        """Time to fly one leg."""
        return self.range_m / self.speed_m_s

    def _travelled_m(self, t_s: float) -> float:
        """Arc flown by `t_s`, with the loop mode applied — the same three
        modes `Waypoints` offers, on a one-legged route."""
        distance = self.speed_m_s * max(0.0, t_s)
        if self.loop == "once":
            return min(distance, self.range_m)
        if self.loop == "cycle":
            return distance % self.range_m
        leg = distance % (2 * self.range_m)
        return leg if leg <= self.range_m else 2 * self.range_m - leg

    def position(self, t_s: float) -> Vec3:
        # Arc measured at the surface, so `range_m` means ground distance
        # rather than distance flown at altitude.
        angle = self._travelled_m(t_s) / EARTH_RADIUS_M
        psi = math.radians(self.heading_deg)
        r = EARTH_RADIUS_M + self.altitude_m
        return Vec3(
            r * math.sin(angle) * math.sin(psi),
            r * math.sin(angle) * math.cos(psi),
            r * math.cos(angle) - EARTH_RADIUS_M,
        )
