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
