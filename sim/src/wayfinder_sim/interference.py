"""Interference sources: transmitters that carry nothing and cost everyone.

A `Jammer` radiates `power_dbm` from wherever its `Mobility` puts it, and its
signal reaches every receiver on the links it targets through free-space
loss at its own frequency. A reception then has to beat the *sum* of that
interference — plus, on a contended `Medium`, every frame overlapping it — by
the capture margin to survive. That is the signal-to-interference test real
receivers apply, and it is what makes jamming a function of geometry: a
jammer beside one node silences it while a node across the valley, hearing a
strong neighbour, barely notices.

This models a wideband noise jammer, on whenever its `active` window says so.
It does not model a reactive jammer (one that keys up only on hearing a
preamble) or a protocol-aware one; both are cheaper for the attacker and
harsher for the mesh, and both would sit behind the same `received_dbm`.
"""

from __future__ import annotations

import dataclasses
import math

from .channel import FreeSpacePathLoss
from .mobility import Mobility, Vec3

__all__ = ["DEFAULT_CAPTURE_DB", "Jammer", "sum_dbm"]

DEFAULT_CAPTURE_DB = 6.0
"""Signal-to-interference margin a reception needs on a link with no
`Medium` to supply its own `capture_db`."""


@dataclasses.dataclass(frozen=True)
class Jammer:
    """A noise source. `links` names the links it reaches (`None`: all of
    them — a wideband jammer); `active` is the `(start_s, end_s)` window it
    transmits in (`None`: always)."""

    name: str
    mobility: Mobility
    power_dbm: float
    freq_hz: float = 2.4e9
    links: tuple[str, ...] | None = None
    active: tuple[float, float] | None = None

    def __post_init__(self) -> None:
        if self.active is not None and not self.active[0] < self.active[1]:
            raise ValueError(
                f"jammer {self.name!r}: active window {self.active} is empty"
            )
        if isinstance(self.links, str):
            # A bare string would be matched as a substring by `in`.
            raise TypeError(
                f"jammer {self.name!r}: links must be a tuple of names, not a str"
            )
        if self.links is not None:
            object.__setattr__(self, "links", tuple(self.links))

    def is_active(self, t_s: float) -> bool:
        """Whether it is transmitting at `t_s`."""
        return self.active is None or self.active[0] <= t_s < self.active[1]

    def overlaps(self, start_s: float, end_s: float) -> bool:
        """Whether it transmits at any point in `[start_s, end_s]` — the same
        half-open `[start, end)` window `is_active` uses, so an instant query
        (`start_s == end_s`) agrees with it."""
        return self.active is None or (
            self.active[0] <= end_s and self.active[1] > start_s
        )

    def reaches(self, link: str) -> bool:
        """Whether it targets `link`."""
        return self.links is None or link in self.links

    def received_dbm(self, rx: Vec3, t_s: float) -> float:
        """Its power arriving at `rx`, ignoring whether it is active."""
        distance = self.mobility.position(t_s).distance_to(rx)
        return self.power_dbm - FreeSpacePathLoss(freq_hz=self.freq_hz).path_loss_db(
            distance
        )


def sum_dbm(levels_dbm) -> float | None:
    """Power sum of `levels_dbm`, in dBm; `None` for nothing at all."""
    total_mw = sum(10.0 ** (level / 10.0) for level in levels_dbm)
    return 10.0 * math.log10(total_mw) if total_mw > 0 else None
