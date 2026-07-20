"""A mesh-node spec.

`Node` is a plan, not the real router — `Simulation` builds the actual
`wf.PyDriver` from it plus the `Link`s that name it as an endpoint, so a
scenario never sizes a trickle list or assigns interface indices by hand.
"""

from __future__ import annotations

import dataclasses

import wayfinder_py as wf

from .mobility import Mobility, Static, Vec3

DEFAULT_TRICKLE = (200, 2000)
"""(i_min_ms, i_max_ms) — a reasonably fast default Trickle schedule."""


@dataclasses.dataclass
class Node:
    """`name` is how scenarios and `Link`s refer to this node; `mac` is
    auto-derived from this node's position in `Simulation`'s node list when
    left `None`. `trickle` is this node's default per-interface Trickle
    schedule, overridable per-`Link`. `tick_interval_ms` is how often
    `Simulation` calls this node's `PyDriver.tick`; when `None` it's derived
    from `trickle`'s `i_min_ms`."""

    name: str
    mobility: Mobility = dataclasses.field(default_factory=lambda: Static(Vec3()))
    mac: wf.PyMac | None = None
    trickle: tuple[int, int] = DEFAULT_TRICKLE
    tick_interval_ms: int | None = None
