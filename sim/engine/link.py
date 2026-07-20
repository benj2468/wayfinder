"""An L2 segment joining nodes, carrying a channel model.

Two endpoints is a point-to-point link; more than two is a shared LAN where
every member hears every other (per-pair metrics still come from the same
`channel`, evaluated once per receiver on each delivery).
"""

from __future__ import annotations

import dataclasses

from .channel import Channel


@dataclasses.dataclass
class Link:
    """`endpoints` names the member `Node`s (by `Node.name`), at least two
    distinct. `name` defaults to the endpoints joined with `-`, matching
    `sim/topology.py`'s deterministic-name convention. `trickle`, if set,
    overrides every member's `Node.trickle` for the interface this link
    creates on that node."""

    endpoints: tuple[str, ...]
    channel: Channel
    name: str | None = None
    trickle: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        if len(set(self.endpoints)) < 2:
            raise ValueError(
                f"link {self.endpoints!r} must connect at least two distinct nodes"
            )
        if self.name is None:
            self.name = "-".join(self.endpoints)
