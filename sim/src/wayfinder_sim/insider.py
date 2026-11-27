"""A member of the mesh that misbehaves at forwarding — the insider half of a
red-team scenario.

`forge` and `Simulation.inject` model an attacker with no credentials. This
models one holding a captured radio: its router, certificate and keys are all
genuine, and its firmware simply declines to put some of what the router
produced on the air, or puts it there late. `Simulation.misbehave` applies an
`Insider` to a node's egress, so nothing is forged and there is nothing for a
signature check to refuse.

The filter reads only the BATMAN packet-type byte. It therefore cannot tell a
frame the node relays from one it originated: a node dropping data drops its
own data too, or sends it late. A wormhole is not modelled here.
"""

from __future__ import annotations

import dataclasses
import math
from random import Random

from . import forge

DATA_PACKET_TYPES = frozenset(
    {forge.PACKET_BCAST, forge.PACKET_UNICAST, forge.PACKET_MCAST}
)
"""The packet types carrying application payloads. Everything else (adverts,
heartbeats, next-hop proofs, certificate and probe traffic) is control."""


@dataclasses.dataclass(frozen=True)
class Insider:
    """What a captured node refuses to transmit, or transmits late."""

    drop_types: frozenset[int] | None
    """The BATMAN packet types subject to dropping, or `None` for every frame
    the node emits."""

    drop_fraction: float = 1.0
    """The share of those frames dropped, each decided independently."""

    delay_ms: float = 0.0
    """How long a frame of `delay_types` is held before it goes on the air."""

    delay_types: frozenset[int] | None = DATA_PACKET_TYPES
    """The BATMAN packet types held for `delay_ms`, or `None` for every frame
    the node emits. Ignored while `delay_ms` is zero."""

    def __post_init__(self) -> None:
        if not 0.0 <= self.drop_fraction <= 1.0:
            raise ValueError(f"drop_fraction={self.drop_fraction} is not in [0, 1]")
        if not (math.isfinite(self.delay_ms) and self.delay_ms >= 0.0):
            raise ValueError(f"delay_ms={self.delay_ms} is not a finite time >= 0")

    @classmethod
    def selective_forwarding(cls) -> Insider:
        """Take part in routing perfectly and drop every data frame. No metric
        built from adverts can see this."""
        return cls(DATA_PACKET_TYPES)

    @classmethod
    def grayhole(cls, drop_fraction: float) -> Insider:
        """Selective forwarding of only `drop_fraction` of data frames — the
        version that looks like a bad radio."""
        return cls(DATA_PACKET_TYPES, drop_fraction)

    @classmethod
    def blackhole(cls) -> Insider:
        """Transmit nothing at all, control included: it hears the mesh and
        contributes nothing to it, so its neighbours see it go silent."""
        return cls(None)

    @classmethod
    def delaying(
        cls, delay_ms: float, packet_types: frozenset[int] | None = DATA_PACKET_TYPES
    ) -> Insider:
        """Drop nothing and hold `packet_types` (data by default, `None` for
        everything) for `delay_ms`. Held frames keep their order among
        themselves, but frames not held overtake them, and an authenticated
        next hop then refuses a directed one whose replay counter is behind: a
        delay of data alone also loses some of it."""
        if not delay_ms > 0.0:
            raise ValueError(f"delay_ms={delay_ms} delays nothing")
        return cls(frozenset(), delay_ms=delay_ms, delay_types=packet_types)

    def drops(self, frame: bytes, rng: Random) -> bool:
        """Whether this firmware withholds `frame`, a complete link frame.
        Draws from `rng` only for a frame it might drop."""
        if not _is_one_of(frame, self.drop_types):
            return False
        return self.drop_fraction >= 1.0 or rng.random() < self.drop_fraction

    def holds_ms(self, frame: bytes) -> float:
        """How long this firmware sits on `frame` before sending it; zero for a
        frame it passes straight on."""
        if self.delay_ms and _is_one_of(frame, self.delay_types):
            return self.delay_ms
        return 0.0


def _is_one_of(frame: bytes, packet_types: frozenset[int] | None) -> bool:
    """Whether `frame` is a BATMAN frame of one of `packet_types`; `None`
    matches every frame."""
    if packet_types is None:
        return True
    return (
        int.from_bytes(frame[12:14], "big") == forge.BATMAN_ETHERTYPE
        and len(frame) > forge.LINK_HEADER_LEN
        and frame[forge.LINK_HEADER_LEN] in packet_types
    )
