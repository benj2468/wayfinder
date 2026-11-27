"""A member of the mesh that misbehaves at forwarding — the insider half of a
red-team scenario.

`forge` and `Simulation.inject` model an attacker with no credentials. This
models one holding a captured radio: its router, certificate and keys are all
genuine, and its firmware simply declines to put some of what the router
produced on the air. `Simulation.misbehave` applies an `Insider` to a node's
egress, so nothing is forged and there is nothing for a signature check to
refuse.

The filter reads only the BATMAN packet-type byte. It therefore cannot tell a
frame the node relays from one it originated: a node dropping data drops its
own data too. Delay and wormhole behaviours are not modelled here.
"""

from __future__ import annotations

import dataclasses
from random import Random

from . import forge

DATA_PACKET_TYPES = frozenset(
    {forge.PACKET_BCAST, forge.PACKET_UNICAST, forge.PACKET_MCAST}
)
"""The packet types carrying application payloads. Everything else (adverts,
heartbeats, next-hop proofs, certificate and probe traffic) is control."""


@dataclasses.dataclass(frozen=True)
class Insider:
    """What a captured node refuses to transmit."""

    drop_types: frozenset[int] | None
    """The BATMAN packet types subject to dropping, or `None` for every frame
    the node emits."""

    drop_fraction: float = 1.0
    """The share of those frames dropped, each decided independently."""

    def __post_init__(self) -> None:
        if not 0.0 <= self.drop_fraction <= 1.0:
            raise ValueError(f"drop_fraction={self.drop_fraction} is not in [0, 1]")

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

    def drops(self, frame: bytes, rng: Random) -> bool:
        """Whether this firmware withholds `frame`, a complete link frame.
        Draws from `rng` only for a frame it might drop."""
        if self.drop_types is not None:
            protocol = int.from_bytes(frame[12:14], "big")
            if (
                protocol != forge.BATMAN_ETHERTYPE
                or len(frame) <= forge.LINK_HEADER_LEN
                or frame[forge.LINK_HEADER_LEN] not in self.drop_types
            ):
                return False
        return self.drop_fraction >= 1.0 or rng.random() < self.drop_fraction
