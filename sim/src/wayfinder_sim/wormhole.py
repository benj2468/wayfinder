"""A wormhole — two colluding radios that carry frames between distant parts
of a mesh, so that nodes far apart believe they are neighbours.

Neither end needs a key. Every frame is repeated verbatim, link header,
signature and all, so what arrives at the far end is genuine, and a challenge
to prove oneself is carried back to whoever really can answer it. Once the
shortcut has drawn the routes, the attacker may carry everything (and read or
delay it at leisure) or only the control traffic that keeps the shortcut
looking healthy.

Install one with `Simulation.wormhole`. Both ends are ordinary `Node`s so that
they have a position and links, and hear only what their channels deliver. While
the wormhole is open an end is a bare repeater: its router is given nothing
(though it still beacons for itself, which an authenticated mesh rejects).
The tunnel between the ends is out of band, but what an end re-emits is an
ordinary transmission, subject to its links' channels and media.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from . import forge

FramePredicate = Callable[[bytes], bool]
"""Takes a whole link frame; true if the wormhole should carry it."""

_PACKET_MCAST = 0x04
"""`batman::wire::BatmanPacketType::Mcast`, which `forge` does not name."""

_DATA_PACKET_TYPES = frozenset(
    {forge.PACKET_BCAST, forge.PACKET_UNICAST, _PACKET_MCAST}
)


def control_only(frame: bytes) -> bool:
    """Carry everything except the mesh frames that hold application data
    (unicast, broadcast, multicast): the blackholing wormhole."""
    if len(frame) <= forge.LINK_HEADER_LEN:
        return True
    protocol = int.from_bytes(frame[12:14], "big")
    return (
        protocol != forge.BATMAN_ETHERTYPE
        or frame[forge.LINK_HEADER_LEN] not in _DATA_PACKET_TYPES
    )


@dataclasses.dataclass
class Wormhole:
    """One tunnel between the radios `a` and `b`, and what it has done."""

    a: str
    b: str
    passes: FramePredicate | None
    """Which frames cross; `None` carries everything."""
    latency_ms: float
    """Delay the tunnel adds to each frame it carries."""
    start_s: float
    until_s: float | None
    """When it closes, or `None` to stay open for the rest of the run."""
    tunnelled: int = 0
    """Frames heard at one end and re-emitted at the other."""
    withheld: int = 0
    """Frames heard at one end that `passes` refused to carry."""

    def is_open(self, t_s: float) -> bool:
        """Whether the tunnel is carrying frames at simulation time `t_s`."""
        return t_s >= self.start_s and (self.until_s is None or t_s < self.until_s)

    def far_end(self, name: str) -> str:
        """The other radio from `name`, which must be one of the two ends."""
        return self.b if name == self.a else self.a
