"""Topology builders — wiring vocabulary mirroring `sim/topology.py`'s
`diamond`/`complete_graph`/`path`/`shared_lan`, adapted to this in-process
engine: there are no docker networks here, so a link is a Python `Link`
object carrying a `Channel` rather than a bare list of member names.
"""

from __future__ import annotations

from typing import Callable, Sequence, Union

from .channel import Channel
from .link import Link

ChannelLike = Union[Channel, Callable[[str, str], Channel]]
"""Either one `Channel` instance shared by every edge a builder creates
(safe — channels are stateless, evaluated with a caller-supplied RNG), or a
`(a, b) -> Channel` factory called per edge so each gets its own tuning
(e.g. distance-varying radios in a `complete_graph`)."""


def _resolve(channel: ChannelLike, a: str, b: str) -> Channel:
    if isinstance(channel, Channel):
        return channel
    return channel(a, b)


def pair(a: str, b: str, channel: ChannelLike) -> Link:
    """A single point-to-point link between `a` and `b`."""
    return Link((a, b), _resolve(channel, a, b))


def path(names: Sequence[str], channel: ChannelLike) -> list[Link]:
    """A line `names[0] — names[1] — … — names[-1]`, one p2p link per
    adjacency."""
    return [pair(a, b, channel) for a, b in zip(names, names[1:])]


def complete_graph(names: Sequence[str], channel: ChannelLike) -> list[Link]:
    """Every pair of `names` joined by its own point-to-point link — K_n as
    `n*(n-1)/2` distinct links, each an interface the router paces
    independently. For "all hear all on one wire" instead, use
    `shared_lan`."""
    return [pair(a, b, channel) for i, a in enumerate(names) for b in names[i + 1 :]]


def shared_lan(names: Sequence[str], channel: Channel) -> list[Link]:
    """One segment shared by all `names` (a single multi-access link) — every
    member hears every other, with per-pair metrics still evaluated from
    `channel` at delivery time."""
    return [Link(tuple(names), channel)]


def diamond(a: str, b: str, c: str, d: str, channel: ChannelLike) -> list[Link]:
    """A 4-node diamond: `a` fans out to `b` and `c`, which both rejoin at
    `d` — two disjoint 2-hop paths between `a` and `d`."""
    return [
        pair(a, b, channel),
        pair(a, c, channel),
        pair(b, d, channel),
        pair(c, d, channel),
    ]


def star(hub: str, spokes: Sequence[str], channel: ChannelLike) -> list[Link]:
    """`hub` joined to every node in `spokes`, each its own point-to-point
    link."""
    return [pair(hub, spoke, channel) for spoke in spokes]
