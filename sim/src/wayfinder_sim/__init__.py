"""A generalized, physics-driven mesh simulation engine.

Drives the real Rust mesh router (via `wayfinder_py`'s tick-based
`PyDriver`) against Python-side models of node mobility and RF/wired
channels, so a scenario script only supplies *what* to simulate (topology,
channel tuning, flight paths) and not the tick/delivery/bookkeeping
machinery that makes it run.

Every export is resolved lazily (`__getattr__`, PEP 562) rather than
imported eagerly: it lets `sim/tests/` build up one submodule at a time
without every other submodule already existing, and it means importing
`wayfinder_sim.mobility` alone never pulls in `scenario`'s `simpy`
dependency or `plotting`'s `matplotlib` one — the latter being the `plot`
extra, and so absent from a headless install.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


class NoLinkError(ValueError):
    """No `Link` joins the two given nodes — raised by
    `Simulation.sample_channel`.

    A dedicated type (rather than a bare `ValueError`) so a caller building a
    channel graph (e.g. `wayfinder_ml.generate.channel_graph`) can catch
    exactly "these two nodes aren't linked" without also absorbing a real bug
    in a `Channel.evaluate()` implementation that happens to raise
    `ValueError` for its own reasons.
    """


if TYPE_CHECKING:
    from .channel import Channel, ChannelSample, FreeSpacePathLoss, PerfectWire
    from .link import Link
    from .mobility import Mobility, Orbit, Static, Vec3, Waypoints
    from .node import Node
    from .recorder import Recorder
    from .scenario import Simulation
    from .sweep import SweepResult, run_sweep

__all__ = [
    "Channel",
    "ChannelSample",
    "FreeSpacePathLoss",
    "Link",
    "Mobility",
    "NoLinkError",
    "Node",
    "Orbit",
    "PerfectWire",
    "Recorder",
    "Simulation",
    "Static",
    "SweepResult",
    "Vec3",
    "Waypoints",
    "run_sweep",
]

# name -> submodule it lives in.
_EXPORTS = {
    "Channel": "channel",
    "ChannelSample": "channel",
    "FreeSpacePathLoss": "channel",
    "PerfectWire": "channel",
    "Link": "link",
    "Mobility": "mobility",
    "Orbit": "mobility",
    "Static": "mobility",
    "Vec3": "mobility",
    "Waypoints": "mobility",
    "Node": "node",
    "Recorder": "recorder",
    "Simulation": "scenario",
    "SweepResult": "sweep",
    "run_sweep": "sweep",
}


def __getattr__(name: str) -> Any:
    submodule = _EXPORTS.get(name)
    if submodule is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(f".{submodule}", __name__), name)
