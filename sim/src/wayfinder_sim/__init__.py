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
    from .channel import (
        Channel,
        ChannelSample,
        EarthOccluded,
        FreeSpacePathLoss,
        PerfectWire,
        RadioModel,
        TerrainMasked,
        knife_edge_loss_db,
    )
    from .connectivity import (
        ConnectivityStats,
        Outage,
        connectivity_stats,
        outage_windows,
    )
    from .interactive import Timeline, terrain_scene, track_scene, write_html
    from .link import Link
    from .mobility import (
        EARTH_RADIUS_M,
        EarthOrbit,
        GreatCircle,
        Mobility,
        Orbit,
        Static,
        Vec3,
        Waypoints,
    )
    from .node import Node
    from .recorder import Recorder
    from .report import (
        ImagePanel,
        RunReport,
        ScenePanel,
        sweep_report_html,
        write_sweep_report,
    )
    from .scenario import Simulation
    from .sweep import SweepResult, run_sweep
    from .terrain import (
        Bounds,
        FlatGround,
        GaussianPeak,
        Heightmap,
        MountainRange,
        Terrain,
        TerrainFollowing,
        elevation_profile,
        has_line_of_sight,
        max_fresnel_parameter,
        peak_sites,
        valley_sites,
    )

__all__ = [
    "EARTH_RADIUS_M",
    "Bounds",
    "Channel",
    "ChannelSample",
    "ConnectivityStats",
    "EarthOccluded",
    "EarthOrbit",
    "FlatGround",
    "FreeSpacePathLoss",
    "GaussianPeak",
    "GreatCircle",
    "Heightmap",
    "ImagePanel",
    "Link",
    "Mobility",
    "MountainRange",
    "NoLinkError",
    "Node",
    "Orbit",
    "Outage",
    "PerfectWire",
    "RadioModel",
    "Recorder",
    "RunReport",
    "ScenePanel",
    "Simulation",
    "Static",
    "SweepResult",
    "Terrain",
    "TerrainFollowing",
    "TerrainMasked",
    "Timeline",
    "Vec3",
    "Waypoints",
    "connectivity_stats",
    "elevation_profile",
    "has_line_of_sight",
    "knife_edge_loss_db",
    "max_fresnel_parameter",
    "outage_windows",
    "peak_sites",
    "run_sweep",
    "sweep_report_html",
    "terrain_scene",
    "track_scene",
    "valley_sites",
    "write_html",
    "write_sweep_report",
]

# name -> submodule it lives in.
_EXPORTS = {
    "Channel": "channel",
    "ChannelSample": "channel",
    "EARTH_RADIUS_M": "mobility",
    "EarthOccluded": "channel",
    "EarthOrbit": "mobility",
    "FreeSpacePathLoss": "channel",
    "GreatCircle": "mobility",
    "PerfectWire": "channel",
    "RadioModel": "channel",
    "TerrainMasked": "channel",
    "knife_edge_loss_db": "channel",
    "ConnectivityStats": "connectivity",
    "Outage": "connectivity",
    "connectivity_stats": "connectivity",
    "outage_windows": "connectivity",
    "Timeline": "interactive",
    "terrain_scene": "interactive",
    "track_scene": "interactive",
    "write_html": "interactive",
    "Link": "link",
    "Mobility": "mobility",
    "Orbit": "mobility",
    "Static": "mobility",
    "Vec3": "mobility",
    "Waypoints": "mobility",
    "Node": "node",
    "Recorder": "recorder",
    "ImagePanel": "report",
    "RunReport": "report",
    "ScenePanel": "report",
    "sweep_report_html": "report",
    "write_sweep_report": "report",
    "Simulation": "scenario",
    "SweepResult": "sweep",
    "run_sweep": "sweep",
    "Bounds": "terrain",
    "FlatGround": "terrain",
    "GaussianPeak": "terrain",
    "Heightmap": "terrain",
    "MountainRange": "terrain",
    "Terrain": "terrain",
    "TerrainFollowing": "terrain",
    "elevation_profile": "terrain",
    "has_line_of_sight": "terrain",
    "max_fresnel_parameter": "terrain",
    "peak_sites": "terrain",
    "valley_sites": "terrain",
}


def __getattr__(name: str) -> Any:
    submodule = _EXPORTS.get(name)
    if submodule is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(f".{submodule}", __name__), name)
