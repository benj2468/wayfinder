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
    from .adversary import CapturedFrame, Wiretap
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
        BY_DESIGN,
        GAP,
        HELD,
        VERDICTS,
        FindingReport,
        ImagePanel,
        RunReport,
        ScenePanel,
        Verdict,
        red_team_report_html,
        sweep_report_html,
        write_red_team_report,
        write_sweep_report,
    )
    from .scenario import Simulation
    from .security import Credential, Mesh
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
    "BY_DESIGN",
    "EARTH_RADIUS_M",
    "GAP",
    "HELD",
    "VERDICTS",
    "Bounds",
    "CapturedFrame",
    "Channel",
    "ChannelSample",
    "ConnectivityStats",
    "Credential",
    "EarthOccluded",
    "EarthOrbit",
    "FindingReport",
    "FlatGround",
    "FreeSpacePathLoss",
    "GaussianPeak",
    "GreatCircle",
    "Heightmap",
    "ImagePanel",
    "Link",
    "Mesh",
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
    "Verdict",
    "Waypoints",
    "Wiretap",
    "connectivity_stats",
    "elevation_profile",
    "has_line_of_sight",
    "knife_edge_loss_db",
    "max_fresnel_parameter",
    "outage_windows",
    "peak_sites",
    "red_team_report_html",
    "run_sweep",
    "sweep_report_html",
    "terrain_scene",
    "track_scene",
    "valley_sites",
    "write_html",
    "write_red_team_report",
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
    "CapturedFrame": "adversary",
    "Wiretap": "adversary",
    "Link": "link",
    "Mobility": "mobility",
    "Orbit": "mobility",
    "Static": "mobility",
    "Vec3": "mobility",
    "Waypoints": "mobility",
    "Node": "node",
    "Recorder": "recorder",
    "BY_DESIGN": "report",
    "FindingReport": "report",
    "GAP": "report",
    "HELD": "report",
    "ImagePanel": "report",
    "RunReport": "report",
    "ScenePanel": "report",
    "VERDICTS": "report",
    "Verdict": "report",
    "red_team_report_html": "report",
    "sweep_report_html": "report",
    "write_red_team_report": "report",
    "write_sweep_report": "report",
    "Simulation": "scenario",
    "Credential": "security",
    "Mesh": "security",
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
