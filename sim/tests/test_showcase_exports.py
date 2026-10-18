"""The terrain and satellite scenarios' results-page exports: the claims the
page makes from them hold on a cut-down run."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

import mountain_relay
import satellite_relay
from wayfinder_sim.showcase import showcase_dict


def test_mountain_export_profiles_a_ridge_blocking_the_worst_outage():
    results = mountain_relay.run_placement_sweep(["summits", "valley floor"])
    data = showcase_dict(
        mountain_relay.showcase(results, mountain_relay.build_terrain())
    )
    assert data["slug"] == "mountain-relay"
    profile = data["charts"][-1]
    ground, los, _ = (s["y"] for s in profile["series"])
    # The page says the ridge blocks the line of sight: it must.
    assert any(g > l for g, l in zip(ground, los))


def test_satellite_export_one_plane_beats_a_split_constellation():
    results = satellite_relay.run_constellation_sweep([(1, 6), (2, 3)])
    data = showcase_dict(satellite_relay.showcase(results))
    assert data["slug"] == "satellite-relay"
    route = {row[0]: row[3] for row in data["table"][1:]}
    assert route["1x6 (6 satellites)"] > route["2x3 (6 satellites)"]
