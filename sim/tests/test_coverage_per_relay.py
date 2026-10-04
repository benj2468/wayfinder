"""Pins what `sim/scenarios/coverage_per_relay.py` claims: greedy placement
grows coverage monotonically with diminishing returns, and the geometric
plan agrees with what traffic actually got through the real router."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

import mountain_relay as world  # noqa: E402
from coverage_per_relay import greedy_layouts, knee, run_layouts  # noqa: E402


def test_greedy_planned_coverage_grows_with_diminishing_returns():
    layouts = greedy_layouts(world.build_terrain(), 4)
    planned = [p for _, p in layouts]
    assert planned == sorted(planned)
    gains = [b - a for a, b in zip([0.0, *planned], planned)]
    assert gains[0] >= gains[-1]
    # Each layout extends the previous one: a deployment grows, never moves.
    for (small, _), (big, _) in zip(layouts, layouts[1:]):
        assert big[: len(small)] == small


def test_delivered_coverage_tracks_the_plan():
    results = run_layouts(seeds=(0,), max_relays=3)
    for r in results:
        assert abs(r.planned - r.measured_mean) < 0.05, r.relays
    assert knee(results).relays <= 3
