"""Pins both sides of the default profile's table edge in
`sim/scenarios/scale.py`: a mesh well inside it converges within seconds and
delivers both ways, and a mesh just past it degrades instead of collapsing
into an advert storm (#104)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from scale import run_size


def test_a_mesh_inside_the_table_converges_fast_and_delivers_both_ways():
    run = run_size(49)
    assert run.converged_s is not None and run.converged_s < 10.0
    assert run.to_hq > 0.98
    assert run.from_hq > 0.98
    assert run.hq_table == 48


def test_a_mesh_just_past_the_table_edge_does_not_storm():
    """Past the 128-entry table, routers evict and re-learn originators every
    round. Before #104 each re-learn reset Trickle and re-flooded, so control
    traffic jumped ~6x and delivery collapsed (163 frames/s/node and 80%/83% at
    132 nodes). The cost per node must stay near the healthy mesh's."""
    inside = run_size(121)
    past = run_size(132)
    assert past.frames_per_node_s < 1.5 * inside.frames_per_node_s
    assert past.to_hq > 0.95
    assert past.from_hq > 0.9
