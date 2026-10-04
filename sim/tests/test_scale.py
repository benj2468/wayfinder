"""Pins the healthy side of `sim/scenarios/scale.py`: a mesh well inside the
default profile's table converges within seconds and delivers both ways.
(The collapse past the table edge takes minutes to simulate; the scenario
itself reports it.)"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from scale import run_size  # noqa: E402


def test_a_mesh_inside_the_table_converges_fast_and_delivers_both_ways():
    run = run_size(49)
    assert run.converged_s is not None and run.converged_s < 10.0
    assert run.to_hq > 0.98
    assert run.from_hq > 0.98
    assert run.hq_table == 48
