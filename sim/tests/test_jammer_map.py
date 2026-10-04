"""Pins what `sim/scenarios/jammer_map.py` claims: jamming is receiver-side,
so a weak jammer only matters beside HQ, and a stronger one denies a wider
radius."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from jammer_map import run_position  # noqa: E402


def test_no_jammer_delivers():
    assert run_position(None, None, 0.0).delivered > 0.98


def test_a_weak_jammer_hurts_only_beside_hq():
    assert run_position(0.0, 0.0, 5.0).delivered < 0.2
    assert run_position(1350.0, 900.0, 5.0).delivered > 0.9


def test_a_stronger_jammer_reaches_further():
    spot = (450.0, 450.0)
    assert run_position(*spot, 20.0).delivered < run_position(*spot, 5.0).delivered
