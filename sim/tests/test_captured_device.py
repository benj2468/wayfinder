"""Pins what `sim/scenarios/captured_device.py` claims on the results page:
a captured radio that ignores its own revocation is still shut out by the
members once HQ alone is told, no outsider's packet is accepted, and a
legitimate newcomer gets in."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from captured_device import NEWCOMER, OUTSIDERS, run_capture  # noqa: E402


@pytest.fixture(scope="module")
def run():
    return run_capture(seed=0)


def test_the_captured_radio_is_excluded_by_the_members(run):
    assert run.all_know_s is not None and run.all_know_s < 5.0
    assert run.excluded_s is not None and run.excluded_s < 5.0
    assert run.accepted_after_exclusion == 0


def test_no_outsider_packet_is_accepted(run):
    for name in OUTSIDERS:
        assert run.outsider_flows[name].sent, name
        assert not run.outsider_flows[name].received, name


def test_a_legitimate_newcomer_joins(run):
    assert run.newcomer_joined_s is not None and run.newcomer_joined_s < 5.0
    assert run.outsider_flows[NEWCOMER].received
