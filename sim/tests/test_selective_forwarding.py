"""Pins what `sim/scenarios/selective_forwarding.py` measures: a captured relay
that keeps relaying adverts and drops data stays on the route, while one that
goes wholly silent is routed around."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from selective_forwarding import BEHAVIOURS, run_attack, showcase
from wayfinder_sim.showcase import showcase_dict


@pytest.fixture(scope="module")
def runs():
    return {name: run_attack(name, seed=0) for name in BEHAVIOURS}


def test_every_behaviour_attacks_the_same_relay(runs):
    assert len({r.captured for r in runs.values()}) == 1


def test_the_honest_control_delivers(runs):
    assert runs["honest"].delivery_after > 0.9


def test_selective_forwarding_is_not_routed_around(runs):
    run = runs["selective forwarding"]
    assert run.delivery_after < 0.1
    assert run.carried_share > 0.9
    assert run.tq_after >= run.tq_before - 5


def test_a_silent_relay_is_routed_around(runs):
    assert runs["blackhole"].delivery_after > 0.8
    assert runs["blackhole"].carried_share < 0.2


def test_what_the_relay_swallows_is_what_goes_missing(runs):
    """The carried share is read off the air, so under selective forwarding it
    accounts for the loss: what was handed to the relay did not arrive."""
    run = runs["selective forwarding"]
    assert run.delivery_after <= 1.0 - run.carried_share + 0.02


def test_the_export_covers_every_behaviour(runs):
    data = showcase_dict(showcase({n: (r,) for n, r in runs.items()}))
    assert data["slug"] == "selective-forwarding"
    assert [row[0] for row in data["table"][1:]] == list(BEHAVIOURS)
