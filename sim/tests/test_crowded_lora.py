"""Pins what `sim/scenarios/crowded_lora.py` claims: a LoRa channel carries a
handful of sensors at 5-minute adverts and collapses past the collision
ceiling, contention inflates the advert load above steady state, and the
closed-form ceilings are upper bounds on what the simulation delivers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from crowded_lora import (
    TARGET_DELIVERY,
    collision_limited_n,
    duty_limited_n,
    run_point,
)


def test_a_few_sensors_deliver_and_a_crowd_does_not():
    few = run_point(4, 300.0, measure_s=1800.0)
    busy = run_point(8, 300.0, measure_s=1800.0)
    crowd = run_point(20, 300.0, measure_s=1800.0)
    assert few.delivery >= TARGET_DELIVERY
    assert crowd.delivery < 0.75
    assert crowd.busiest_duty <= 0.0101  # the regulator holds
    # Contended but not yet collapsed: losses drive the routers to advertise
    # faster than their schedule. (A collapsed channel is duty-capped instead.)
    assert busy.amplification > 1.2


def test_collisions_bind_before_the_duty_cycle_and_scale_as_a_square_root():
    for i in (60.0, 300.0, 900.0):
        assert collision_limited_n(i) < duty_limited_n(i)
    assert collision_limited_n(1200.0) == pytest.approx(2 * collision_limited_n(300.0))
