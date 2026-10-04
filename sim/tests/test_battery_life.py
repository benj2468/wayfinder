"""Pins what `sim/scenarios/battery_life.py` claims: a routing node's energy
is dominated by listening, so its battery life barely moves with the advert
schedule, and the measured figures are consistent with the energy model."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from battery_life import RADIO, listen_share, median_sensor, run_network  # noqa: E402


def test_listening_dominates_a_routing_nodes_energy():
    nodes = run_network(4, 300.0, measure_s=1800.0)
    med = median_sensor(nodes)
    assert listen_share(med) > 0.85
    # Average power sits just above the always-open receiver's draw.
    assert RADIO.rx_mw <= med.power_mw() < RADIO.rx_mw * 1.2


def test_battery_life_barely_moves_with_the_advert_schedule():
    fast = median_sensor(run_network(4, 60.0, measure_s=1800.0)).life_days()
    slow = median_sensor(run_network(4, 900.0, measure_s=1800.0)).life_days()
    assert slow >= fast
    assert slow / fast < 1.2
