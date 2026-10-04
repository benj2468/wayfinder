"""Pins what `sim/scenarios/failover.py` claims.

The scenario is a plain script, so its numbers could drift with the engine
unnoticed. Pinned here are the facts the results page states: the mesh routes
around a dead relay without help, the healed path avoids it, a rebooted relay
relearns the mesh, and keep-alives shorten the worst case.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from failover import (  # noqa: E402
    DEFAULT_TRICKLE,
    FAIL_AT_S,
    run_failover,
)


def test_the_mesh_routes_around_a_dead_relay_and_the_relay_rejoins():
    run = run_failover(seed=0)
    assert run.recovered_s is not None
    assert run.recovered_s < 30.0
    assert run.path_after is not None
    assert run.victim not in run.path_after
    assert run.rejoin_s is not None and run.rejoin_s < 10.0
    # Once healed, the stream flows again until the relay comes back (fading
    # still costs the odd frame; nothing retransmits).
    healed = FAIL_AT_S + run.recovered_s + 2.0
    assert run.flow.delivery_ratio(healed, healed + 20.0) >= 0.98


def test_keepalives_shorten_the_worst_case():
    seeds = range(4)
    plain = [
        run_failover(s, recover_at_s=None, duration_s=FAIL_AT_S + 60).recovered_s
        for s in seeds
    ]
    with_ka = [
        run_failover(
            s, DEFAULT_TRICKLE, keepalive_ms=250, recover_at_s=None, duration_s=FAIL_AT_S + 60
        ).recovered_s
        for s in seeds
    ]
    assert None not in plain and None not in with_ka
    assert max(with_ka) < max(plain)
    assert max(with_ka) < 3.0
