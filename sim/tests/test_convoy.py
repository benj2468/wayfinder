"""Pins the engine limits `sim/scenarios/convoy_relay.py` reports.

The scenario is a plain script, not collected by pytest, so the numbers it
prints could drift with the engine and nobody would notice — the same reason
`test_red_team.py` pins that script's verdicts. What is pinned here is not
the scenario's prose but the two facts underneath it: that a chain's usable
depth is bounded by TTL at hop 50, and that a profile tells "no route" apart
from "the metric bottomed out".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from convoy_relay import (
    LOSS_LIMITED,
    TTL_LIMITED,
    UNCONSTRAINED,
    DepthProfile,
    measure_ideal_chain,
)


def profile(tq_by_hop, *, reliable=None, best=None) -> DepthProfile:
    """A `DepthProfile` with the depths defaulting to what `tq_by_hop`
    implies, so a test states only the part it is about."""
    routed = [h for h, tq in enumerate(tq_by_hop, start=1) if tq is not None]
    deepest = max(routed, default=0)
    return DepthProfile(
        spacing_m=100.0,
        hop_quality=200,
        tq_by_hop=tuple(tq_by_hop),
        best_hop=deepest if best is None else best,
        reliable_hop=deepest if reliable is None else reliable,
    )


def test_an_ideal_chain_pins_both_engine_limits():
    """Over links good enough that loss cannot be what stopped it, a chain
    exposes the two constants the scenario reports:

    * an originated OGM leaves with `ttl: 50` and every forwarding hop
      decrements it, so hop 50 is the last one that can hear the head;
    * it leaves with TQ 255 and loses 10 a hop, so its metric is exhausted
      at hop 26 — less than half way to the horizon.

    Both are wire-level constants with no other test that would notice them
    changing, and the gap between them is the scenario's point: every hop
    from 26 to 50 routes on a metric that can no longer rank anything.
    """
    ideal = measure_ideal_chain(vehicles=55, settle_s=40.0)

    assert ideal.horizon_hop == 50
    assert ideal.saturated_from == 26


def test_a_bottomed_out_metric_is_not_a_missing_route():
    """TQ 0 is a route whose metric has saturated — still forwarding, just no
    longer able to rank itself against anything. Reading it as "no route"
    would report the metric floor as the loss wall."""
    p = profile([200, 190, 0, 0])

    assert p.saturated_from == 3
    assert p.best_hop == 4, "a TQ-0 hop still has a route"


def test_the_metric_floor_does_not_limit_reach():
    """The floor and the two reach walls bound different things, so a column
    that saturated its metric and still reached its own tail is
    unconstrained in reach — reporting it as limited would name the wrong
    wall, and the one it names does not stop traffic."""
    p = profile([200, 190, 0, 0])

    assert p.saturated_from is not None
    assert p.regime == UNCONSTRAINED


def test_a_column_that_ends_before_its_metric_does_is_loss_limited():
    """No hop ever reaches the floor because the chain runs out first."""
    p = profile([200, 190, 180, None, None])

    assert p.saturated_from is None
    assert p.best_hop == 3
    assert p.regime == LOSS_LIMITED


def test_a_column_shorter_than_every_wall_is_neither():
    """A short column at good spacing reaches its own tail without coming
    near a wall. It has no floor, but calling that loss-limited would report
    a column that worked perfectly as one that failed."""
    p = profile([200, 190, 180])

    assert p.saturated_from is None
    assert p.reliable_hop == 3, "reaches its own tail"
    assert p.regime == UNCONSTRAINED


def test_a_column_reaching_the_ttl_horizon_is_ttl_limited():
    """A column good enough to get past the loss wall runs into `ttl: 50`
    instead — and by then its metric has been saturated for 24 hops, because
    a starting TQ of 255 losing 10 a hop bottoms out at 26 whatever the
    links are like. Nothing reaches hop 50 with a meaningful metric."""
    p = profile([200] * 25 + [0] * 25 + [None] * 5)

    assert p.regime == TTL_LIMITED
    assert p.saturated_from == 26, "saturated long before the horizon"


def test_a_flickering_column_is_not_steady():
    """`stable` compares the two depths across the settled window: a column
    that reached hop 29 at its best but held only 23 has not settled."""
    p = profile([200] * 23 + [None] * 6, reliable=23, best=29)

    assert not p.stable
    assert p.reliable_hop < p.best_hop


def test_a_column_holding_one_depth_is_steady():
    p = profile([200] * 10, reliable=10, best=10)

    assert p.stable
