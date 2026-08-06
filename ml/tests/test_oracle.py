"""The oracle is the supervision signal: it sees the simulator's true
instantaneous channel graph — per-pair delivery probability the router can
never observe — and computes the next hop a perfectly-informed router would
pick. Training teaches router-visible features to predict it.
"""

from __future__ import annotations

import math

import pytest

from wayfinder_ml import oracle


def test_etx_is_inverse_delivery_probability() -> None:
    """Expected transmission count: a link that delivers half its frames costs
    two transmissions per success."""
    assert oracle.etx(1.0) == pytest.approx(1.0)
    assert oracle.etx(0.5) == pytest.approx(2.0)
    assert oracle.etx(0.25) == pytest.approx(4.0)


def test_etx_of_dead_link_is_infinite() -> None:
    """A zero-delivery link must be unusable, not merely expensive."""
    assert math.isinf(oracle.etx(0.0))


def test_chain_routes_toward_destination() -> None:
    """a - b - c: every node's best next hop is simply the next one along."""
    graph = {("a", "b"): 1.0, ("b", "c"): 1.0}
    hops = oracle.best_next_hops(graph, dest="c")
    assert hops["a"] == "b"
    assert hops["b"] == "c"


def test_destination_has_no_next_hop() -> None:
    graph = {("a", "b"): 1.0}
    assert oracle.best_next_hops(graph, dest="b")["b"] is None


def test_prefers_reliable_two_hop_over_lossy_one_hop() -> None:
    """The whole point of the model. A direct link that delivers 20% of frames
    (ETX 5) is worse than two perfect hops (ETX 2) — but hop-count-flavoured
    metrics prefer the direct link, so this is exactly the case a learned
    scorer should win."""
    graph = {
        ("a", "d"): 0.2,
        ("a", "b"): 1.0,
        ("b", "d"): 1.0,
    }
    assert oracle.best_next_hops(graph, dest="d")["a"] == "b"


def test_prefers_direct_link_when_it_is_actually_good() -> None:
    """The mirror case: the oracle must not simply be biased toward detours."""
    graph = {
        ("a", "d"): 1.0,
        ("a", "b"): 0.5,
        ("b", "d"): 0.5,
    }
    assert oracle.best_next_hops(graph, dest="d")["a"] == "d"


def test_unreachable_node_has_no_next_hop() -> None:
    graph = {("a", "b"): 1.0, ("c", "d"): 1.0}
    hops = oracle.best_next_hops(graph, dest="b")
    assert hops["c"] is None
    assert hops["d"] is None


def test_dead_link_does_not_connect() -> None:
    """A zero-probability edge is present in the graph but must not be treated
    as a usable path."""
    graph = {("a", "b"): 0.0}
    assert oracle.best_next_hops(graph, dest="b")["a"] is None


def test_asymmetric_graph_uses_forward_direction() -> None:
    """Channels can be asymmetric; the cost from `a` toward `dest` must be the
    a->b direction, not b->a."""
    graph = {("a", "b"): 1.0, ("b", "a"): 0.1, ("b", "c"): 1.0}
    assert oracle.best_next_hops(graph, dest="c")["a"] == "b"


def test_path_costs_are_reported() -> None:
    """The per-node cost-to-destination is the raw material for soft targets:
    a row where two candidates are near-equal should not be trained as hard as
    one where the best is clearly better."""
    graph = {("a", "b"): 0.5, ("b", "c"): 0.5}
    costs = oracle.costs_to(graph, dest="c")
    assert costs["c"] == pytest.approx(0.0)
    assert costs["b"] == pytest.approx(2.0)
    assert costs["a"] == pytest.approx(4.0)
