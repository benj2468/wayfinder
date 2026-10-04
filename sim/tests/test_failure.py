"""Scheduled node and link failures: the primitive a resilience study needs.

A failed node is powered off — it neither transmits nor receives — and a
recovered one *reboots*: its router comes back empty, the way a power-cycled
board loses everything it held in RAM.
"""

import pytest

pytest.importorskip("simpy")

from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.topology import diamond, pair

FAST = (50, 500)


def _diamond_sim() -> Simulation:
    nodes = [Node(n, trickle=FAST) for n in ("a", "b", "c", "d")]
    return Simulation(nodes, diamond("a", "b", "c", "d", PerfectWire()), seed=0)


def test_failed_relay_is_routed_around():
    sim = _diamond_sim()
    sim.run(until_s=3.0)
    first = sim.route_via("a", "d")
    assert first in ("a-b", "a-c")
    relay = "b" if first == "a-b" else "c"

    sim.fail_node(relay, at_s=3.0)
    sim.run(until_s=40.0)

    other = "a-c" if relay == "b" else "a-b"
    assert sim.route_via("a", "d") == other


def test_failed_node_is_down_and_silent():
    nodes = [Node(n, trickle=FAST) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)
    sim.fail_node("b", at_s=0.0)
    sim.run(until_s=5.0)

    assert not sim.is_up("b")
    assert sim.is_up("a")
    assert not sim.has_route("a", "b")
    # Nothing reached b's router either: it is off, not merely muted.
    assert not sim.has_route("b", "a")


def test_recovered_node_reboots_and_rejoins():
    nodes = [Node(n, trickle=FAST) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)
    sim.run(until_s=3.0)
    assert sim.has_route("b", "a")

    sim.fail_node("b", at_s=3.0, recover_s=4.0)
    sim.run(until_s=4.01)
    assert sim.is_up("b")
    # A reboot, not a resume: the router it came back with knows nobody.
    assert not sim.has_route("b", "a")

    sim.run(until_s=8.0)
    assert sim.has_route("b", "a")
    assert sim.has_route("a", "b")


def test_failed_link_is_routed_around_and_restored():
    sim = _diamond_sim()
    sim.run(until_s=3.0)
    first = sim.route_via("a", "d")
    assert first is not None

    sim.fail_link(first, at_s=3.0, recover_s=60.0)
    sim.run(until_s=40.0)
    assert sim.route_via("a", "d") not in (None, first)
    assert not sim.is_link_up(first)

    sim.run(until_s=61.0)
    assert sim.is_link_up(first)


def test_fail_unknown_names_raise():
    sim = _diamond_sim()
    with pytest.raises(KeyError):
        sim.fail_node("zz", at_s=1.0)
    with pytest.raises(KeyError):
        sim.fail_link("zz", at_s=1.0)


def test_recover_before_fail_is_refused():
    sim = _diamond_sim()
    with pytest.raises(ValueError):
        sim.fail_node("b", at_s=5.0, recover_s=4.0)
    with pytest.raises(ValueError):
        sim.fail_link("a-b", at_s=5.0, recover_s=5.0)
