import pytest

pytest.importorskip("simpy")

import wayfinder_py as wf  # noqa: E402

from engine.channel import PerfectWire  # noqa: E402
from engine.node import Node  # noqa: E402
from engine.scenario import Simulation  # noqa: E402
from engine.topology import diamond, pair  # noqa: E402


def test_two_node_route_converges():
    wf.init_tracing()
    nodes = [Node("a", trickle=(50, 500)), Node("b", trickle=(50, 500))]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=3.0, sample_interval_ms=50)

    assert sim.route_via("a", "b") == "a-b"
    assert sim.route_via("b", "a") == "a-b"


def test_no_route_before_convergence():
    nodes = [Node("a", trickle=(50, 500)), Node("b", trickle=(50, 500))]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    assert sim.route_via("a", "b") is None


def test_probe_recording_tracks_route_transition():
    wf.init_tracing()
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)
    sim.record("route", lambda s: s.route_via("a", "b"))

    rec = sim.run(until_s=3.0, sample_interval_ms=50)

    transitions = rec.transitions("route")
    assert transitions
    assert transitions[0][1] == "a-b"


def test_local_send_is_delivered_end_to_end():
    wf.init_tracing()
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)
    sim.send("a", "b", b"hello", at_s=2.5)

    sim.run(until_s=4.0)

    assert sim.poll_local("b") == b"hello"


def test_diamond_multihop_route_converges():
    wf.init_tracing()
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c", "d")]
    links = diamond("a", "b", "c", "d", PerfectWire())
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=5.0, sample_interval_ms=50)

    assert sim.route_via("a", "d") in ("a-b", "a-c")
    assert sim.route_via("d", "a") in ("b-d", "c-d")


def test_rejects_link_to_unknown_node():
    nodes = [Node("a")]
    links = [pair("a", "ghost", PerfectWire())]
    with pytest.raises(ValueError):
        Simulation(nodes, links, seed=0)


def test_rejects_duplicate_node_names():
    nodes = [Node("a"), Node("a")]
    with pytest.raises(ValueError):
        Simulation(nodes, [], seed=0)
