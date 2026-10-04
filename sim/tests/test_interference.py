"""Jammers: a transmitter that carries nothing and raises the floor every
receiver in range has to beat."""

from __future__ import annotations

import pytest

pytest.importorskip("simpy")

from wayfinder_sim.channel import FreeSpacePathLoss, PerfectWire
from wayfinder_sim.interference import Jammer
from wayfinder_sim.medium import FixedRate, Medium
from wayfinder_sim.mobility import Static, Vec3
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.topology import pair, shared_lan

FAST = (50, 500)
RADIO = FreeSpacePathLoss(tx_power_dbm=14.0, noise_sigma_db=0.0, delivery_steepness=5.0)


def _pair_sim(medium: Medium | None = None) -> Simulation:
    nodes = [
        Node("a", mobility=Static(Vec3(0.0, 0.0, 0.0)), trickle=FAST),
        Node("b", mobility=Static(Vec3(200.0, 0.0, 0.0)), trickle=FAST),
    ]
    links = shared_lan(["a", "b"], RADIO, medium=medium)
    return Simulation(nodes, links, seed=0)


def test_jammer_received_power_follows_free_space_loss():
    jammer = Jammer("j", mobility=Static(Vec3()), power_dbm=30.0, freq_hz=2.4e9)
    near = jammer.received_dbm(Vec3(10.0, 0.0, 0.0), 0.0)
    far = jammer.received_dbm(Vec3(100.0, 0.0, 0.0), 0.0)
    assert near - far == pytest.approx(20.0, abs=0.01)  # 10x distance, 20 dB


def test_a_nearby_jammer_silences_a_link_while_active():
    sim = _pair_sim()
    flow = sim.stream("a", "b", rate_hz=10, start_s=3.0, duration_s=12.0)
    sim.add_jammer(
        Jammer("j", mobility=Static(Vec3(210.0, 0.0, 0.0)), power_dbm=20.0, active=(6.0, 10.0))
    )
    sim.run(until_s=16.0)

    assert flow.delivery_ratio(3.0, 5.9) == 1.0
    assert flow.delivery_ratio(6.5, 9.9) == 0.0
    assert flow.delivery_ratio(12.0, 15.0) == 1.0
    assert sim.radio_stats("b").jammed > 0


def test_a_distant_jammer_does_nothing():
    sim = _pair_sim()
    flow = sim.stream("a", "b", rate_hz=10, start_s=3.0, duration_s=5.0)
    sim.add_jammer(Jammer("j", mobility=Static(Vec3(50_000.0, 0.0, 0.0)), power_dbm=20.0))
    sim.run(until_s=9.0)
    assert flow.delivery_ratio() == 1.0


def test_a_jammer_adds_to_collisions_on_a_contended_medium():
    sim = _pair_sim(Medium(phy=FixedRate(bitrate_bps=50_000)))
    flow = sim.stream("a", "b", rate_hz=10, start_s=3.0, duration_s=6.0)
    sim.add_jammer(Jammer("j", mobility=Static(Vec3(210.0, 0.0, 0.0)), power_dbm=20.0, active=(5.0, 7.0)))
    sim.run(until_s=10.0)
    assert flow.delivery_ratio(5.5, 6.9) == 0.0
    assert sim.radio_stats("b").jammed > 0


def test_a_jammer_scoped_to_one_link_leaves_the_others_alone():
    nodes = [
        Node("a", mobility=Static(Vec3(0.0, 0.0, 0.0)), trickle=FAST),
        Node("b", mobility=Static(Vec3(200.0, 0.0, 0.0)), trickle=FAST),
    ]
    links = [pair("a", "b", RADIO), pair("a", "b", PerfectWire())]
    links[1].name = "wire"
    sim = Simulation(nodes, links, seed=0)
    sim.add_jammer(Jammer("j", mobility=Static(Vec3(210.0, 0.0, 0.0)), power_dbm=30.0, links=("a-b",)))
    flow = sim.stream("a", "b", rate_hz=10, start_s=5.0, duration_s=5.0)
    sim.run(until_s=11.0)
    # The radio is jammed; the wire carries everything.
    assert flow.delivery_ratio() == 1.0
    assert sim.route_via("a", "b") == "wire"


def test_unknown_link_in_scope_is_refused():
    sim = _pair_sim()
    with pytest.raises(KeyError):
        sim.add_jammer(Jammer("j", mobility=Static(Vec3()), power_dbm=10.0, links=("nope",)))


def test_interference_at_reports_total_jammer_power():
    sim = _pair_sim()
    assert sim.interference_dbm("b") is None
    sim.add_jammer(Jammer("j", mobility=Static(Vec3(210.0, 0.0, 0.0)), power_dbm=20.0))
    level = sim.interference_dbm("b")
    assert level is not None and level > -60.0
