"""A captured node that misbehaves at forwarding (`wayfinder_sim.insider`).

Every case is an authenticated `hq — relay — team` chain over a perfect wire,
so the only thing that can lose a packet is the relay itself."""

from __future__ import annotations

import pytest

pytest.importorskip("simpy")

from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.insider import Insider
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.security import Credential, Mesh
from wayfinder_sim.topology import path

ATTACK_AT_S = 20.0
END_S = 40.0


def chain(insider: Insider | None, seed: int = 0):
    """Converge the chain, stream team→hq across the attack, and return the
    simulation and the flow."""
    mesh = Mesh(mesh_id=1, root_seed=bytes([7]) * 32)
    nodes = [Node(n, credential=Credential()) for n in ("hq", "relay", "team")]
    sim = Simulation(
        nodes, path(["hq", "relay", "team"], PerfectWire()), seed=seed, mesh=mesh
    )
    flow = sim.stream("team", "hq", rate_hz=20.0, start_s=10.0, duration_s=29.0)
    if insider is not None:
        sim.misbehave("relay", insider, at_s=ATTACK_AT_S)
    sim.run(until_s=END_S)
    return sim, flow


def after_attack(flow) -> float:
    return flow.delivery_ratio(ATTACK_AT_S + 0.5, END_S)


def test_an_honest_relay_delivers_everything():
    sim, flow = chain(None)
    assert after_attack(flow) == 1.0
    assert sim.insider_drops("relay") == 0


def test_selective_forwarding_drops_data_while_the_route_looks_perfect():
    honest, _ = chain(None)
    sim, flow = chain(Insider.selective_forwarding())
    assert flow.delivery_ratio(10.0, ATTACK_AT_S - 0.5) == 1.0
    assert after_attack(flow) == 0.0
    assert sim.insider_drops("relay") > 0
    assert sim.route_path("team", "hq") == ("team", "relay", "hq")
    assert sim.tq_to("team", "hq") == honest.tq_to("team", "hq")


def test_a_grayhole_drops_about_its_share_and_repeats_for_a_seed():
    _, flow = chain(Insider.grayhole(0.5), seed=3)
    _, again = chain(Insider.grayhole(0.5), seed=3)
    assert 0.35 < after_attack(flow) < 0.65
    assert flow.received == again.received


def test_a_blackhole_forwards_nothing_so_the_route_through_it_ages_out():
    sim, flow = chain(Insider.blackhole())
    assert after_attack(flow) == 0.0
    assert not sim.has_route("team", "hq")


@pytest.mark.parametrize("fraction", [-0.1, 1.1])
def test_a_drop_fraction_outside_zero_to_one_is_refused(fraction):
    with pytest.raises(ValueError):
        Insider.grayhole(fraction)


def test_misbehaving_an_unknown_node_is_refused():
    sim = Simulation([Node("a")], [])
    with pytest.raises(KeyError):
        sim.misbehave("nobody", Insider.blackhole())
