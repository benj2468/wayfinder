"""`Simulation.wormhole`: two keyless radios tunnelling frames between two
parts of an authenticated mesh.

The topology is a four-hop chain, `hq - r1 - r2 - r3 - field`, with one
attacker radio in earshot of each end. Honest traffic from `field` to `hq`
goes via `r3`; a wormhole makes `hq` look like `field`'s direct neighbour.
"""

from __future__ import annotations

import pytest
from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.security import Credential, Mesh
from wayfinder_sim.topology import pair, path
from wayfinder_sim.wormhole import control_only

CHAIN = ["hq", "r1", "r2", "r3", "field"]
ONSET_S = 30.0


def _mesh_sim(seed: int = 0) -> Simulation:
    nodes = [Node(name, credential=Credential()) for name in CHAIN]
    nodes += [Node("eve_a"), Node("eve_b")]
    links = [
        *path(CHAIN, PerfectWire()),
        pair("hq", "eve_a", PerfectWire()),
        pair("field", "eve_b", PerfectWire()),
    ]
    return Simulation(
        nodes, links, seed=seed, mesh=Mesh(mesh_id=1, root_seed=bytes([7]) * 32)
    )


@pytest.mark.parametrize(
    ("a", "b"),
    [("eve_a", "eve_a"), ("eve_a", "hq"), ("eve_a", "nobody")],
    ids=["same-node", "ends-hear-each-other", "unknown-node"],
)
def test_a_wormhole_that_cannot_exist_is_refused(a, b):
    sim = _mesh_sim()
    with pytest.raises((KeyError, ValueError)):
        sim.wormhole(a, b)


def test_one_radio_cannot_be_the_end_of_two_wormholes():
    sim = _mesh_sim()
    sim.wormhole("eve_a", "eve_b")
    with pytest.raises(ValueError):
        sim.wormhole("eve_b", "eve_a")


def test_a_wormhole_draws_the_route_through_itself():
    sim = _mesh_sim()
    tunnel = sim.wormhole("eve_a", "eve_b", at_s=ONSET_S)
    sim.run(until_s=ONSET_S)
    assert sim.next_hop("field", "hq") == "r3"
    assert tunnel.tunnelled == 0, "nothing may cross before the onset"

    flow = sim.stream("field", "hq", rate_hz=10.0, start_s=60.0, duration_s=20.0)
    sim.run(until_s=85.0)

    assert sim.next_hop("field", "hq") == "hq"
    assert sim.route_via("field", "hq") == "field-eve_b"
    assert tunnel.tunnelled > 0
    assert tunnel.withheld == 0
    assert flow.delivery_ratio() == 1.0


def test_a_control_only_wormhole_swallows_the_traffic_it_attracted():
    sim = _mesh_sim()
    tunnel = sim.wormhole("eve_a", "eve_b", passes=control_only, at_s=ONSET_S)
    flow = sim.stream("field", "hq", rate_hz=10.0, start_s=60.0, duration_s=20.0)
    sim.run(until_s=85.0)

    assert sim.next_hop("field", "hq") == "hq"
    assert flow.delivery_ratio() == 0.0
    assert tunnel.withheld >= len(flow.sent)


def test_the_route_recovers_once_the_wormhole_closes():
    sim = _mesh_sim()
    sim.wormhole("eve_a", "eve_b", passes=control_only, at_s=ONSET_S, until_s=60.0)
    flow = sim.stream("field", "hq", rate_hz=10.0, start_s=120.0, duration_s=10.0)
    sim.run(until_s=135.0)

    assert sim.next_hop("field", "hq") == "r3"
    assert flow.delivery_ratio() == 1.0


@pytest.mark.parametrize(
    ("latency_ms", "captured"),
    [(200.0, True), (2000.0, False)],
    ids=["quick-tunnel", "slow-tunnel"],
)
def test_the_tunnels_latency_decides_whether_it_captures_the_route(
    latency_ms, captured
):
    sim = _mesh_sim()
    sim.wormhole("eve_a", "eve_b", latency_ms=latency_ms, at_s=ONSET_S)
    sim.run(until_s=90.0)

    assert (sim.next_hop("field", "hq") == "hq") is captured


def test_a_wormhole_run_repeats_for_a_seed():
    def run() -> tuple[int, int]:
        sim = _mesh_sim(seed=3)
        tunnel = sim.wormhole("eve_a", "eve_b", passes=control_only, at_s=5.0)
        sim.stream("field", "hq", rate_hz=10.0, start_s=20.0, duration_s=5.0)
        sim.run(until_s=30.0)
        return tunnel.tunnelled, tunnel.withheld

    assert run() == run()
