"""A captured node that misbehaves at forwarding (`wayfinder_sim.insider`).

Every case is an authenticated `hq — relay — team` chain over a perfect wire,
so the only thing that can lose a packet is the relay itself."""

from __future__ import annotations

from random import Random

import pytest

pytest.importorskip("simpy")

from wayfinder_sim import forge
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


DELAY_MS = 300.0


def test_a_delaying_relay_delivers_late_while_the_route_looks_perfect():
    honest, _ = chain(None)
    sim, flow = chain(Insider.delaying(DELAY_MS))
    # A second short of the end: later packets are still held when it stops.
    assert flow.delivery_ratio(ATTACK_AT_S, END_S - 1.5) == 1.0
    late = [
        flow.received[s] - t
        for s, t in flow.sent
        if s in flow.received and t >= ATTACK_AT_S
    ]
    early = [flow.received[s] - t for s, t in flow.sent if t < ATTACK_AT_S - 0.5]
    assert min(late) >= DELAY_MS / 1000.0
    assert max(early) < DELAY_MS / 1000.0
    assert sim.insider_delays("relay") > 0
    assert sim.insider_drops("relay") == 0
    assert sim.route_path("team", "hq") == ("team", "relay", "hq")
    assert sim.tq_to("team", "hq") == honest.tq_to("team", "hq")


def test_a_frame_held_across_a_reboot_is_lost():
    mesh = Mesh(mesh_id=1, root_seed=bytes([7]) * 32)
    nodes = [Node(n, credential=Credential()) for n in ("hq", "relay", "team")]
    sim = Simulation(nodes, path(["hq", "relay", "team"], PerfectWire()), mesh=mesh)
    flow = sim.stream("team", "hq", rate_hz=20.0, start_s=10.0, duration_s=5.0)
    # Held far longer than the stream, with the relay rebooting in between.
    sim.misbehave("relay", Insider.delaying(20_000.0), at_s=9.0)
    sim.fail_node("relay", at_s=16.0, recover_s=17.0)
    sim.run(until_s=40.0)
    assert sim.insider_delays("relay") > 0
    assert flow.delivery_ratio() == 0.0


@pytest.mark.parametrize("delay_ms", [0.0, -1.0, float("nan"), float("inf")])
def test_a_delay_that_is_not_a_positive_time_is_refused(delay_ms):
    with pytest.raises(ValueError):
        Insider.delaying(delay_ms)


def link_frame(packet_type: int | None, protocol: int = forge.BATMAN_ETHERTYPE):
    """A link header of `protocol`, then the packet-type byte if there is one."""
    header = bytes(12) + protocol.to_bytes(2, "big")
    return header if packet_type is None else header + bytes([packet_type])


@pytest.mark.parametrize(
    "frame",
    [
        link_frame(forge.PACKET_UNICAST, protocol=0x0800),
        link_frame(None),
        link_frame(forge.PACKET_OGM),
    ],
    ids=["not-batman", "header-only", "control"],
)
def test_selective_forwarding_passes_what_is_not_batman_data(frame):
    assert not Insider.selective_forwarding().drops(frame, Random(0))


@pytest.mark.parametrize("packet_type", [forge.PACKET_OGM, forge.PACKET_UNICAST])
def test_the_drop_fraction_bounds_are_accepted_and_absolute(packet_type):
    frame = link_frame(packet_type)
    rng = Random(0)
    assert not any(Insider(None, 0.0).drops(frame, rng) for _ in range(100))
    assert all(Insider(None, 1.0).drops(frame, rng) for _ in range(100))


def test_misbehaving_an_unknown_node_is_refused():
    sim = Simulation([Node("a")], [])
    with pytest.raises(KeyError):
        sim.misbehave("nobody", Insider.blackhole())


def test_delaying_holds_data_only_unless_told_otherwise():
    data, control = link_frame(forge.PACKET_UNICAST), link_frame(forge.PACKET_OGM)
    rng = Random(0)
    insider = Insider.delaying(DELAY_MS)
    assert insider.holds_ms(data) == DELAY_MS
    assert insider.holds_ms(control) == 0.0
    assert not insider.drops(data, rng)
    everything = Insider.delaying(DELAY_MS, packet_types=None)
    assert everything.holds_ms(control) == DELAY_MS
    assert Insider.selective_forwarding().holds_ms(data) == 0.0
