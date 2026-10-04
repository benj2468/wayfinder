"""Application traffic: a steady stream of numbered packets and what became of
each — the measurement a failover number is made of."""

import pytest

pytest.importorskip("simpy")

from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.topology import diamond, pair
from wayfinder_sim.traffic import Flow, Outage

FAST = (50, 500)


def _pair_sim() -> Simulation:
    nodes = [Node(n, trickle=FAST) for n in ("a", "b")]
    return Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)


def test_stream_on_a_converged_link_delivers_everything():
    sim = _pair_sim()
    flow = sim.stream("a", "b", rate_hz=10, start_s=2.0, duration_s=3.0)
    sim.run(until_s=6.0)

    assert len(flow.sent) == 30
    assert flow.delivery_ratio() == 1.0
    assert flow.outages() == []


def test_stream_payloads_do_not_reach_poll_local():
    sim = _pair_sim()
    sim.stream("a", "b", rate_hz=10, start_s=2.0, duration_s=1.0)
    sim.send("a", "b", b"hello", at_s=2.5)
    sim.run(until_s=4.0)

    assert sim.poll_local("b") == b"hello"
    assert sim.poll_local("b") is None


def test_stream_records_loss_while_the_destination_is_down():
    sim = _pair_sim()
    flow = sim.stream("a", "b", rate_hz=10, start_s=2.0, duration_s=8.0)
    sim.fail_node("b", at_s=4.0, recover_s=6.0)
    sim.run(until_s=12.0)

    assert 0.0 < flow.delivery_ratio() < 1.0
    outages = flow.outages()
    assert outages
    worst = max(outages, key=lambda o: o.lost)
    assert worst.start_s >= 3.9
    assert worst.lost >= 15  # at least the two seconds the node was off


def test_recovery_after_reports_time_to_first_delivery_and_loss():
    sim = Simulation(
        [Node(n, trickle=FAST) for n in ("a", "b", "c", "d")],
        diamond("a", "b", "c", "d", PerfectWire()),
        seed=0,
    )
    flow = sim.stream("a", "d", rate_hz=20, start_s=3.0, duration_s=57.0)
    sim.run(until_s=3.0)
    relay = "b" if sim.route_via("a", "d") == "a-b" else "c"
    sim.fail_node(relay, at_s=5.0)
    sim.run(until_s=61.0)

    recovery = flow.recovery_after(5.0)
    assert recovery.recovered_s is not None
    assert recovery.recovered_s > 0.0
    assert recovery.lost > 0
    # After it heals, the stream is whole again.
    assert flow.delivery_ratio(start_s=5.0 + recovery.recovered_s + 1.0) == 1.0


def test_recovery_after_with_no_loss_is_zero():
    flow = Flow(src="a", dest="b", flow_id=0)
    for seq in range(10):
        flow.record_sent(seq, seq * 0.1)
        flow.record_received(seq, seq * 0.1 + 0.01)
    recovery = flow.recovery_after(0.35)
    assert recovery.lost == 0
    assert recovery.recovered_s == pytest.approx(0.05)


def test_recovery_after_that_never_recovers_is_none():
    flow = Flow(src="a", dest="b", flow_id=0)
    for seq in range(10):
        flow.record_sent(seq, seq * 0.1)
        if seq < 3:
            flow.record_received(seq, seq * 0.1 + 0.01)
    recovery = flow.recovery_after(0.25)
    assert recovery.recovered_s is None
    assert recovery.lost == 7


def test_outages_group_consecutive_losses():
    flow = Flow(src="a", dest="b", flow_id=0)
    delivered = {0, 1, 4, 5, 9}
    for seq in range(10):
        flow.record_sent(seq, float(seq))
        if seq in delivered:
            flow.record_received(seq, float(seq))
    assert flow.outages() == [
        Outage(start_s=2.0, end_s=3.0, lost=2),
        Outage(start_s=6.0, end_s=8.0, lost=3),
    ]
    assert flow.outages(min_lost=3) == [Outage(start_s=6.0, end_s=8.0, lost=3)]


def test_empty_flow_has_no_ratio():
    flow = Flow(src="a", dest="b", flow_id=0)
    assert flow.delivery_ratio() is None


def test_latency_is_receive_minus_send():
    flow = Flow(src="a", dest="b", flow_id=0)
    flow.record_sent(0, 1.0)
    flow.record_received(0, 1.25)
    assert flow.latencies_s() == [pytest.approx(0.25)]
