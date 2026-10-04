"""A shared radio medium: airtime, collisions, half-duplex, duty cycle and
the energy a radio spends — the physics a crowded LoRa channel is made of."""

from __future__ import annotations

import pytest

pytest.importorskip("simpy")

import wayfinder_py as wf
from wayfinder_sim.channel import FreeSpacePathLoss, PerfectWire
from wayfinder_sim.link import Link
from wayfinder_sim.medium import EnergyModel, FixedRate, LoRaPhy, Medium
from wayfinder_sim.mobility import Static, Vec3
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.topology import shared_lan

FAST = (50, 500)


def _garbage(n: int = 20) -> bytes:
    """A broadcast frame the routers will drop as malformed — enough to
    occupy the air, which is all the medium cares about."""
    return bytes(wf.PyMac.BROADCAST.bytes) + bytes(6) + b"\xff\xff" + bytes(n)


# --- airtime ---------------------------------------------------------------


def test_lora_time_on_air_matches_the_semtech_formula():
    # Reference values from Semtech's LoRa calculator (explicit header, CRC on,
    # 8-symbol preamble, CR 4/5).
    assert LoRaPhy(sf=7, bw_hz=125e3).airtime_s(10) == pytest.approx(0.041216, abs=1e-6)
    assert LoRaPhy(sf=9, bw_hz=125e3).airtime_s(20) == pytest.approx(0.185344, abs=1e-6)
    # SF12 at 125 kHz turns on low-data-rate optimisation.
    assert LoRaPhy(sf=12, bw_hz=125e3).airtime_s(10) == pytest.approx(0.991232, abs=1e-6)


def test_lora_fragments_frames_longer_than_its_payload_limit():
    phy = LoRaPhy(sf=7, bw_hz=125e3, max_payload=100)
    assert phy.airtime_s(250) == pytest.approx(
        2 * phy.airtime_s(100) + phy.airtime_s(50), rel=1e-9
    )


def test_fixed_rate_airtime_is_bits_over_rate():
    assert FixedRate(bitrate_bps=250_000, overhead_bytes=6).airtime_s(19) == pytest.approx(
        25 * 8 / 250_000
    )


# --- delivery, collisions, half-duplex --------------------------------------


def _three(medium: Medium, *, c_x: float = 100.0) -> Simulation:
    """a — b — c on one segment; a and c both hear b."""
    nodes = [
        Node("a", mobility=Static(Vec3(-100.0, 0.0, 0.0)), trickle=(60_000, 60_000)),
        Node("b", mobility=Static(Vec3(0.0, 0.0, 0.0)), trickle=(60_000, 60_000)),
        Node("c", mobility=Static(Vec3(c_x, 0.0, 0.0)), trickle=(60_000, 60_000)),
    ]
    radio = FreeSpacePathLoss(tx_power_dbm=14.0, noise_sigma_db=0.0, delivery_steepness=5.0)
    return Simulation(nodes, [Link(("a", "b", "c"), radio, medium=medium)], seed=0)


def test_a_frame_arrives_one_airtime_after_it_is_sent():
    medium = Medium(phy=FixedRate(bitrate_bps=10_000))
    sim = _three(medium)
    sim.inject("a", _garbage(), at_s=5.0)
    sim.run(until_s=5.0 + 0.9 * medium.phy.airtime_s(len(_garbage())))
    assert sim.radio_stats("b").rx_frames == 0
    sim.run(until_s=6.0)
    assert sim.radio_stats("b").rx_frames == 1
    assert sim.radio_stats("a").tx_airtime_s == pytest.approx(medium.phy.airtime_s(len(_garbage())))


def test_overlapping_equal_power_frames_collide():
    sim = _three(Medium(phy=FixedRate(bitrate_bps=10_000), capture_db=6.0))
    sim.inject("a", _garbage(), at_s=5.0)
    sim.inject("c", _garbage(), at_s=5.001)
    sim.run(until_s=6.0)
    b = sim.radio_stats("b")
    assert b.rx_frames == 0
    assert b.collisions == 2


def test_a_much_stronger_frame_captures_the_receiver():
    # c sits 10 m from b, a 100 m: c's frame is 20 dB stronger at b.
    sim = _three(Medium(phy=FixedRate(bitrate_bps=10_000), capture_db=6.0), c_x=10.0)
    sim.inject("a", _garbage(), at_s=5.0)
    sim.inject("c", _garbage(), at_s=5.001)
    sim.run(until_s=6.0)
    b = sim.radio_stats("b")
    assert b.rx_frames == 1
    assert b.collisions == 1


def test_a_radio_cannot_hear_while_it_transmits():
    sim = _three(Medium(phy=FixedRate(bitrate_bps=10_000)))
    sim.inject("b", _garbage(), at_s=5.0)
    sim.inject("a", _garbage(), at_s=5.001)
    sim.run(until_s=6.0)
    assert sim.radio_stats("b").rx_frames == 0
    assert sim.radio_stats("b").half_duplex_losses == 1
    # c heard b (and a's frame collided with b's at c only if both reach it;
    # a is 200 m from c, b 100 m: b's frame captures c).
    assert sim.radio_stats("c").rx_frames >= 1


def test_one_radio_sends_its_queue_back_to_back_never_overlapping():
    medium = Medium(phy=FixedRate(bitrate_bps=10_000))
    sim = _three(medium)
    for _ in range(3):
        sim.inject("a", _garbage(), at_s=5.0)
    sim.run(until_s=6.0)
    assert sim.radio_stats("b").rx_frames == 3
    assert sim.radio_stats("b").collisions == 0


def test_the_queue_overflows_rather_than_growing_without_bound():
    sim = _three(Medium(phy=FixedRate(bitrate_bps=1_000), queue_limit=2))
    for _ in range(5):
        sim.inject("a", _garbage(), at_s=5.0)
    sim.run(until_s=10.0)
    a = sim.radio_stats("a")
    # One on the air, two waiting, two dropped.
    assert a.queue_drops == 2
    assert a.tx_frames == 3


# --- duty cycle ---------------------------------------------------------------


def test_duty_cycle_bounds_airtime_share():
    medium = Medium(phy=FixedRate(bitrate_bps=10_000), duty_cycle=0.1, queue_limit=1000)
    sim = _three(medium)
    for i in range(200):
        sim.inject("a", _garbage(), at_s=1.0 + i * 0.001)
    sim.run(until_s=21.0)
    a = sim.radio_stats("a")
    one = medium.phy.airtime_s(len(_garbage()))
    assert a.tx_airtime_s <= 0.1 * 20.0 + one
    assert a.tx_airtime_s >= 0.1 * 20.0 - 2 * one
    assert a.duty_wait_s > 0.0


def test_routers_converge_over_a_lora_medium():
    phy = LoRaPhy(sf=7, bw_hz=125e3)
    nodes = [Node(n, trickle=(2000, 20_000)) for n in ("a", "b", "c")]
    sim = Simulation(nodes, shared_lan(["a", "b", "c"], PerfectWire(), medium=Medium(phy=phy)), seed=0)
    sim.run(until_s=60.0)
    assert sim.has_route("a", "c")
    assert sim.radio_stats("a").tx_airtime_s > 0.0


# --- energy -------------------------------------------------------------------


def test_energy_charges_tx_rx_and_idle_time_at_their_own_power():
    model = EnergyModel(tx_mw=100.0, rx_mw=10.0, idle_mw=1.0)
    sim = _three(Medium(phy=FixedRate(bitrate_bps=10_000)))
    sim.inject("a", _garbage(), at_s=5.0)
    sim.run(until_s=10.0)
    stats = sim.radio_stats("a")
    expected_mj = (
        stats.tx_airtime_s * 100.0
        + stats.rx_airtime_s * 10.0
        + (10.0 - stats.tx_airtime_s - stats.rx_airtime_s) * 1.0
    )
    assert sim.energy_mj("a", model) == pytest.approx(expected_mj)
    assert sim.average_power_mw("a", model) == pytest.approx(expected_mj / 10.0)


def test_battery_life_is_capacity_over_average_power():
    model = EnergyModel(tx_mw=100.0, rx_mw=10.0, idle_mw=1.0)
    assert model.battery_life_h(capacity_mwh=1000.0, average_power_mw=2.0) == pytest.approx(500.0)
