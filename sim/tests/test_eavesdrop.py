"""A listener with a position: it hears what the radio physics lets it hear,
rather than everything that crosses a named link."""

from __future__ import annotations

import pytest
import wayfinder_py as wf
from wayfinder_sim import forge
from wayfinder_sim.adversary import Adversary
from wayfinder_sim.channel import FreeSpacePathLoss, PerfectWire, TerrainMasked
from wayfinder_sim.interference import Jammer
from wayfinder_sim.medium import FixedRate, Medium
from wayfinder_sim.mobility import Static, Vec3, Waypoints
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.terrain import GaussianPeak, MountainRange
from wayfinder_sim.topology import pair, shared_lan

# Noise-free with a hard cutoff, so "in range" is a fact rather than a draw.
_RADIO = FreeSpacePathLoss(noise_sigma_db=0.0, max_range_m=1000.0)


def _at(x: float, y: float = 0.0, z: float = 2.0) -> Static:
    return Static(Vec3(x, y, z))


def _pair(channel=_RADIO, medium: Medium | None = None, seed: int = 1) -> Simulation:
    nodes = [Node("a", mobility=_at(0.0)), Node("b", mobility=_at(100.0))]
    return Simulation(nodes, [pair("a", "b", channel, medium=medium)], seed=seed)


def _listener(name: str, x: float, y: float = 0.0) -> Adversary:
    return Adversary(name, _at(x, y))


def test_a_listener_in_range_hears_both_ends_and_one_out_of_range_neither():
    sim = _pair()
    near = sim.wiretap("a-b", at=_listener("near", 50.0, 50.0))
    far = sim.wiretap("a-b", at=_listener("far", 0.0, 5000.0))
    sim.run(until_s=3.0)

    assert near.by_source(sim.mac("a")) and near.by_source(sim.mac("b"))
    assert near.missed == 0
    assert len(far) == 0
    assert far.missed == len(near), "every transmission was on air for both"


def test_range_is_judged_per_transmitter():
    """A listener close to one end and beyond the other hears only that end."""
    sim = _pair()
    tap = sim.wiretap("a-b", at=_listener("beside-a", -950.0))
    sim.run(until_s=3.0)

    assert tap.by_source(sim.mac("a"))
    assert not tap.by_source(sim.mac("b"))


def test_a_moving_listener_hears_only_while_close_enough():
    sim = _pair()
    walker = Waypoints((Vec3(0.0, 5000.0, 2.0), Vec3(0.0, 0.0, 2.0)), speed_m_s=500.0)
    tap = sim.wiretap("a-b", at=Adversary("walker", walker))
    sim.run(until_s=15.0)

    assert tap.frames, "it arrives"
    assert min(f.t_s for f in tap.frames) > 7.9, "nothing heard beyond 1 km"


def test_a_mountain_hides_a_transmitter_from_the_listener():
    hill = MountainRange((GaussianPeak(x=0.0, y=300.0, height_m=400.0, sigma_m=60.0),))
    sim = _pair(TerrainMasked(_RADIO, hill))
    behind = sim.wiretap("a-b", at=_listener("behind", 0.0, 600.0))
    open_ground = sim.wiretap("a-b", at=_listener("open", 0.0, -600.0))
    sim.run(until_s=3.0)

    assert open_ground.by_source(sim.mac("a"))
    assert not behind.by_source(sim.mac("a"))


def test_listening_does_not_change_what_the_mesh_receives():
    """The listener draws from its own stream: a lossy run is identical with
    and without it."""

    def run(listen: bool) -> list[tuple[bool, int | None]]:
        lossy = FreeSpacePathLoss(noise_sigma_db=6.0)
        nodes = [Node("a", mobility=_at(0.0)), Node("b", mobility=_at(500.0))]
        sim = Simulation(nodes, [pair("a", "b", lossy)], seed=3)
        if listen:
            sim.wiretap("a-b", at=_listener("l", 250.0))
        sim.record("tq", lambda s: (s.has_route("a", "b"), s.tq_to("a", "b")))
        return list(sim.run(until_s=10.0).column("tq"))

    assert run(True) == run(False)


def test_a_lossy_listen_is_reproducible_for_a_seed():
    def heard(seed: int) -> list[float]:
        sim = _pair(FreeSpacePathLoss(), seed=seed)
        tap = sim.wiretap("a-b", at=_listener("edge", 0.0, 500.0))
        sim.run(until_s=20.0)
        assert tap.frames and tap.missed
        return [f.t_s for f in tap.frames]

    assert heard(5) == heard(5)


def test_a_jammer_beside_the_listener_deafens_it_but_not_the_mesh():
    sim = _pair()
    sim.add_jammer(Jammer("j", _at(0.0, 801.0), power_dbm=20.0))
    tap = sim.wiretap("a-b", at=_listener("jammed", 0.0, 800.0))
    sim.run(until_s=3.0)

    assert len(tap) == 0 and tap.missed > 0
    assert sim.has_route("a", "b")


def test_frames_colliding_at_the_listener_are_lost_to_it():
    """Two frames keyed up together at equal range destroy each other at the
    listener; one sent alone gets through."""
    nodes = [
        Node(n, mobility=_at(x), trickle=(60_000, 60_000))
        for n, x in (("a", -100.0), ("b", 100.0), ("c", 0.0))
    ]
    medium = Medium(FixedRate(bitrate_bps=10_000))
    sim = Simulation(nodes, shared_lan(["a", "b", "c"], _RADIO, medium=medium), seed=1)
    link = "a-b-c"
    tap = sim.wiretap(link, at=_listener("mid", 0.0, 100.0))
    for src, at_s in (("a", 30.0), ("b", 30.0), ("a", 31.0)):
        marker = forge.link_frame(wf.PyMac.BROADCAST, sim.mac(src), b"marker" * 10)
        sim.inject(src, marker, at_s=at_s)
    sim.run(until_s=32.0)

    assert [round(f.t_s) for f in tap.containing(b"marker")] == [31]


def test_a_wire_cannot_be_overheard_from_a_distance():
    sim = _pair(PerfectWire())
    with pytest.raises(ValueError, match="wire"):
        sim.wiretap("a-b", at=_listener("l", 0.0))


def test_adversary_names_identify_one_adversary():
    sim = _pair()
    eve = _listener("eve", 0.0)
    sim.wiretap("a-b", at=eve)
    with pytest.raises(ValueError, match="eve"):
        sim.wiretap("a-b", at=_listener("eve", 10.0))
    with pytest.raises(ValueError, match="eve"):
        sim.wiretap("a-b", at=eve)
