import pytest

pytest.importorskip("simpy")

from engine.channel import PerfectWire  # noqa: E402
from engine.mobility import Static, Vec3, Waypoints  # noqa: E402
from engine.node import Node  # noqa: E402
from engine.scenario import Simulation  # noqa: E402
from engine.sweep import run_sweep  # noqa: E402
from engine.topology import pair  # noqa: E402


def _build(trickle_i_min_ms: int) -> Simulation:
    nodes = [
        Node("a", trickle=(trickle_i_min_ms, 500)),
        Node("b", trickle=(trickle_i_min_ms, 500)),
    ]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)
    sim.record("route", lambda s: s.route_via("a", "b"))
    return sim


def test_run_sweep_returns_one_result_per_value_in_order():
    values = [50, 100, 200]

    results = run_sweep(_build, values, until_s=3.0, sample_interval_ms=50)

    assert [r.param for r in results] == values
    for r in results:
        assert len(r.recorder.times_s) > 0
        assert r.recorder.column("route")[-1] == "a-b"


def _build_moving(speed_m_s: float) -> Simulation:
    nodes = [
        Node("a", mobility=Static(Vec3(0, 0, 0))),
        Node(
            "b",
            mobility=Waypoints(
                (Vec3(0, 0, 0), Vec3(100, 0, 0)), speed_m_s=speed_m_s, loop="once"
            ),
        ),
    ]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)
    sim.record("distance", lambda s: s.distance("a", "b"))
    return sim


def test_run_sweep_builds_an_independent_simulation_per_value():
    # A shared/reused Simulation across values (rather than a fresh `build`
    # call per value) would leak state between runs — e.g. all results
    # showing the same trajectory regardless of `speed_m_s`.
    results = run_sweep(
        _build_moving, [10.0, 50.0], until_s=2.0, sample_interval_ms=100
    )

    slow_final_distance = results[0].recorder.column("distance")[-1]
    fast_final_distance = results[1].recorder.column("distance")[-1]
    assert fast_final_distance > slow_final_distance
