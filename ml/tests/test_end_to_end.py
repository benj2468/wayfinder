"""End-to-end: a real simulation of real routers produces trainable rows.

Every other test in this suite uses fakes so it can run with only numpy. This
one deliberately does not — it drives `wayfinder_sim`, which drives real
`wayfinder_py.PyDriver`s, and asserts that what comes out the far end is a
valid `FeatureBatch`. It is the only test that would catch the two halves
drifting apart.

Skipped where SimPy or the PyO3 extension are absent, matching how
`sim/tests` gates its own SimPy-touching cases.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("simpy")
pytest.importorskip("wayfinder_py")

from wayfinder_sim.channel import PerfectWire  # noqa: E402
from wayfinder_sim.node import Node  # noqa: E402
from wayfinder_sim.scenario import Simulation  # noqa: E402
from wayfinder_sim.topology import pair, path  # noqa: E402

from wayfinder_ml import generate, scenarios, schema, stats  # noqa: E402

SCENARIO_DIR = Path(__file__).resolve().parents[2] / "sim" / "scenarios"
"""The repo's own scenarios — the ones `wayfinder-ml generate` is pointed at
in anger."""


def _converged_pair() -> Simulation:
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)
    sim.run(until_s=3.0, sample_interval_ms=50)
    return sim


def test_snapshot_of_a_real_router_has_the_learned_originator() -> None:
    snapshot = generate.router_snapshot(_converged_pair(), "a")

    assert snapshot.node == "a"
    assert [o.originator for o in snapshot.originators] == ["b"]
    assert snapshot.originators[0].best_next_hop == "b"
    assert snapshot.originators[0].paths[0].neighbor == "b"


def test_channel_graph_of_a_perfect_wire_is_certain_delivery() -> None:
    graph = generate.channel_graph(_converged_pair(), ["a", "b"])
    assert graph == {("a", "b"): 1.0, ("b", "a"): 1.0}


def test_sample_instant_produces_a_valid_labelled_batch() -> None:
    batch = generate.sample_instant(_converged_pair())

    batch.validate()
    assert batch.rows == 2, "one row per node, each knowing one originator"
    assert all(label != schema.NO_LABEL for label in batch.label), (
        "on a two-node wire the only candidate is also the oracle's choice"
    )


def test_three_hop_chain_labels_the_relay_as_next_hop() -> None:
    """The end-to-end claim that matters: on a chain a-b-c, the oracle's next
    hop from `a` to `c` is `b`, and that must be the slot the label selects."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c")]
    sim = Simulation(nodes, path(["a", "b", "c"], PerfectWire()), seed=0)
    sim.run(until_s=6.0, sample_interval_ms=50)

    snapshot = generate.router_snapshot(sim, "a")
    to_c = next(o for o in snapshot.originators if o.originator == "c")
    assert to_c.best_next_hop == "b", "BATMAN itself relays via b"

    batch = generate.sample_instant(sim)
    batch.validate()
    assert batch.rows > 0


def test_episode_rows_sweeps_a_real_simpy_clock() -> None:
    """The sweep steps `sim.env` directly, so the one thing a fake cannot
    check is that SimPy accepts those steps — sub-second intervals land on
    fractional milliseconds, and SimPy refuses a step that does not advance."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c")]
    sim = Simulation(nodes, path(["a", "b", "c"], PerfectWire()), seed=0)

    batch = generate.episode_rows(sim, duration_s=6.0, interval_s=0.5, warmup_s=2.0)

    batch.validate()
    assert sim.env.now == 6000
    assert batch.rows > 0
    assert stats.labelled_fraction(batch) > 0


def test_a_scenario_run_writes_rows_from_a_repo_scenario(tmp_path) -> None:
    """The whole command, on the real thing: resolve `drone_relay.py`, sweep
    it, and get a dataset back."""
    scenario = scenarios.load(str(SCENARIO_DIR / "drone_relay.py"))

    episodes = list(
        generate.episodes(
            scenario.build, count=2, seed=0, duration_s=20.0, interval_s=5.0
        )
    )

    assert [e.seed for e in episodes] == [0, 1]
    for episode in episodes:
        episode.batch.validate()
        assert episode.batch.rows > 0


def test_repo_scenarios_load_without_a_plotting_stack() -> None:
    """Generation wants `build_simulation` and nothing else. A scenario that
    imports matplotlib at module scope makes a headless generation box need a
    plotting stack it will never draw with — so the repo's own scenarios keep
    those imports inside their plotting functions, and this is the test that
    notices when one drifts back."""
    if "matplotlib" in sys.modules:
        pytest.skip("matplotlib already imported by another test or plugin")

    for name in ("drone_relay", "satellite_relay"):
        scenario = scenarios.load(str(SCENARIO_DIR / f"{name}.py"))

        assert scenario.name == name
        assert scenario.duration_s and scenario.duration_s > 0
        assert scenario.build(0).node_names, "the factory builds a real Simulation"

    assert "matplotlib" not in sys.modules
