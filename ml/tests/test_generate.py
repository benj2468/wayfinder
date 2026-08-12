"""Generation-side tests.

These use the stand-ins in `fakesim` rather than the real
`wayfinder_sim.scenario.Simulation`: the generator touches only a handful of its
methods, so a fake keeps these tests runnable without SimPy or the PyO3
extension. `tests/test_end_to_end.py` drives the real thing.
"""

from __future__ import annotations

import pytest
from fakesim import (
    FakeDriver,
    FakeLink,
    FakeMac,
    FakePath,
    FakeRecord,
    FakeSample,
    FakeSim,
)
from wayfinder_ml import generate
from wayfinder_sim import NoLinkError

ROWS_PER_INSTANT = 2
"""`FakeSim` is two nodes, each knowing one originator — so one row apiece."""


class _FakeChannelSim:
    """Mimics `Simulation.sample_channel`, including its `NoLinkError` for a
    pair with no link between them."""

    def __init__(self, pairs: dict[frozenset[str], float]) -> None:
        self._pairs = pairs

    def sample_channel(self, a: str, b: str) -> FakeSample:
        key = frozenset((a, b))
        if key not in self._pairs:
            raise NoLinkError(f"no link between {a!r} and {b!r}")
        return FakeSample(self._pairs[key])


class _BrokenChannelSim:
    """A `Channel.evaluate()` bug raising plain `ValueError` — must not be
    mistaken for `NoLinkError`'s "not linked"."""

    def sample_channel(self, a: str, b: str) -> FakeSample:
        raise ValueError("tx_power_dbm must be positive")


def test_channel_graph_covers_both_directions() -> None:
    """The oracle treats edges as directed, so a link must appear twice."""
    sim = _FakeChannelSim({frozenset(("a", "b")): 0.75})

    graph = generate.channel_graph(sim, ["a", "b"])

    assert graph == {("a", "b"): 0.75, ("b", "a"): 0.75}


def test_channel_graph_does_not_swallow_a_genuine_channel_bug() -> None:
    """A `ValueError` that isn't `NoLinkError` is a real bug in the channel
    model, not a topology gap — it must propagate, not vanish as a dropped
    edge."""
    with pytest.raises(ValueError, match="tx_power_dbm"):
        generate.channel_graph(_BrokenChannelSim(), ["a", "b"])


def test_channel_graph_skips_unlinked_pairs() -> None:
    """Nodes with no link between them are simply absent, not zero-probability
    edges — the oracle distinguishes 'no link' from 'dead link' only by
    absence."""
    sim = _FakeChannelSim({frozenset(("a", "b")): 1.0})

    graph = generate.channel_graph(sim, ["a", "b", "c"])

    assert set(graph) == {("a", "b"), ("b", "a")}


def test_channel_graph_is_empty_for_a_single_node() -> None:
    assert generate.channel_graph(_FakeChannelSim({}), ["a"]) == {}


class _SimWithRouter:
    """Stands in for `Simulation`'s router-facing accessors."""

    def __init__(self, driver, macs):
        self._driver, self._macs = driver, macs
        self.env = FakeSim().env

    def driver(self, node):
        return self._driver

    def node_for_mac(self, mac):
        return self._macs.get(mac)


def test_router_snapshot_translates_macs_to_node_names() -> None:
    """Router state is keyed by MAC; the oracle works in node names, so the
    snapshot must be expressed in names or the two cannot be joined."""
    sim = FakeSim()
    sim.env.run(1000)

    snapshot = generate.router_snapshot(sim, "a")

    assert snapshot.node == "a"
    assert snapshot.now_ms == 1000
    assert [o.originator for o in snapshot.originators] == ["b"]
    assert snapshot.originators[0].best_next_hop == "b"
    assert [p.neighbor for p in snapshot.originators[0].paths] == ["b"]
    assert [link.neighbor for link in snapshot.links] == ["b"]


def test_router_snapshot_carries_occupancy_and_neighbor_count() -> None:
    snapshot = generate.router_snapshot(FakeSim(), "a")
    assert snapshot.neighbor_count == 1
    assert snapshot.originator_occupancy == (1, 32)


def test_router_snapshot_rejects_an_unresolvable_mac() -> None:
    """Every MAC in a simulated router belongs to a simulated node. One that
    does not resolve means a real bug, so it must not be quietly dropped."""
    stray = FakeMac("ghost")
    driver = FakeDriver(
        records=[FakeRecord(stray, stray, [FakePath(stray)])], links=[FakeLink(stray)]
    )
    sim = _SimWithRouter(driver, {})

    with pytest.raises(ValueError, match="does not belong to any node"):
        generate.router_snapshot(sim, "a")


# --- episode sweep -------------------------------------------------------


def test_episode_rows_samples_the_whole_window_at_the_interval() -> None:
    """A sweep is `sample_instant` on a cadence: both endpoints included, so a
    4 s episode at 1 s yields five instants, not four."""
    sim = FakeSim()

    batch = generate.episode_rows(sim, duration_s=4.0, interval_s=1.0)

    batch.validate()
    assert sim.sampled_at == [0, 1000, 2000, 3000, 4000]
    assert batch.rows == 5 * ROWS_PER_INSTANT


def test_episode_rows_skips_the_warmup_window() -> None:
    """Before a mesh converges its routers hold no candidates and its OGM
    intervals are unestimated, so the earliest instants are noise the model
    would have to unlearn. Warmup runs the clock through them unsampled."""
    sim = FakeSim()

    batch = generate.episode_rows(sim, duration_s=4.0, interval_s=1.0, warmup_s=2.0)

    assert sim.sampled_at == [2000, 3000, 4000]
    assert batch.rows == 3 * ROWS_PER_INSTANT


def test_episode_rows_samples_once_when_the_window_is_a_single_instant() -> None:
    sim = FakeSim()

    batch = generate.episode_rows(sim, duration_s=2.0, interval_s=1.0, warmup_s=2.0)

    assert sim.sampled_at == [2000]
    assert batch.rows == ROWS_PER_INSTANT


def test_episode_rows_never_runs_the_clock_backwards() -> None:
    """`FakeClock` refuses a backwards step exactly as SimPy does; an interval
    finer than the clock's resolution must not trip it."""
    sim = FakeSim()

    generate.episode_rows(sim, duration_s=0.05, interval_s=0.01)

    assert sim.sampled_at == sorted(sim.sampled_at)


def test_episode_rows_rejects_a_non_positive_interval() -> None:
    """Zero would loop forever; negative would walk backwards. Both are
    mistakes worth catching before a sweep starts, not after."""
    with pytest.raises(ValueError, match="interval_s"):
        generate.episode_rows(FakeSim(), duration_s=1.0, interval_s=0.0)


def test_episode_rows_rejects_a_warmup_past_the_end() -> None:
    with pytest.raises(ValueError, match="warmup_s"):
        generate.episode_rows(FakeSim(), duration_s=1.0, interval_s=0.5, warmup_s=2.0)


def test_episodes_walk_consecutive_seeds_from_a_fresh_simulation() -> None:
    """Each episode gets its own simulation, built from its own seed — the
    same seed twice would silently double a row's weight in the dataset."""
    built: list[int] = []

    def build(seed: int) -> FakeSim:
        built.append(seed)
        return FakeSim(seed)

    episodes = list(
        generate.episodes(build, count=3, seed=5, duration_s=1.0, interval_s=1.0)
    )

    assert built == [5, 6, 7]
    assert [e.seed for e in episodes] == [5, 6, 7]
    for episode in episodes:
        episode.batch.validate()
        assert episode.batch.rows == 2 * ROWS_PER_INSTANT


def test_episodes_are_produced_lazily() -> None:
    """Shards are written per episode so a long sweep can be interrupted and
    resumed. That only holds if episodes are yielded as they finish rather
    than accumulated in memory first."""
    built: list[int] = []

    def build(seed: int) -> FakeSim:
        built.append(seed)
        return FakeSim(seed)

    stream = generate.episodes(build, count=3, seed=0, duration_s=1.0, interval_s=1.0)
    next(stream)

    assert built == [0], "only the first episode's simulation has been built"


def test_episodes_rejects_a_non_positive_count() -> None:
    with pytest.raises(ValueError, match="count"):
        list(
            generate.episodes(FakeSim, count=0, seed=0, duration_s=1.0, interval_s=1.0)
        )
