"""Simulation -> dataset shards. The repo-bound half of the pipeline.

Data comes from `wayfinder_sim`, which already drives *real* routers: each node
is a `wayfinder_py.PyDriver` wrapping the actual `wayfinder_tick_driver::
Driver`, ticked against Python-side mobility and channel models. So the
features are a real router's real state, not a reimplementation of BATMAN in
Python that would drift from the shipped engine.

The labels come from `oracle`, using ground truth the same simulation holds:
true positions and true per-pair delivery probability. Training therefore
teaches the router's noisy, delayed view to predict what a perfectly-informed
router would have done — supervised imitation of a privileged expert, which
needs no reward shaping and no environment interaction loop.

Sampling one instant costs one channel graph plus one Dijkstra per
destination, shared across every node — so per-node cost is the feature walk
alone, and a scenario can be sampled densely without the labeling dominating.
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Iterator, Sequence
from itertools import combinations
from typing import Any, Callable

from wayfinder_sim import NoLinkError

from .features import (
    LinkObservation,
    OriginatorObservation,
    PathObservation,
    RouterSnapshot,
    build_batch,
)
from .oracle import Edge, best_next_hops, costs_to, etx
from .schema import FeatureBatch, concat, empty


def channel_graph(sim: Any, nodes: Sequence[str]) -> dict[Edge, float]:
    """Ground-truth delivery probability for every linked pair, both
    directions.

    Uses `Simulation.sample_channel`, which evaluates on a dedicated probe RNG
    stream — so building the answer key never perturbs the simulated deliveries
    the features are drawn from. Pairs with no link between them are omitted
    rather than recorded as zero: the oracle reads absence as "no link" and a
    zero as "a link that currently delivers nothing", and those differ.

    Catches only `NoLinkError`, not `ValueError` generally — a custom
    `Channel.evaluate()` that raises `ValueError` for a real bug (a bad
    parameter, a math-domain error) must propagate as a hard failure, not get
    silently reinterpreted as "these two nodes aren't linked."
    """
    graph: dict[Edge, float] = {}
    for a, b in combinations(nodes, 2):
        try:
            sample = sim.sample_channel(a, b)
        except NoLinkError:
            continue  # not linked
        graph[(a, b)] = sample.delivery_probability
        graph[(b, a)] = sample.delivery_probability
    return graph


def router_snapshot(sim: Any, node: str) -> RouterSnapshot:
    """Read `node`'s observable router state out of a running simulation.

    Router state is keyed by MAC while the oracle and topology are written in
    node names, so every identifier is translated on the way out — otherwise
    the features and the labels could not be joined.
    """
    driver = sim.driver(node)

    def name_of(mac: Any) -> str:
        resolved = sim.node_for_mac(mac)
        if resolved is None:
            # Every MAC a simulated router holds was assigned to a simulated
            # node. One that does not resolve means the mapping is wrong, and
            # dropping it would quietly shrink the dataset instead.
            raise ValueError(
                f"router state names {mac}, which does not belong to any node"
            )
        return resolved

    originators = tuple(
        OriginatorObservation(
            originator=name_of(record.originator),
            last_heard_ms=record.last_heard_ms,
            last_seqno=record.last_seqno,
            max_tq=record.max_tq,
            best_next_hop=name_of(record.best_next_hop),
            paths=tuple(
                PathObservation(
                    neighbor=name_of(path.neighbor),
                    last_tq=path.last_tq,
                    last_seqno=path.last_seqno,
                    last_heard_ms=path.last_heard_ms,
                    interval_estimate_ms=path.interval_estimate_ms,
                )
                for path in record.paths
            ),
        )
        for record in driver.originator_table()
    )

    links = tuple(
        LinkObservation(
            neighbor=name_of(record.neighbor),
            iface_idx=record.iface_idx,
            ewma_quality=record.ewma_quality,
            sample_count=record.sample_count,
        )
        for record in driver.link_quality_records()
    )

    return RouterSnapshot(
        node=node,
        now_ms=int(sim.env.now),
        originators=originators,
        links=links,
        neighbor_count=driver.neighbor_count(),
        originator_occupancy=driver.originator_occupancy(),
    )


def sample_instant(sim: Any, nodes: Sequence[str] | None = None) -> FeatureBatch:
    """Label every node's current router state against the oracle, and return
    the resulting rows as one batch.

    The channel graph and the per-destination shortest-path solutions are
    computed once and shared across all nodes, since the ground truth at an
    instant is the same for everyone looking at it.
    """
    names = list(nodes) if nodes is not None else list(sim.node_names)
    graph = channel_graph(sim, names)

    # One Dijkstra per destination, reused by every node that routes to it.
    hops_to: dict[str, dict[str, str | None]] = {}
    costs_to_dest: dict[str, dict[str, float]] = {}
    for dest in names:
        hops_to[dest] = best_next_hops(graph, dest)
        costs_to_dest[dest] = costs_to(graph, dest)

    batches = []
    for node in names:
        snapshot = router_snapshot(sim, node)
        best_hop = {
            originator.originator: hops_to[originator.originator].get(node)
            for originator in snapshot.originators
            if originator.originator in hops_to
        }
        cost_via: dict[tuple[str, str], float] = {}
        for originator in snapshot.originators:
            costs = costs_to_dest.get(originator.originator)
            if costs is None:
                continue
            for path in originator.paths:
                hop_cost = etx(graph.get((node, path.neighbor), 0.0))
                onward = costs.get(path.neighbor, math.inf)
                cost_via[(originator.originator, path.neighbor)] = hop_cost + onward
        batches.append(build_batch(snapshot, best_next_hop=best_hop, cost_via=cost_via))

    return concat(batches) if batches else empty()


@dataclasses.dataclass(frozen=True)
class Episode:
    """One scenario run's rows, and the seed that produced them.

    The seed travels with the batch because it names the shard: a resumed or
    parallelised sweep has to be able to tell which episodes it already has.
    """

    seed: int
    batch: FeatureBatch


def episode_rows(
    sim: Any,
    *,
    duration_s: float,
    interval_s: float,
    warmup_s: float = 0.0,
    nodes: Sequence[str] | None = None,
) -> FeatureBatch:
    """Run `sim` forward to `duration_s`, sampling labelled rows every
    `interval_s`, and return them as one batch.

    Both endpoints are sampled, so a 4 s episode at 1 s yields five instants.
    Time is stepped through `sim.env` rather than `Simulation.run` because
    `run` attaches a fresh recorder and a fresh sampling process on every
    call — harmless once, but a sweep calls it hundreds of times, and probe
    sampling is not what a generation run is paying for.

    `warmup_s` runs the clock forward unsampled. Before a mesh converges its
    routers hold no candidates and have not yet estimated their neighbors' OGM
    cadences, so those instants are mostly noise: rows the oracle can label but
    that teach the model about startup rather than about routing.
    """
    if interval_s <= 0:
        raise ValueError(f"interval_s must be positive, got {interval_s}")
    if warmup_s > duration_s:
        raise ValueError(
            f"warmup_s ({warmup_s}) is past the end of the episode "
            f"(duration_s {duration_s}); nothing would be sampled"
        )

    # Step count up front, from a fixed origin: accumulating `t += interval_s`
    # drifts, and a drift that lands two samples on the same instant would
    # duplicate rows rather than fail.
    steps = math.floor((duration_s - warmup_s) / interval_s + 1e-9)
    batches = [
        _sample_at(sim, warmup_s + step * interval_s, nodes)
        for step in range(int(steps) + 1)
    ]
    return concat(batches) if batches else empty()


def episodes(
    build: Callable[[int], Any],
    *,
    count: int,
    seed: int,
    duration_s: float,
    interval_s: float,
    warmup_s: float = 0.0,
    nodes: Sequence[str] | None = None,
) -> Iterator[Episode]:
    """Sweep `count` episodes, building a fresh simulation per episode from
    consecutive seeds starting at `seed`.

    Fresh per episode, never reused: continuing one simulation would make the
    second episode a continuation of the first, correlating rows that the
    training split assumes are independent draws.

    Episodes are yielded as they finish, so a caller can write each shard
    before starting the next one and a long sweep can be interrupted without
    losing what it already produced.
    """
    if count <= 0:
        raise ValueError(f"count must be positive, got {count}")

    def stream() -> Iterator[Episode]:
        for offset in range(count):
            episode_seed = seed + offset
            yield Episode(
                seed=episode_seed,
                batch=episode_rows(
                    build(episode_seed),
                    duration_s=duration_s,
                    interval_s=interval_s,
                    warmup_s=warmup_s,
                    nodes=nodes,
                ),
            )

    return stream()


def _sample_at(sim: Any, t_s: float, nodes: Sequence[str] | None) -> FeatureBatch:
    """Advance `sim` to `t_s` (if it is not already past it) and sample."""
    target_ms = t_s * 1000.0
    if target_ms > sim.env.now:
        sim.env.run(until=target_ms)
    return sample_instant(sim, nodes)
