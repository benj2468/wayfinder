"""Router state -> training rows.

The dataclasses here mirror, field for field, the Rust types a live router
already holds — `batman::NeighborStats`, `batman::OriginatorRecord`,
`wayfinder::LinkQualityRecord` — and nothing else. That restriction is the
point: a feature the model trains on but a node cannot compute at inference
time is a feature that silently breaks on deployment. If you want to add one,
it has to be observable from `CentralRouter`.

`generate.router_snapshot` populates these from a live simulation, via
`PyDriver`'s router-state projection. They stay plain dataclasses rather than
wrapping the PyO3 types directly so the transform is testable without the
extension built, and so a second state source (a real node's management API,
say) could feed the same pipeline unchanged.
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Mapping

import numpy as np

from .schema import (
    AGE_RATIO_CLIP,
    CANDIDATE_FEATURES,
    LOG_SCALE,
    MAX_PATHS,
    NEIGHBOR_COUNT_SCALE,
    NO_LABEL,
    QUALITY_SCALE,
    SEQNO_LAG_SCALE,
    FeatureBatch,
    empty,
)


@dataclasses.dataclass(frozen=True)
class PathObservation:
    """One candidate path to an originator — mirrors `batman::NeighborStats`."""

    neighbor: str
    """The immediate neighbor relaying OGMs for this path."""
    last_tq: int
    """Transmission quality 0..=255 of the most recent OGM on this path."""
    last_seqno: int
    """Sequence number of the most recent OGM accepted on this path."""
    last_heard_ms: int
    """Engine clock when this path was last refreshed."""
    interval_estimate_ms: int
    """Peak-hold estimate of this path's OGM cadence; `0` until a second OGM
    gives a first gap to measure."""


@dataclasses.dataclass(frozen=True)
class OriginatorObservation:
    """A destination and its candidate paths — mirrors
    `batman::OriginatorRecord`."""

    originator: str
    last_heard_ms: int
    last_seqno: int
    """Freshest sequence number heard via *any* path; per-path lag is measured
    against it."""
    max_tq: int
    best_next_hop: str
    """The neighbor classical BATMAN currently selects — the baseline the model
    is measured against, recorded so evaluation can compare without re-running
    the router."""
    paths: tuple[PathObservation, ...]


@dataclasses.dataclass(frozen=True)
class LinkObservation:
    """Local link quality to one neighbor — mirrors
    `wayfinder::LinkQualityRecord`."""

    neighbor: str
    iface_idx: int
    ewma_quality: int
    sample_count: int


@dataclasses.dataclass(frozen=True)
class RouterSnapshot:
    """Everything one node can observe about itself at one instant."""

    node: str
    now_ms: int
    originators: tuple[OriginatorObservation, ...]
    links: tuple[LinkObservation, ...]
    neighbor_count: int
    originator_occupancy: tuple[int, int]
    """`(used, capacity)` of the originator table. A saturated table changes
    what the candidate set means, because entries are being evicted."""


def _log_scaled(value: float) -> float:
    """`log1p` compression onto roughly `[0, 1]` — for counts and intervals
    that span orders of magnitude and whose differences matter most when
    small."""
    return math.log1p(max(value, 0.0)) / LOG_SCALE


def _candidate_row(
    path: PathObservation,
    originator: OriginatorObservation,
    link: LinkObservation | None,
    now_ms: int,
) -> list[float]:
    """One candidate's feature vector, in `CANDIDATE_FEATURES` order."""
    # A path with no measured cadence yet cannot be aged against one; report
    # zero staleness rather than dividing by zero, and let `link_samples`
    # carry the "we barely know this path" signal instead.
    if path.interval_estimate_ms > 0:
        age_ratio = min(
            (now_ms - path.last_heard_ms) / path.interval_estimate_ms, AGE_RATIO_CLIP
        )
    else:
        age_ratio = 0.0

    lag = max(originator.last_seqno - path.last_seqno, 0) / SEQNO_LAG_SCALE
    return [
        path.last_tq / QUALITY_SCALE,
        (link.ewma_quality / QUALITY_SCALE) if link else 0.0,
        _log_scaled(link.sample_count) if link else 0.0,
        age_ratio,
        _log_scaled(path.interval_estimate_ms),
        min(lag, 1.0),
    ]


def _context_row(
    originator: OriginatorObservation, snapshot: RouterSnapshot
) -> list[float]:
    """Per-row context, in `CONTEXT_FEATURES` order."""
    used, capacity = snapshot.originator_occupancy
    if originator.paths:
        newest = max(p.last_heard_ms for p in originator.paths)
        intervals = [
            p.interval_estimate_ms
            for p in originator.paths
            if p.interval_estimate_ms > 0
        ]
        cadence = min(intervals) if intervals else 0
        age_ratio = (
            min((snapshot.now_ms - newest) / cadence, AGE_RATIO_CLIP)
            if cadence
            else 0.0
        )
    else:
        age_ratio = 0.0
    return [
        originator.max_tq / QUALITY_SCALE,
        age_ratio,
        len(originator.paths) / MAX_PATHS,
        snapshot.neighbor_count / NEIGHBOR_COUNT_SCALE,
        (used / capacity) if capacity else 0.0,
    ]


def build_batch(
    snapshot: RouterSnapshot,
    *,
    best_next_hop: Mapping[str, str | None],
    cost_via: Mapping[tuple[str, str], float],
) -> FeatureBatch:
    """Build one training row per originator that has at least one candidate.

    `best_next_hop` maps originator -> the neighbor an oracle would route
    through from this node; `cost_via` maps `(originator, neighbor)` -> the
    oracle's ETX to that originator when leaving via that neighbor. Both come
    from `oracle`, which sees ground truth this snapshot cannot.

    An originator whose oracle hop is not among its candidates yields a row
    labelled `NO_LABEL`: the features are still worth keeping (they measure
    how often the candidate set itself is the binding constraint) but the row
    carries no target for the loss.
    """
    link_by_neighbor = {link.neighbor: link for link in snapshot.links}

    candidates: list[np.ndarray] = []
    masks: list[np.ndarray] = []
    contexts: list[list[float]] = []
    labels: list[int] = []
    costs: list[np.ndarray] = []

    for originator in snapshot.originators:
        if not originator.paths:
            continue  # nothing to rank

        row = np.zeros((MAX_PATHS, len(CANDIDATE_FEATURES)), dtype=np.float32)
        mask = np.zeros(MAX_PATHS, dtype=bool)
        # Masked slots must never look attractive to a cost-weighted loss.
        cost = np.full(MAX_PATHS, math.inf, dtype=np.float32)

        target = best_next_hop.get(originator.originator)
        label = NO_LABEL

        for slot, path in enumerate(originator.paths[:MAX_PATHS]):
            row[slot] = _candidate_row(
                path, originator, link_by_neighbor.get(path.neighbor), snapshot.now_ms
            )
            mask[slot] = True
            via = cost_via.get((originator.originator, path.neighbor))
            if via is not None:
                cost[slot] = via
            if target is not None and path.neighbor == target:
                label = slot

        candidates.append(row)
        masks.append(mask)
        contexts.append(_context_row(originator, snapshot))
        labels.append(label)
        costs.append(cost)

    if not candidates:
        return empty()

    return FeatureBatch(
        candidates=np.stack(candidates),
        mask=np.stack(masks),
        context=np.asarray(contexts, dtype=np.float32),
        label=np.asarray(labels, dtype=np.int8),
        cost=np.stack(costs),
    )
