"""The feature/label contract shared by every stage of the pipeline.

This module is the single source of truth for what a training row *is*. Three
independent implementations have to agree on it: the generator that walks a
simulated router's state, the trainer that fits a model to it, and the Rust
inference path that must rebuild a byte-identical vector on a live node. Any
change here is a wire-format change — bump `SCHEMA_VERSION` when you make one.

**The problem shape.** BATMAN already maintains up to four candidate paths to
each originator (`batman::OriginatorRecord::paths`, an `HVec<NeighborStats,
4>`) and selects among them by `argmax(last_tq)`. The model does not invent
routes; it replaces that one `argmax` with a learned score over the same four
candidates. So a row is: one originator, as seen from one node, at one instant
— with a fixed four slots of candidate features, a validity mask, and a label
naming the slot a perfectly-informed router would have chosen.

**Normalization is deliberately arithmetic.** Every feature below is scaled by
a constant or a ratio of quantities the router already holds — never by a
fitted scaler (mean/stddev learned from a dataset). A fitted scaler would be a
second artifact the Rust side must load and keep in step with the weights;
constants can be transcribed into the inference code and reviewed by eye.
"""

from __future__ import annotations

import dataclasses

import numpy as np

SCHEMA_VERSION = 2
"""Bumped whenever the feature columns, their order, or their scaling change.
`shards.read_shard` refuses anything it does not recognise."""

MAX_PATHS = 4
"""Candidate slots per row. Not a tunable: it is the capacity of
`batman::OriginatorRecord::paths`, so a router physically cannot offer more."""

# Normalization constants. These are the numbers the Rust inference path must
# transcribe verbatim; they are named rather than inlined so a mismatch shows
# up as a diff in one place instead of a scattered magic number.
QUALITY_SCALE = 255.0
"""Divisor for the 0..=255 TQ and EWMA-quality scales."""

LOG_SCALE = 16.0
"""Divisor applied after `log1p` to sample counts and millisecond intervals,
chosen so realistic values land in roughly `[0, 1]`: `log1p(8e6) / 16 ≈ 1.0`."""

SEQNO_LAG_SCALE = 255.0
"""Divisor for sequence-number lag, clipped at 1.0 afterwards — beyond a
couple of hundred missed OGMs a path is simply dead, and the exact figure
stops carrying information."""

NEIGHBOR_COUNT_SCALE = 32.0
"""Divisor for the neighbor count, at the order of a well-connected node's
degree rather than the table capacity."""

AGE_RATIO_CLIP = 6.0
"""Ceiling for `age_ratio`/`originator_age_ratio`, matching
`batman::MAX_MISSED_OGMS` — the number of missed cadence intervals a live path
can reach before the router itself purges it. Unlike `seqno_lag`, staleness
has no built-in ceiling of its own (a tiny learned cadence gone quiet can
otherwise produce an arbitrarily large ratio), so this exists purely to keep
the feature finite and bounded like every other candidate/context column."""

NO_LABEL = -1
"""Label for a row the oracle could not supervise — the true best next hop was
not among the router's candidates, so no slot is correct. These rows are kept
(they measure how often the candidate set itself is the limiting factor) but
must be excluded from the training loss."""

CANDIDATE_FEATURES: tuple[str, ...] = (
    # `NeighborStats.last_tq / 255` — BATMAN's own metric for this path, and
    # the baseline the model has to beat. Fed in as an input so the model can
    # fall back on it wherever it has nothing better.
    "tq",
    # EWMA quality of the local link to this candidate neighbor
    # (`LinkQualityRecord.ewma_quality / 255`). Distinct from `tq`, which is
    # end-to-end to the originator: a path can hold good TQ over a link that
    # is currently degrading.
    "link_quality",
    # `log1p(LinkQualityRecord.sample_count) / 16` — confidence in
    # `link_quality`. A one-sample estimate and a thousand-sample one should
    # not be trusted equally, and TQ alone does not carry that.
    "link_samples",
    # `(now - last_heard) / interval_estimate`, clipped to `AGE_RATIO_CLIP` —
    # staleness against this path's *own* learned cadence rather than a fixed
    # timeout, matching how `purge_stale` ages it. ~1.0 means "due now"; the
    # clip means "as gone-quiet as a still-live path can be."
    "age_ratio",
    # `log1p(interval_estimate_ms) / 16` — how slowly this path reports. A
    # fast-cadence path's staleness is fresher evidence than a slow one's.
    "interval",
    # `(originator.last_seqno - path.last_seqno) / 255`, clipped to 1.0 — how
    # far behind this path is versus the freshest OGM heard by any path. The
    # strongest single signal that a path is on its way out.
    "seqno_lag",
)

CONTEXT_FEATURES: tuple[str, ...] = (
    "max_tq",
    "originator_age_ratio",
    "num_candidates",
    "neighbor_count",
    "originator_occupancy",
)
"""Per-row context, shared across the four candidates: the originator's best
TQ and staleness, how many slots are actually filled, and how loaded this
node's tables are (`neighbor_count / 32`, and originator table used/capacity).
Occupancy matters because a saturated table changes what the candidate set
even means — entries are being evicted."""


@dataclasses.dataclass
class FeatureBatch:
    """A block of training rows, in shard column order.

    Shapes, for `n` rows:
      `candidates` `(n, MAX_PATHS, len(CANDIDATE_FEATURES))` float32
      `mask`       `(n, MAX_PATHS)` bool — which slots hold a real candidate
      `context`    `(n, len(CONTEXT_FEATURES))` float32
      `label`      `(n,)` int8 — chosen slot index, or `NO_LABEL`
      `cost`       `(n, MAX_PATHS)` float32 — oracle ETX-to-destination via
                   each slot, for soft targets; `inf` for unusable slots
    """

    candidates: np.ndarray
    mask: np.ndarray
    context: np.ndarray
    label: np.ndarray
    cost: np.ndarray

    def __post_init__(self) -> None:
        # Enforced at construction, not left to a caller's discipline to call
        # `validate()` — every construction site (`build_batch`, `train`'s and
        # `evaluate`'s row-sliced batches, `shards.read_shard`, `concat`) gets
        # the check for free.
        self.validate()

    @property
    def rows(self) -> int:
        """Number of training rows in this batch."""
        return int(self.candidates.shape[0])

    def validate(self) -> None:
        """Raise `ValueError` unless every array agrees on row count, width,
        and the label/mask consistency the loss depends on.

        Runs automatically at construction (`__post_init__`); calling it again
        after mutating a batch's arrays in place re-checks the current state.
        """
        n = self.rows
        for name, arr, expected in (
            ("mask", self.mask, (n, MAX_PATHS)),
            ("context", self.context, (n, len(CONTEXT_FEATURES))),
            ("label", self.label, (n,)),
            ("cost", self.cost, (n, MAX_PATHS)),
        ):
            if arr.shape[0] != n:
                raise ValueError(
                    f"{name} row count {arr.shape[0]} != candidates row count {n}"
                )
            if arr.shape != expected:
                raise ValueError(f"{name} shape {arr.shape} != expected {expected}")

        if self.candidates.shape[1:] != (MAX_PATHS, len(CANDIDATE_FEATURES)):
            raise ValueError(
                f"candidate feature block {self.candidates.shape[1:]} != "
                f"expected {(MAX_PATHS, len(CANDIDATE_FEATURES))}"
            )

        labelled = self.label != NO_LABEL
        if np.any(self.label[labelled] < 0) or np.any(
            self.label[labelled] >= MAX_PATHS
        ):
            raise ValueError(f"label out of range [0, {MAX_PATHS})")
        rows = np.flatnonzero(labelled)
        if rows.size and not np.all(self.mask[rows, self.label[rows]]):
            raise ValueError("label selects a masked (empty) candidate slot")


def empty() -> FeatureBatch:
    """A zero-row batch, correctly shaped.

    A sampling instant can legitimately produce no rows — early in a run, before
    any node has heard an OGM. That is not an error, but the arrays still have
    to carry the right widths so `concat` can join them with populated ones.
    """
    return FeatureBatch(
        candidates=np.zeros((0, MAX_PATHS, len(CANDIDATE_FEATURES)), dtype=np.float32),
        mask=np.zeros((0, MAX_PATHS), dtype=bool),
        context=np.zeros((0, len(CONTEXT_FEATURES)), dtype=np.float32),
        label=np.zeros(0, dtype=np.int8),
        cost=np.zeros((0, MAX_PATHS), dtype=np.float32),
    )


def split(
    batch: FeatureBatch, *, eval_fraction: float, seed: int
) -> tuple[FeatureBatch, FeatureBatch]:
    """Partition `batch`'s rows into `(train, held_out)`, disjoint and
    exhaustive, by a seeded random shuffle.

    Training and evaluating on the same rows measures memorization, not
    generalization — `evaluate`'s agreement/lift numbers are only meaningful
    against rows the model never trained on. This is the row-level split that
    makes that possible; `cli.py`'s `train` subcommand is the caller.
    """
    if not 0.0 < eval_fraction < 1.0:
        raise ValueError(f"eval_fraction must be in (0, 1), got {eval_fraction}")

    order = np.random.default_rng(seed).permutation(batch.rows)
    n_eval = int(round(batch.rows * eval_fraction))
    eval_idx, train_idx = order[:n_eval], order[n_eval:]

    def _take(idx: np.ndarray) -> FeatureBatch:
        return FeatureBatch(
            candidates=batch.candidates[idx],
            mask=batch.mask[idx],
            context=batch.context[idx],
            label=batch.label[idx],
            cost=batch.cost[idx],
        )

    return _take(train_idx), _take(eval_idx)


def concat(batches: list[FeatureBatch]) -> FeatureBatch:
    """Join batches end to end, preserving order — how a directory of shards
    becomes one dataset."""
    if not batches:
        raise ValueError("cannot concatenate zero batches")
    return FeatureBatch(
        candidates=np.concatenate([b.candidates for b in batches]),
        mask=np.concatenate([b.mask for b in batches]),
        context=np.concatenate([b.context for b in batches]),
        label=np.concatenate([b.label for b in batches]),
        cost=np.concatenate([b.cost for b in batches]),
    )
