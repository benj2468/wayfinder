"""What a dataset says about itself, before anything trains on it.

Row counts do not tell you whether a dataset is worth training on. These do:
how often BATMAN's own `argmax(tq)` already matches the oracle, and — when it
does not — how much ETX that costs. A directory where the baseline is right
everywhere contains no lesson, however many rows it has, and the README's open
question ("are the scenarios where classical TQ is wrong common enough to
matter?") is answered here rather than after a training run.

numpy only, deliberately: this is the half of the pipeline that runs wherever
the shards were copied to, so inspecting a dataset must never require torch,
SimPy, or the PyO3 extension.
"""

from __future__ import annotations

import dataclasses

import numpy as np

from .schema import (
    CANDIDATE_FEATURES,
    CONTEXT_FEATURES,
    MAX_PATHS,
    NO_LABEL,
    FeatureBatch,
)

_TQ_COLUMN = CANDIDATE_FEATURES.index("tq")
"""Which candidate column carries `NeighborStats.last_tq`, the quantity
BATMAN's own selection maximises."""

_REGRET_EPSILON = 1e-6
"""Below this, a difference in ETX is float32 noise rather than a decision
worth counting as a disagreement."""


@dataclasses.dataclass(frozen=True)
class ColumnStats:
    """One feature column's spread, over the values that actually exist.

    Normalization here is hand-written arithmetic shared with the Rust
    inference path, so a column outside its intended range — or one that is
    always zero because the state never reached it — is a correctness bug, not
    a curiosity.
    """

    name: str
    minimum: float
    median: float
    maximum: float
    zeros: int
    """How many sampled values are exactly zero. A column that is *all* zeros
    is the signature of a feature that never got wired up."""
    samples: int
    """Values behind these numbers: filled slots for a candidate feature,
    rows for a context feature."""


@dataclasses.dataclass(frozen=True)
class Summary:
    """A dataset's headline numbers."""

    rows: int
    labelled: int
    """Rows the oracle could supervise. The rest kept a candidate set that did
    not contain the true best next hop."""
    baseline_agreements: int
    """Labelled rows where `argmax(tq)` already picks the oracle's slot."""
    labelled_decisions: int
    """Labelled rows offering more than one candidate — the only rows where a
    selection policy can be wrong at all."""
    decision_agreements: int
    """Of `labelled_decisions`, how many the baseline gets right. This is the
    number a learned scorer has to beat: a one-candidate row's label *is* its
    only slot, so pooling those in inflates the baseline's apparent skill in
    proportion to how many of them a dataset happens to contain."""
    regret_rows: int
    """Labelled rows where the baseline's pick costs strictly more ETX than
    the oracle's — the rows with something to learn from."""
    mean_regret: float
    """Mean ETX given up by the baseline across labelled rows with finite
    costs on both picks, zeros included. The dataset's available headroom."""
    baseline_dead_ends: int
    """Labelled rows where the baseline picks a candidate the oracle cannot
    reach the destination through at all. Counted apart from `mean_regret`
    because infinite regret would swallow the mean whole."""
    label_counts: tuple[int, ...]
    """Labelled rows per candidate slot. Heavy skew toward slot 0 means a
    model can match the baseline by learning BATMAN's ordering."""
    candidate_counts: tuple[int, ...]
    """Rows by how many candidate slots they fill, `candidate_counts[k - 1]`
    holding the count for `k` candidates. A one-candidate row contains no
    decision at all."""

    @property
    def labelled_fraction(self) -> float:
        """Share of rows the loss can use, in `[0, 1]`."""
        return self.labelled / self.rows if self.rows else 0.0

    @property
    def baseline_agreement(self) -> float:
        """Share of labelled rows the baseline already gets right, in
        `[0, 1]` — the accuracy a learned scorer has to beat."""
        return self.baseline_agreements / self.labelled if self.labelled else 0.0

    @property
    def decision_agreement(self) -> float:
        """Share of labelled multi-candidate rows the baseline gets right, in
        `[0, 1]`. `0.0` when the dataset contains no decisions at all — which
        is itself the finding, not a score."""
        return (
            self.decision_agreements / self.labelled_decisions
            if self.labelled_decisions
            else 0.0
        )

    @property
    def regret_fraction(self) -> float:
        """Share of labelled rows where the baseline's pick is measurably
        worse, in `[0, 1]`."""
        return self.regret_rows / self.labelled if self.labelled else 0.0

    @property
    def decisions(self) -> int:
        """Rows offering more than one candidate — the only rows where a
        selection policy can differ from any other."""
        return sum(self.candidate_counts[1:])


def baseline_choice(batch: FeatureBatch) -> np.ndarray:
    """The slot BATMAN's own `argmax(last_tq)` selects for each row.

    Masked slots are excluded rather than merely scoring zero: an empty slot
    holds zeros today, but a shard is a file, and a selection that depends on
    padding would be wrong the moment one carried anything else. Rows with no
    candidates at all yield `NO_LABEL`.
    """
    tq = np.where(batch.mask, batch.candidates[:, :, _TQ_COLUMN], -np.inf)
    chosen = np.argmax(tq, axis=1).astype(np.int8)
    return np.where(batch.mask.any(axis=1), chosen, NO_LABEL).astype(np.int8)


def labelled_fraction(batch: FeatureBatch) -> float:
    """Share of rows the oracle could supervise, in `[0, 1]`.

    The rest are rows whose true best next hop was not among the router's
    candidates. They are kept deliberately — they measure how often the
    candidate set is itself the binding constraint — but the loss cannot use
    them, so a dataset's usable size is this fraction of its row count.
    """
    if batch.rows == 0:
        return 0.0
    return float((batch.label != NO_LABEL).sum()) / batch.rows


def summarize(batch: FeatureBatch) -> Summary:
    """Compute every headline number for `batch` in one pass."""
    labelled = batch.label != NO_LABEL
    rows = np.flatnonzero(labelled)
    baseline = baseline_choice(batch)

    agrees = baseline[rows] == batch.label[rows]
    # A row with one candidate has no decision in it: its only slot is both
    # the baseline's pick and the label, so counting it as an agreement
    # measures the topology, not the policy.
    has_choice = batch.mask[rows].sum(axis=1) > 1 if rows.size else np.zeros(0, bool)

    # Costs of the two picks, row by row, over labelled rows only.
    oracle_cost = batch.cost[rows, batch.label[rows]] if rows.size else np.zeros(0)
    baseline_cost = batch.cost[rows, baseline[rows]] if rows.size else np.zeros(0)
    comparable = np.isfinite(oracle_cost) & np.isfinite(baseline_cost)
    regret = baseline_cost[comparable] - oracle_cost[comparable]

    return Summary(
        rows=batch.rows,
        labelled=int(labelled.sum()),
        baseline_agreements=int(agrees.sum()),
        labelled_decisions=int(has_choice.sum()),
        decision_agreements=int((agrees & has_choice).sum()),
        regret_rows=int((regret > _REGRET_EPSILON).sum()),
        mean_regret=float(regret.mean()) if regret.size else 0.0,
        baseline_dead_ends=int(
            (~np.isfinite(baseline_cost) & np.isfinite(oracle_cost)).sum()
        ),
        label_counts=tuple(
            int((batch.label[rows] == slot).sum()) for slot in range(MAX_PATHS)
        ),
        candidate_counts=tuple(
            int((batch.mask.sum(axis=1) == filled).sum())
            for filled in range(1, MAX_PATHS + 1)
        ),
    )


def candidate_columns(batch: FeatureBatch) -> list[ColumnStats]:
    """Per-candidate-feature spread, over filled slots only.

    Empty slots are zeros; folding them in would report a minimum of zero for
    every feature and bury the scaling bug this exists to surface.
    """
    filled = batch.candidates[batch.mask]  # (filled slots, features)
    return [
        _column(name, filled[:, index]) for index, name in enumerate(CANDIDATE_FEATURES)
    ]


def context_columns(batch: FeatureBatch) -> list[ColumnStats]:
    """Per-context-feature spread, over every row."""
    return [
        _column(name, batch.context[:, index])
        for index, name in enumerate(CONTEXT_FEATURES)
    ]


def _column(name: str, values: np.ndarray) -> ColumnStats:
    if values.size == 0:
        return ColumnStats(name, 0.0, 0.0, 0.0, zeros=0, samples=0)
    return ColumnStats(
        name=name,
        minimum=float(values.min()),
        median=float(np.median(values)),
        maximum=float(values.max()),
        zeros=int((values == 0.0).sum()),
        samples=int(values.size),
    )
