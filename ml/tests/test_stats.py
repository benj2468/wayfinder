"""Dataset statistics: what a shard directory says about itself before
anything trains on it.

Batches here are built by hand rather than generated, so each test states the
exact dataset that produces the number it asserts. numpy only — these run on
the training box, which is the point of them.
"""

from __future__ import annotations

import numpy as np
import pytest

from wayfinder_ml import stats
from wayfinder_ml.schema import (
    CANDIDATE_FEATURES,
    CONTEXT_FEATURES,
    MAX_PATHS,
    NO_LABEL,
    FeatureBatch,
    empty,
)

_TQ = CANDIDATE_FEATURES.index("tq")


def _batch(*, tq, mask, label, cost=None, context=None) -> FeatureBatch:
    """A batch carrying only what these statistics read: per-slot `tq`, the
    mask, labels, and oracle costs. Other candidate features stay zero."""
    tq = np.asarray(tq, dtype=np.float32)
    rows = tq.shape[0]
    candidates = np.zeros((rows, MAX_PATHS, len(CANDIDATE_FEATURES)), dtype=np.float32)
    candidates[:, :, _TQ] = tq
    return FeatureBatch(
        candidates=candidates,
        mask=np.asarray(mask, dtype=bool),
        context=(
            np.zeros((rows, len(CONTEXT_FEATURES)), dtype=np.float32)
            if context is None
            else np.asarray(context, dtype=np.float32)
        ),
        label=np.asarray(label, dtype=np.int8),
        cost=(
            np.full((rows, MAX_PATHS), np.inf, dtype=np.float32)
            if cost is None
            else np.asarray(cost, dtype=np.float32)
        ),
    )


# --- the baseline --------------------------------------------------------


def test_baseline_choice_is_argmax_tq() -> None:
    """`argmax(last_tq)` is exactly what BATMAN does today, and the thing a
    learned scorer has to beat."""
    batch = _batch(
        tq=[[0.1, 0.9, 0.4, 0.0]],
        mask=[[True, True, True, False]],
        label=[1],
    )

    assert list(stats.baseline_choice(batch)) == [1]


def test_baseline_choice_ignores_masked_slots() -> None:
    """An empty slot's features are zero, but nothing stops a *stale* shard
    from carrying junk there. Only filled slots are candidates, so the pick
    has to come from the mask, not from the array width."""
    batch = _batch(
        tq=[[0.3, 0.99, 0.0, 0.0]],
        mask=[[True, False, False, False]],
        label=[0],
    )

    assert list(stats.baseline_choice(batch)) == [0]


def test_baseline_choice_of_a_row_with_no_candidates_is_unlabelled() -> None:
    batch = _batch(tq=[[0.0] * 4], mask=[[False] * 4], label=[NO_LABEL])

    assert list(stats.baseline_choice(batch)) == [NO_LABEL]


def test_baseline_agreement_is_measured_only_over_labelled_rows() -> None:
    """A row the oracle could not supervise has no right answer, so counting
    it either way would move the number that decides whether a dataset is
    worth training on."""
    batch = _batch(
        tq=[[0.9, 0.1, 0, 0], [0.9, 0.1, 0, 0], [0.9, 0.1, 0, 0]],
        mask=[[True, True, False, False]] * 3,
        label=[0, 1, NO_LABEL],
    )

    summary = stats.summarize(batch)

    assert summary.labelled == 2
    assert summary.baseline_agreements == 1
    assert summary.baseline_agreement == 0.5


def test_baseline_agreement_is_also_reported_over_rows_with_a_choice() -> None:
    """A one-candidate row cannot be got wrong: the only slot is the label.
    Pooling those with real decisions inflates the baseline's apparent skill —
    a dataset of mostly single-candidate rows reads as ~100% agreement while
    containing no decisions at all — so the decision-restricted figure is the
    one to compare a model against."""
    batch = _batch(
        tq=[[0.9, 0.0, 0, 0], [0.9, 0.0, 0, 0], [0.9, 0.1, 0, 0]],
        mask=[
            [True, False, False, False],
            [True, False, False, False],
            [True, True, False, False],
        ],
        label=[0, 0, 1],
    )

    summary = stats.summarize(batch)

    assert summary.baseline_agreement == pytest.approx(2 / 3), "pooled, and flattering"
    assert summary.labelled_decisions == 1
    assert summary.decision_agreements == 0
    assert summary.decision_agreement == 0.0


def test_decision_agreement_of_a_dataset_with_no_decisions_in_it() -> None:
    """Every row has one candidate: nothing to choose, so no agreement figure
    to report rather than a misleading 100%."""
    batch = _batch(
        tq=[[0.9, 0, 0, 0]] * 2,
        mask=[[True, False, False, False]] * 2,
        label=[0, 0],
    )

    summary = stats.summarize(batch)

    assert summary.labelled_decisions == 0
    assert summary.decision_agreement == 0.0


def test_baseline_agreement_of_a_dataset_with_nothing_to_learn() -> None:
    """The case the README calls out: on easy topologies BATMAN already agrees
    with the oracle everywhere, so there is no lift available and the honest
    answer is 100%."""
    batch = _batch(
        tq=[[0.9, 0.1, 0, 0], [0.2, 0.8, 0, 0]],
        mask=[[True, True, False, False]] * 2,
        label=[0, 1],
    )

    assert stats.summarize(batch).baseline_agreement == 1.0


# --- headroom ------------------------------------------------------------


def test_etx_regret_is_what_the_baseline_gives_up() -> None:
    """Regret is the ETX the baseline's pick costs over the oracle's — the
    magnitude behind a disagreement, since disagreeing about two near-equal
    paths does not matter and disagreeing about a dead one does."""
    batch = _batch(
        tq=[[0.9, 0.1, 0, 0], [0.9, 0.1, 0, 0]],
        mask=[[True, True, False, False]] * 2,
        label=[1, 0],
        cost=[[5.0, 2.0, np.inf, np.inf], [3.0, 9.0, np.inf, np.inf]],
    )

    summary = stats.summarize(batch)

    # Row 0: batman takes slot 0 (ETX 5) where the oracle takes slot 1 (ETX
    # 2) — 3.0 of regret. Row 1: they agree, so none.
    assert summary.regret_rows == 1
    assert summary.mean_regret == pytest.approx(1.5)


def test_a_baseline_pick_the_oracle_cannot_reach_is_counted_separately() -> None:
    """Infinite regret would swallow the mean whole. A baseline pick with no
    path behind it at all is its own category — the worst thing in a dataset,
    and the most interesting."""
    batch = _batch(
        tq=[[0.9, 0.1, 0, 0]],
        mask=[[True, True, False, False]],
        label=[1],
        cost=[[np.inf, 2.0, np.inf, np.inf]],
    )

    summary = stats.summarize(batch)

    assert summary.baseline_dead_ends == 1
    assert summary.mean_regret == 0.0, "no finite pair contributed to the mean"


def test_regret_ignores_unlabelled_rows() -> None:
    batch = _batch(
        tq=[[0.9, 0.1, 0, 0]],
        mask=[[True, True, False, False]],
        label=[NO_LABEL],
        cost=[[5.0, 2.0, np.inf, np.inf]],
    )

    summary = stats.summarize(batch)

    assert summary.regret_rows == 0
    assert summary.baseline_dead_ends == 0


# --- shape of the dataset ------------------------------------------------


def test_label_histogram_counts_the_chosen_slot() -> None:
    """Slot skew is the quiet failure: if nearly every label is slot 0, a
    model reaches baseline accuracy by learning BATMAN's own ordering and the
    measured lift means nothing."""
    batch = _batch(
        tq=np.zeros((4, MAX_PATHS)),
        mask=np.ones((4, MAX_PATHS), dtype=bool),
        label=[0, 0, 2, NO_LABEL],
    )

    assert stats.summarize(batch).label_counts == (2, 0, 1, 0)


def test_candidate_histogram_counts_filled_slots_per_row() -> None:
    """How often the router even has a choice. A dataset of one-candidate rows
    has no decision in it, whatever its row count says."""
    batch = _batch(
        tq=np.zeros((3, MAX_PATHS)),
        mask=[
            [True, False, False, False],
            [True, True, False, False],
            [True, True, True, True],
        ],
        label=[0, 0, 0],
    )

    assert stats.summarize(batch).candidate_counts == (1, 1, 0, 1)


def test_summarize_an_empty_batch_does_not_divide_by_zero() -> None:
    summary = stats.summarize(empty())

    assert summary.rows == 0
    assert summary.labelled_fraction == 0.0
    assert summary.baseline_agreement == 0.0
    assert summary.mean_regret == 0.0


# --- feature columns -----------------------------------------------------


def test_candidate_columns_read_only_filled_slots() -> None:
    """An empty slot is zeros. Folding those into the statistics would report
    a minimum of 0 for every feature and hide the scaling bug this is here to
    catch."""
    batch = _batch(
        tq=[[0.4, 0.8, 0.0, 0.0]],
        mask=[[True, True, False, False]],
        label=[0],
    )

    column = next(c for c in stats.candidate_columns(batch) if c.name == "tq")

    assert column.samples == 2
    assert column.minimum == pytest.approx(0.4)
    assert column.maximum == pytest.approx(0.8)
    assert column.zeros == 0


def test_candidate_columns_count_zeros_so_a_dead_feature_shows() -> None:
    """A feature that is always zero is a wiring bug — the router state never
    reached it — and it is invisible in a min/max pair alone."""
    batch = _batch(
        tq=[[0.0, 0.0, 0, 0]],
        mask=[[True, True, False, False]],
        label=[0],
    )

    column = next(c for c in stats.candidate_columns(batch) if c.name == "tq")

    assert column.zeros == 2
    assert column.samples == 2


def test_context_columns_cover_every_context_feature() -> None:
    batch = _batch(
        tq=np.zeros((2, MAX_PATHS)),
        mask=np.ones((2, MAX_PATHS), dtype=bool),
        label=[0, 1],
        context=[[0.5] * len(CONTEXT_FEATURES), [1.5] * len(CONTEXT_FEATURES)],
    )

    columns = stats.context_columns(batch)

    assert [c.name for c in columns] == list(CONTEXT_FEATURES)
    assert columns[0].minimum == pytest.approx(0.5)
    assert columns[0].maximum == pytest.approx(1.5)
    assert columns[0].samples == 2


def test_labelled_fraction_counts_only_supervised_rows() -> None:
    """The share of a dataset the loss can actually use."""
    batch = _batch(
        tq=np.zeros((4, MAX_PATHS)),
        mask=np.ones((4, MAX_PATHS), dtype=bool),
        label=[0, 1, NO_LABEL, NO_LABEL],
    )

    assert stats.labelled_fraction(batch) == 0.5
    assert stats.labelled_fraction(empty()) == 0.0
