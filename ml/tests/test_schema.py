"""The feature/label schema is the contract between three implementations:
the Python generator that writes it, the Python trainer that consumes it, and
(eventually) the Rust inference path that must rebuild the identical vector on
a live router. These tests pin the properties that keep those three in step.
"""

from __future__ import annotations

import numpy as np
import pytest
from wayfinder_ml import schema


def test_max_paths_matches_batman_capacity() -> None:
    """`OriginatorRecord.paths` is an `HVec<NeighborStats, 4>`, so the model's
    candidate slot count is not a tunable — it is that capacity."""
    assert schema.MAX_PATHS == 4


def test_feature_names_are_unique_and_ordered() -> None:
    """Order is load-bearing: it is the column order in the shard and the
    element order the Rust side will fill at inference."""
    assert len(set(schema.CANDIDATE_FEATURES)) == len(schema.CANDIDATE_FEATURES)
    assert len(set(schema.CONTEXT_FEATURES)) == len(schema.CONTEXT_FEATURES)
    assert isinstance(schema.CANDIDATE_FEATURES, tuple)
    assert isinstance(schema.CONTEXT_FEATURES, tuple)


def _batch(rows: int = 3) -> schema.FeatureBatch:
    rng = np.random.default_rng(0)
    return schema.FeatureBatch(
        candidates=rng.random(
            (rows, schema.MAX_PATHS, len(schema.CANDIDATE_FEATURES)), dtype=np.float32
        ),
        mask=np.ones((rows, schema.MAX_PATHS), dtype=bool),
        context=rng.random((rows, len(schema.CONTEXT_FEATURES)), dtype=np.float32),
        label=np.zeros(rows, dtype=np.int8),
        cost=rng.random((rows, schema.MAX_PATHS), dtype=np.float32),
    )


def test_valid_batch_passes_validation() -> None:
    _batch().validate()


def test_batch_rejects_mismatched_row_counts() -> None:
    """A shard whose arrays disagree on row count would silently train on
    misaligned features and labels — the worst possible failure mode.

    Enforced at construction (`__post_init__` calls `validate()`), not left
    for a caller to remember to check — `build_batch`/`train`/`evaluate` all
    construct a `FeatureBatch` without an explicit `.validate()` call and
    still need this caught."""
    batch = _batch(rows=3)
    with pytest.raises(ValueError, match="row count"):
        schema.FeatureBatch(
            candidates=batch.candidates,
            mask=batch.mask,
            context=batch.context,
            label=batch.label[:2],
            cost=batch.cost,
        )


def test_batch_rejects_wrong_feature_width() -> None:
    """Catches a schema bump on one side of the pipeline but not the other."""
    batch = _batch()
    with pytest.raises(ValueError, match="candidate feature"):
        schema.FeatureBatch(
            candidates=batch.candidates[:, :, :-1],
            mask=batch.mask,
            context=batch.context,
            label=batch.label,
            cost=batch.cost,
        )


def test_batch_rejects_label_pointing_at_masked_slot() -> None:
    """A label must select a slot that actually holds a candidate; otherwise
    the target is unreachable and the row is pure noise."""
    batch = _batch(rows=1)
    batch.mask[0, :] = [True, False, False, False]
    batch.label[0] = 1
    with pytest.raises(ValueError, match="masked"):
        batch.validate()


def test_unlabelled_rows_are_allowed() -> None:
    """`NO_LABEL` marks a row the oracle could not label (e.g. the true next
    hop was not among the router's candidates). Those rows are still useful
    for evaluation, so validation must not reject them."""
    batch = _batch(rows=1)
    batch.label[0] = schema.NO_LABEL
    batch.validate()


def test_rows_reports_batch_length() -> None:
    assert _batch(rows=7).rows == 7


def test_split_partitions_every_row_exactly_once() -> None:
    """`train`/`evaluate` must never share a row — that's the whole point of
    holding rows out — nor may either half quietly drop one."""
    batch = _batch(rows=20)
    # Distinguish rows by a value nothing else in `_batch` sets, so identity
    # survives the split unambiguously.
    batch.context[:, 0] = np.arange(20, dtype=np.float32)

    train, held_out = schema.split(batch, eval_fraction=0.25, seed=0)

    assert train.rows + held_out.rows == 20
    seen = sorted(train.context[:, 0].tolist() + held_out.context[:, 0].tolist())
    assert seen == list(range(20))


def test_split_holds_out_the_requested_fraction() -> None:
    batch = _batch(rows=100)
    train, held_out = schema.split(batch, eval_fraction=0.25, seed=0)
    assert held_out.rows == 25
    assert train.rows == 75


def test_split_is_deterministic_given_a_seed() -> None:
    batch = _batch(rows=20)
    batch.context[:, 0] = np.arange(20, dtype=np.float32)

    a_train, a_held_out = schema.split(batch, eval_fraction=0.25, seed=7)
    b_train, b_held_out = schema.split(batch, eval_fraction=0.25, seed=7)

    np.testing.assert_array_equal(a_train.context, b_train.context)
    np.testing.assert_array_equal(a_held_out.context, b_held_out.context)


def test_split_rejects_a_fraction_outside_zero_one() -> None:
    batch = _batch(rows=10)
    with pytest.raises(ValueError, match="eval_fraction"):
        schema.split(batch, eval_fraction=1.0, seed=0)
    with pytest.raises(ValueError, match="eval_fraction"):
        schema.split(batch, eval_fraction=0.0, seed=0)
