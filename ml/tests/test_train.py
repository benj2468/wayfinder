"""Training-half tests.

Skipped wholesale without torch, mirroring how `sim/tests` skips its
SimPy-touching cases — the `[train]` extra is not installed on a box that only
generates data.
"""

from __future__ import annotations

import numpy as np
import pytest

from wayfinder_ml import schema

torch = pytest.importorskip("torch")

from wayfinder_ml.train import NextHopScorer, evaluate, train  # noqa: E402


def _learnable_batch(rows: int = 512) -> schema.FeatureBatch:
    """A dataset where the oracle follows `link_quality` and TQ points the
    opposite way.

    This is the project's thesis in miniature: the model wins by reading a
    signal TQ does not contain. Classical BATMAN takes `argmax(tq)` and is
    wrong on every row by construction, so any agreement the model reaches is
    genuine lift rather than agreement with the baseline.

    The target must be a *pointwise* function of a candidate's own features —
    see `NextHopScorer`, which scores each candidate independently. A target
    like "the second-best TQ slot" is not pointwise (it depends on the other
    candidates' values) and this architecture cannot represent it at all.
    """
    rng = np.random.default_rng(0)
    quality = rng.random((rows, schema.MAX_PATHS)).astype(np.float32)

    candidates = np.zeros(
        (rows, schema.MAX_PATHS, len(schema.CANDIDATE_FEATURES)), dtype=np.float32
    )
    candidates[:, :, schema.CANDIDATE_FEATURES.index("link_quality")] = quality
    # Anti-correlated, so argmax(tq) is argmin(link_quality) — always wrong.
    candidates[:, :, schema.CANDIDATE_FEATURES.index("tq")] = 1.0 - quality

    label = quality.argmax(axis=1).astype(np.int8)

    return schema.FeatureBatch(
        candidates=candidates,
        mask=np.ones((rows, schema.MAX_PATHS), dtype=bool),
        context=np.zeros((rows, len(schema.CONTEXT_FEATURES)), dtype=np.float32),
        label=label,
        cost=np.zeros((rows, schema.MAX_PATHS), dtype=np.float32),
    )


def test_scorer_emits_one_logit_per_slot() -> None:
    model = NextHopScorer()
    scores = model(
        torch.zeros(3, schema.MAX_PATHS, len(schema.CANDIDATE_FEATURES)),
        torch.ones(3, schema.MAX_PATHS, dtype=torch.bool),
        torch.zeros(3, len(schema.CONTEXT_FEATURES)),
    )
    assert scores.shape == (3, schema.MAX_PATHS)


def test_masked_slots_never_win() -> None:
    """An empty slot must be unselectable however attractive its features."""
    model = NextHopScorer()
    candidates = torch.randn(8, schema.MAX_PATHS, len(schema.CANDIDATE_FEATURES))
    mask = torch.ones(8, schema.MAX_PATHS, dtype=torch.bool)
    mask[:, 2:] = False

    scores = model(candidates, mask, torch.zeros(8, len(schema.CONTEXT_FEATURES)))

    assert torch.all(scores.argmax(dim=1) < 2)


def test_training_beats_the_batman_baseline() -> None:
    """The only result that matters: the model must outperform `argmax(tq)`
    against the oracle."""
    batch = _learnable_batch()
    model = train(batch, epochs=60, device=torch.device("cpu"))

    result = evaluate(model, batch, device=torch.device("cpu"))

    assert result.baseline_agreement == 0.0  # baseline is wrong by construction
    assert result.model_agreement > 0.5
    assert result.lift > 0.5


def test_training_raises_loudly_on_non_finite_loss() -> None:
    """A diverging/NaN-poisoned run must fail hard, not finish and hand back a
    model that only looks trained — see the module docstring: `evaluate`'s
    agreement numbers can't tell a legitimately weak model apart from a
    NaN-collapsed one, so the loop itself has to catch it."""
    batch = _learnable_batch(rows=8)
    batch.candidates[:] = np.nan

    with pytest.raises(RuntimeError, match="non-finite loss"):
        train(batch, epochs=1, device=torch.device("cpu"))


def test_training_refuses_a_fully_unlabelled_dataset() -> None:
    batch = _learnable_batch(rows=8)
    batch.label[:] = schema.NO_LABEL
    with pytest.raises(ValueError, match="no labelled rows"):
        train(batch, device=torch.device("cpu"))


def test_evaluate_on_unlabelled_dataset_reports_no_rows() -> None:
    batch = _learnable_batch(rows=8)
    batch.label[:] = schema.NO_LABEL
    result = evaluate(NextHopScorer(), batch, device=torch.device("cpu"))
    assert result.rows == 0
