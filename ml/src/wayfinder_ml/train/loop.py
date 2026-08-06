"""Fitting the scorer, and measuring it against the metric it has to beat.

The headline number is not accuracy — it is **agreement with the oracle
relative to classical BATMAN's agreement with the oracle**, on the same rows.
A model that matches BATMAN exactly scores 100% "accuracy" against BATMAN's
own choices and is worth nothing. `evaluate` therefore reports both, so a
training run that is not actually beating the baseline is obvious.
"""

from __future__ import annotations

import dataclasses

import numpy as np
import torch
from torch import nn

from ..schema import CANDIDATE_FEATURES, NO_LABEL, FeatureBatch
from .model import NextHopScorer


@dataclasses.dataclass(frozen=True)
class Evaluation:
    """How often each policy picked the oracle's next hop, over labelled rows."""

    rows: int
    model_agreement: float
    baseline_agreement: float
    """Classical BATMAN's own agreement — `argmax(tq)` over the same
    candidates. The model is only interesting above this line."""

    @property
    def lift(self) -> float:
        """Percentage points the model gains over classical BATMAN."""
        return self.model_agreement - self.baseline_agreement


def _tensors(
    batch: FeatureBatch, device: torch.device
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
    return (
        torch.from_numpy(np.ascontiguousarray(batch.candidates)).to(device),
        torch.from_numpy(np.ascontiguousarray(batch.mask)).to(device),
        torch.from_numpy(np.ascontiguousarray(batch.context)).to(device),
        torch.from_numpy(np.ascontiguousarray(batch.label)).long().to(device),
    )


def pick_device() -> torch.device:
    """CUDA where present (a rented GPU, or the Orin's iGPU), else CPU.

    Kept as one function so every entry point agrees, and so running the same
    command on a laptop and on the Jetson differs only in speed.
    """
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def train(
    batch: FeatureBatch,
    *,
    epochs: int = 20,
    batch_size: int = 1024,
    lr: float = 1e-3,
    device: torch.device | None = None,
    seed: int = 0,
) -> NextHopScorer:
    """Fit a `NextHopScorer` on `batch`'s labelled rows.

    Unlabelled rows (`NO_LABEL` — the oracle's hop was not a candidate) are
    dropped from the loss: they have no correct slot, so any target would be
    noise. They are still worth generating, and `evaluate` counts them, since
    their frequency is how you tell "the model is wrong" apart from "the
    router never had the right option".
    """
    torch.manual_seed(seed)
    device = device or pick_device()
    model = NextHopScorer().to(device)

    keep = np.flatnonzero(batch.label != NO_LABEL)
    if keep.size == 0:
        raise ValueError("no labelled rows to train on")
    labelled = FeatureBatch(
        candidates=batch.candidates[keep],
        mask=batch.mask[keep],
        context=batch.context[keep],
        label=batch.label[keep],
        cost=batch.cost[keep],
    )

    candidates, mask, context, label = _tensors(labelled, device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss()

    model.train()
    for epoch in range(epochs):
        order = torch.randperm(labelled.rows, device=device)
        for start in range(0, labelled.rows, batch_size):
            idx = order[start : start + batch_size]
            optimizer.zero_grad()
            logits = model(candidates[idx], mask[idx], context[idx])
            loss = loss_fn(logits, label[idx])
            if not torch.isfinite(loss):
                raise RuntimeError(
                    f"training diverged: non-finite loss at epoch {epoch}, "
                    f"step {start} — a NaN-poisoned model is worse than no "
                    "model, since evaluate()'s agreement numbers can't tell "
                    "it apart from a legitimately weak one"
                )
            loss.backward()
            optimizer.step()
    return model


@torch.no_grad()
def evaluate(
    model: NextHopScorer, batch: FeatureBatch, *, device: torch.device | None = None
) -> Evaluation:
    """Compare the model and classical BATMAN against the oracle, on
    `batch`'s labelled rows."""
    device = device or pick_device()
    keep = np.flatnonzero(batch.label != NO_LABEL)
    if keep.size == 0:
        return Evaluation(rows=0, model_agreement=0.0, baseline_agreement=0.0)

    labelled = FeatureBatch(
        candidates=batch.candidates[keep],
        mask=batch.mask[keep],
        context=batch.context[keep],
        label=batch.label[keep],
        cost=batch.cost[keep],
    )
    candidates, mask, context, label = _tensors(labelled, device)

    model.eval()
    chosen = model(candidates, mask, context).argmax(dim=1)

    # Classical BATMAN is argmax over the TQ feature, restricted to populated
    # slots. Looked up by name so reordering `CANDIDATE_FEATURES` cannot
    # silently turn the baseline into some other column.
    tq_idx = CANDIDATE_FEATURES.index("tq")
    tq = candidates[:, :, tq_idx].masked_fill(~mask, -1.0)
    baseline = tq.argmax(dim=1)

    return Evaluation(
        rows=int(keep.size),
        model_agreement=float((chosen == label).float().mean()),
        baseline_agreement=float((baseline == label).float().mean()),
    )
