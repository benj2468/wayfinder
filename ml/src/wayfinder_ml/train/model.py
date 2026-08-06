"""The scorer.

A deliberately small network: it scores each of the four candidate slots
independently through a shared MLP, then a masked softmax picks among them.
Sharing the trunk across slots is what makes the model permutation-equivariant
— slot order is an artifact of insertion order in an `HVec`, and a model that
could read meaning into it would learn a spurious cue that changes under
recompilation.

**This scorer is pointwise, and that is a real constraint.** Each candidate's
score depends only on its own features plus the shared per-row context; there
is no interaction *between* candidates. So the model can learn "what is this
path worth?" and argmax it, but it cannot learn any target defined by rank
among the candidates (say, "the second-best TQ") — such a function is not
representable here at all, and training against one silently converges to
garbage rather than failing loudly.

That is the right trade for this task: the oracle's label *is* pointwise, since
"best next hop" means "lowest true ETX through this candidate", and ETX through
a candidate is a property of that candidate alone. If a future target needs
cross-candidate reasoning, this has to become an attention block over the four
slots first — see the README.

Size is a design decision, not a limitation. The input is eleven numbers per
candidate and the output is a choice among four; on an Orin this is
microseconds either way. The GPU earns its place in *training* — sweeping
scenarios and fitting over millions of rows — and in leaving headroom for a
richer context (neighbourhood-level graph features) later, not in making this
forward pass fast.
"""

from __future__ import annotations

import torch
from torch import nn

from ..schema import CANDIDATE_FEATURES, CONTEXT_FEATURES, MAX_PATHS

MASKED_SCORE = -1e9
"""Additive penalty for empty slots. A large finite number rather than `-inf`,
which produces `NaN` gradients when a row's every slot is masked."""


class NextHopScorer(nn.Module):
    """Scores `MAX_PATHS` candidate next hops, returning one logit per slot.

    Slot logits for masked (empty) candidates are driven to `MASKED_SCORE`, so
    a softmax over the output never assigns them probability.
    """

    def __init__(self, hidden: int = 32) -> None:
        super().__init__()
        width = len(CANDIDATE_FEATURES) + len(CONTEXT_FEATURES)
        self.trunk = nn.Sequential(
            nn.Linear(width, hidden),
            nn.ReLU(),
            nn.Linear(hidden, hidden),
            nn.ReLU(),
            nn.Linear(hidden, 1),
        )

    def forward(
        self, candidates: torch.Tensor, mask: torch.Tensor, context: torch.Tensor
    ) -> torch.Tensor:
        """`candidates` `(B, MAX_PATHS, F)`, `mask` `(B, MAX_PATHS)` bool,
        `context` `(B, C)` -> logits `(B, MAX_PATHS)`."""
        # Every slot sees the same per-row context alongside its own features.
        shared = context.unsqueeze(1).expand(-1, MAX_PATHS, -1)
        scores = self.trunk(torch.cat([candidates, shared], dim=-1)).squeeze(-1)
        return scores.masked_fill(~mask, MASKED_SCORE)
