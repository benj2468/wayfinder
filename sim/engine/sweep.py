"""Parameter sweeps: run the same topology-building function across several
parameter values, collecting each run's `Recorder` for comparison — e.g.
"how does the failover distance change as a radio's transmit power varies?"

The mechanism (build-and-run N independent `Simulation`s) lives here; which
parameter to vary, how to derive a summary metric from each `Recorder`
(e.g. `Recorder.transitions(...)`), and how to plot the comparison stay
scenario-specific.
"""

from __future__ import annotations

import dataclasses
from typing import Callable, Generic, Sequence, TypeVar

from .recorder import Recorder
from .scenario import Simulation

T = TypeVar("T")


@dataclasses.dataclass(frozen=True)
class SweepResult(Generic[T]):
    """One `build(param)` run's outcome."""

    param: T
    recorder: Recorder


def run_sweep(
    build: Callable[[T], Simulation],
    values: Sequence[T],
    *,
    until_s: float,
    sample_interval_ms: int = 50,
) -> list[SweepResult[T]]:
    """Build and run a fresh `Simulation` from `build(value)` for each of
    `values` — a fresh one per value, never reused, so runs can't leak state
    into each other — returning one `SweepResult` per run in the same order."""
    return [
        SweepResult(
            param=value,
            recorder=build(value).run(
                until_s=until_s, sample_interval_ms=sample_interval_ms
            ),
        )
        for value in values
    ]
