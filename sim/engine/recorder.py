"""Columnar capture of a `Simulation`'s registered probe signals over time."""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass
class Recorder:
    """One row per sample instant; one column per probe name registered via
    `Simulation.record`. Built incrementally by `Simulation.run` via
    `append`, then handed back to the scenario for summarizing/plotting."""

    interval_ms: int
    times_s: list[float] = dataclasses.field(default_factory=list)
    columns: dict[str, list[Any]] = dataclasses.field(default_factory=dict)

    def append(self, t_s: float, values: dict[str, Any]) -> None:
        """Append one sample row: `t_s` plus this instant's value for every
        probe in `values` (keyed by probe name)."""
        self.times_s.append(t_s)
        for name, value in values.items():
            self.columns.setdefault(name, []).append(value)

    def column(self, name: str) -> list[Any]:
        """The recorded values for probe `name`, one per `times_s` entry."""
        return self.columns[name]

    def transitions(self, name: str) -> list[tuple[float, Any]]:
        """`(t_s, new_value)` for each point where probe `name`'s value
        differs from its previous non-`None` value — `None` samples (e.g.
        before a route first resolves) are skipped rather than counted as a
        transition, so a summary reads as "when did this signal first
        become X, then next become Y" rather than flickering on gaps."""
        out: list[tuple[float, Any]] = []
        last: Any = None
        for t_s, value in zip(self.times_s, self.columns.get(name, [])):
            if value is not None and value != last:
                out.append((t_s, value))
                last = value
        return out
