"""Turning a recorded connectivity signal into the numbers a coverage study
reports: what fraction of a flight had a usable route, and how the lost time
was distributed.

The distinction matters more than it looks. "94% connected" is the same
figure whether that 6% arrived as one four-minute blackout in the middle of a
canyon or as a hundred half-second flickers, and those are completely
different operational outcomes — so `ConnectivityStats` carries the outage
windows alongside the fraction rather than only summarising them.

Works on any `Recorder` column whose values are truthy when connected: a
`route_via` probe (a link name or `None`), a `Simulation.reachable` probe (a
tuple of node names, empty when nothing is in reach), or anything else via
`predicate`.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any

from .recorder import Recorder

Predicate = Callable[[Any], bool]
"""Decides whether one recorded sample counts as connected. The default,
`bool`, treats `None` and an empty collection as disconnected."""


@dataclasses.dataclass(frozen=True)
class Outage:
    """One contiguous stretch with no connectivity, as a half-open interval
    `[start_s, end_s)`.

    `start_s` is the time of the first disconnected sample; `end_s` is the
    time of the sample that recovered, or — for an outage still in progress
    when the recording ended — one sample interval past the last sample. That
    convention makes `duration_s` exactly the disconnected time the samples
    represent, so the windows and the totals never disagree.
    """

    start_s: float
    end_s: float

    @property
    def duration_s(self) -> float:
        """How long the outage lasted."""
        return self.end_s - self.start_s


@dataclasses.dataclass(frozen=True)
class ConnectivityStats:
    """A recorded run's connectivity, summarised."""

    total_s: float
    """Time the recording covers."""

    connected_s: float
    """Time with a usable route."""

    outages: tuple[Outage, ...]
    """Every stretch without one, in time order."""

    @property
    def disconnected_s(self) -> float:
        """Time without a usable route — equal to the outage durations
        summed."""
        return self.total_s - self.connected_s

    @property
    def connected_fraction(self) -> float:
        """Share of the run with a usable route, in `[0, 1]`. An empty
        recording is reported as `0.0` rather than raising."""
        if self.total_s == 0.0:
            return 0.0
        return self.connected_s / self.total_s

    @property
    def outage_count(self) -> int:
        """How many separate outages occurred."""
        return len(self.outages)

    @property
    def longest_outage_s(self) -> float:
        """The worst single outage — the figure that decides whether a gap is
        survivable (a buffered telemetry hiccup) or not (a lost link). `0.0`
        when there were none."""
        return max((o.duration_s for o in self.outages), default=0.0)


def outage_windows(
    rec: Recorder, column: str, *, predicate: Predicate = bool
) -> tuple[Outage, ...]:
    """Every contiguous stretch of `column` where `predicate` says the run
    was disconnected, in time order.

    Distinct from `Recorder.transitions`, which skips `None` samples by
    design (so a switch summary reads as "became X, then became Y") and
    therefore cannot see a dropout at all.
    """
    if not rec.times_s:
        # A recording with no samples has no columns either, so this has to
        # come before the lookup — otherwise "nothing was recorded" would be
        # indistinguishable from "this probe was never registered", and the
        # latter must stay a loud KeyError.
        return ()

    values = rec.column(column)
    interval_s = rec.interval_ms / 1000.0

    windows: list[Outage] = []
    start_s: float | None = None
    for t_s, value in zip(rec.times_s, values):
        if not predicate(value):
            if start_s is None:
                start_s = t_s
        elif start_s is not None:
            windows.append(Outage(start_s, t_s))
            start_s = None
    if start_s is not None:
        # Still disconnected when the recording stopped: the final sample
        # stands for a whole interval, like every other one.
        windows.append(Outage(start_s, rec.times_s[-1] + interval_s))
    return tuple(windows)


def connectivity_stats(
    rec: Recorder, column: str, *, predicate: Predicate = bool
) -> ConnectivityStats:
    """Summarise `column`'s connectivity over the whole recording.

    Time is attributed by sample count — each of the `Recorder`'s evenly
    spaced samples stands for one `interval_ms` — so the resolution of the
    answer is the recording's sample interval, and a scenario studying
    sub-second dropouts needs to sample accordingly.
    """
    if not rec.times_s:
        return ConnectivityStats(total_s=0.0, connected_s=0.0, outages=())

    values = rec.column(column)
    interval_s = rec.interval_ms / 1000.0
    connected = sum(1 for value in values if predicate(value))
    return ConnectivityStats(
        total_s=len(values) * interval_s,
        connected_s=connected * interval_s,
        outages=outage_windows(rec, column, predicate=predicate),
    )
