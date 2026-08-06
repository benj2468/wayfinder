"""A stand-in for `wayfinder_sim.scenario.Simulation`, shared by the generation-side
tests.

The generator only ever touches a handful of the simulation's methods, so a
fake keeps these tests runnable with numpy alone — no SimPy, no PyO3
extension. `tests/test_end_to_end.py` is where the real thing is driven; that
is the test that catches the two drifting apart, and this one deliberately
does not try to be a second copy of it.

`FakeSim`'s clock only moves when something drives it, which is what makes the
episode sweep testable: the times it sampled at are recorded, so "sampled once
per interval, and never during warmup" is an assertion rather than a guess.
"""

from __future__ import annotations


class FakeSample:
    """Mimics `wayfinder_sim.channel.Channel.evaluate`'s result, as far as the
    generator reads it."""

    def __init__(self, probability: float) -> None:
        self.delivery_probability = probability


class FakeMac:
    """A `wf.PyMac` stand-in: opaque, hashable, and comparable — which is all
    `node_for_mac` needs of it."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FakeMac) and other.name == self.name

    def __repr__(self) -> str:
        return f"FakeMac({self.name!r})"


class FakePath:
    """One candidate path — mirrors `wf.PyNeighborStats`."""

    def __init__(self, neighbor, tq=200, seqno=10, heard=900, interval=100):
        self.neighbor = neighbor
        self.last_tq = tq
        self.last_seqno = seqno
        self.last_heard_ms = heard
        self.interval_estimate_ms = interval


class FakeRecord:
    """One originator and its candidates — mirrors `wf.PyOriginatorRecord`."""

    def __init__(self, originator, best, paths):
        self.originator = originator
        self.best_next_hop = best
        self.max_tq = 200
        self.last_seqno = 10
        self.last_heard_ms = 900
        self.paths = paths


class FakeLink:
    """One link-quality row — mirrors `wf.PyLinkQualityRecord`."""

    def __init__(self, neighbor):
        self.neighbor = neighbor
        self.iface_idx = 0
        self.ewma_quality = 180
        self.sample_count = 42


class FakeDriver:
    """The router-state projection `router_snapshot` reads."""

    def __init__(self, records, links):
        self._records, self._links = records, links

    def originator_table(self):
        return self._records

    def link_quality_records(self):
        return self._links

    def neighbor_count(self):
        return 1

    def originator_occupancy(self):
        return (1, 32)


class FakeClock:
    """`simpy.Environment`'s two-member surface as the sweep uses it, with
    SimPy's own refusal to run backwards preserved — stepping to a time
    already past is the mistake most likely to make a sweep silently sample
    the same instant twice."""

    def __init__(self) -> None:
        self.now = 0

    def run(self, until: float) -> None:
        if until <= self.now:
            raise ValueError(f"until ({until}) must be greater than {self.now}")
        self.now = until


class FakeSim:
    """Two nodes on a perfect link, each already knowing the other.

    Records the clock reading at every `sample_channel` call in `sampled_at`,
    since `channel_graph` runs exactly once per sampled instant — that list is
    the sweep's observable schedule.
    """

    def __init__(self, seed: int = 0) -> None:
        self.seed = seed
        self.env = FakeClock()
        self.sampled_at: list[float] = []
        macs = {name: FakeMac(name) for name in ("a", "b")}
        self._macs = {mac: name for name, mac in macs.items()}
        self._drivers = {
            name: FakeDriver(
                records=[FakeRecord(macs[peer], macs[peer], [FakePath(macs[peer])])],
                links=[FakeLink(macs[peer])],
            )
            for name, peer in (("a", "b"), ("b", "a"))
        }

    @property
    def node_names(self) -> tuple[str, ...]:
        return ("a", "b")

    def driver(self, node: str) -> FakeDriver:
        return self._drivers[node]

    def node_for_mac(self, mac) -> str | None:
        return self._macs.get(mac)

    def sample_channel(self, a: str, b: str) -> FakeSample:
        self.sampled_at.append(self.env.now)
        return FakeSample(1.0)


class SilentSim(FakeSim):
    """A simulation whose routers have heard nothing — no originators, so no
    rows. What an episode that is too short, or a topology that never links
    up, actually looks like."""

    def __init__(self, seed: int = 0) -> None:
        super().__init__(seed)
        self._drivers = {name: FakeDriver([], []) for name in self.node_names}


SCENARIO_MODULE = '''\
"""A scenario module, written to a temp directory by the CLI tests."""

import sys

sys.path.insert(0, {tests_dir!r})

from fakesim import FakeSim, SilentSim

DURATION_S = 4.0


def build_simulation(seed: int = 0) -> FakeSim:
    return FakeSim(seed)


def build_silent(seed: int = 0) -> SilentSim:
    return SilentSim(seed)
'''
"""Source of a loadable scenario module wrapping `FakeSim` — `str.format` it
with `tests_dir` and write it wherever a test needs a scenario file to point
`wayfinder-ml generate` at."""
