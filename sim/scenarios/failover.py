"""Failover scenario: kill the relay that is carrying traffic, and measure how
long the mesh takes to heal.

Topology — twelve radios on a 3x4 field grid, one shared channel::

    hq ---- n01 ---- n02 ---- n03
     |        |        |        |
    n10 ---- n11 ---- n12 ---- n13
     |        |        |        |
    n20 ---- n21 ---- n22 ---- team

Every node hears every other through `FreeSpacePathLoss`: adjacent nodes
(450 m) well, diagonals (~640 m) marginally, anything further barely or not at
all. So the corner-to-corner path from the field team to HQ is several hops,
and there is always more than one way through. That redundancy is what
"self-healing" claims to use; the scenario measures how quickly it actually
does.

**The experiment.** The team streams ten packets a second to HQ. Partway
through, the relay carrying that stream is powered off. Later it is powered
back on — and it *reboots*, coming back with an empty router that has to
relearn the mesh. Three numbers come out of one run:

- **time to reroute**: from the power-off to the first packet that arrives
  over the new path — what a user of the link experiences as the outage;
- **packets lost** in that gap;
- **time to rejoin**: from the power-on until HQ has a route to the rebooted
  relay again.

All three are read off delivered traffic (`Simulation.stream`) and the
routers' own tables, never inferred from a schedule.

**The trade-off.** Nothing in BATMAN detects a dead neighbour directly: a
path ages out when the OGMs that kept it alive stop arriving, and how often
they arrive is the Trickle schedule's `i_max`. A faster schedule heals faster
and costs more airtime on every node, all the time, failure or not. The
sweep runs the same failure across a range of `i_max` and plots recovery time
against control-plane overhead, which is the curve an operator picks a point
on — and the reason a duty-cycle-limited LoRa segment heals slower than a
Wi-Fi one.

The second half of the sweep is the cheaper answer. Keep-alive heartbeats
(`Node.tx_keepalive_interval_ms`) are tiny, single-hop and never re-flooded,
and a neighbour that misses three of them has its paths zeroed at once
(`MAX_MISSED_KEEPALIVES`) rather than after six missed OGMs
(`MAX_MISSED_OGMS`). Plotted on the same cost axis, they buy a short worst
case for far less airtime than a faster OGM schedule does.

Run: `uv run --group sim python sim/scenarios/failover.py [--export DIR]`
"""

from __future__ import annotations

import argparse
import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim.channel import FreeSpacePathLoss
from wayfinder_sim.mobility import Static, Vec3
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.showcase import (
    Chart,
    Headline,
    Marker,
    Series,
    Showcase,
    downsample,
    write_showcase,
)
from wayfinder_sim.topology import shared_lan
from wayfinder_sim.traffic import Flow

ROWS, COLS = 3, 4
SPACING_M = 450.0
HQ = "hq"
TEAM = "team"
RATE_HZ = 10.0
DEFAULT_TRICKLE = (200, 2000)
TX_POWER_DBM = 24.0
MAX_RANGE_M = 700.0
DELIVERY_STEEPNESS = 1.0
"""A digital radio's packet-error waterfall is a dB or two wide. The model's
default (0.3/dB, ~10 dB wide) is tuned for studies that want a gradual
fade; here it would drop ~8% of frames on every in-range diagonal hop, and
with no link-layer retransmission a three-hop stream would lose a fifth of
its packets before anything failed — measuring the radio, not the healing."""

STREAM_START_S = 20.0
FAIL_AT_S = 60.0
RECOVER_AT_S = 120.0
DURATION_S = 180.0

SWEEP_I_MAX_MS = (500, 1000, 2000, 4000, 8000)
SWEEP_KEEPALIVE_MS = (2000, 1000, 500, 250)
SWEEP_SEEDS = tuple(range(10))


def node_name(row: int, col: int) -> str:
    """Grid position to node name; the two corners carry the story's roles."""
    if (row, col) == (0, 0):
        return HQ
    if (row, col) == (ROWS - 1, COLS - 1):
        return TEAM
    return f"n{row}{col}"


def build_simulation(
    seed: int = 0,
    trickle: tuple[int, int] = DEFAULT_TRICKLE,
    keepalive_ms: int | None = None,
) -> Simulation:
    """The field grid on one shared radio channel, optionally with every node
    sending keep-alive heartbeats every `keepalive_ms`."""
    nodes = [
        Node(
            node_name(r, c),
            mobility=Static(Vec3(c * SPACING_M, r * SPACING_M, 2.0)),
            trickle=trickle,
            tx_keepalive_interval_ms=keepalive_ms,
        )
        for r in range(ROWS)
        for c in range(COLS)
    ]
    radio = FreeSpacePathLoss(
        tx_power_dbm=TX_POWER_DBM,
        max_range_m=MAX_RANGE_M,
        delivery_steepness=DELIVERY_STEEPNESS,
    )
    return Simulation(nodes, shared_lan([n.name for n in nodes], radio), seed=seed)


@dataclass(frozen=True)
class FailoverRun:
    """One failure, measured."""

    trickle: tuple[int, int]
    keepalive_ms: int | None
    seed: int
    victim: str
    path_before: tuple[str, ...] | None
    path_after: tuple[str, ...] | None
    recovered_s: float | None
    lost: int
    rejoin_s: float | None
    overhead_fps: float
    """Frames per second per node before the stream starts — the steady-state
    control-plane cost of this schedule, with no data in it."""
    flow: Flow
    times_s: list[float]
    hops: list[int | None]
    victim_reachable: list[bool]


def run_failover(
    seed: int = 0,
    trickle: tuple[int, int] = DEFAULT_TRICKLE,
    *,
    keepalive_ms: int | None = None,
    fail_at_s: float = FAIL_AT_S,
    recover_at_s: float | None = RECOVER_AT_S,
    duration_s: float = DURATION_S,
) -> FailoverRun:
    """Converge, stream team→HQ, kill the first relay on the stream's path,
    reboot it later, and measure."""
    sim = build_simulation(seed, trickle, keepalive_ms)
    flow = sim.stream(
        TEAM, HQ, rate_hz=RATE_HZ, start_s=STREAM_START_S, duration_s=duration_s
    )
    sim.record("path", _live_path)

    sim.run(until_s=STREAM_START_S)
    overhead_fps = sum(sim.tx_frames(n) for n in sim.node_names) / (
        len(sim.node_names) * STREAM_START_S
    )
    sim.run(until_s=fail_at_s)
    path_before = sim.route_path(TEAM, HQ)
    if path_before is None or len(path_before) < 3:
        raise RuntimeError(f"no multi-hop route to fail before t={fail_at_s}s: {path_before}")
    victim = path_before[1]

    sim.fail_node(victim, at_s=fail_at_s, recover_s=recover_at_s)
    # Rejoined = the rebooted relay has learned its own way back to HQ. Asked
    # of the relay rather than of HQ, because HQ can keep a stale record of a
    # dead neighbour for a while; the relay reboots empty, so its table
    # cannot claim anything it has not relearned.
    sim.record("victim_reachable", lambda s: s.is_up(victim) and s.has_route(victim, HQ))
    rec = sim.run(until_s=duration_s)

    recovery = flow.recovery_after(fail_at_s)
    paths = rec.column("path")
    path_after = None
    if recovery.recovered_s is not None:
        # The path in use once healed, read a few seconds after the first
        # delivery so it is the settled one rather than the first to answer.
        settle_s = fail_at_s + recovery.recovered_s + 3.0
        path_after = next(
            (p for t, p in zip(rec.times_s, paths) if t >= settle_s and p is not None),
            None,
        )

    rejoin_s = None
    if recover_at_s is not None:
        for t, ok in zip(rec.times_s, rec.column("victim_reachable")):
            if t >= recover_at_s and ok:
                rejoin_s = t - recover_at_s
                break

    return FailoverRun(
        trickle=trickle,
        keepalive_ms=keepalive_ms,
        seed=seed,
        victim=victim,
        path_before=path_before,
        path_after=path_after,
        recovered_s=recovery.recovered_s,
        lost=recovery.lost,
        rejoin_s=rejoin_s,
        overhead_fps=overhead_fps,
        flow=flow,
        times_s=list(rec.times_s),
        hops=[_hops(p) for p in paths],
        victim_reachable=[bool(v) if v is not None else False for v in rec.column("victim_reachable")],
    )


def _live_path(sim: Simulation) -> tuple[str, ...] | None:
    """The team→HQ path, or `None` if any node on it is powered off.

    `route_path` walks each hop's own table, and a dead relay's table is
    frozen as it was when it died — still pointing onward. A path through it
    resolves on paper and carries nothing, so it counts as broken here.
    """
    path = sim.route_path(TEAM, HQ)
    if path is None or not all(sim.is_up(n) for n in path):
        return None
    return path


def _hops(path: tuple[str, ...] | None) -> int | None:
    return None if path is None else len(path) - 1


def delivery_timeline(flow: Flow, bin_s: float = 1.0) -> tuple[list[float], list[float | None]]:
    """Per-bin delivery ratio of `flow`, binned on send time."""
    if not flow.sent:
        return [], []
    end = flow.sent[-1][1]
    xs: list[float] = []
    ys: list[float | None] = []
    t = flow.sent[0][1]
    while t <= end:
        xs.append(round(t + bin_s / 2, 3))
        ys.append(flow.delivery_ratio(t, t + bin_s - 1e-9))
        t += bin_s
    return xs, ys


@dataclass(frozen=True)
class SweepPoint:
    """Every seed's failure under one detection setting."""

    family: str
    """`"ogm"` (OGM schedule varied, no keep-alive) or `"keepalive"` (the
    default OGM schedule plus a heartbeat)."""
    setting_ms: int
    runs: tuple[FailoverRun, ...]

    @property
    def overhead_fps(self) -> float:
        return statistics.mean(r.overhead_fps for r in self.runs)

    @property
    def recoveries_s(self) -> list[float]:
        # A run that never healed inside its window counts at the window's
        # end — an underestimate, said so in the method note; none do here.
        return [r.recovered_s if r.recovered_s is not None else float("inf") for r in self.runs]

    @property
    def median_s(self) -> float:
        return statistics.median(self.recoveries_s)

    @property
    def worst_s(self) -> float:
        return max(self.recoveries_s)

    @property
    def median_lost(self) -> float:
        return statistics.median(r.lost for r in self.runs)


def run_sweep(seeds: Sequence[int] = SWEEP_SEEDS) -> list[SweepPoint]:
    """The same failure under two ways of detecting it: a faster OGM schedule
    (i_min = i_max/10), or the default schedule plus keep-alive heartbeats."""
    points = []
    for i_max in SWEEP_I_MAX_MS:
        trickle = (max(50, i_max // 10), i_max)
        # A slow schedule converges and heals slowly; give it room in
        # proportion, so the window never truncates a recovery.
        scale = max(1.0, i_max / 2000)
        runs = tuple(
            run_failover(
                seed,
                trickle,
                fail_at_s=FAIL_AT_S * scale,
                recover_at_s=None,
                duration_s=FAIL_AT_S * scale + 60 * scale,
            )
            for seed in seeds
        )
        points.append(SweepPoint("ogm", i_max, runs))
    for keepalive_ms in SWEEP_KEEPALIVE_MS:
        runs = tuple(
            run_failover(
                seed,
                DEFAULT_TRICKLE,
                keepalive_ms=keepalive_ms,
                recover_at_s=None,
                duration_s=FAIL_AT_S + 60,
            )
            for seed in seeds
        )
        points.append(SweepPoint("keepalive", keepalive_ms, runs))
    return points


def print_summary(run: FailoverRun, sweep: Sequence[SweepPoint]) -> None:
    print("Failover — one relay powered off mid-stream, then rebooted")
    print(f"  path before : {' → '.join(run.path_before or ())}")
    print(f"  victim      : {run.victim} (off at {FAIL_AT_S:.0f}s, on at {RECOVER_AT_S:.0f}s)")
    print(f"  path after  : {' → '.join(run.path_after or ()) or 'none'}")
    print(f"  rerouted in : {_fmt_s(run.recovered_s)}, {run.lost} packets lost")
    print(f"  rejoined in : {_fmt_s(run.rejoin_s)} after reboot")
    print()
    print("  detection                  frames/s/node   median   worst   median lost")
    for p in sweep:
        print(
            f"  {_label(p):<26} {p.overhead_fps:>13.2f} {p.median_s:>7.1f}s {p.worst_s:>6.1f}s"
            f" {p.median_lost:>12.0f}"
        )


def _label(point: SweepPoint) -> str:
    if point.family == "ogm":
        return f"OGM every {point.setting_ms / 1000:g} s"
    return f"+ keep-alive {point.setting_ms} ms"


def _fmt_s(value: float | None) -> str:
    return "never" if value is None else f"{value:.1f} s"


def showcase(run: FailoverRun, sweep: Sequence[SweepPoint]) -> Showcase:
    """The results-page entry for this scenario."""
    xs, ys = delivery_timeline(run.flow)
    hop_x, hop_y = downsample(run.times_s, run.hops)
    ogm = [p for p in sweep if p.family == "ogm"]
    ka = [p for p in sweep if p.family == "keepalive"]
    default = next(p for p in ogm if p.setting_ms == DEFAULT_TRICKLE[1])
    best_ka = min(ka, key=lambda p: (p.worst_s, p.overhead_fps))
    markers = [
        Marker(FAIL_AT_S, f"{run.victim} powered off"),
        Marker(RECOVER_AT_S, f"{run.victim} reboots"),
    ]
    return Showcase(
        slug="failover",
        title="Kill a relay, watch it heal",
        category="resilience",
        scenario="sim/scenarios/failover.py",
        question="When the radio carrying my traffic dies, how long until traffic flows again?",
        headlines=[
            Headline(
                f"{default.median_s:.1f} s",
                "median time to reroute",
                f"worst {default.worst_s:.1f} s over {len(default.runs)} failures, default settings",
            ),
            Headline(
                f"{best_ka.worst_s:.1f} s",
                "worst case with keep-alives",
                f"{best_ka.setting_ms} ms heartbeat, "
                f"+{(best_ka.overhead_fps / default.overhead_fps - 1) * 100:.0f}% control traffic",
            ),
            Headline(
                _fmt_s(run.rejoin_s),
                "to rejoin after a reboot",
                "the relay comes back with an empty routing table",
            ),
        ],
        summary=(
            f"A field team streams to HQ across a twelve-radio grid. The relay carrying the "
            f"stream is powered off mid-transfer, and the mesh routes around it with no operator "
            f"action. In the run charted here it took {_fmt_s(run.recovered_s)} "
            f"({run.lost} packets lost) to move from {' → '.join(run.path_before or ())} to "
            f"{' → '.join(run.path_after or ()) or 'no path'}. How long healing takes is a design choice. "
            f"With routing adverts alone, a dead relay is noticed only after six adverts go missing, so "
            f"the worst case grows with the advert interval. Keep-alive heartbeats catch the "
            f"failure after three misses for a fraction of the airtime: at {best_ka.setting_ms} ms they "
            f"cap recovery at {best_ka.worst_s:.1f} s, where adverts alone needed "
            f"{default.worst_s:.1f} s."
        ),
        method=(
            "Each node runs the real wayfinder router, compiled from this repository, inside a "
            "discrete-event simulation. Radios follow free-space path loss with per-frame fading on "
            "one shared channel (24 dBm, 700 m hard range, 450 m grid). A powered-off node neither "
            "sends nor hears; a reboot gives it a fresh router. Recovery is measured from delivered "
            "packets, not routing tables: it is the time from power-off to the first packet that "
            f"arrives afterwards. Each setting repeats the failure under {len(SWEEP_SEEDS)} random "
            "seeds; overhead is all frames sent per node per second before any data flows."
        ),
        charts=[
            Chart(
                title="Packets delivered, per second",
                x_label="time (s)",
                y_label="delivery ratio",
                series=[Series("team → HQ", xs, ys, kind="step")],
                markers=markers,
                y_range=(0.0, 1.0),
            ),
            Chart(
                title="Hops on the team → HQ path",
                x_label="time (s)",
                y_label="hops",
                series=[Series("path length", hop_x, hop_y, kind="step")],
                markers=markers,
                caption=(
                    "A break in the line is a moment with no complete path. The flicker between "
                    "lengths is near-equal routes trading places as fading moves their measured quality."
                ),
            ),
            Chart(
                title="Worst-case recovery vs. what it costs",
                x_label="control frames / s / node",
                y_label="worst time to reroute (s)",
                series=[
                    Series("faster routing adverts", [p.overhead_fps for p in ogm], [p.worst_s for p in ogm], kind="line"),
                    Series("default adverts + keep-alive", [p.overhead_fps for p in ka], [p.worst_s for p in ka], kind="line"),
                ],
                caption=(
                    "Lower-left is better. Each point is ten failures; keep-alives buy a short "
                    "worst case for far less airtime than speeding up the adverts."
                ),
            ),
            Chart(
                title="Every failure, by detection setting",
                x_label="control frames / s / node",
                y_label="time to reroute (s)",
                series=[
                    Series(
                        "routing adverts only",
                        [p.overhead_fps for p in ogm for _ in p.runs],
                        [r for p in ogm for r in p.recoveries_s],
                        kind="scatter",
                    ),
                    Series(
                        "with keep-alive",
                        [p.overhead_fps for p in ka for _ in p.runs],
                        [r for p in ka for r in p.recoveries_s],
                        kind="scatter",
                    ),
                ],
                caption=(
                    "Recovery is bimodal: instant when another path already looks better, slow when "
                    "the mesh must wait for the dead one to age out — up to six advert gaps, which "
                    "is why the worst case grows in step with the advert interval."
                ),
            ),
        ],
        table=[["detection", "frames/s/node", "median reroute (s)", "worst reroute (s)", "median packets lost"]]
        + [
            [_label(p), round(p.overhead_fps, 2), round(p.median_s, 1), round(p.worst_s, 1), p.median_lost]
            for p in sweep
        ],
        params={
            "nodes": ROWS * COLS,
            "grid_spacing_m": SPACING_M,
            "tx_power_dbm": TX_POWER_DBM,
            "max_range_m": MAX_RANGE_M,
            "stream_rate_hz": RATE_HZ,
            "trickle_ms": list(DEFAULT_TRICKLE),
            "sweep_i_max_ms": list(SWEEP_I_MAX_MS),
            "sweep_keepalive_ms": list(SWEEP_KEEPALIVE_MS),
            "seeds": len(SWEEP_SEEDS),
        },
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--export", type=Path, help="write showcase JSON into this directory")
    parser.add_argument("--quick", action="store_true", help="three seeds per sweep point")
    args = parser.parse_args(argv)
    wf.init_tracing()

    run = run_failover()
    sweep = run_sweep(seeds=SWEEP_SEEDS[:3] if args.quick else SWEEP_SEEDS)
    print_summary(run, sweep)
    if args.export:
        print(f"wrote {write_showcase(showcase(run, sweep), args.export)}")


if __name__ == "__main__":
    main()
