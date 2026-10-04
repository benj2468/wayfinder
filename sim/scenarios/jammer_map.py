"""Jammer map: where can one jammer hurt this mesh, and how much?

The field grid from `failover.py` — twelve 2.4 GHz radios, 450 m apart, HQ
in one corner — with every node streaming readings to HQ. A single
wideband noise jammer (`wayfinder_sim.interference.Jammer`) is switched on
partway through, and the run measures what share of the field's traffic still
reaches HQ while it transmits. Then the jammer moves, and it all runs again:
one run per cell of a grid laid over the area, so the result is a map —
colour is how much traffic got through with the jammer standing *there*.

**Why a map and not a number.** Jamming is a receiver-side effect: a frame
dies when the jammer's power at the *receiver* drowns it (signal-to-
interference below the capture margin), so what a jammer can deny depends on
whose receivers it sits beside. A jammer at the edge of the field takes out
the one or two radios nearest it and the mesh routes around them. The same
jammer beside HQ silences the one receiver every packet has to reach, and no
amount of path diversity helps. The map shows which places are which, and so
where a deployment needs a second gateway, or where it needs to be guarded.

Two jammer powers are mapped: a few-milliwatt hobby jammer, and a hundred-
milliwatt unit. The difference is the radius of denial — the distance inside
which a receiver can no longer hear its 450 m neighbour.

Run: `uv run --group sim python sim/scenarios/jammer_map.py [--export DIR]`
"""

from __future__ import annotations

import argparse
import statistics
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim.interference import Jammer
from wayfinder_sim.mobility import Static, Vec3
from wayfinder_sim.showcase import (
    Chart,
    Headline,
    Heatmap,
    Series,
    Showcase,
    write_showcase,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import failover as field

RATE_HZ = 2.0
JAM_ON_S = 30.0
JAM_FOR_S = 30.0
POWERS_DBM = (5.0, 20.0)
STEP_M = 150.0
MARGIN_M = 300.0
SEED = 0


def grid_axes(step_m: float = STEP_M) -> tuple[list[float], list[float]]:
    """Jammer positions: the field's extent plus a margin, every `step_m`."""
    x_max = (field.COLS - 1) * field.SPACING_M + MARGIN_M
    y_max = (field.ROWS - 1) * field.SPACING_M + MARGIN_M
    xs = [-MARGIN_M + i * step_m for i in range(int((x_max + MARGIN_M) // step_m) + 1)]
    ys = [-MARGIN_M + j * step_m for j in range(int((y_max + MARGIN_M) // step_m) + 1)]
    return xs, ys


def node_sites() -> dict[str, Vec3]:
    return {
        field.node_name(r, c): Vec3(c * field.SPACING_M, r * field.SPACING_M, 2.0)
        for r in range(field.ROWS)
        for c in range(field.COLS)
    }


@dataclass(frozen=True)
class JamRun:
    """One jammer position and power."""

    x: float
    y: float
    power_dbm: float
    delivered: float
    """Share of every node's readings to HQ, sent while the jammer was on,
    that arrived."""
    before: float
    """The same share in the equal stretch before it switched on."""


def run_position(
    x: float | None, y: float | None, power_dbm: float, *, seed: int = SEED
) -> JamRun:
    """Converge, stream every node → HQ, switch on a jammer at `(x, y)` (or
    none when `x` is `None`), and measure delivery before and during."""
    sim = field.build_simulation(seed)
    senders = [n for n in sim.node_names if n != field.HQ]
    flows = [
        sim.stream(
            n,
            field.HQ,
            rate_hz=RATE_HZ,
            start_s=JAM_ON_S - JAM_FOR_S,
            duration_s=2 * JAM_FOR_S,
        )
        for n in senders
    ]
    if x is not None and y is not None:
        sim.add_jammer(
            Jammer(
                "jammer",
                mobility=Static(Vec3(x, y, 2.0)),
                power_dbm=power_dbm,
                freq_hz=2.4e9,
                active=(JAM_ON_S, JAM_ON_S + JAM_FOR_S),
            )
        )
    sim.run(until_s=JAM_ON_S + JAM_FOR_S + 1.0)

    def share(start: float, end: float) -> float:
        sent = got = 0
        for f in flows:
            for seq, t in f.sent:
                if start <= t < end:
                    sent += 1
                    got += seq in f.received
        return got / sent if sent else 0.0

    return JamRun(
        x=0.0 if x is None else x,
        y=0.0 if y is None else y,
        power_dbm=power_dbm,
        delivered=share(JAM_ON_S, JAM_ON_S + JAM_FOR_S),
        before=share(JAM_ON_S - JAM_FOR_S, JAM_ON_S),
    )


def run_map(power_dbm: float, step_m: float = STEP_M) -> list[JamRun]:
    xs, ys = grid_axes(step_m)
    return [run_position(x, y, power_dbm) for y in ys for x in xs]


def heatmap_for(runs: Sequence[JamRun], step_m: float = STEP_M) -> Heatmap:
    xs, ys = grid_axes(step_m)
    lookup = {(r.x, r.y): r.delivered for r in runs}
    return Heatmap(
        xs=xs,
        ys=ys,
        values=[[lookup.get((x, y)) for x in xs] for y in ys],
        label="share of traffic reaching HQ",
        value_range=(0.0, 1.0),
    )


def hq_distance(run: JamRun) -> float:
    return (run.x**2 + run.y**2) ** 0.5


def denial_radius_m(runs: Sequence[JamRun], threshold: float = 0.5) -> float:
    """Distance from HQ inside which the jammer cuts delivery below
    `threshold` at every position measured — the radius it must reach."""
    far_ok = [hq_distance(r) for r in runs if r.delivered >= threshold]
    near_bad = [hq_distance(r) for r in runs if r.delivered < threshold]
    if not near_bad:
        return 0.0
    return min(far_ok) if far_ok else max(near_bad)


def print_summary(baseline: JamRun, maps: dict[float, list[JamRun]]) -> None:
    print(
        f"Jammer map — {len(node_sites())} radios, every node streaming to HQ at {RATE_HZ:g}/s"
    )
    print(f"  no jammer: {baseline.delivered:.1%} delivered")
    for power, runs in maps.items():
        worst = min(runs, key=lambda r: r.delivered)
        print(
            f"  {power:>4.0f} dBm: median {statistics.median(r.delivered for r in runs):.1%}, worst {worst.delivered:.1%} "
            f"at ({worst.x:.0f}, {worst.y:.0f}); positions below 50%: {sum(r.delivered < 0.5 for r in runs)}/{len(runs)}; "
            f"denial radius around HQ ≈ {denial_radius_m(runs):.0f} m"
        )


def showcase(
    baseline: JamRun, maps: dict[float, list[JamRun]], step_m: float = STEP_M
) -> Showcase:
    sites = node_sites()
    weak, strong = min(maps), max(maps)
    node_series = [
        Series(
            "radios",
            [p.x for p in sites.values()],
            [p.y for p in sites.values()],
            kind="scatter",
        ),
        Series("HQ", [0.0], [0.0], kind="scatter"),
    ]

    def by_distance(runs: Sequence[JamRun]) -> tuple[list[float], list[float]]:
        buckets: dict[float, list[float]] = {}
        for r in runs:
            buckets.setdefault(round(hq_distance(r) / step_m) * step_m, []).append(
                r.delivered
            )
        keys = sorted(buckets)
        return keys, [statistics.median(buckets[k]) for k in keys]

    weak_runs, strong_runs = maps[weak], maps[strong]
    weak_bad = sum(r.delivered < 0.5 for r in weak_runs)
    strong_bad = sum(r.delivered < 0.5 for r in strong_runs)
    strong_median = statistics.median(r.delivered for r in strong_runs)
    return Showcase(
        slug="jammer-map",
        title="Where a jammer hurts",
        category="resilience",
        scenario="sim/scenarios/jammer_map.py",
        question="If someone brings a jammer, where can they stand to hurt us, and how badly?",
        headlines=[
            Headline(
                f"{weak_bad} of {len(weak_runs)}",
                f"positions where a {weak:.0f} dBm jammer halves traffic",
                f"it has to stand within ~{denial_radius_m(weak_runs):.0f} m of HQ; elsewhere the mesh routes around it",
            ),
            Headline(
                f"{strong_bad} of {len(strong_runs)}",
                f"positions where a {strong:.0f} dBm jammer halves traffic",
                f"median delivery across all positions {strong_median:.0%}",
            ),
            Headline(
                f"{denial_radius_m(strong_runs):.0f} m",
                f"from HQ before a {strong:.0f} dBm jammer stops mattering",
                f"{denial_radius_m(weak_runs):.0f} m for a {weak:.0f} dBm one",
            ),
        ],
        summary=(
            f"Every radio in the field streams readings to HQ while a noise jammer switches on, then "
            f"the jammer is moved and the run repeated, once per cell of a "
            f"{len(grid_axes(step_m)[0])}×{len(grid_axes(step_m)[1])} grid. Jamming happens at the "
            f"receiver: a frame dies when the jammer's power where it lands drowns the signal. A weak "
            f"{weak:.0f} dBm jammer deafens only the radio it stands beside, and the mesh routes around "
            f"it. It does real damage from {weak_bad} of {len(weak_runs)} positions, all on top of HQ, "
            f"the one receiver every packet has to reach. At {strong:.0f} dBm the picture changes. A "
            f"receiver can no longer hear its 450 m neighbour from several hundred metres away, so one "
            f"jammer deafens several radios at once, and there's no clean path left to route around "
            f"them. Traffic halves from {strong_bad} of {len(strong_runs)} positions, and the median "
            f"position leaves {strong_median:.0%} getting through. Path diversity defends against a "
            f"weak jammer. Against a strong one, the defences are shorter hops, which make every "
            f"signal stronger than the noise, and more than one gateway."
        ),
        method=(
            "The real wayfinder router on the failover scenario's grid (2.4 GHz, 24 dBm, 700 m range, "
            f"one shared channel). Every non-HQ node streams to HQ at {RATE_HZ:g} packets/s. The jammer is a "
            f"wideband noise source radiating {weak:.0f} or {strong:.0f} dBm with free-space loss, on "
            f"for {JAM_FOR_S:.0f} s. A reception survives only if its signal exceeds the jammer's "
            f"power at the receiver by a 6 dB capture margin. Each cell is a separate run, every "
            f"{step_m:.0f} m."
        ),
        charts=[
            Chart(
                title=f"Traffic reaching HQ, by jammer position ({strong:.0f} dBm)",
                x_label="east (m)",
                y_label="north (m)",
                series=node_series,
                heatmap=heatmap_for(strong_runs, step_m),
                caption="Each cell is one run with the jammer standing there. Dots are the radios; HQ is the corner at the origin.",
            ),
            Chart(
                title=f"The same map for a weak jammer ({weak:.0f} dBm)",
                x_label="east (m)",
                y_label="north (m)",
                series=node_series,
                heatmap=heatmap_for(weak_runs, step_m),
            ),
            Chart(
                title="Damage vs. distance from HQ",
                x_label="jammer distance from HQ (m)",
                y_label="share of traffic reaching HQ",
                series=[
                    Series(f"{strong:.0f} dBm", *by_distance(strong_runs)),
                    Series(f"{weak:.0f} dBm", *by_distance(weak_runs)),
                ],
                y_range=(0.0, 1.0),
                caption="Median over every position at that distance.",
            ),
        ],
        params={
            "radios": len(sites),
            "stream_rate_hz": RATE_HZ,
            "jammer_powers_dbm": list(POWERS_DBM),
            "grid_step_m": step_m,
            "jam_seconds": JAM_FOR_S,
            "baseline_delivery": round(baseline.delivered, 4),
        },
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument(
        "--export", type=Path, help="write showcase JSON into this directory"
    )
    parser.add_argument("--quick", action="store_true", help="coarse 300 m grid")
    args = parser.parse_args(argv)
    wf.init_tracing()

    step = 300.0 if args.quick else STEP_M
    baseline = run_position(None, None, 0.0)
    maps = {p: run_map(p, step) for p in POWERS_DBM}
    print_summary(baseline, maps)
    if args.export:
        print(f"wrote {write_showcase(showcase(baseline, maps, step), args.export)}")


if __name__ == "__main__":
    main()
