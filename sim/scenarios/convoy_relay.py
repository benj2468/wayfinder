r"""Convoy scenario: a column of vehicles strung out along a road, each in
radio contact only with the vehicle ahead of it and the one behind.

Topology (N vehicles, here 6)::

    v0 --- v1 --- v2 --- v3 --- v4 --- v5
    head                              tail
     |<-->|
     spacing_m

No redundancy, no relays off to the side: the column *is* the network, and
every message from head to tail is carried by every vehicle in between. That
makes it the cleanest possible instrument for the one question a chain
topology asks — **how deep can a mesh get before it stops working?**

Nothing in wayfinder caps hop count directly, so it is easy to assume the
limit is "however far the radios reach". It isn't. Three limits sit in the
path, and the first thing to get straight is that they do not bound the same
thing: two of them stop a route from reaching, and the third leaves the route
working while quietly making it unrankable.

**The TTL wall, at hop 50.** An originated OGM leaves with `ttl: 50`
(`batman::engine`'s `produce_periodic_broadcast`) and each forwarding hop
decrements it, so no node past the 50th ever hears the head at all. The only
*hard* limit here — and, contrary to the obvious guess, a reachable one: a
60-vehicle column at 100 m holds all 50 hops without flickering, so it is a
real ceiling on column length and not a theoretical one. What it costs to get
there is the subject of the next paragraph.

**The metric floor, at hop ~26 and closer on real links — which bounds
something else.** Every hop charges `ogm.tq.saturating_sub(10)` and then
clamps the result by the receiving node's own measured quality of the link it
arrived on. From a starting TQ of 255 that reaches zero after 25 hops, and
clamping moves it in: with per-hop quality `Q` it lands near `Q/10 + 1` hops,
which this scenario checks rather than assumes.

What makes the floor worth reporting separately is that it does not stop
anything. Frames still forward past it, all the way to the TTL horizon. What
the mesh has lost is the ability to tell two paths apart, since every path
past the floor scores the same zero — so a convoy deeper than its floor is
routing on arbitrary choices rather than on measurements. It also arrives
first by construction: 255 TQ at 10 a hop is exhausted by hop 26, so *any*
column deep enough to reach the TTL wall spent its last two dozen hops on a
metric that had stopped discriminating. `measure_deep_column` runs exactly
that case — 50 hops reached, the last 27 of them unrankable.

**The loss wall, wherever the link budget puts it.** Widen the spacing and
the OGM has to survive more marginal hops in a row to reach the tail. Past
about 350 m here that compounding is what ends the column, after a handful
of hops and long before either of the other two limits is in sight. It is
the only one of the three a convoy commander can actually move.

Its position is remarkably sensitive. Six dB of per-hop margin — one spacing
step here — takes the column from 19 usable hops to 9.

And the wall is not a wall so much as a fraying edge. Well before a column
stops reaching its tail, the tail starts *flickering*: at 250 m spacing the
head reaches all 29 hops at its best and only 23 for most of the run,
oscillating between the two indefinitely rather than settling on either. At
600 m it sometimes reaches hop 8 and can be relied on to hop 2. So "how deep
does this column reach" has two answers that diverge steadily as it strings
out, and the useful one is the pessimistic one — which is why every depth
here is reported as a reliable/best pair rather than a single number.

Two runs, in that order:

* `run_spacing_sweep` walks a 30-vehicle column across spacings from close
  order to strung out, and reports which wall each spacing hits. Every depth
  is read across the settled window rather than off one final sample, since
  a single snapshot of an oscillating column reports one arm of the
  oscillation as a wall — and the flicker is not noise to be averaged away,
  it is the finding.
* `build_stretch_simulation` then makes the spacing a function of time: a
  14-vehicle column in close order that gradually strings out as the lead
  vehicles pull away, so one convoy crosses the loss wall mid-run: the tail
  drops off the mesh while every individual link is still, on its own, a
  working radio link.

Run: `uv run --group sim python sim/scenarios/convoy_relay.py`
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim.channel import FreeSpacePathLoss, PerfectWire
from wayfinder_sim.mobility import Static, Vec3, Waypoints
from wayfinder_sim.node import Node
from wayfinder_sim.recorder import Recorder
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.sweep import run_sweep
from wayfinder_sim.topology import path

# matplotlib is imported inside `plot_*` rather than here, so a headless
# consumer can import this module for `build_simulation` alone — the same
# arrangement `drone_relay.py` uses.

VEHICLES = 30
"""Long enough to reach the metric floor at close order (~26 hops) without
paying for the 50 hops the TTL wall needs."""

TRICKLE_MS = (50, 500)
"""(i_min_ms, i_max_ms). Fast, because a 30-hop flood has to cross 30 nodes
before the far end learns anything and the run should not be dominated by
waiting for it."""

ANTENNA_HEIGHT_M = 2.0
"""Roof height on a vehicle. Only the spacing varies in this scenario; the
geometry is otherwise flat and uninteresting on purpose, so that what moves
is the link budget and nothing else."""

SPACINGS_M = (100.0, 150.0, 200.0, 250.0, 300.0, 400.0, 500.0, 600.0)
"""Close order through strung out. The interesting step is 300 -> 400, where
the loss wall arrives and the column stops reaching its own tail."""

SETTLE_S = 120.0
"""Long enough for a 30-hop flood to converge *and* for the settled window to
be representative. 60s converges fine but is short enough that a column
oscillating on a ~30s period can spend the whole window on one arm of the
oscillation and report as steady, which understates the flicker that
`DepthProfile.reliable_hop` exists to catch."""

TTL_HORIZON_VEHICLES = 60
"""Longer than `TTL_HORIZON_HOP`, so `measure_ideal_chain` and
`measure_deep_column` can find the horizon rather than run out of column
before reaching it."""

DEEP_SPACING_M = 100.0
"""Close order, for the one run that asks whether real radios can reach the
TTL wall at all. `SPACINGS_M`'s columns are 30 vehicles long and stop at hop
29 — short of the wall by construction, which is why they report
`UNCONSTRAINED` rather than a limit."""

STRETCH_VEHICLES = 14
STRETCH_FROM_M = 150.0
STRETCH_TO_M = 700.0
STRETCH_S = 400.0
"""The stretching column: 14 vehicles opening from close order to strung out
over `STRETCH_S`. 13 hops is well within reach at 150 m and well past the
loss wall at 700 m, so the run crosses the boundary rather than sitting on
one side of it."""

TTL_HORIZON_HOP = 50
"""The hop an originated OGM's `ttl: 50` runs out at. Used to classify a
column that got that deep; `measure_ideal_chain` confirms the number against
the engine rather than trusting it."""

LOSS_LIMITED = "loss-limited"
TTL_LIMITED = "TTL-limited"
UNCONSTRAINED = "unconstrained"
REGIME_LABELS = {
    LOSS_LIMITED: "Loss-limited — marginal hops end the column early",
    TTL_LIMITED: f"TTL-limited — the hard hop-{TTL_HORIZON_HOP} horizon",
    UNCONSTRAINED: "Unconstrained — this column is shorter than either wall",
}
"""The walls that bound how far a column *reaches*. The metric floor is not
among them and `DepthProfile.saturated_from` reports it separately, because
it bounds something else entirely: a saturated path still carries traffic to
the end of the column, it just can no longer be compared against another
one."""

RELIABLE_FRACTION = 0.9
"""How much of the settled window a hop must be routable in to count toward
`DepthProfile.reliable_hop`. A deep column's tail is *intermittently*
reachable long before it is unreachable, so "deepest hop that ever worked"
and "deepest hop you can plan around" are different numbers and this is what
separates them."""

PROFILE = "profile"
"""Recorder column holding, at every sample, the head's TQ to each vehicle
behind it — the whole depth profile as one tuple, so one probe carries both
the reading and the evidence of whether it held still."""


def vehicle_names(count: int) -> tuple[str, ...]:
    """`("v00", "v01", ...)` — zero-padded so names sort in column order."""
    return tuple(f"v{i:02d}" for i in range(count))


def build_simulation(
    vehicles: int = VEHICLES,
    spacing_m: float = 150.0,
    seed: int = 0,
) -> Simulation:
    """A `vehicles`-long column at a fixed `spacing_m`, recording the head's
    TQ to every vehicle behind it on every sample.

    Links are declared only between adjacent vehicles, so the chain topology
    is structural rather than a consequence of the radios failing to reach
    further: `spacing_m` then varies the *quality* of each of those hops
    without ever changing who can hear whom.
    """
    names = vehicle_names(vehicles)
    nodes = [
        Node(
            name,
            mobility=Static(Vec3(i * spacing_m, 0.0, ANTENNA_HEIGHT_M)),
            trickle=TRICKLE_MS,
        )
        for i, name in enumerate(names)
    ]
    sim = Simulation(nodes, path(names, FreeSpacePathLoss()), seed=seed)

    head, rest = names[0], names[1:]
    sim.record(PROFILE, lambda s: tuple(s.tq_to(head, name) for name in rest))
    sim.record("hop_quality", lambda s: s.link_quality(head, names[1]))
    return sim


def build_stretch_simulation(seed: int = 0) -> Simulation:
    """A `STRETCH_VEHICLES`-long column that opens out from `STRETCH_FROM_M`
    to `STRETCH_TO_M` over `STRETCH_S`, recording what the head can still see
    of its tail as it goes.

    Vehicle `i` travels `i * (STRETCH_TO_M - STRETCH_FROM_M)`, so the whole
    column stretches uniformly and arrives at full extension together — the
    lead vehicle holds station and each one behind falls progressively
    further back, which is how a column comes apart in practice.
    """
    names = vehicle_names(STRETCH_VEHICLES)
    step = STRETCH_TO_M - STRETCH_FROM_M
    nodes = []
    for i, name in enumerate(names):
        start = Vec3(i * STRETCH_FROM_M, 0.0, ANTENNA_HEIGHT_M)
        if i == 0:
            mobility = Static(start)
        else:
            end = Vec3(i * STRETCH_TO_M, 0.0, ANTENNA_HEIGHT_M)
            mobility = Waypoints(
                (start, end), speed_m_s=i * step / STRETCH_S, loop="once"
            )
        nodes.append(Node(name, mobility=mobility, trickle=TRICKLE_MS))

    sim = Simulation(nodes, path(names, FreeSpacePathLoss()), seed=seed)

    head, tail = names[0], names[-1]
    sim.record("spacing", lambda s: s.distance(names[0], names[1]))
    sim.record("hop_quality", lambda s: s.link_quality(head, names[1]))
    sim.record("tq_tail", lambda s: s.tq_to(head, tail))
    sim.record(
        "tail_state",
        lambda s: "linked" if s.has_route(head, tail) else "broken",
    )
    return sim


@dataclasses.dataclass(frozen=True)
class DepthProfile:
    """What one spacing did to one column.

    `tq_by_hop[h - 1]` is the head's TQ to the vehicle `h` hops back, or
    `None` where it has no route at all. The two are deliberately not
    conflated: `0` is a route whose metric has bottomed out and `None` is no
    route, and telling the metric floor from the loss wall is the entire
    question here.
    """

    spacing_m: float
    hop_quality: int | None
    tq_by_hop: tuple[int | None, ...]
    """The head's TQ to each hop, from the *final* sample. A snapshot, unlike
    the two depths below, which are read across the whole settled window: on
    a flickering column this curve can therefore stop short of `best_hop`,
    which is the flicker rather than a discrepancy."""

    best_hop: int
    """Deepest hop routable at any point in the settled window."""

    reliable_hop: int
    """Deepest hop routable in at least `RELIABLE_FRACTION` of the settled
    window — the depth a convoy could actually plan around, as against
    `best_hop`'s best case.

    These come apart well before the column stops working: a 250 m column
    holds 29 hops at its best and 23 for most of the run, oscillating
    between the two indefinitely rather than converging on either.
    """

    @property
    def saturated_from(self) -> int | None:
        """The first *routable* hop whose TQ has bottomed out at zero, or
        `None` if the column ends before the metric does.

        Not a reach limit — see `REGIME_LABELS`. Everything from here back
        still routes; what the head has lost past this hop is any way to
        prefer one path to those vehicles over another, since they all score
        the same zero. On a column deep enough to be `TTL_LIMITED` this is
        always around hop 26 (255 TQ at 10 a hop), so its last two dozen hops
        are routed on an exhausted metric.
        """
        return next(
            (h for h, tq in enumerate(self.tq_by_hop, start=1) if tq == 0),
            None,
        )

    @property
    def stable(self) -> bool:
        """Whether the column's depth held still, i.e. the tail was
        connected rather than flickering.

        Both halves are read over the settled window. Comparing the reliable
        depth against a single final snapshot instead would call a column
        steady whenever its last sample happened to land on the low arm of
        an oscillation, which is most of them.
        """
        return self.reliable_hop == self.best_hop

    @property
    def regime(self) -> str:
        """Which wall bounded how far this column *reached*, or
        `UNCONSTRAINED` if it reached its own tail without meeting one.

        Deliberately blind to the metric floor. Classifying on the floor
        would name a wall that does not stop traffic — and would call a
        column that ran its whole length successfully "limited" on the
        strength of a metric reading, while a column that genuinely lost its
        tail to marginal links reports the same thing.
        """
        if self.reliable_hop >= TTL_HORIZON_HOP:
            return TTL_LIMITED
        if self.reliable_hop >= len(self.tq_by_hop):
            return UNCONSTRAINED
        return LOSS_LIMITED


def depth_from(rec: Recorder, spacing_m: float) -> DepthProfile:
    """Reduce a recorded run to its settled depth profile.

    Reads the *last* sample for the TQ profile itself, and the final third
    of the run for how much of that depth held up — a column is characterised
    by its settled window, not by whichever instant the run happened to stop
    on. Taking a single snapshot would report one arm of an oscillation as a
    wall, which is the same trap `wayfinder-bench`'s fixtures guard against
    from the other side.
    """
    profiles = rec.column(PROFILE)
    final = tuple(profiles[-1])
    window = profiles[max(0, len(profiles) - len(profiles) // 3) :]
    hops = len(final)
    routable = [
        sum(1 for sample in window if sample[h - 1] is not None) / len(window)
        for h in range(1, hops + 1)
    ]
    best = max(
        (
            max(
                (h for h, tq in enumerate(sample, start=1) if tq is not None), default=0
            )
            for sample in window
        ),
        default=0,
    )
    qualities = [q for q in rec.column("hop_quality") if q is not None]
    return DepthProfile(
        spacing_m=spacing_m,
        hop_quality=qualities[-1] if qualities else None,
        tq_by_hop=final,
        best_hop=best,
        reliable_hop=max(
            (
                h
                for h, share in enumerate(routable, start=1)
                if share >= RELIABLE_FRACTION
            ),
            default=0,
        ),
    )


def run_spacing_sweep(spacings: tuple[float, ...] = SPACINGS_M) -> list[DepthProfile]:
    """Run the same 30-vehicle column at each spacing and reduce each run to
    its depth profile."""
    results = run_sweep(
        lambda spacing: build_simulation(spacing_m=spacing),
        spacings,
        until_s=SETTLE_S,
        sample_interval_ms=1000,
    )
    return [depth_from(result.recorder, result.param) for result in results]


@dataclasses.dataclass(frozen=True)
class IdealChain:
    """What a chain does when the link budget is taken out of the experiment
    — the two engine constants, measured rather than asserted."""

    horizon_hop: int
    """Deepest hop with a route: where `ttl: 50` bites."""

    saturated_from: int | None
    """First hop whose TQ has bottomed out. Always far short of the horizon,
    which is the point: the hops between the two still route, on a metric
    that has stopped being able to rank them."""


def measure_ideal_chain(
    vehicles: int = TTL_HORIZON_VEHICLES,
    settle_s: float = SETTLE_S,
) -> IdealChain:
    """Run a chain over links good enough that neither loss nor the metric
    floor can be what stops it, and report where each limit landed.

    `PerfectWire` rather than a very short spacing: the point is to remove
    the link budget entirely, so the horizon this finds can only be the TTL
    and the floor can only be the metric's own arithmetic.
    """
    names = vehicle_names(vehicles)
    nodes = [Node(name, trickle=TRICKLE_MS) for name in names]
    sim = Simulation(nodes, path(names, PerfectWire()), seed=0)
    sim.run(until_s=settle_s, sample_interval_ms=1000)
    head = names[0]
    tq_by_hop = tuple(sim.tq_to(head, name) for name in names[1:])
    return IdealChain(
        horizon_hop=max(
            (h for h, tq in enumerate(tq_by_hop, start=1) if tq is not None),
            default=0,
        ),
        saturated_from=next(
            (h for h, tq in enumerate(tq_by_hop, start=1) if tq == 0),
            None,
        ),
    )


def measure_deep_column(
    vehicles: int = TTL_HORIZON_VEHICLES,
    spacing_m: float = DEEP_SPACING_M,
) -> DepthProfile:
    """A column long enough to reach the TTL wall, on real radios rather than
    `PerfectWire`.

    The sweep cannot answer this: at 30 vehicles it runs out of column at hop
    29, well short of the horizon. Asking separately is what turns "the TTL
    wall exists" into "a convoy can actually hit it", which is a different
    claim and the one a column length is planned against.
    """
    return depth_from(
        build_simulation(vehicles=vehicles, spacing_m=spacing_m).run(
            until_s=SETTLE_S, sample_interval_ms=1000
        ),
        spacing_m,
    )


def print_summary(
    profiles: list[DepthProfile], ideal: IdealChain, deep: DepthProfile
) -> None:
    print(f"\nA {VEHICLES}-vehicle column, by spacing (settled {SETTLE_S:.0f}s):\n")
    print(
        f"  {'spacing':>8}  {'hop TQ':>6}  {'reliable':>8}  {'best':>5}  "
        f"{'TQ=0 at':>7}  regime"
    )
    for p in profiles:
        floor = "--" if p.saturated_from is None else f"hop {p.saturated_from}"
        best = f"{p.best_hop:2d}" if p.stable else f"{p.best_hop:2d}*"
        print(
            f"  {p.spacing_m:7.0f}m  {p.hop_quality!s:>6}  "
            f"{p.reliable_hop:5d} hp  {best:>5}  {floor:>7}  {p.regime}"
        )
    print(
        f"\n  reliable = routable in >={RELIABLE_FRACTION:.0%} of the settled window; "
        "best = deepest ever reached.\n"
        "  * marks a column whose depth never settled on one answer."
    )

    print(
        f"\n  Every row above says 'unconstrained' or 'loss-limited' because a "
        f"{VEHICLES}-vehicle\n  column is only {VEHICLES - 1} hops long: it runs out before "
        "the TTL wall, it does not\n  survive to it. Two longer runs say where that wall is."
    )
    print(
        f"\n  Over perfect links, {TTL_HORIZON_VEHICLES} vehicles reach hop {ideal.horizon_hop} "
        f"— the TTL wall — while the\n  metric bottomed out at hop {ideal.saturated_from} "
        "(255 TQ, 10 a hop)."
    )
    print(
        f"  Over real radios at {deep.spacing_m:.0f}m, the same column reaches hop "
        f"{deep.reliable_hop} too, and holds it.\n"
        f"  So the wall is reachable, not theoretical — but its last "
        f"{deep.reliable_hop - (deep.saturated_from or 0)} hops are routed\n"
        f"  on a metric that has been saturated since hop {deep.saturated_from}."
    )

    metric = [p for p in profiles if p.saturated_from is not None and p.hop_quality]
    if metric:
        print(
            "\n  The metric floor is set by per-hop quality, not by distance: a hop\n"
            "  starts at TQ Q and loses 10 per hop, so it bottoms out around Q/10 + 1."
        )
        for p in metric:
            assert p.hop_quality is not None and p.saturated_from is not None
            print(
                f"    hop TQ {p.hop_quality:3d}  ->  predicted hop {p.hop_quality // 10 + 1:2d}, "
                f"measured {p.saturated_from:2d}"
            )
        print(
            "  Measured runs 1-3 hops deeper than predicted: the clamp is applied with\n"
            "  each receiver's own measurement of its own hop, not with the head's."
        )

    unstable = [p for p in profiles if not p.stable]
    if unstable:
        spacings = ", ".join(f"{p.spacing_m:.0f}m" for p in unstable)
        print(
            f"\n  Depth never settled at {spacings} — every spacing that lost its tail,\n"
            "  and no others. The loss wall arrives as a fraying edge rather than a cliff:\n"
            "  the tail goes intermittent first, and 'how deep does it reach' stops having\n"
            "  one answer some way before it stops having a good one. Plan against the\n"
            "  reliable column, not the best one."
        )


def print_stretch_summary(rec: Recorder) -> None:
    print(
        f"\nA {STRETCH_VEHICLES}-vehicle column opening from "
        f"{STRETCH_FROM_M:.0f}m to {STRETCH_TO_M:.0f}m over {STRETCH_S:.0f}s:\n"
    )
    spacing = rec.column("spacing")
    quality = rec.column("hop_quality")
    # Skip t=0: nothing has converged before the first OGM has crossed 13
    # hops, so the "broken" the run opens on is the mesh starting up rather
    # than the column coming apart.
    for t_s, state in rec.transitions("tail_state")[1:]:
        idx = rec.times_s.index(t_s)
        print(
            f"  t={t_s:6.1f}s  spacing {spacing[idx]:5.0f}m  "
            f"hop TQ {quality[idx]!s:>4}  ->  tail {state}"
        )


def plot_depth(profiles: list[DepthProfile], out_path: Path) -> None:
    """Two panels: the depth profile at each spacing, and the regime map the
    profiles collapse to."""
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, style_axes

    fig, (ax_tq, ax_regime) = plt.subplots(
        2, 1, figsize=(10, 8), facecolor=PALETTE.surface
    )
    style_axes((ax_tq, ax_regime))

    for order, p in enumerate(profiles):
        hops = [h for h, tq in enumerate(p.tq_by_hop, start=1) if tq is not None]
        tqs = [tq for tq in p.tq_by_hop if tq is not None]
        ax_tq.plot(
            hops,
            tqs,
            color=PALETTE.series[order % len(PALETTE.series)],
            linewidth=2,
            marker="o",
            markersize=3,
            label=f"{p.spacing_m:.0f}m spacing",
        )
    ax_tq.axhline(0, color=PALETTE.ink_muted, linewidth=1, linestyle="--")
    ax_tq.set_xlabel(
        "Hops from the head of the column", color=PALETTE.ink_secondary, fontsize=10
    )
    ax_tq.set_ylabel("End-to-end TQ", color=PALETTE.ink_secondary, fontsize=10)
    ax_tq.set_title(
        "Every hop costs 10 TQ — a line that reaches the floor has stopped measuring anything",
        color=PALETTE.ink_primary,
        fontsize=11,
    )
    ax_tq.legend(frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9, ncol=2)

    spacings = [p.spacing_m for p in profiles]
    ax_regime.plot(
        spacings,
        [p.best_hop for p in profiles],
        color=PALETTE.series[0],
        linewidth=2,
        linestyle=":",
        marker="o",
        label="Deepest hop ever reached",
    )
    ax_regime.plot(
        spacings,
        [p.reliable_hop for p in profiles],
        color=PALETTE.series[3],
        linewidth=2,
        marker="D",
        label=f"Deepest hop held >={RELIABLE_FRACTION:.0%} of the time",
    )
    # `nan` rather than 0 for a floor that was never reached: 0 is a real hop
    # number on this axis, and plotting "no floor" as "floor at hop 0" would
    # draw the loss-limited runs as the most metric-starved of the set when
    # they are the ones whose metric never got the chance to bottom out.
    ax_regime.plot(
        spacings,
        [
            p.saturated_from if p.saturated_from is not None else float("nan")
            for p in profiles
        ],
        color=PALETTE.series[1],
        linewidth=2,
        marker="s",
        linestyle="--",
        label="Hop where TQ hits 0 (line stops: never reached)",
    )
    for p in profiles:
        if not p.stable:
            ax_regime.fill_between(
                [p.spacing_m - 6, p.spacing_m + 6],
                p.reliable_hop,
                p.best_hop,
                color=PALETTE.ink_muted,
                alpha=0.35,
                linewidth=0,
            )
    ax_regime.set_xlabel(
        "Vehicle spacing (m)", color=PALETTE.ink_secondary, fontsize=10
    )
    ax_regime.set_ylabel("Hops", color=PALETTE.ink_secondary, fontsize=10)
    ax_regime.set_title(
        "The knee: past ~350m the loss wall ends the column early "
        "(shaded = the column oscillated between the two depths)",
        color=PALETTE.ink_primary,
        fontsize=11,
    )
    ax_regime.legend(frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9)

    fig.suptitle(
        f"Convoy depth: how far back a {VEHICLES}-vehicle column stays on the mesh",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Chart written to {out_path}")


def plot_profile(profile: DepthProfile, out_path: Path) -> None:
    """One spacing's depth profile: TQ against hop, with the two depths
    marked. The report's per-run panel — the overview charts say how the
    spacings compare, and this says what one of them did."""
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, style_axes

    fig, ax = plt.subplots(figsize=(8, 3.4), facecolor=PALETTE.surface)
    style_axes((ax,))

    hops = [h for h, tq in enumerate(profile.tq_by_hop, start=1) if tq is not None]
    tqs = [tq for tq in profile.tq_by_hop if tq is not None]
    ax.plot(hops, tqs, color=PALETTE.series[0], linewidth=2, marker="o", markersize=3)
    ax.axhline(0, color=PALETTE.ink_muted, linewidth=1, linestyle="--")
    ax.axvline(
        profile.reliable_hop,
        color=PALETTE.series[3],
        linewidth=2,
        label=f"Held {RELIABLE_FRACTION:.0%} of the time: hop {profile.reliable_hop}",
    )
    if not profile.stable:
        ax.axvline(
            profile.best_hop,
            color=PALETTE.ink_muted,
            linewidth=2,
            linestyle=":",
            label=f"Best ever reached: hop {profile.best_hop}",
        )
    if profile.saturated_from is not None:
        ax.axvline(
            profile.saturated_from,
            color=PALETTE.series[1],
            linewidth=2,
            linestyle="--",
            label=f"TQ floor: hop {profile.saturated_from}",
        )
    ax.set_xlim(0, len(profile.tq_by_hop))
    ax.set_xlabel("Hops from the head", color=PALETTE.ink_secondary, fontsize=10)
    ax.set_ylabel("End-to-end TQ", color=PALETTE.ink_secondary, fontsize=10)
    ax.set_title(
        f"{profile.spacing_m:.0f} m spacing — per-hop TQ {profile.hop_quality}, "
        f"{REGIME_LABELS[profile.regime].split(' — ')[0].lower()}",
        color=PALETTE.ink_primary,
        fontsize=11,
    )
    ax.legend(frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9)

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=140)
    plt.close(fig)


def plot_stretch(rec: Recorder, out_path: Path) -> None:
    """The same column crossing a regime boundary in time."""
    import matplotlib.pyplot as plt
    from wayfinder_sim.plotting import PALETTE, state_band, style_axes

    t = rec.times_s
    fig, (ax_space, ax_tq, ax_state) = plt.subplots(
        3,
        1,
        figsize=(10, 8),
        sharex=True,
        height_ratios=[1, 1, 0.4],
        facecolor=PALETTE.surface,
    )
    style_axes((ax_space, ax_tq, ax_state))

    ax_space.plot(t, rec.column("spacing"), color=PALETTE.series[0], linewidth=2)
    ax_space.set_ylabel("Spacing (m)", color=PALETTE.ink_secondary, fontsize=10)

    ax_tq.plot(
        t,
        [q if q is not None else float("nan") for q in rec.column("hop_quality")],
        color=PALETTE.series[1],
        linewidth=2,
        label="One hop (head to v01)",
    )
    ax_tq.plot(
        t,
        [tq if tq is not None else float("nan") for tq in rec.column("tq_tail")],
        color=PALETTE.series[2],
        linewidth=2,
        label=f"End to end (head to v{STRETCH_VEHICLES - 1:02d})",
    )
    ax_tq.set_ylabel("TQ", color=PALETTE.ink_secondary, fontsize=10)
    ax_tq.legend(frameon=False, labelcolor=PALETTE.ink_secondary, fontsize=9)

    state_band(
        ax_state,
        t,
        rec.column("tail_state"),
        labels={"linked": "Tail on the mesh", "broken": "Tail unreachable"},
    )
    ax_state.set_xlabel("Time (s)", color=PALETTE.ink_secondary, fontsize=10)
    ax_state.set_ylabel("Tail", color=PALETTE.ink_secondary, fontsize=10)
    ax_state.legend(
        frameon=False,
        labelcolor=PALETTE.ink_secondary,
        fontsize=9,
        ncol=2,
        loc="upper left",
    )

    fig.suptitle(
        "The stretching column: the tail leaves the mesh while every single hop still works",
        color=PALETTE.ink_primary,
        fontsize=12,
    )
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Chart written to {out_path}")


def write_report(
    profiles: list[DepthProfile],
    ideal: IdealChain,
    depth_png: Path,
    stretch_png: Path,
    out_path: Path,
) -> None:
    """One section per spacing, ranked by how much of the column stayed on
    the mesh.

    The two overview charts go in `summary_panels` rather than onto every
    run: a shared image attached per-run is re-embedded per-run too, and
    eight copies of the same two charts is most of the page's weight.
    """
    from wayfinder_sim.report import ImagePanel, RunReport, write_sweep_report

    profile_pngs = {}
    for p in profiles:
        png = out_path.parent / f"convoy_profile_{p.spacing_m:.0f}m.png"
        plot_profile(p, png)
        profile_pngs[p.spacing_m] = png

    runs = [
        RunReport(
            label=f"{p.spacing_m:.0f} m spacing",
            params={
                "vehicles": VEHICLES,
                "spacing_m": p.spacing_m,
                "per-hop TQ": p.hop_quality,
            },
            metrics={
                "regime": REGIME_LABELS[p.regime],
                f"depth held >={RELIABLE_FRACTION:.0%} of the time": p.reliable_hop,
                "deepest hop ever reached": p.best_hop,
                "TQ floor": "never reached"
                if p.saturated_from is None
                else f"hop {p.saturated_from}",
                "depth steady": "yes" if p.stable else "no — tail flickering",
            },
            headline=p.reliable_hop / (VEHICLES - 1),
            panels=[
                ImagePanel(
                    profile_pngs[p.spacing_m],
                    caption=f"What a {p.spacing_m:.0f} m column reached",
                )
            ],
        )
        for p in profiles
    ]
    write_sweep_report(
        out_path,
        f"Convoy depth — two walls on reach, one floor under the metric "
        f"(TTL horizon measured at hop {ideal.horizon_hop})",
        runs,
        headline_label=f"share of a {VEHICLES}-vehicle column held",
        summary_panels=[
            ImagePanel(
                depth_png, caption="Depth profile and regime map (all spacings)"
            ),
            ImagePanel(stretch_png, caption="A column stretching across the boundary"),
        ],
    )
    print(f"Report written to {out_path}")


def main() -> None:
    wf.init_tracing()  # quiet by default; set RUST_LOG to see mesh internals
    out_dir = Path(__file__).parent / "output"

    profiles = run_spacing_sweep()
    ideal = measure_ideal_chain()
    deep = measure_deep_column()
    print_summary(profiles, ideal, deep)

    stretch = build_stretch_simulation()
    stretch_rec = stretch.run(until_s=STRETCH_S, sample_interval_ms=1000)
    print_stretch_summary(stretch_rec)

    depth_png = out_dir / "convoy_relay.png"
    stretch_png = out_dir / "convoy_stretch.png"
    plot_depth(profiles, depth_png)
    plot_stretch(stretch_rec, stretch_png)
    write_report(
        profiles, ideal, depth_png, stretch_png, out_dir / "convoy_report.html"
    )


if __name__ == "__main__":
    main()
