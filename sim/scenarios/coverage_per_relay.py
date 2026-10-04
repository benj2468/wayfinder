"""Coverage per relay: how much of a mission each additional relay buys, and
where the curve flattens.

`mountain_relay.py` compares a handful of hand-named placement strategies.
This asks the budgeting question instead: *given N relays, how much of the
flight is covered, and what does the N+1th add?* The terrain, flight and
radios are `mountain_relay.py`'s, so the two answer to the same world.

**Two numbers per N.** Every relay has its own backhaul, so the drone counts
as connected whenever it can reach any relay. That makes coverage estimable
from geometry alone — the radio's mean RSSI after terrain loss, along the
track — and cheap enough to *optimise*: relays are placed greedily, each one
at whichever candidate site (summits and valley floor alike) adds the most
predicted coverage given the ones already placed.

Then every layout is flown through the real router, with the drone sending
probe packets to every relay, and a second of flight counts as covered only if
a probe got through. That figure tracks the geometric plan closely — which is
the useful result, since it means the cheap planner can be trusted to choose
sites. What does *not* track it is the routing table: "has a route" stays
true through a short shadow, because a route outlives several missed adverts
while carrying nothing, so route-based coverage overstates what traffic gets.
All three figures are reported.

**Reading the curve.** The marginal gain falls off quickly — the first relay
covers the open stretches any site can see, and each one after it is bought
for an ever-smaller remaining shadow. The page reports the knee: the smallest
N past which another relay adds less than `KNEE_GAIN` of the flight.

Run: `uv run --group sim python sim/scenarios/coverage_per_relay.py [--export DIR]`
"""

from __future__ import annotations

import argparse
import dataclasses
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim.channel import FreeSpacePathLoss, TerrainMasked
from wayfinder_sim.connectivity import connectivity_stats
from wayfinder_sim.mobility import Static, Vec3, Waypoints
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.showcase import Chart, Headline, Series, Showcase, write_showcase
from wayfinder_sim.terrain import Terrain, TerrainFollowing, peak_sites, valley_sites
from wayfinder_sim.topology import shared_lan

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mountain_relay as world  # noqa: E402  — the same range, flight and radios

MAX_RELAYS = 6
PROBE_RATE_HZ = 2.0
"""Rate of the drone's probe stream to each relay. Coverage is scored on
these packets arriving, per one-second bin."""
CANDIDATES_PER_KIND = 12
CANDIDATE_SEPARATION_M = 800.0
PLAN_SAMPLES = 400
"""Points along the track the geometric planner scores coverage at."""

KNEE_GAIN = 0.03
"""A relay adding less than this share of the flight is past the knee."""

SEEDS = (0, 1, 2)


def radio(terrain: Terrain) -> TerrainMasked:
    """`mountain_relay.py`'s radio, terrain-masked."""
    return TerrainMasked(
        FreeSpacePathLoss(
            freq_hz=world.FREQ_HZ,
            tx_power_dbm=world.TX_POWER_DBM,
            max_range_m=world.MAX_RANGE_M,
        ),
        terrain,
    )


def candidate_sites(terrain: Terrain) -> list[Vec3]:
    """Where a relay may go: summits anywhere, and valley floor along the
    route — each with its mast added."""
    sites = [
        *peak_sites(
            terrain,
            world.WORLD,
            CANDIDATES_PER_KIND,
            spacing_m=200.0,
            min_separation_m=CANDIDATE_SEPARATION_M,
        ),
        *valley_sites(
            terrain,
            world.CORRIDOR,
            CANDIDATES_PER_KIND,
            spacing_m=200.0,
            min_separation_m=CANDIDATE_SEPARATION_M,
        ),
    ]
    return [dataclasses.replace(s, z=s.z + world.MAST_HEIGHT_M) for s in sites]


def flight(terrain: Terrain) -> TerrainFollowing:
    return TerrainFollowing(
        Waypoints(world.FLIGHT_TRACK, speed_m_s=world.SPEED_M_S, loop="once"),
        terrain,
        agl_m=world.AGL_M,
    )


def coverage_matrix(terrain: Terrain, sites: Sequence[Vec3]) -> list[list[bool]]:
    """`[site][sample]`: whether the drone at that track sample has a usable
    mean link to that site — delivery probability at least one half after
    path loss, terrain loss and the hard range cutoff, with no fading."""
    model = radio(terrain)
    base = model.base
    track = flight(terrain)
    duration = world.flight_duration_s()
    points = [track.position(duration * i / (PLAN_SAMPLES - 1)) for i in range(PLAN_SAMPLES)]
    matrix = []
    for site in sites:
        row = []
        for p in points:
            d = p.distance_to(site)
            if base.max_range_m is not None and d > base.max_range_m:
                row.append(False)
                continue
            rssi = base.tx_power_dbm + base.rx_gain_dbi - base.path_loss_db(d) - model.excess_loss_db(p, site)
            row.append(base.delivery_probability(rssi) >= 0.5)
        matrix.append(row)
    return matrix


def greedy_layouts(terrain: Terrain, max_relays: int = MAX_RELAYS) -> list[tuple[list[Vec3], float]]:
    """For N = 1..max_relays, the greedy layout and its planned coverage
    share. Greedy is within (1 - 1/e) of optimal for a coverage objective,
    and — unlike re-optimising from scratch for each N — it describes a
    deployment that grows by adding relays, never moving one."""
    sites = candidate_sites(terrain)
    matrix = coverage_matrix(terrain, sites)
    covered = [False] * PLAN_SAMPLES
    chosen: list[int] = []
    layouts = []
    for _ in range(max_relays):
        best, best_gain = None, -1
        for i, row in enumerate(matrix):
            if i in chosen:
                continue
            gain = sum(1 for c, r in zip(covered, row) if r and not c)
            if gain > best_gain:
                best, best_gain = i, gain
        if best is None:
            break
        chosen.append(best)
        covered = [c or r for c, r in zip(covered, matrix[best])]
        layouts.append(([sites[i] for i in chosen], sum(covered) / PLAN_SAMPLES))
    return layouts


def build_simulation(terrain: Terrain, sites: Sequence[Vec3], seed: int = 0) -> Simulation:
    """The drone and `sites`' relays on one terrain-masked channel."""
    names = [f"r{i + 1}" for i in range(len(sites))]
    nodes = [
        Node("drone", mobility=flight(terrain), trickle=world.TRICKLE_MS, tx_keepalive_interval_ms=world.KEEPALIVE_MS),
        *(
            Node(n, mobility=Static(site), trickle=world.TRICKLE_MS, tx_keepalive_interval_ms=world.KEEPALIVE_MS)
            for n, site in zip(names, sites)
        ),
    ]
    sim = Simulation(nodes, shared_lan([n.name for n in nodes], radio(terrain)), seed=seed)
    sim.record("reachable", lambda s: s.reachable("drone", names))
    return sim


def delivered_coverage(flows, duration_s: float, bin_s: float = 1.0) -> float:
    """Share of `bin_s` bins in which at least one probe packet sent in that
    bin reached some relay — coverage as traffic experiences it."""
    bins = int(duration_s // bin_s)
    if bins == 0:
        return 0.0
    hit = [False] * bins
    for flow in flows:
        for seq, t in flow.sent:
            i = int(t // bin_s)
            if i < bins and seq in flow.received:
                hit[i] = True
    return sum(hit) / bins


@dataclass(frozen=True)
class LayoutResult:
    """One N: where the relays went, and both coverage figures."""

    relays: int
    sites: list[Vec3]
    planned: float
    measured: list[float]
    """Share of one-second bins in which a probe packet got through, per seed."""
    routed: list[float]
    """Share of the flight the drone's routing table held a route to some
    relay, per seed — the optimistic figure: a route outlives a brief shadow
    by several missed adverts, carrying nothing meanwhile."""
    longest_outage_s: list[float]

    @property
    def measured_mean(self) -> float:
        return sum(self.measured) / len(self.measured)

    @property
    def routed_mean(self) -> float:
        return sum(self.routed) / len(self.routed)


def run_layouts(seeds: Sequence[int] = SEEDS, max_relays: int = MAX_RELAYS) -> list[LayoutResult]:
    terrain = world.build_terrain()
    duration = world.flight_duration_s()
    results = []
    for sites, planned in greedy_layouts(terrain, max_relays):
        measured, routed, longest = [], [], []
        for seed in seeds:
            sim = build_simulation(terrain, sites, seed)
            flows = [
                sim.stream("drone", f"r{i + 1}", rate_hz=PROBE_RATE_HZ, start_s=0.0, duration_s=duration)
                for i in range(len(sites))
            ]
            rec = sim.run(until_s=duration, sample_interval_ms=world.SAMPLE_INTERVAL_MS)
            stats = connectivity_stats(rec, "reachable")
            measured.append(delivered_coverage(flows, duration))
            routed.append(stats.connected_fraction)
            longest.append(_longest_dark_s(flows, duration))
        results.append(LayoutResult(len(sites), sites, planned, measured, routed, longest))
    return results


def _longest_dark_s(flows, duration_s: float, bin_s: float = 1.0) -> float:
    """Longest run of one-second bins in which no probe got through."""
    bins = int(duration_s // bin_s)
    hit = [False] * bins
    for flow in flows:
        for seq, t in flow.sent:
            i = int(t // bin_s)
            if i < bins and seq in flow.received:
                hit[i] = True
    longest = run = 0
    for h in hit:
        run = 0 if h else run + 1
        longest = max(longest, run)
    return longest * bin_s


def knee(results: Sequence[LayoutResult]) -> LayoutResult:
    """The smallest layout past which one more relay adds under `KNEE_GAIN`."""
    for here, after in zip(results, results[1:]):
        if after.measured_mean - here.measured_mean < KNEE_GAIN:
            return here
    return results[-1]


def print_summary(results: Sequence[LayoutResult]) -> None:
    print("Coverage per relay — greedy placement, planned vs. flown")
    print("  relays  planned  delivered  routed  longest gap  marginal")
    prev = 0.0
    for r in results:
        print(
            f"  {r.relays:>6}  {r.planned:>7.1%}  {r.measured_mean:>9.1%}  {r.routed_mean:>6.1%}  "
            f"{max(r.longest_outage_s):>9.0f} s  {r.measured_mean - prev:>+8.1%}"
        )
        prev = r.measured_mean
    k = knee(results)
    print(f"  knee: {k.relays} relays ({k.measured_mean:.1%}); the next adds < {KNEE_GAIN:.0%}")


def showcase(results: Sequence[LayoutResult]) -> Showcase:
    """The results-page entry for this scenario."""
    k = knee(results)
    ns = [r.relays for r in results]
    marginal = [results[0].measured_mean] + [
        b.measured_mean - a.measured_mean for a, b in zip(results, results[1:])
    ]
    terrain = world.build_terrain()
    track = flight(terrain)
    duration = world.flight_duration_s()
    track_pts = [track.position(duration * i / 199) for i in range(200)]
    final = results[-1].sites
    return Showcase(
        slug="coverage-per-relay",
        title="Coverage per relay",
        category="planning",
        scenario="sim/scenarios/coverage_per_relay.py",
        question="How many relays does this mission need, and what does each extra one buy?",
        headlines=[
            Headline(
                f"{k.relays} relays",
                f"cover {k.measured_mean:.0%} of the flight",
                f"the next adds under {KNEE_GAIN:.0%}",
            ),
            Headline(
                f"{results[0].measured_mean:.0%}",
                "with a single well-sited relay",
                "the open stretches any site can see",
            ),
            Headline(
                f"{max(abs(r.planned - r.measured_mean) for r in results) * 100:.1f} pts",
                "worst gap between plan and flight",
                "so the geometric planner can be trusted to pick sites",
            ),
        ],
        summary=(
            f"A drone crosses 8 km of mountains at {world.AGL_M:.0f} m above the ground, and every "
            f"relay has its own backhaul, so the drone is connected whenever it can reach any relay. "
            f"Relays are added one at a time, each placed where it covers the most of what the others "
            f"miss. The first relay alone covers {results[0].measured_mean:.0%} of the flight. "
            f"Returns fall off quickly after that: {k.relays} relays reach {k.measured_mean:.0%}, "
            f"and each one beyond that adds less than {KNEE_GAIN:.0%}. Every layout is also flown "
            f"through the real router, counting a second as covered only when a probe packet "
            f"got through. Delivered coverage lands within "
            f"{max(abs(r.planned - r.measured_mean) for r in results) * 100:.1f} points of the "
            f"geometric plan. The routing table is more optimistic: a route outlives a short "
            f"shadow by several missed adverts, so route-based coverage reads up to "
            f"{max(r.routed_mean - r.measured_mean for r in results) * 100:.1f} points higher "
            f"than what traffic actually got."
        ),
        method=(
            "Terrain is a sum of Gaussian peaks (8 x 6 km); radio links are 900 MHz free-space loss "
            "plus single knife-edge diffraction over the worst ridge (ITU-R P.526), 30 dBm with a "
            "6 km cutoff. Candidate sites are the 12 highest summits and 12 lowest corridor points. "
            "The planner scores mean-RSSI coverage at 400 points along the track and adds relays "
            "greedily. Each layout is then flown by the real wayfinder router with keep-alives at "
            f"500 ms over {len(SEEDS)} seeds; the drone sends {PROBE_RATE_HZ:g} probe packets/s to each "
            "relay, and a one-second bin is covered when any of them arrives."
        ),
        charts=[
            Chart(
                title="Share of the flight covered",
                x_label="relays deployed",
                y_label="share of flight",
                series=[
                    Series("planned (geometry)", ns, [r.planned for r in results], kind="line"),
                    Series("delivered (real router)", ns, [r.measured_mean for r in results], kind="line"),
                    Series("route held", ns, [r.routed_mean for r in results], kind="line"),
                ],
                y_range=(0.0, 1.0),
            ),
            Chart(
                title="What each extra relay adds",
                x_label="relay number",
                y_label="added share of flight",
                series=[Series("marginal coverage", [str(n) for n in ns], marginal, kind="bar")],
                caption=f"Past the knee at {k.relays}, each relay buys less than {KNEE_GAIN:.0%} of the flight.",
            ),
            Chart(
                title="Longest blackout",
                x_label="relays deployed",
                y_label="seconds",
                series=[Series("worst outage over seeds", ns, [max(r.longest_outage_s) for r in results], kind="line")],
                caption="Coverage share hides how the gaps are spread; this is the single longest one.",
            ),
            Chart(
                title="Where the relays went (plan view)",
                x_label="east (m)",
                y_label="north (m)",
                series=[
                    Series("flight track", [p.x for p in track_pts], [p.y for p in track_pts], kind="line"),
                    Series(
                        "relay sites, in order added",
                        [s.x for s in final],
                        [s.y for s in final],
                        kind="scatter",
                    ),
                ],
            ),
        ],
        table=[["relays", "planned", "measured", "longest gap (s)"]]
        + [[r.relays, round(r.planned, 3), round(r.measured_mean, 3), round(max(r.longest_outage_s), 1)] for r in results],
        params={
            "max_relays": MAX_RELAYS,
            "freq_mhz": world.FREQ_HZ / 1e6,
            "tx_power_dbm": world.TX_POWER_DBM,
            "agl_m": world.AGL_M,
            "seeds": len(SEEDS),
        },
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--export", type=Path, help="write showcase JSON into this directory")
    parser.add_argument("--quick", action="store_true", help="one seed, up to four relays")
    args = parser.parse_args(argv)
    wf.init_tracing()

    results = run_layouts(SEEDS[:1], 4) if args.quick else run_layouts()
    print_summary(results)
    if args.export:
        print(f"wrote {write_showcase(showcase(results), args.export)}")


if __name__ == "__main__":
    main()
