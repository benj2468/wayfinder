"""Crowded LoRa channel: how many sensors fit on one channel before the mesh's
own routing chatter crowds out their data?

Topology — a gateway and N sensors scattered over a 1.5 km disc, all on one
868 MHz LoRa channel (SF7, 125 kHz), every node in range of most others::

          s3      s7
      s1      gw      s5
          s2   s6   s4

Each sensor reports a short reading to the gateway every couple of minutes.
That is a trivial data load — a few bytes per node per minute — and on its own
one LoRa channel would carry hundreds of such sensors. What it actually
carries is decided by two things the data never sees:

**The N² flood.** wayfinder floods every routing advert (OGM) out of every
interface, so on one shared segment each node re-broadcasts every other
node's advert once per Trickle round: N² frames per round where a classic
broadcast would cost N. That is the price of having no split-horizon (see
`CLAUDE.md`), and on a fast medium it is invisible.

**Two ceilings, and the lower one is not the obvious one.** Trickle fires
each round uniformly within `[I/2, I)`, so a round averages `0.75·I`, and the
channel carries `N²·T / 0.75·I` of advert airtime (`T` one advert's airtime).

- *Duty cycle.* EU 868 MHz rules allow each radio 1% of airtime, and each
  node relays N adverts per round: `N·T / 0.75·I ≤ 0.01`. Past that, adverts
  queue behind the off-time, queues overflow, routes age out.
- *Collisions.* LoRa radios do not listen before talking (pure ALOHA), so
  every reading risks landing on an advert. At channel load `G` a frame
  survives with probability `e^(-2G)`; keeping losses to 5% needs `G` under
  ~2.5%, so `N ≤ √(0.025 · 0.75·I / T)`.

The second binds first, and it scales with the *square root* of the advert
interval: slowing adverts tenfold buys ~3x the sensors, not 10x — the N²
flood (no split-horizon, see `CLAUDE.md`) is what turns a linear budget into
a square-root one.

The scenario sweeps N against several advert schedules and reports, for
each, delivered readings, how the airtime splits between routing and data,
and the largest N still delivering `TARGET_DELIVERY` — plotted against both
closed-form ceilings, so the simulation checks the arithmetic and the
arithmetic checks the simulation.

Run: `uv run --group sim python sim/scenarios/crowded_lora.py [--export DIR]`
"""

from __future__ import annotations

import argparse
import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim import forge
from wayfinder_sim.channel import FreeSpacePathLoss
from wayfinder_sim.medium import LoRaPhy, Medium
from wayfinder_sim.mobility import Static, Vec3
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.showcase import Chart, Headline, Series, Showcase, write_showcase
from wayfinder_sim.topology import shared_lan

GATEWAY = "gw"
RADIUS_M = 1500.0
FREQ_HZ = 868e6
TX_POWER_DBM = 14.0
PHY = LoRaPhy(sf=7, bw_hz=125e3)
DUTY_CYCLE = 0.01
REPORT_S = 120.0
READING = b"t=21.4,h=40"  # the payload size that matters, not the content

SENSOR_COUNTS = (2, 4, 6, 8, 10, 14, 20, 30)
ADVERT_I_MAX_S = (60, 300, 900, 1800)
MEASURE_S = 3600.0
TARGET_DELIVERY = 0.95
SEED = 0


def lora_radio() -> FreeSpacePathLoss:
    """868 MHz free-space loss with a LoRa receiver's scale: SF7 at 125 kHz
    hears down to about -123 dBm, and its packet-error curve is a couple of
    dB wide."""
    return FreeSpacePathLoss(
        freq_hz=FREQ_HZ,
        tx_power_dbm=TX_POWER_DBM,
        rssi_floor_dbm=-123.0,
        rssi_ceiling_dbm=-83.0,
        delivery_steepness=1.0,
    )


def medium(duty_cycle: float = DUTY_CYCLE) -> Medium:
    return Medium(phy=PHY, duty_cycle=duty_cycle, capture_db=6.0, queue_limit=32)


def sensor_sites(n: int, seed: int = SEED) -> list[Vec3]:
    """`n` points uniform over the disc, reproducibly."""
    rng = random.Random(seed)
    sites = []
    for _ in range(n):
        r = RADIUS_M * math.sqrt(rng.random())
        a = rng.random() * 2 * math.pi
        sites.append(Vec3(r * math.cos(a), r * math.sin(a), 2.0))
    return sites


def trickle_for(i_max_s: float) -> tuple[int, int]:
    """An advert schedule settling at `i_max_s`, starting eight times faster."""
    i_max = int(i_max_s * 1000)
    return (i_max // 8, i_max)


@dataclass(frozen=True)
class ChannelRun:
    """One (sensor count, advert schedule) point."""

    sensors: int
    i_max_s: float
    delivery: float
    utilisation: float
    """Share of wall time the channel carried a transmission (summed over
    radios; overlapping transmissions count twice, as they cost twice)."""
    routing_airtime_s: float
    data_airtime_s: float
    other_airtime_s: float
    busiest_duty: float
    """The highest per-radio transmit share over the window — against the
    1% the rules allow."""
    queue_drops: int
    collisions: int
    measure_s: float

    @property
    def amplification(self) -> float:
        """Measured advert airtime over the quiet-channel steady state. Above
        one means contention is making the routers advertise faster: a lost
        advert reads as a changed next hop or a lost route, either of which
        resets Trickle to its fastest interval."""
        steady = steady_routing_airtime_s(self.sensors + 1, self.i_max_s, self.measure_s)
        return self.routing_airtime_s / steady if steady else 0.0


def run_point(n: int, i_max_s: float, *, seed: int = SEED, measure_s: float = MEASURE_S, duty_cycle: float = DUTY_CYCLE) -> ChannelRun:
    """Warm up for two advert rounds, then measure `measure_s` of readings."""
    trickle = trickle_for(i_max_s)
    nodes = [Node(GATEWAY, mobility=Static(Vec3(0.0, 0.0, 10.0)), trickle=trickle)]
    names = [f"s{i + 1}" for i in range(n)]
    nodes += [Node(name, mobility=Static(site), trickle=trickle) for name, site in zip(names, sensor_sites(n, seed))]
    link = shared_lan([x.name for x in nodes], lora_radio(), medium=medium(duty_cycle))
    sim = Simulation(nodes, link, seed=seed)
    tap = sim.wiretap(link[0].name or "")

    warmup_s = 2 * i_max_s + 60.0
    rng = random.Random(seed + 1)
    flows = [
        sim.stream(
            name,
            GATEWAY,
            rate_hz=1.0 / REPORT_S,
            start_s=warmup_s + rng.random() * REPORT_S,
            duration_s=measure_s - REPORT_S,
        )
        for name in names
    ]
    sim.run(until_s=warmup_s)
    tap.reset()
    before = {x.name: (sim.radio_stats(x.name).tx_airtime_s, sim.radio_stats(x.name).queue_drops, sim.radio_stats(x.name).collisions) for x in nodes}
    sim.run(until_s=warmup_s + measure_s)

    sent = sum(len(f.sent) for f in flows)
    got = sum(len(f.received) for f in flows)
    routing = data = other = 0.0
    for frame in tap.frames:
        airtime = PHY.airtime_s(len(frame.raw))
        kind = frame.packet_type
        if kind in (forge.PACKET_OGM, forge.PACKET_KEEPALIVE):
            routing += airtime
        elif kind == forge.PACKET_UNICAST:
            data += airtime
        else:
            other += airtime
    duties = [(sim.radio_stats(x.name).tx_airtime_s - before[x.name][0]) / measure_s for x in nodes]
    return ChannelRun(
        sensors=n,
        i_max_s=i_max_s,
        delivery=got / sent if sent else 0.0,
        utilisation=(routing + data + other) / measure_s,
        routing_airtime_s=routing,
        data_airtime_s=data,
        other_airtime_s=other,
        busiest_duty=max(duties),
        queue_drops=sum(sim.radio_stats(x.name).queue_drops - before[x.name][1] for x in nodes),
        collisions=sum(sim.radio_stats(x.name).collisions - before[x.name][2] for x in nodes),
        measure_s=measure_s,
    )


OGM_FRAME_LEN = forge.LINK_HEADER_LEN + 20 + 8
"""A relayed open-mesh advert on the wire: link header, the OGM header, and
the 8-byte previous-sender TVLV a relay appends — 42 bytes, measured off a
wiretap rather than assumed."""


def ogm_airtime_s() -> float:
    """Airtime of one relayed open-mesh advert."""
    return PHY.airtime_s(OGM_FRAME_LEN)


def steady_routing_airtime_s(nodes: int, i_max_s: float, window_s: float = MEASURE_S) -> float:
    """Advert airtime over `window_s` on a quiet channel in steady state:
    `nodes²` adverts per mean Trickle round of `0.75·I`."""
    return nodes**2 * (window_s / (TRICKLE_MEAN_ROUND * i_max_s)) * ogm_airtime_s()


TRICKLE_MEAN_ROUND = 0.75
"""A Trickle fire lands uniformly in `[I/2, I)`: rounds average `0.75·I`."""


def duty_limited_n(i_max_s: float, duty_cycle: float = DUTY_CYCLE) -> float:
    """The N at which relaying N adverts per round uses a radio's whole
    duty-cycle budget: `N·T = duty · 0.75·I`."""
    return duty_cycle * TRICKLE_MEAN_ROUND * i_max_s / ogm_airtime_s()


def collision_limited_n(i_max_s: float, loss: float = 1.0 - TARGET_DELIVERY) -> float:
    """The N at which pure-ALOHA collisions with the advert flood alone cost
    a reading `loss`: survival is `e^(-2G)` at load `G = N²·T / 0.75·I`."""
    load = -math.log(1.0 - loss) / 2.0
    return math.sqrt(load * TRICKLE_MEAN_ROUND * i_max_s / ogm_airtime_s())


SEEDS = (0, 1, 2)
"""Near its limit the channel is chaotic — one seed collapses where its
neighbour holds — so every point is the median-delivery run of several."""


def median_run(n: int, i_max_s: float, seeds: Sequence[int] = SEEDS) -> ChannelRun:
    """The run with the median delivery across `seeds`: a real run rather
    than an average of runs, so its airtime split still adds up."""
    runs = sorted((run_point(n, i_max_s, seed=s) for s in seeds), key=lambda r: r.delivery)
    return runs[len(runs) // 2]


def run_sweep(
    counts: Sequence[int] = SENSOR_COUNTS,
    schedules: Sequence[float] = ADVERT_I_MAX_S,
    seeds: Sequence[int] = SEEDS,
) -> list[ChannelRun]:
    return [median_run(n, i, seeds) for i in schedules for n in counts]


def capacity(runs: Sequence[ChannelRun], i_max_s: float) -> int | None:
    """Largest swept N still delivering `TARGET_DELIVERY`, before the first
    that does not."""
    best = None
    for r in sorted((r for r in runs if r.i_max_s == i_max_s), key=lambda r: r.sensors):
        if r.delivery < TARGET_DELIVERY:
            break
        best = r.sensors
    return best


def print_summary(runs: Sequence[ChannelRun]) -> None:
    print(f"Crowded LoRa — SF7/125 kHz, {DUTY_CYCLE:.0%} duty cycle, one reading per {REPORT_S:.0f} s")
    print(f"  one advert = {ogm_airtime_s() * 1000:.0f} ms on air")
    print("  adverts  sensors  delivered  channel  busiest radio  routing share  advert amp.  queue drops")
    for r in runs:
        total = r.routing_airtime_s + r.data_airtime_s + r.other_airtime_s
        share = r.routing_airtime_s / total if total else 0.0
        print(
            f"  {r.i_max_s:>5.0f} s  {r.sensors:>7}  {r.delivery:>9.1%}  {r.utilisation:>7.1%}"
            f"  {r.busiest_duty:>13.2%}  {share:>13.0%}  {r.amplification:>10.2f}x  {r.queue_drops:>11}"
        )
    for i in sorted({r.i_max_s for r in runs}):
        print(
            f"  adverts every {i:.0f} s: {capacity(runs, i)} sensors at ≥{TARGET_DELIVERY:.0%}; "
            f"collision ceiling ≈ {collision_limited_n(i):.1f}, duty ceiling ≈ {duty_limited_n(i):.1f}"
        )


def _median_amp(runs: Sequence[ChannelRun]) -> float:
    """Median advert amplification over the points that still worked —
    collapsed points are dominated by queue drops, not by resets."""
    values = sorted(r.amplification for r in runs if r.delivery >= 0.5)
    return values[len(values) // 2] if values else 0.0


def showcase(runs: Sequence[ChannelRun]) -> Showcase:
    schedules = sorted({r.i_max_s for r in runs})
    counts = sorted({r.sensors for r in runs})

    def label(i: float) -> str:
        return f"adverts every {i / 60:g} min" if i >= 120 else f"adverts every {i:g} s"

    def per_schedule(metric):
        return [
            Series(label(i), [r.sensors for r in runs if r.i_max_s == i], [metric(r) for r in runs if r.i_max_s == i])
            for i in schedules
        ]

    fast, slow = schedules[0], schedules[-1]
    cap_fast, cap_slow = capacity(runs, fast), capacity(runs, slow)
    return Showcase(
        slug="crowded-lora",
        title="Sensors on one LoRa channel",
        category="capacity",
        scenario="sim/scenarios/crowded_lora.py",
        question="How many battery sensors can share one LoRa channel before the network stops delivering?",
        headlines=[
            Headline(
                f"{cap_fast if cap_fast is not None else 0}",
                f"sensors at {label(fast).replace('adverts every ', 'adverts every ')}",
                f"most that still deliver ≥{TARGET_DELIVERY:.0%} of readings",
            ),
            Headline(
                f"{cap_slow if cap_slow is not None else 0}" + ("+" if cap_slow == counts[-1] else ""),
                f"sensors at {label(slow)}",
                "capacity grows only with the square root of the advert interval",
            ),
            Headline(
                f"{_median_amp(runs):.1f}x",
                "more adverts than a quiet channel would carry",
                "lost adverts reset the routers to their fastest rate",
            ),
        ],
        summary=(
            f"Each sensor sends one short reading every {REPORT_S / 60:g} minutes, which by itself is a "
            f"trivial load. The limit comes from the mesh itself. Every routing advert is re-broadcast "
            f"by every node on the channel, so N sensors cost N² adverts per round. LoRa radios don't "
            f"listen before they talk, so readings collide with that advert traffic, and the collisions "
            f"bite before EU rules' {DUTY_CYCLE:.0%} duty cycle does. With adverts every {fast:g} s the "
            f"channel delivers ≥{TARGET_DELIVERY:.0%} of readings for {cap_fast or 0} sensors. Slowing "
            f"adverts to every {slow / 60:g} minutes lifts that to {cap_slow or 0}, but only by about the "
            f"square root of the slowdown, because the advert load grows with N². Contention also "
            f"feeds on itself. A lost advert reads to its receivers as a changed route, which resets "
            f"them to their fastest advertising rate, so a busy channel carries about "
            f"{_median_amp(runs):.1f}x the adverts a quiet one would. That is why the simulated "
            f"capacity lands below the closed-form ceiling (chart 4). Use the arithmetic as an upper "
            f"bound and the simulation for sizing. Slower adverts also mean slower failover, as the "
            f"relay scenario measures."
        ),
        method=(
            f"One {FREQ_HZ / 1e6:.0f} MHz LoRa channel (SF7, 125 kHz, CR 4/5) modelled with real time-on-air, "
            "pure-ALOHA collisions with a 6 dB capture margin, half-duplex radios and ETSI-style "
            f"per-transmission off-time for a {DUTY_CYCLE:.0%} duty cycle. Sensors are uniform over a "
            f"{RADIUS_M / 1000:g} km disc at {TX_POWER_DBM:.0f} dBm. Each point warms up for two advert rounds "
            f"and then measures one hour. Routing and data airtime are split by packet type from a "
            f"wiretap on the channel. Each point is the median-delivery run of {len(SEEDS)} seeds."
        ),
        charts=[
            Chart(
                title="Readings delivered",
                x_label="sensors on the channel",
                y_label="delivery ratio",
                series=per_schedule(lambda r: r.delivery),
                y_range=(0.0, 1.0),
            ),
            Chart(
                title="Busiest radio's transmit share",
                x_label="sensors on the channel",
                y_label="share of time transmitting",
                series=per_schedule(lambda r: r.busiest_duty),
                caption=f"The legal ceiling is {DUTY_CYCLE:.0%}. A radio pinned there is queueing adverts it cannot send.",
            ),
            Chart(
                title=f"Where the airtime goes ({label(fast)})",
                x_label="sensors on the channel",
                y_label="seconds on air per hour",
                series=[
                    Series("routing adverts", [r.sensors for r in runs if r.i_max_s == fast], [r.routing_airtime_s for r in runs if r.i_max_s == fast], kind="bar"),
                    Series("sensor readings", [r.sensors for r in runs if r.i_max_s == fast], [r.data_airtime_s for r in runs if r.i_max_s == fast], kind="bar"),
                ],
            ),
            Chart(
                title="Advert load vs. a quiet channel",
                x_label="sensors on the channel",
                y_label="measured ÷ steady-state advert airtime",
                series=per_schedule(lambda r: r.amplification),
                caption="Above 1, contention is making the routers re-advertise faster than their schedule would on its own.",
            ),
            Chart(
                title="Measured capacity vs. the arithmetic",
                x_label="advert interval (s)",
                y_label="sensors",
                series=[
                    Series("simulated (≥95% delivered)", schedules, [float(capacity(runs, i) or 0) for i in schedules], kind="line"),
                    Series("collision ceiling √(0.025·0.75I/T)", schedules, [collision_limited_n(i) for i in schedules], kind="line"),
                ],
                x_log=True,
                caption=(
                    "The closed form assumes a quiet channel's advert rate; contention raises it, so the "
                    "simulation lands below. The duty-cycle ceiling (0.01·0.75I/T) is far higher — "
                    f"{duty_limited_n(schedules[0]):.0f} to {duty_limited_n(schedules[-1]):.0f} sensors over "
                    "this range — so collisions bind long before it does."
                ),
            ),
        ],
        table=[["advert interval (s)", "sensors", "delivered", "busiest radio duty", "routing airtime (s/h)", "data airtime (s/h)", "queue drops"]]
        + [[r.i_max_s, r.sensors, round(r.delivery, 3), round(r.busiest_duty, 4), round(r.routing_airtime_s, 1), round(r.data_airtime_s, 1), r.queue_drops] for r in runs],
        params={
            "phy": "LoRa SF7/125kHz CR4/5",
            "duty_cycle": DUTY_CYCLE,
            "report_interval_s": REPORT_S,
            "sensor_counts": list(SENSOR_COUNTS),
            "advert_i_max_s": list(ADVERT_I_MAX_S),
            "measure_s": MEASURE_S,
        },
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--export", type=Path, help="write showcase JSON into this directory")
    parser.add_argument("--quick", action="store_true", help="fewer points")
    args = parser.parse_args(argv)
    wf.init_tracing()

    runs = run_sweep((4, 8, 14), (60, 300), seeds=(0,)) if args.quick else run_sweep()
    print_summary(runs)
    if args.export:
        print(f"wrote {write_showcase(showcase(runs), args.export)}")


if __name__ == "__main__":
    main()
