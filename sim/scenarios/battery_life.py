"""Battery life: how long a LoRa mesh node runs on batteries, and what its
energy is actually spent on.

The network is `crowded_lora.py`'s — a gateway and sensors on one 868 MHz
LoRa channel, one reading every couple of minutes — and every radio's
transmit, receive and idle time is metered by the contended medium
(`wayfinder_sim.medium`). `EnergyModel` prices each state for an
SX1262-class radio at 3.3 V: ~150 mW transmitting at 14 dBm, ~17 mW
receiving.

**The finding is about listening.** A wayfinder node is a router: it has to
hear every neighbour's advert to keep its routes, so its receiver never
sleeps, and an open receiver draws receive power whether or not anything
arrives. Against that, the airtime a sensor actually spends transmitting is
tiny — a reading is ~80 ms every two minutes — so the battery is set almost
entirely by how long the radio listens, not by what it sends. That is why
tuning the advert schedule barely moves battery life (the sweep shows it),
and why the lever that does move it is a receiver that can sleep between
frames.

**What the comparisons are.** Every mesh number here is simulated: the real
router, the real advert schedule, every frame's airtime. The *listening-power*
sweep re-prices the same measured activity with a cheaper idle state — the
figure low-power listening (channel-activity detection) would reach if the
mesh could tolerate its receivers dozing. wayfinder does not do that today,
and a dozing receiver misses frames the simulation does not model, so that
curve is an upper bound on what the feature would be worth, not a measured
result. The sleeping-leaf figure is the same: a sensor that never routes,
waking only to send, priced from its own transmissions.

Run: `uv run --group sim python sim/scenarios/battery_life.py [--export DIR]`
"""

from __future__ import annotations

import argparse
import dataclasses
import random
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim.medium import EnergyModel, RadioStats
from wayfinder_sim.mobility import Static, Vec3
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.showcase import Chart, Headline, Series, Showcase, write_showcase
from wayfinder_sim.topology import shared_lan

sys.path.insert(0, str(Path(__file__).resolve().parent))
import crowded_lora as lora

RADIO = EnergyModel(tx_mw=150.0, rx_mw=17.0, idle_mw=17.0)
"""A mesh router's radio: its receiver is always open, so idle *is* receive."""

SLEEP_MW = 0.005
"""An SX1262 asleep with its RTC running, ~1.5 µA."""

BATTERIES_MWH = {
    "2x AA lithium": 2 * 3000.0 * 1.5,
    "18650 Li-ion cell": 3400.0 * 3.6,
}
PRIMARY = "2x AA lithium"

SENSORS = 6
ADVERT_I_MAX_S = (60, 300, 900, 1800)
SENSOR_COUNTS = (2, 4, 6, 8, 10)
DEFAULT_I_MAX_S = 300.0
LISTEN_MW = (17.0, 5.0, 1.0, 0.3, 0.1)
MEASURE_S = 3600.0


def _delta(after: RadioStats, before: RadioStats) -> RadioStats:
    return RadioStats(
        **{
            f.name: getattr(after, f.name) - getattr(before, f.name)
            for f in dataclasses.fields(RadioStats)
        }
    )


@dataclass(frozen=True)
class NodeEnergy:
    """One node's measured activity over the window."""

    name: str
    role: str
    stats: RadioStats
    window_s: float

    def power_mw(self, model: EnergyModel = RADIO) -> float:
        return model.energy_mj(self.window_s, self.stats) / self.window_s

    def breakdown_mj_per_h(self, model: EnergyModel = RADIO) -> dict[str, float]:
        """Energy per hour by radio state."""
        scale = 3600.0 / self.window_s
        idle_s = max(
            0.0, self.window_s - self.stats.tx_airtime_s - self.stats.rx_airtime_s
        )
        return {
            "transmit": self.stats.tx_airtime_s * model.tx_mw * scale,
            "receive": self.stats.rx_airtime_s * model.rx_mw * scale,
            "listen": idle_s * model.idle_mw * scale,
        }

    def life_days(self, model: EnergyModel = RADIO, battery: str = PRIMARY) -> float:
        return (
            EnergyModel.battery_life_h(BATTERIES_MWH[battery], self.power_mw(model))
            / 24.0
        )


def run_network(
    sensors: int = SENSORS,
    i_max_s: float = DEFAULT_I_MAX_S,
    *,
    seed: int = lora.SEED,
    measure_s: float = MEASURE_S,
) -> list[NodeEnergy]:
    """Warm up, then meter every radio over `measure_s` of normal reporting."""
    trickle = lora.trickle_for(i_max_s)
    names = [f"s{i + 1}" for i in range(sensors)]
    nodes = [Node(lora.GATEWAY, mobility=Static(Vec3(0.0, 0.0, 10.0)), trickle=trickle)]
    nodes += [
        Node(n, mobility=Static(p), trickle=trickle)
        for n, p in zip(names, lora.sensor_sites(sensors, seed))
    ]
    sim = Simulation(
        nodes,
        shared_lan([x.name for x in nodes], lora.lora_radio(), medium=lora.medium()),
        seed=seed,
    )
    warmup_s = 2 * i_max_s + 60.0
    rng = random.Random(seed + 1)
    for n in names:
        sim.stream(
            n,
            lora.GATEWAY,
            rate_hz=1.0 / lora.REPORT_S,
            start_s=warmup_s + rng.random() * lora.REPORT_S,
            duration_s=measure_s,
        )
    sim.run(until_s=warmup_s)
    before = {x.name: dataclasses.replace(sim.radio_stats(x.name)) for x in nodes}
    sim.run(until_s=warmup_s + measure_s)
    return [
        NodeEnergy(
            x.name,
            "gateway" if x.name == lora.GATEWAY else "sensor",
            _delta(sim.radio_stats(x.name), before[x.name]),
            measure_s,
        )
        for x in nodes
    ]


def median_sensor(nodes: Sequence[NodeEnergy]) -> NodeEnergy:
    sensors = sorted(
        (n for n in nodes if n.role == "sensor"), key=lambda n: n.power_mw()
    )
    return sensors[len(sensors) // 2]


def busiest_sensor(nodes: Sequence[NodeEnergy]) -> NodeEnergy:
    return max((n for n in nodes if n.role == "sensor"), key=lambda n: n.power_mw())


def gateway(nodes: Sequence[NodeEnergy]) -> NodeEnergy:
    return next(n for n in nodes if n.role == "gateway")


def leaf_power_mw(node: NodeEnergy) -> float:
    """A sensor that never routes: asleep except for its own readings. Priced
    from the readings alone — one data frame per report — not from the mesh
    node's transmissions, which include relaying everyone's adverts."""
    reading_s = lora.PHY.airtime_s(35)
    tx_s = (node.window_s / lora.REPORT_S) * reading_s
    return (tx_s * RADIO.tx_mw + (node.window_s - tx_s) * SLEEP_MW) / node.window_s


@dataclass(frozen=True)
class Study:
    base: list[NodeEnergy]
    by_schedule: dict[float, list[NodeEnergy]]
    by_count: dict[int, list[NodeEnergy]]


def run_study(quick: bool = False) -> Study:
    schedules = ADVERT_I_MAX_S[:2] if quick else ADVERT_I_MAX_S
    counts = SENSOR_COUNTS[:3] if quick else SENSOR_COUNTS
    return Study(
        base=run_network(),
        by_schedule={i: run_network(SENSORS, i) for i in schedules},
        by_count={n: run_network(n, DEFAULT_I_MAX_S) for n in counts},
    )


def listen_share(node: NodeEnergy) -> float:
    b = node.breakdown_mj_per_h()
    return b["listen"] / sum(b.values())


def print_summary(study: Study) -> None:
    gw, med = gateway(study.base), median_sensor(study.base)
    print(
        f"Battery life — {SENSORS} sensors + gateway, adverts every {DEFAULT_I_MAX_S:.0f} s, one reading per {lora.REPORT_S:.0f} s"
    )
    for node in (gw, med, busiest_sensor(study.base)):
        b = node.breakdown_mj_per_h()
        print(
            f"  {node.name:<4} {node.role:<8} {node.power_mw():6.2f} mW  life {node.life_days():6.1f} days on {PRIMARY}"
            f"   listen {b['listen']:8.0f}  rx {b['receive']:6.0f}  tx {b['transmit']:6.0f} mJ/h  ({listen_share(node):.1%} listening)"
        )
    print(
        f"  a sleeping, non-routing leaf: {leaf_power_mw(med):.3f} mW → {EnergyModel.battery_life_h(BATTERIES_MWH[PRIMARY], leaf_power_mw(med)) / 24 / 365:.1f} years"
    )
    print("  advert interval → median sensor life (days)")
    for i, nodes in study.by_schedule.items():
        print(
            f"    {i:>5.0f} s  {median_sensor(nodes).life_days():6.1f}   gateway {gateway(nodes).life_days():6.1f}"
        )
    print("  listen power → median sensor life (days, upper bound)")
    for mw in LISTEN_MW:
        model = dataclasses.replace(RADIO, idle_mw=mw)
        print(f"    {mw:>5.1f} mW  {med.life_days(model):8.1f}")


def showcase(study: Study) -> Showcase:
    gw, med, busy = (
        gateway(study.base),
        median_sensor(study.base),
        busiest_sensor(study.base),
    )
    roles = [("gateway", gw), ("typical sensor", med), ("busiest sensor", busy)]
    leaf_years = (
        EnergyModel.battery_life_h(BATTERIES_MWH[PRIMARY], leaf_power_mw(med))
        / 24
        / 365
    )
    schedules = sorted(study.by_schedule)
    counts = sorted(study.by_count)
    return Showcase(
        slug="battery-life",
        title="Battery life of a mesh node",
        category="planning",
        scenario="sim/scenarios/battery_life.py",
        question="How long will a node run on batteries, and what actually drains them?",
        headlines=[
            Headline(
                f"{med.life_days():.0f} days",
                f"for a typical sensor on {PRIMARY}",
                f"{med.power_mw():.1f} mW average, routing for its neighbours",
            ),
            Headline(
                f"{listen_share(med):.0%}",
                "of the energy is spent listening",
                "the receiver stays open to hear every routing advert",
            ),
            Headline(
                f"{leaf_years:.0f} years",
                "for a sensor that sleeps instead of routing",
                "same readings, no mesh duties; radio only, before battery self-discharge",
            ),
        ],
        summary=(
            f"Every node in a wayfinder mesh is a router, so its receiver never sleeps: it has to hear "
            f"its neighbours' routing adverts to keep its routes. An open LoRa receiver draws about "
            f"{RADIO.rx_mw:g} mW whether or not anything arrives, and that dominates everything else. "
            f"A typical sensor here spends {listen_share(med):.0%} of its energy listening and lasts "
            f"{med.life_days():.0f} days on {PRIMARY}. Its transmissions (its readings, plus relayed "
            f"adverts) barely register, which is why slowing the advert schedule hardly changes battery "
            f"life (chart 2). The lever that matters is a receiver that can sleep between frames. "
            f"Chart 4 prices the same measured traffic at lower listening power to show what that "
            f"would be worth. A sensor that didn't route at all would last {leaf_years:.0f} years, "
            f"which is the cost of being part of a mesh."
        ),
        method=(
            "The network and channel are the crowded-LoRa scenario's: SF7 at 868 MHz, 1% duty cycle, "
            f"{SENSORS} sensors plus a gateway, one reading per {lora.REPORT_S:.0f} s. Every radio's transmit, "
            "receive and idle time is metered from the simulated medium over one hour after warm-up and "
            f"priced for an SX1262-class radio at 3.3 V ({RADIO.tx_mw:g} mW transmit, {RADIO.rx_mw:g} mW "
            f"receive or listening). Batteries: {PRIMARY} ≈ {BATTERIES_MWH[PRIMARY] / 1000:.0f} Wh. The "
            "listening-power and sleeping-leaf figures re-price measured activity and are upper bounds: "
            "wayfinder does not doze its receiver today, and a dozing receiver would miss frames this "
            "model does not account for."
        ),
        charts=[
            Chart(
                title="Where the energy goes (per hour)",
                x_label="node",
                y_label="millijoules per hour",
                series=[
                    Series(
                        state,
                        [label for label, _ in roles],
                        [n.breakdown_mj_per_h()[state] for _, n in roles],
                        kind="bar",
                    )
                    for state in ("listen", "receive", "transmit")
                ],
                caption="Listening, with the receiver open waiting for frames, outweighs everything the radio actually sends or receives.",
            ),
            Chart(
                title="Battery life vs. advert interval",
                x_label="advert interval (s)",
                y_label=f"days on {PRIMARY}",
                series=[
                    Series(
                        "typical sensor",
                        schedules,
                        [
                            median_sensor(study.by_schedule[i]).life_days()
                            for i in schedules
                        ],
                    ),
                    Series(
                        "gateway",
                        schedules,
                        [gateway(study.by_schedule[i]).life_days() for i in schedules],
                    ),
                ],
                x_log=True,
                caption="Nearly flat: fewer adverts save transmit and receive energy, but listening costs the same.",
            ),
            Chart(
                title="Battery life vs. sensors on the channel",
                x_label="sensors on the channel",
                y_label=f"days on {PRIMARY}",
                series=[
                    Series(
                        "typical sensor",
                        counts,
                        [median_sensor(study.by_count[n]).life_days() for n in counts],
                    ),
                    Series(
                        "gateway",
                        counts,
                        [gateway(study.by_count[n]).life_days() for n in counts],
                    ),
                ],
            ),
            Chart(
                title="What a sleeping receiver would be worth (upper bound)",
                x_label="average listening power (mW)",
                y_label=f"days on {PRIMARY}",
                series=[
                    Series(
                        "typical sensor",
                        list(LISTEN_MW),
                        [
                            med.life_days(dataclasses.replace(RADIO, idle_mw=mw))
                            for mw in LISTEN_MW
                        ],
                    )
                ],
                x_log=True,
                caption=f"{RADIO.rx_mw:g} mW is an always-open receiver, today's behaviour. Lower values re-price the same measured traffic.",
            ),
        ],
        table=[
            [
                "node",
                "average power (mW)",
                f"days on {PRIMARY}",
                "days on 18650",
                "listening share",
            ]
        ]
        + [
            [
                label,
                round(n.power_mw(), 2),
                round(n.life_days(), 1),
                round(n.life_days(battery="18650 Li-ion cell"), 1),
                round(listen_share(n), 3),
            ]
            for label, n in roles
        ],
        params={
            "sensors": SENSORS,
            "advert_i_max_s": DEFAULT_I_MAX_S,
            "report_interval_s": lora.REPORT_S,
            "tx_mw": RADIO.tx_mw,
            "rx_mw": RADIO.rx_mw,
            "battery_mwh": BATTERIES_MWH,
        },
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument(
        "--export", type=Path, help="write showcase JSON into this directory"
    )
    parser.add_argument("--quick", action="store_true", help="fewer sweep points")
    args = parser.parse_args(argv)
    wf.init_tracing()

    study = run_study(quick=args.quick)
    print_summary(study)
    if args.export:
        print(f"wrote {write_showcase(showcase(study), args.export)}")


if __name__ == "__main__":
    main()
