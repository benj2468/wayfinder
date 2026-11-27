"""Selective-forwarding scenario: a captured radio stays in the mesh, keeps
routing, and quietly drops the traffic it is asked to carry.

The authenticated twelve-radio field grid of `captured_device.py`. The field
team streams to HQ; at `ATTACK_AT_S` the relay then carrying that stream is
taken over (`Simulation.misbehave`) and nobody is told — no revocation, no
failure, nothing forged.

**Behaviours compared**, all on the same relay for a given seed:

- `honest`: the control. Whatever this loses is the radio, not the attacker.
- `grayhole`: drops half the data frames it emits.
- `selective forwarding`: relays all control traffic, drops all data.
- `blackhole`: transmits nothing at all, which to its neighbours is a node
  that died.

**What is measured**, from the attack onset to the end of the stream: the share
of packets that reached HQ, the share that were handed to the captured radio
(read off the air with a wiretap), the team's end-to-end TQ toward HQ, and for
the blackhole how long until delivery was sustained again
(`Flow.restored_after`).

On some seeds the team's traffic moves to another relay for part of the run
even with everyone honest (seed 4: 28% of packets). A selective forwarder
loses less on those seeds; that movement is not detection.

Run: `uv run --group sim python sim/scenarios/selective_forwarding.py
[--export DIR]`
"""

from __future__ import annotations

import argparse
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import wayfinder_py as wf
from captured_device import HQ, TEAM, build_simulation, delivery_timeline
from wayfinder_sim import forge
from wayfinder_sim.insider import Insider
from wayfinder_sim.showcase import (
    Chart,
    Headline,
    Marker,
    Series,
    Showcase,
    downsample,
    write_showcase,
)
from wayfinder_sim.traffic import Flow, decode_payload, encode_payload

GRAYHOLE_FRACTION = 0.5
BEHAVIOURS: Mapping[str, Insider | None] = {
    "honest": None,
    "grayhole": Insider.grayhole(GRAYHOLE_FRACTION),
    "selective forwarding": Insider.selective_forwarding(),
    "blackhole": Insider.blackhole(),
}

RATE_HZ = 10.0
STREAM_START_S = 20.0
PICK_AT_S = 35.0
"""When the relay to capture is chosen, and sampling starts."""
ATTACK_AT_S = 40.0
END_S = 100.0
SAMPLE_MS = 100
MIN_DELIVERY_BEFORE = 0.9
SWEEP_SEEDS = tuple(range(10))


@dataclass(frozen=True)
class AttackRun:
    """One behaviour on one seed, measured."""

    behaviour: str
    seed: int
    captured: str
    flow: Flow
    times_s: list[float]
    tq: list[int | None]
    """The team's end-to-end TQ toward HQ at each sample; `None` is no route."""
    carried: frozenset[int]
    """Sequence numbers of the stream packets transmitted to the captured
    radio, as heard on the air."""
    drops: int

    @property
    def delivery_before(self) -> float:
        return _require(self.flow.delivery_ratio(STREAM_START_S, ATTACK_AT_S - 0.5))

    @property
    def delivery_after(self) -> float:
        # Stop a second short: the last packets are still in flight at END_S.
        return _require(self.flow.delivery_ratio(ATTACK_AT_S, END_S - 1.0))

    @property
    def carried_share(self) -> float:
        """Share of the packets sent after the onset that were handed to the
        captured radio."""
        after = [s for s, t in self.flow.sent if ATTACK_AT_S <= t <= END_S - 1.0]
        return sum(s in self.carried for s in after) / len(after)

    @property
    def tq_before(self) -> float:
        return self._mean_tq(PICK_AT_S, ATTACK_AT_S)

    @property
    def tq_after(self) -> float:
        return self._mean_tq(ATTACK_AT_S, END_S)

    @property
    def restored_s(self) -> float | None:
        return self.flow.restored_after(ATTACK_AT_S)

    def _mean_tq(self, start_s: float, end_s: float) -> float:
        """Mean over the samples that had a route; 0 if none did."""
        values = [
            q
            for t, q in zip(self.times_s, self.tq)
            if start_s <= t < end_s and q is not None
        ]
        return statistics.fmean(values) if values else 0.0


def _require(value: float | None) -> float:
    if value is None:
        raise RuntimeError("no packets were sent in the window being measured")
    return value


def _stream_seq(frame: bytes, flow_id: int) -> int | None:
    """The sequence number of the stream packet `frame` carries, if any. Found
    by its header, since an authenticated frame has a tag after the payload."""
    prefix = encode_payload(flow_id, 0)[:-4]
    at = frame.find(prefix)
    if at < 0:
        return None
    decoded = decode_payload(frame[at : at + len(prefix) + 4])
    return None if decoded is None else decoded[1]


def run_attack(behaviour: str, seed: int = 0) -> AttackRun:
    """Converge, pick the relay carrying team→HQ, and have it behave as
    `BEHAVIOURS[behaviour]` from `ATTACK_AT_S`."""
    insider = BEHAVIOURS[behaviour]
    sim = build_simulation(seed, joiners=False)
    flow = sim.stream(
        TEAM,
        HQ,
        rate_hz=RATE_HZ,
        start_s=STREAM_START_S,
        duration_s=END_S - STREAM_START_S,
    )
    # Chosen before the behaviours diverge, so every one of them attacks the
    # same radio.
    sim.run(until_s=PICK_AT_S)
    route = sim.route_path(TEAM, HQ)
    if route is None or len(route) < 3:
        raise RuntimeError(f"seed {seed}: no multi-hop team→HQ route: {route}")
    captured = route[1]
    if insider is not None:
        sim.misbehave(captured, insider, at_s=ATTACK_AT_S)

    sim.record("tq", lambda s: s.tq_to(TEAM, HQ))
    # One shared segment, so one tap hears every hop.
    tap = sim.wiretap("-".join(sim.node_names))
    rec = sim.run(until_s=END_S, sample_interval_ms=SAMPLE_MS)
    drops = sim.insider_drops(captured)
    if insider is not None and drops == 0:
        raise RuntimeError(f"seed {seed}: {behaviour} withheld nothing")
    relay = sim.mac(captured)
    carried = frozenset(
        seq
        for frame in tap.of_type(forge.PACKET_UNICAST)
        if frame.dst == relay
        and (seq := _stream_seq(frame.raw, flow.flow_id)) is not None
    )
    run = AttackRun(
        behaviour=behaviour,
        seed=seed,
        captured=captured,
        flow=flow,
        times_s=list(rec.times_s),
        tq=list(rec.column("tq")),
        carried=carried,
        drops=drops,
    )
    # A stream already failing before the onset would pass off the radio as the
    # attacker.
    if run.delivery_before < MIN_DELIVERY_BEFORE:
        raise RuntimeError(
            f"seed {seed}: only {run.delivery_before:.0%} delivered before the attack"
        )
    return run


Sweep = Mapping[str, Sequence[AttackRun]]


def run_sweep(seeds: Sequence[int] = SWEEP_SEEDS) -> Sweep:
    """Every behaviour over every seed."""
    return {name: tuple(run_attack(name, s) for s in seeds) for name in BEHAVIOURS}


def _median(runs: Sequence[AttackRun], field: str) -> float:
    values = [getattr(r, field) for r in runs]
    if None in values:
        raise RuntimeError(f"{runs[0].behaviour}: {field} missing on some seeds")
    return statistics.median(values)


TABLE_HEADER = [
    "behaviour",
    "delivered (median)",
    "delivered (worst seed)",
    "delivered (best seed)",
    "handed to captured radio",
    "TQ before",
    "TQ after",
]


def table(sweep: Sweep) -> list[list[object]]:
    """One row per behaviour: medians over its seeds, and the delivery
    extremes."""
    return [
        [
            name,
            round(_median(runs, "delivery_after"), 3),
            round(min(r.delivery_after for r in runs), 3),
            round(max(r.delivery_after for r in runs), 3),
            round(_median(runs, "carried_share"), 3),
            round(_median(runs, "tq_before"), 1),
            round(_median(runs, "tq_after"), 1),
        ]
        for name, runs in sweep.items()
    ]


def showcase(sweep: Sweep) -> Showcase:
    """The results-page entry. Charts show each behaviour's first seed; the
    table and headlines are medians over all of them."""
    seeds = len(sweep["honest"])
    markers = [Marker(ATTACK_AT_S, "relay captured")]
    delivery, tq = [], []
    for name, runs in sweep.items():
        xs, ys = delivery_timeline(runs[0].flow, bin_s=2.0)
        delivery.append(Series(name, xs, ys, kind="step"))
        tx, ty = downsample(runs[0].times_s, runs[0].tq)
        tq.append(Series(name, tx, ty, kind="step"))
    selective = sweep["selective forwarding"]
    return Showcase(
        slug="selective-forwarding",
        title="A relay that keeps routing and drops the traffic",
        category="security",
        scenario="sim/scenarios/selective_forwarding.py",
        question="If a captured radio goes on taking part in routing but drops our data, does the mesh notice?",
        headlines=[
            Headline(
                f"{_median(selective, 'delivery_after'):.0%}",
                "of packets delivered under selective forwarding",
                f"median over {seeds} runs; honest relay: "
                f"{_median(sweep['honest'], 'delivery_after'):.0%}",
            ),
            Headline(
                f"{_median(selective, 'carried_share'):.0%}",
                "of packets were still handed to the captured radio",
                "nothing in the routing metric reflects dropped data",
            ),
            Headline(
                f"{_median(sweep['blackhole'], 'restored_s'):.1f} s",
                "to route around a radio that goes wholly silent",
                "median until delivery was sustained again",
            ),
        ],
        summary=(
            "A captured radio that keeps sending its routing adverts and drops the "
            "data it is asked to relay looks exactly like a good relay. The mesh "
            "judges paths by adverts, so it has no reason to leave. One that falls "
            "silent altogether is treated as dead and routed around."
        ),
        method=(
            "Every node runs the real wayfinder router with mesh authentication "
            "on. The captured radio keeps its genuine certificate and keys; the "
            "simulator discards chosen frames after its router emits them, so "
            "nothing is forged. Twelve radios, 450 m grid, 24 dBm, 700 m range, "
            f"one shared channel without airtime or collisions. {RATE_HZ:.0f} "
            f"packets/s from the field team to HQ; {seeds} seeds."
        ),
        charts=[
            Chart(
                title="Field team → HQ: delivery",
                x_label="time (s)",
                y_label="delivery ratio",
                series=delivery,
                markers=markers,
                y_range=(0.0, 1.0),
            ),
            Chart(
                title="The field team's route quality toward HQ",
                x_label="time (s)",
                y_label="TQ (0-255)",
                series=tq,
                markers=markers,
                y_range=(0.0, 255.0),
            ),
        ],
        table=[list(TABLE_HEADER), *table(sweep)],
        params={
            "members": 12,
            "attack_at_s": ATTACK_AT_S,
            "grayhole_fraction": GRAYHOLE_FRACTION,
            "stream_rate_hz": RATE_HZ,
            "seeds": seeds,
        },
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument(
        "--export", type=Path, help="write showcase JSON into this directory"
    )
    parser.add_argument("--quick", action="store_true", help="three seeds")
    args = parser.parse_args(argv)
    wf.init_tracing()

    sweep = run_sweep(SWEEP_SEEDS[:3] if args.quick else SWEEP_SEEDS)
    print("Selective forwarding — the relay carrying team→HQ is captured")
    print("  " + " | ".join(TABLE_HEADER))
    for row in table(sweep):
        print("  " + " | ".join(str(cell) for cell in row))
    restored = [r.restored_s for r in sweep["blackhole"]]
    print(f"  blackhole, seconds to sustained delivery per seed: {restored}")
    if args.export:
        print(f"wrote {write_showcase(showcase(sweep), args.export)}")


if __name__ == "__main__":
    main()
