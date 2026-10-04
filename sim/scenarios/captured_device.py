"""Captured-device scenario: a radio is stolen, the operator revokes it, and
the mesh shuts it out — while outsiders try, and fail, to get in.

The same twelve-radio field grid as `failover.py`, but authenticated: every
node holds a membership certificate signed by the mesh root, signs the OGMs it
sends, and refuses ones that do not verify (`wayfinder_sim.security`).

**A captured device is the hard case.** An outsider holds nothing and is
refused on sight. A captured radio holds a perfectly valid certificate and the
key that goes with it — it *is* a member, as far as any cryptography can tell,
and an attacker can keep it running, relaying and sending. The only remedy is
the active one: the mesh root signs a revocation naming it, and every member
that holds that record stops trusting it.

**What is measured.** The operator can reach exactly one node — HQ, the
gateway — and pushes the revocation there (`Simulation.revoke(notify=…)`).
Nothing else is told directly. From that moment the scenario records, every
50 ms:

- how many members hold the revocation (`knows_revoked`), so the time for the
  order to cross the mesh is measured rather than assumed;
- how many still admit the captured radio (`admitted`) or still route to it;
- whether packets the captured radio sends to HQ still arrive;
- whether the field team's own stream, which the captured radio was relaying,
  reroutes around it.

A revocation that reached every node but left traffic flowing through the
captured relay would be a paper exclusion; the traffic columns are what show
it is a real one.

**Outsiders.** Alongside, three would-be joiners sit inside radio range of HQ
and stream to it for the whole run: a stock open router with no credentials,
a node holding a structurally perfect certificate from a *different* mesh
root, and a former member whose certificate has expired. A legitimate new
member is powered on mid-run as the control. Each is scored by the one number
that matters — how many of its packets HQ accepted.

Run: `uv run --group sim python sim/scenarios/captured_device.py [--export DIR]`
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
from wayfinder_sim.security import Credential, Mesh
from wayfinder_sim.showcase import (
    Chart,
    Headline,
    Marker,
    Series,
    Showcase,
    write_showcase,
)
from wayfinder_sim.topology import shared_lan
from wayfinder_sim.traffic import Flow

ROWS, COLS = 3, 4
SPACING_M = 450.0
HQ = "hq"
TEAM = "team"
TX_POWER_DBM = 24.0
MAX_RANGE_M = 700.0
DELIVERY_STEEPNESS = 1.0  # see failover.py: a digital radio's sharp waterfall
RATE_HZ = 10.0
HOP_LATENCY_MS = 5.0
"""Air time plus processing per hop for a small 2.4 GHz radio. Without it a
re-flooded record crosses every hop in the same instant and the propagation
this scenario times collapses to zero."""

MESH_ROOT_SEED = bytes([0xA5]) * 32
FOREIGN_ROOT_SEED = bytes([0x5A]) * 32
MESH_ID = 0x5741

STREAM_START_S = 20.0
REVOKE_AT_S = 40.0
NEWCOMER_ON_S = 30.0
DURATION_S = 90.0
SWEEP_SEEDS = tuple(range(10))

OPEN_ROUTER = "open-router"
FOREIGN = "foreign-cert"
EXPIRED = "expired-cert"
NEWCOMER = "new-member"
OUTSIDERS = (OPEN_ROUTER, FOREIGN, EXPIRED)

# Inside radio range of HQ (and of each other), off the grid's own lines.
_JOINER_SITES = {
    OPEN_ROUTER: Vec3(225.0, 225.0, 2.0),
    FOREIGN: Vec3(-200.0, 150.0, 2.0),
    EXPIRED: Vec3(150.0, -200.0, 2.0),
    NEWCOMER: Vec3(-150.0, -150.0, 2.0),
}


def node_name(row: int, col: int) -> str:
    """Grid position to node name; the corners carry the story's roles."""
    if (row, col) == (0, 0):
        return HQ
    if (row, col) == (ROWS - 1, COLS - 1):
        return TEAM
    return f"n{row}{col}"


def mesh() -> Mesh:
    """The mesh under test, from a fixed root so runs are reproducible."""
    return Mesh(mesh_id=MESH_ID, root_seed=MESH_ROOT_SEED)


def build_simulation(seed: int = 0, *, joiners: bool = True) -> Simulation:
    """The authenticated field grid, plus (with `joiners`) the outsiders and
    the new member, all on one shared radio channel."""
    grid = [
        Node(
            node_name(r, c),
            mobility=Static(Vec3(c * SPACING_M, r * SPACING_M, 2.0)),
            credential=Credential(),
        )
        for r in range(ROWS)
        for c in range(COLS)
    ]
    extra: list[Node] = []
    if joiners:
        extra = [
            # A stock router with no mesh identity at all: open, unauthenticated.
            Node(OPEN_ROUTER, mobility=Static(_JOINER_SITES[OPEN_ROUTER])),
            Node(
                FOREIGN,
                mobility=Static(_JOINER_SITES[FOREIGN]),
                credential=Credential(
                    mesh=Mesh(mesh_id=MESH_ID, root_seed=FOREIGN_ROOT_SEED)
                ),
            ),
            Node(
                EXPIRED,
                mobility=Static(_JOINER_SITES[EXPIRED]),
                credential=Credential(valid_from_s=-86_400.0, valid_until_s=-1.0),
            ),
            Node(
                NEWCOMER,
                mobility=Static(_JOINER_SITES[NEWCOMER]),
                credential=Credential(),
            ),
        ]
    radio = FreeSpacePathLoss(
        tx_power_dbm=TX_POWER_DBM,
        max_range_m=MAX_RANGE_M,
        delivery_steepness=DELIVERY_STEEPNESS,
        latency_ms=HOP_LATENCY_MS,
    )
    nodes = grid + extra
    sim = Simulation(
        nodes, shared_lan([n.name for n in nodes], radio), seed=seed, mesh=mesh()
    )
    if joiners:
        # The new member is switched on mid-run, so its admission is timed
        # from a cold start rather than converging with everyone at t=0.
        sim.fail_node(NEWCOMER, at_s=0.0, recover_s=NEWCOMER_ON_S)
    return sim


def members(sim: Simulation, excluding: str) -> list[str]:
    """The grid's legitimate members other than `excluding`."""
    return [
        n
        for n in sim.node_names
        if n != excluding and n not in OUTSIDERS and n != NEWCOMER
    ]


@dataclass(frozen=True)
class CaptureRun:
    """One capture, revocation and exclusion, measured."""

    seed: int
    captured: str
    notify: tuple[str, ...]
    times_s: list[float]
    knows: list[int]
    admits: list[int]
    routes: list[int]
    member_count: int
    learned_at_s: dict[str, float | None]
    """Per member, seconds after the revocation at which it first held it."""
    hops_from_hq: dict[str, int | None]
    captured_flow: Flow
    team_flow: Flow
    outsider_flows: dict[str, Flow]
    newcomer_joined_s: float | None
    """Seconds from the new member's power-on to HQ accepting its first
    packet — joining as its user experiences it. (The verified-peer table,
    `admitted`, catches up later on its own proof cadence.)"""

    @property
    def all_know_s(self) -> float | None:
        """When the last member learned of the revocation."""
        values = list(self.learned_at_s.values())
        return None if None in values else max(v for v in values if v is not None)

    @property
    def excluded_s(self) -> float | None:
        """When no member admitted or routed to the captured radio any more."""
        for t, a, r in zip(self.times_s, self.admits, self.routes):
            if t >= REVOKE_AT_S and a == 0 and r == 0:
                return t - REVOKE_AT_S
        return None

    @property
    def accepted_after_exclusion(self) -> int:
        """Packets from the captured radio that reached HQ after the mesh had
        fully excluded it — the number that must be zero."""
        if self.excluded_s is None:
            return len(self.captured_flow.received)
        cutoff = REVOKE_AT_S + self.excluded_s
        return sum(1 for t in self.captured_flow.received.values() if t > cutoff)


def run_capture(
    seed: int = 0, *, notify: Sequence[str] = (HQ,), joiners: bool = True
) -> CaptureRun:
    """Converge, capture the relay carrying team→HQ, revoke it via `notify`,
    and measure the exclusion."""
    sim = build_simulation(seed, joiners=joiners)
    team_flow = sim.stream(
        TEAM, HQ, rate_hz=RATE_HZ, start_s=STREAM_START_S, duration_s=DURATION_S
    )
    outsider_flows = (
        {
            name: sim.stream(
                name, HQ, rate_hz=RATE_HZ, start_s=STREAM_START_S, duration_s=DURATION_S
            )
            for name in (*OUTSIDERS, NEWCOMER)
        }
        if joiners
        else {}
    )
    sim.run(until_s=REVOKE_AT_S - 5.0)
    path = sim.route_path(TEAM, HQ)
    if path is None or len(path) < 3:
        raise RuntimeError(f"no multi-hop team→HQ route to capture a relay on: {path}")
    captured = path[1]
    hops = {}
    for m in members(sim, captured):
        p = sim.route_path(HQ, m)
        hops[m] = None if p is None else len(p) - 1
    # The attacker holds the captured radio: its firmware will discard the
    # order revoking it, and it keeps talking.
    sim.compromise(captured)
    captured_flow = sim.stream(
        captured, HQ, rate_hz=RATE_HZ, start_s=REVOKE_AT_S - 5.0, duration_s=DURATION_S
    )

    others = members(sim, captured)
    for m in others:
        sim.record(f"knows:{m}", lambda s, m=m: s.knows_revoked(m, captured))
    sim.record("knows", lambda s: sum(s.knows_revoked(n, captured) for n in others))
    sim.record(
        "admits", lambda s: sum(captured in s.admitted(n, [captured]) for n in others)
    )
    sim.record("routes", lambda s: sum(s.has_route(n, captured) for n in others))

    sim.run(until_s=REVOKE_AT_S)
    if isinstance(notify, _AllMembers):
        notify = tuple(others)
    sim.revoke(captured, notify=list(notify))
    rec = sim.run(until_s=DURATION_S, sample_interval_ms=50)

    learned = {m: _first_true_after(rec, f"knows:{m}", REVOKE_AT_S) for m in others}
    newcomer_s = (
        outsider_flows[NEWCOMER].recovery_after(NEWCOMER_ON_S).recovered_s
        if joiners
        else None
    )

    return CaptureRun(
        seed=seed,
        captured=captured,
        notify=tuple(notify),
        times_s=list(rec.times_s),
        knows=list(rec.column("knows")),
        admits=list(rec.column("admits")),
        routes=list(rec.column("routes")),
        member_count=len(others),
        learned_at_s=learned,
        hops_from_hq=hops,
        captured_flow=captured_flow,
        team_flow=team_flow,
        outsider_flows=outsider_flows,
        newcomer_joined_s=newcomer_s,
    )


def _first_true_after(rec, column: str, after_s: float) -> float | None:
    """Seconds after `after_s` at which `column` first reads true, or `None`."""
    for t, value in zip(rec.times_s, rec.column(column)):
        if t >= after_s and value:
            return round(t - after_s, 3)
    return None


@dataclass(frozen=True)
class NotifySweep:
    """Every seed's revocation under one way of delivering it."""

    label: str
    runs: tuple[CaptureRun, ...]

    @property
    def all_know_s(self) -> list[float]:
        return [r.all_know_s for r in self.runs if r.all_know_s is not None]

    @property
    def excluded_s(self) -> list[float]:
        return [r.excluded_s for r in self.runs if r.excluded_s is not None]


def run_sweep(seeds: Sequence[int] = SWEEP_SEEDS) -> list[NotifySweep]:
    """Revocation pushed to HQ alone vs. to every member, across seeds."""
    hq_only = tuple(run_capture(s, notify=(HQ,), joiners=False) for s in seeds)
    everyone = tuple(run_capture(s, notify=_ALL, joiners=False) for s in seeds)
    return [
        NotifySweep("pushed to HQ only", hq_only),
        NotifySweep("pushed to every member", everyone),
    ]


class _AllMembers(tuple):
    """Sentinel for "notify every member" — resolved inside `run_capture`
    once the captured relay is known."""


_ALL = _AllMembers()


def print_summary(run: CaptureRun, sweep: Sequence[NotifySweep]) -> None:
    print("Captured device — a relay is stolen; the operator revokes it at HQ only")
    print(f"  captured        : {run.captured} (revoked at {REVOKE_AT_S:.0f}s)")
    print(
        f"  all {run.member_count} members know  : {_fmt(run.all_know_s)} after the push"
    )
    print(
        f"  fully excluded  : {_fmt(run.excluded_s)} (no member admits or routes to it)"
    )
    print(
        f"  accepted after  : {run.accepted_after_exclusion} packets from the captured radio"
    )
    print(
        f"  team stream     : {_team_lost(run)} packets lost in the {TEAM_WINDOW_S:.0f} s after the push"
    )
    print()
    print("  would-be joiners (packets HQ accepted / sent):")
    for name, flow in run.outsider_flows.items():
        print(f"    {name:<14} {len(flow.received):>4} / {len(flow.sent)}")
    print(
        f"  new member's traffic accepted {_fmt(run.newcomer_joined_s)} after power-on"
    )
    print()
    for point in sweep:
        print(
            f"  {point.label:<24} all-know median {statistics.median(point.all_know_s):.2f}s "
            f"worst {max(point.all_know_s):.2f}s; excluded median "
            f"{statistics.median(point.excluded_s):.2f}s worst {max(point.excluded_s):.2f}s"
        )


TEAM_WINDOW_S = 10.0


def _team_lost(run: CaptureRun) -> int:
    """Team-stream packets sent in the window after the revocation that never
    arrived — the cost to honest traffic of cutting its relay out."""
    return sum(
        1
        for seq, t in run.team_flow.sent
        if REVOKE_AT_S <= t < REVOKE_AT_S + TEAM_WINDOW_S
        and seq not in run.team_flow.received
    )


def _fmt(value: float | None) -> str:
    return "never" if value is None else f"{value:.2f} s"


def delivery_timeline(
    flow: Flow, bin_s: float = 1.0
) -> tuple[list[float], list[float | None]]:
    """Per-bin delivery ratio of `flow`, binned on send time."""
    if not flow.sent:
        return [], []
    xs: list[float] = []
    ys: list[float | None] = []
    t = flow.sent[0][1]
    end = flow.sent[-1][1]
    while t <= end:
        xs.append(round(t + bin_s / 2, 3))
        ys.append(flow.delivery_ratio(t, t + bin_s - 1e-9))
        t += bin_s
    return xs, ys


def showcase(run: CaptureRun, sweep: Sequence[NotifySweep]) -> Showcase:
    """The results-page entry for this scenario."""
    window = [
        i
        for i, t in enumerate(run.times_s)
        if REVOKE_AT_S - 2.0 <= t <= REVOKE_AT_S + 6.0
    ]
    wt = [run.times_s[i] - REVOKE_AT_S for i in window]
    cap_x, cap_y = delivery_timeline(run.captured_flow)
    team_x, team_y = delivery_timeline(run.team_flow)
    learned = sorted(
        (
            (m, t, run.hops_from_hq.get(m))
            for m, t in run.learned_at_s.items()
            if t is not None
        ),
        key=lambda row: row[1],
    )
    hq_only = sweep[0]
    joiners = [*OUTSIDERS, NEWCOMER]
    joiner_labels = {
        OPEN_ROUTER: "open router, no credentials",
        FOREIGN: "valid cert, other mesh",
        EXPIRED: "expired cert",
        NEWCOMER: "new member (control)",
    }
    outsider_accepted = sum(len(run.outsider_flows[n].received) for n in OUTSIDERS)
    outsider_sent = sum(len(run.outsider_flows[n].sent) for n in OUTSIDERS)
    markers = [Marker(REVOKE_AT_S, "revocation pushed to HQ")]
    return Showcase(
        slug="captured-device",
        title="A radio is captured",
        category="security",
        scenario="sim/scenarios/captured_device.py",
        question="If someone steals one of our radios, how fast can we cut it off — and can an outsider get in at all?",
        headlines=[
            Headline(
                f"{statistics.median(hq_only.excluded_s):.1f} s",
                "to shut a captured radio out of the whole mesh",
                f"median over {len(hq_only.runs)} runs, revocation pushed to HQ alone; worst {max(hq_only.excluded_s):.1f} s",
            ),
            Headline(
                f"{outsider_accepted}",
                "outsider packets accepted",
                f"of {outsider_sent} sent by three would-be intruders",
            ),
            Headline(
                _fmt(run.newcomer_joined_s),
                "for a legitimate new radio to join",
                "from power-on, with no operator involvement",
            ),
        ],
        summary=(
            f"A captured radio is the hardest case. It holds a valid certificate and the matching key, "
            f"so to any cryptographic check it is a member. The operator revokes it by "
            f"pushing one signed record to the HQ gateway, and the mesh carries that record the rest of the way. "
            f"In the run charted here, all {run.member_count} other radios held the revocation "
            f"{_fmt(run.all_know_s)} after the push. From then on none of them admitted or routed to "
            f"the captured radio, and HQ accepted {run.accepted_after_exclusion} of its packets. The "
            f"field team's traffic had been relayed through the captured radio. It moved to another "
            f"path, losing {_team_lost(run)} packet{'' if _team_lost(run) == 1 else 's'} in the "
            f"{TEAM_WINDOW_S:.0f} s after the push. Meanwhile three outsiders streamed at HQ for the whole run: "
            f"an open router, a node with a flawless certificate from another mesh, and a lapsed member. "
            f"None of their packets were accepted. A genuinely new member's traffic was "
            f"accepted {_fmt(run.newcomer_joined_s)} after it switched on."
        ),
        method=(
            "Every node runs the real wayfinder router with mesh authentication on: Ed25519 membership "
            "certificates, signed routing adverts, pairwise-tagged unicast. Revocation is the "
            "production mechanism, a root-signed record re-flooded on the members' own adverts. The "
            "simulation never delivers it to anyone but HQ. Exclusion is the first instant at which no "
            "member both admits the captured radio and holds a route to it. Radios: 24 dBm, 700 m "
            f"range, one shared channel. Sweep: {len(SWEEP_SEEDS)} seeds per delivery mode."
        ),
        charts=[
            Chart(
                title="The revocation crossing the mesh",
                x_label="seconds after the push",
                y_label="members",
                series=[
                    Series(
                        "hold the revocation",
                        wt,
                        [run.knows[i] for i in window],
                        kind="step",
                    ),
                    Series(
                        "still admit the captured radio",
                        wt,
                        [run.admits[i] for i in window],
                        kind="step",
                    ),
                    Series(
                        "still route to it",
                        wt,
                        [run.routes[i] for i in window],
                        kind="step",
                    ),
                ],
                markers=[Marker(0.0, "pushed to HQ")],
                y_range=(0.0, float(run.member_count)),
            ),
            Chart(
                title="When each radio learned, by hops from HQ",
                x_label="hops from HQ",
                y_label="seconds after the push",
                series=[
                    Series(
                        "member",
                        [h for _, _, h in learned],
                        [t for _, t, _ in learned],
                        kind="scatter",
                    )
                ],
                caption="The order travels on routing adverts, so each hop adds roughly one advert interval.",
            ),
            Chart(
                title="Captured radio → HQ: packets accepted",
                x_label="time (s)",
                y_label="delivery ratio",
                series=[Series("captured radio's stream", cap_x, cap_y, kind="step")],
                markers=markers,
                y_range=(0.0, 1.0),
            ),
            Chart(
                title="Field team → HQ, which the captured radio was relaying",
                x_label="time (s)",
                y_label="delivery ratio",
                series=[Series("team stream", team_x, team_y, kind="step")],
                markers=markers,
                y_range=(0.0, 1.0),
            ),
            Chart(
                title="Would-be joiners: packets HQ accepted",
                x_label="who",
                y_label="packets",
                series=[
                    Series(
                        "accepted",
                        [joiner_labels[n] for n in joiners],
                        [float(len(run.outsider_flows[n].received)) for n in joiners],
                        kind="bar",
                    ),
                    Series(
                        "sent",
                        [joiner_labels[n] for n in joiners],
                        [float(len(run.outsider_flows[n].sent)) for n in joiners],
                        kind="bar",
                    ),
                ],
                caption=f"The new member is switched on at {NEWCOMER_ON_S:.0f} s, so it sends nothing before then.",
            ),
        ],
        table=[
            [
                "delivery",
                "median all-know (s)",
                "worst all-know (s)",
                "median excluded (s)",
                "worst excluded (s)",
            ]
        ]
        + [
            [
                p.label,
                round(statistics.median(p.all_know_s), 2),
                round(max(p.all_know_s), 2),
                round(statistics.median(p.excluded_s), 2),
                round(max(p.excluded_s), 2),
            ]
            for p in sweep
        ],
        params={
            "members": ROWS * COLS,
            "grid_spacing_m": SPACING_M,
            "revoke_at_s": REVOKE_AT_S,
            "stream_rate_hz": RATE_HZ,
            "seeds": len(SWEEP_SEEDS),
        },
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument(
        "--export", type=Path, help="write showcase JSON into this directory"
    )
    parser.add_argument(
        "--quick", action="store_true", help="three seeds per sweep point"
    )
    args = parser.parse_args(argv)
    wf.init_tracing()

    run = run_capture()
    sweep = run_sweep(SWEEP_SEEDS[:3] if args.quick else SWEEP_SEEDS)
    print_summary(run, sweep)
    if args.export:
        print(f"wrote {write_showcase(showcase(run, sweep), args.export)}")


if __name__ == "__main__":
    main()
