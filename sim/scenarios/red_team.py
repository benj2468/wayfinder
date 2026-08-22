"""Red-team scenario: an authenticated mesh under attack.

Stands up a real mesh — a mesh root, per-node membership certificates, signed
OGMs — and runs a battery of attacks against it, each as its own isolated
simulation. Every attack ends in one of three verdicts:

* ``HELD``      — the mesh rejected it. The guarantee holds.
* ``BY DESIGN`` — the attack succeeded, and is supposed to. Wayfinder
  authenticates and segregates; it never encrypts. An attack that only reads
  the wire has confirmed the threat model, not broken it.
* ``GAP``       — the attack succeeded in a way the design does not intend to
  allow. These are the findings.

Every verdict is *measured*, never assumed: each attack asserts against the
router's own state, so a regression turns a ``HELD`` into a ``GAP`` rather
than quietly passing.

Two notes on reading the results:

* Membership is asked of ``Simulation.admitted`` (verified certificates) and
  ``Simulation.has_route`` (learned routes), never of ``route_via`` /
  ``reachable``. Route resolution falls back to the link-quality table, which
  is written when a frame is *received* — before its signature is judged — so
  it resolves an interface even for a peer whose every OGM was rejected.
* An attacker is not a node with a router. It is `wayfinder_sim.forge` bytes
  put on the medium with ``Simulation.inject``, which asks nothing of anyone's
  routing stack — the way a real one works.

Run: ``uv run --group sim python sim/scenarios/red_team.py``
"""

from __future__ import annotations

import dataclasses
import random
from collections.abc import Callable

import wayfinder_py as wf
from wayfinder_sim import forge
from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.security import Credential, Mesh
from wayfinder_sim.topology import pair, shared_lan

MESH_ROOT_SEED = bytes([0xA5]) * 32
"""Fixed mesh root, so a run is reproducible and MACs are stable between
runs — which matters when comparing one report against another."""

FOREIGN_ROOT_SEED = bytes([0x5A]) * 32
"""A second, entirely unrelated mesh root. Its certificates are structurally
perfect and must still be refused."""

MESH_ID = 0xABCD

HELD = "HELD"
BY_DESIGN = "BY DESIGN"
GAP = "GAP"


@dataclasses.dataclass
class Finding:
    """One attack's outcome."""

    name: str
    verdict: str
    detail: str
    """What was actually observed — the measurement, not the intent."""


def mesh() -> Mesh:
    """The mesh under test."""
    return Mesh(mesh_id=MESH_ID, root_seed=MESH_ROOT_SEED)


def foreign_mesh() -> Mesh:
    """An unrelated mesh, for an intruder with valid-looking papers."""
    return Mesh(mesh_id=MESH_ID, root_seed=FOREIGN_ROOT_SEED)


def _members(*names: str) -> list[Node]:
    return [Node(name, credential=Credential()) for name in names]


def _capture_signed_ogm() -> tuple[bytes, wf.PyMac]:
    """Run a legitimate two-node mesh with a listener on the segment, and
    return one genuine signed OGM body from `hq` plus `hq`'s MAC.

    This is the attacker's raw material for every replay-flavoured attack
    below, and it costs nothing to obtain: the mesh broadcasts it.
    """
    m = mesh()
    nodes = [*_members("hq", "relay"), Node("eve")]
    sim = Simulation(nodes, shared_lan(["hq", "relay", "eve"], PerfectWire()), mesh=m)
    tap = sim.wiretap("hq-relay-eve")
    sim.run(until_s=20.0)
    ogms = [f for f in tap.of_type(forge.PACKET_OGM) if f.src == sim.mac("hq")]
    if not ogms:
        raise RuntimeError("captured no signed OGM — the mesh did not converge")
    return ogms[-1].payload, sim.mac("hq")


# --- attacks ------------------------------------------------------------


def attack_unauthenticated_joiner() -> Finding:
    """An outsider running a stock, open router next to the mesh."""
    m = mesh()
    nodes = [*_members("hq"), Node("intruder")]
    sim = Simulation(nodes, [pair("hq", "intruder", PerfectWire())], mesh=m)
    sim.run(until_s=30.0)

    admitted = sim.admitted("hq")
    routed = sim.has_route("hq", "intruder")
    ok = not admitted and not routed
    return Finding(
        "Unauthenticated joiner",
        HELD if ok else GAP,
        f"hq admitted {admitted or 'nobody'}; route to intruder: {routed}",
    )


def attack_foreign_mesh() -> Finding:
    """A node holding a structurally valid certificate from another root."""
    m = mesh()
    nodes = [
        *_members("hq"),
        Node("intruder", credential=Credential(mesh=foreign_mesh())),
    ]
    sim = Simulation(nodes, [pair("hq", "intruder", PerfectWire())], mesh=m)
    sim.run(until_s=30.0)

    admitted = sim.admitted("hq")
    ok = not admitted and not sim.has_route("hq", "intruder")
    return Finding(
        "Foreign-mesh credential",
        HELD if ok else GAP,
        f"hq admitted {admitted or 'nobody'} despite a well-formed foreign cert",
    )


def attack_forged_ogm() -> Finding:
    """Hand-built OGMs claiming an invented originator, with no signature —
    the attack an open mesh has no answer to at all."""
    ghost = wf.PyMac(b"\x02\x00\x00\x00\x00\xc8")

    def run(with_mesh: Mesh | None) -> bool:
        nodes = (
            [*_members("hq"), Node("eve")] if with_mesh else [Node("hq"), Node("eve")]
        )
        sim = Simulation(nodes, [pair("hq", "eve", PerfectWire())], mesh=with_mesh)
        for i in range(60):
            sim.inject(
                "eve",
                forge.link_frame(
                    wf.PyMac.BROADCAST, ghost, forge.ogm(orig=ghost, seqno=i + 1)
                ),
                at_s=0.5 + i * 0.25,
            )
        sim.record("route", lambda s: s.has_route("hq", ghost))
        return any(sim.run(until_s=20.0).column("route"))

    open_mesh_fooled = run(None)
    authed_fooled = run(mesh())
    return Finding(
        "Forged OGM (invented originator)",
        HELD if not authed_fooled else GAP,
        f"open mesh accepts it: {open_mesh_fooled}; authenticated mesh accepts it: {authed_fooled}",
    )


def attack_passive_eavesdrop() -> Finding:
    """A listener on the segment reading application payloads."""
    m = mesh()
    nodes = _members("hq", "field")
    sim = Simulation(nodes, shared_lan(["hq", "field"], PerfectWire()), mesh=m)
    tap = sim.wiretap("hq-field")
    sim.run(until_s=20.0)
    sim.send("hq", "field", b"MEETING AT DAWN", at_s=21.0)
    sim.run(until_s=25.0)

    read = bool(tap.containing(b"MEETING AT DAWN"))
    return Finding(
        "Passive eavesdropping",
        BY_DESIGN if read else HELD,
        (
            "payload readable in the clear off an authenticated mesh — "
            "wayfinder authenticates, it does not encrypt; confidentiality is L3's job"
            if read
            else "payload not observable (unexpected — wayfinder does not encrypt)"
        ),
    )


def attack_ogm_replay() -> Finding:
    """Replay one captured, genuinely-signed OGM at a node that has never met
    its originator — a node that just booted, or one out of the real
    originator's range."""
    body, hq_mac = _capture_signed_ogm()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    frame = forge.link_frame(wf.PyMac.BROADCAST, hq_mac, body)
    for i in range(60):
        sim.inject("eve", frame, at_s=0.5 + i * 0.3)
    sim.record("route", lambda s: s.has_route("victim", hq_mac))
    rec = sim.run(until_s=25.0)

    fooled = any(rec.column("route"))
    return Finding(
        "OGM replay (absent originator)",
        GAP if fooled else HELD,
        (
            "a single captured signed OGM presents an absent node as present; "
            "seqno replay protection is per-receiver state, so it does not cover "
            "a receiver that has none"
            if fooled
            else "replayed OGM rejected"
        ),
    )


def attack_unauthenticated_relay() -> Finding:
    """The sharpest form: an outsider re-floods a member's captured signed OGM
    under its *own* link-layer source, claiming to be a relay for it.

    The OGM is genuine, so it verifies. Only the forwarder is unauthenticated
    — and BATMAN's forwarding model has every relay do exactly this.
    """
    body, hq_mac = _capture_signed_ogm()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    eve_mac = sim.mac("eve")
    relayed = bytearray(body)
    relayed[2] = 250  # TTL is a mutable per-hop field, excluded from the signature
    frame = forge.link_frame(wf.PyMac.BROADCAST, eve_mac, bytes(relayed))
    for i in range(80):
        sim.inject("eve", frame, at_s=0.5 + i * 0.3)
    sim.run(until_s=25.0)

    poisoned = sim.has_route("victim", hq_mac)
    next_hops = {
        str(path.neighbor)
        for record in sim.driver("victim").originator_table()
        if record.originator == hq_mac
        for path in record.paths
    }
    eve_is_next_hop = str(eve_mac) in next_hops
    eve_admitted = eve_mac in sim.driver("victim").neighbor_macs()

    # Does anything actually flow through the poisoned next hop?
    tap = sim.wiretap("victim-eve")
    sim.driver("victim").queue_local_send(hq_mac, b"SENSITIVE TRAFFIC")
    sim.run(until_s=31.0)
    intercepted = bool(tap.containing(b"SENSITIVE TRAFFIC"))

    if intercepted:
        verdict, detail = GAP, "outsider both attracts and reads member traffic"
    elif poisoned and eve_is_next_hop:
        verdict = GAP
        detail = (
            "outsider installs itself as next hop for a member it cannot "
            f"impersonate (admitted={eve_admitted}); traffic is then dropped at "
            "dispatch for want of a pairwise key — a silent blackhole, not "
            "interception"
        )
    else:
        verdict, detail = HELD, "relayed OGM did not poison the route table"
    return Finding("Unauthenticated OGM relay", verdict, detail)


def attack_expired_credential() -> Finding:
    """A member whose enrollment lapses mid-run."""
    m = mesh()
    nodes = [
        Node("hq", credential=Credential()),
        Node("lapsed", credential=Credential(valid_until_s=10.0)),
    ]
    sim = Simulation(nodes, [pair("hq", "lapsed", PerfectWire())], mesh=m)
    sim.run(until_s=40.0)

    routed = sim.has_route("hq", "lapsed")
    still_admitted = "lapsed" in sim.admitted("hq")
    sim.send("hq", "lapsed", b"POST-EXPIRY", at_s=41.0)
    sim.run(until_s=45.0)
    data_flows = sim.poll_local("lapsed") == b"POST-EXPIRY"

    if not routed and not data_flows:
        verdict, detail = HELD, "expired member fully cut off"
    else:
        verdict = GAP
        detail = (
            f"route purged: {not routed}, but the neighbor cache still holds the "
            f"expired cert (admitted: {still_admitted}) and the link-local data "
            f"plane still authenticates with its pairwise key (delivered: {data_flows})"
        )
    return Finding("Expired credential", verdict, detail)


def attack_revocation() -> Finding:
    """An insider turns bad and the root purges it."""
    m = mesh()
    nodes = _members("hq", "field", "rogue")
    links = [
        pair("hq", "field", PerfectWire()),
        pair("hq", "rogue", PerfectWire()),
        pair("field", "rogue", PerfectWire()),
    ]
    sim = Simulation(nodes, links, mesh=m)
    sim.run(until_s=20.0)
    before = "rogue" in sim.admitted("hq")

    sim.revoke("rogue")
    sim.run(until_s=60.0)
    after = "rogue" in sim.admitted("hq")
    routed = sim.has_route("hq", "rogue")

    ok = before and not after and not routed
    return Finding(
        "Revocation of a member",
        HELD if ok else GAP,
        f"admitted before: {before}, after: {after}, route after: {routed}",
    )


def attack_ca_misissuance() -> Finding:
    """A certificate naming one node's MAC over another's key.

    Verification checks the root's signature, not that the MAC derives from
    the key — so an authority that will sign this hands out impersonation.
    The router is not the control here; issuance policy is.
    """
    m = mesh()
    victim_mac = m.keypair("hq").derived_mac
    nodes = [
        Node("hq", credential=Credential()),
        Node("field", credential=Credential()),
        # An attacker whose cert claims hq's address over the attacker's key.
        Node("imposter", credential=Credential(claim_mac=victim_mac)),
    ]
    links = [
        pair("hq", "field", PerfectWire()),
        pair("field", "imposter", PerfectWire()),
    ]
    try:
        sim = Simulation(nodes, links, mesh=m)
    except ValueError as exc:  # pragma: no cover — defensive
        return Finding("CA misissuance (impersonation)", HELD, str(exc))
    sim.run(until_s=30.0)

    fooled = victim_mac in sim.driver("field").neighbor_macs()
    return Finding(
        "CA misissuance (impersonation)",
        GAP if fooled else HELD,
        (
            "a cert binding a key to a MAC it does not derive is accepted — "
            "impersonation resistance rests entirely on the CA refusing to "
            "issue one, not on the router"
            if fooled
            else "router rejected a MAC/key mismatch on its own"
        ),
    )


def attack_flood() -> Finding:
    """A storm of garbage and forged frames, while the mesh must keep routing.

    The question is not whether the frames are accepted — they are not,
    whether they arrive once or ten thousand times — but what the cost of
    rejecting them does to a mesh carrying real traffic through the noise.
    """
    m = mesh()
    nodes = [*_members("hq", "field"), Node("eve")]
    links = [
        pair("hq", "field", PerfectWire()),
        pair("hq", "eve", PerfectWire()),
    ]
    sim = Simulation(nodes, links, mesh=m)
    sim.run(until_s=20.0)
    converged_before = sim.has_route("hq", "field")

    rng = random.Random(0)
    ghost = wf.PyMac(b"\x02\x00\x00\x00\x00\xc8")
    counter = iter(range(1, 10**9))

    def storm() -> bytes:
        if rng.random() < 0.5:
            return forge.garbage(rng, min_len=20, max_len=400)
        return forge.link_frame(
            wf.PyMac.BROADCAST, ghost, forge.ogm(orig=ghost, seqno=next(counter))
        )

    sim.flood("eve", storm, rate_hz=500, start_s=21.0, duration_s=10.0)
    sim.record("route", lambda s: s.has_route("hq", "field"))
    rec = sim.run(until_s=33.0)

    sim.send("hq", "field", b"UNDER FIRE", at_s=33.5)
    sim.run(until_s=38.0)
    delivered = sim.poll_local("field") == b"UNDER FIRE"

    held_route = all(rec.column("route"))
    ghost_learned = sim.has_route("hq", ghost)
    ok = converged_before and held_route and delivered and not ghost_learned
    return Finding(
        "Flood / DoS (500 fps of garbage and forged OGMs)",
        HELD if ok else GAP,
        f"route to field held throughout: {held_route}; real traffic still "
        f"delivered: {delivered}; forged originator learned: {ghost_learned}",
    )


ATTACKS: list[Callable[[], Finding]] = [
    attack_unauthenticated_joiner,
    attack_foreign_mesh,
    attack_forged_ogm,
    attack_revocation,
    attack_flood,
    attack_passive_eavesdrop,
    attack_expired_credential,
    attack_ogm_replay,
    attack_unauthenticated_relay,
    attack_ca_misissuance,
]


def run_all() -> list[Finding]:
    """Run every attack, each against its own freshly built mesh so no attack
    can contaminate the next."""
    return [attack() for attack in ATTACKS]


def print_report(findings: list[Finding]) -> None:
    order = {HELD: 0, BY_DESIGN: 1, GAP: 2}
    width = max(len(f.name) for f in findings)
    print("\n=== Wayfinder red team ===\n")
    for finding in sorted(findings, key=lambda f: (order[f.verdict], f.name)):
        print(f"  [{finding.verdict:^9}] {finding.name:<{width}}  {finding.detail}")

    counts = {verdict: sum(f.verdict == verdict for f in findings) for verdict in order}
    print(
        f"\n  {counts[HELD]} held, {counts[BY_DESIGN]} by design, {counts[GAP]} gap(s)\n"
    )


def main() -> None:
    wf.init_tracing()  # quiet by default; set RUST_LOG to watch the rejections
    print_report(run_all())


if __name__ == "__main__":
    main()
