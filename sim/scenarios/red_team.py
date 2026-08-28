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

Two outputs, from one battery: a console table for the terminal you ran it
in, and ``output/red_team_report.html`` — a single self-contained page that
leads with the gaps and then walks every attack, carrying each one's own
docstring as the explanation of what was attempted. The page is what gets
handed to someone who was not at the terminal.

Run: ``uv run --group sim python sim/scenarios/red_team.py``
"""

from __future__ import annotations

import dataclasses
import inspect
import itertools
import random
import struct
from collections.abc import Callable, Sequence
from pathlib import Path

import wayfinder_py as wf
from wayfinder_sim import forge
from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.node import Node
from wayfinder_sim.report import (
    BY_DESIGN,
    GAP,
    HELD,
    FindingReport,
    write_red_team_report,
)
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

# `HELD` / `BY_DESIGN` / `GAP` come from `wayfinder_sim.report` rather than
# being spelled again here: the page ranks, colours and tallies by those exact
# strings, so a second copy of them would let a rename on this side render as
# an unclassified row on that one instead of failing.


@dataclasses.dataclass
class Finding:
    """One attack's outcome."""

    name: str
    verdict: str
    detail: str
    """What was actually observed — the measurement, not the intent."""

    description: str = ""
    """What was attempted, and why it should have failed.

    Filled in by `described` from the attack function's own docstring, so an
    attack never restates its rationale for the report's benefit — the prose
    stays next to the code that implements it, where it is maintained.
    """


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
    originator's range.

    Held by the next-hop proof, not by anything about the OGM: the replay still
    verifies and is still learned as a path. It simply cannot be *selected*,
    because the address it spoofs would have to answer a challenge with a
    pairwise key the attacker does not hold. See
    ``docs/design/09-mesh-auth-gaps.md`` §4.
    """
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
            else "replayed OGM is accepted for path learning — its signature is "
            "genuine and covers no freshness — but the spoofed next hop cannot "
            "answer a challenge, so it never becomes a usable route"
        ),
    )


def attack_ogm_replay_hijacks_local_traffic() -> Finding:
    """The interception `attack_ogm_replay` doesn't test: even though a
    replayed OGM cannot win `best_next_hop` (§4), can it still make the
    *victim's own locally-originated traffic* leak to the attacker?

    Eve replays hq's captured, genuinely-signed OGM under hq's own spoofed
    link-layer source — unlike `attack_unauthenticated_relay`, which spoofs
    her *own* identity as the relay. That distinction is what makes this a
    different attack surface: the link-quality table's entry for hq's own MAC
    now points at Eve's link, written on receipt before any authentication
    verdict. `victim` still holds hq's real pairwise key regardless — an
    OGM's signature attests its originator no matter who relayed it — so a
    locally-originated send to hq tags correctly under that real key. The
    only open question is which physical interface it goes out on, and
    that's a route decision, not a tagging one: it must be refused the same
    way forwarding through an unproven next hop already is (§4), or the
    proof gate protects relayed traffic while leaving the node's own traffic
    exposed to exactly the interception the whole feature exists to close.
    """
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
    sim.run(until_s=25.0)

    tap = sim.wiretap("victim-eve")
    sim.driver("victim").queue_local_send(hq_mac, b"SENSITIVE TRAFFIC")
    sim.run(until_s=31.0)
    intercepted = bool(tap.containing(b"SENSITIVE TRAFFIC"))

    return Finding(
        "OGM replay hijacks locally-originated traffic",
        GAP if intercepted else HELD,
        (
            "victim's own send to hq is silently addressed to hq directly and "
            "dispatched over whatever interface the spoofed identity poisoned "
            "-- Eve's link -- leaking a real payload she cannot forge but can "
            "read (payloads are never encrypted, only authenticated)"
            if intercepted
            else "a route whose next hop has not proven itself is refused for "
            "locally-originated sends too, not only for forwarding: the send "
            "is dropped rather than silently addressed to an unproven "
            "destination over a route the spoof poisoned"
        ),
    )


def attack_forged_challenge_response_flood() -> Finding:
    """Eve, holding no credential at all, blasts next-hop-proof *responses*
    claiming to answer for hq — without ever holding hq's pairwise key to
    compute a real one.

    hq is captured off the air the same way as `_capture_signed_ogm`'s other
    callers: victim genuinely verifies hq's own signature (an OGM's signature
    attests nothing about who relays it — gap 1/2), so victim keeps hq as a
    candidate next hop and keeps challenging it. hq itself is never live in
    this topology, so every challenge sits outstanding and unanswered —
    exactly the gap Eve is trying to fill by volume instead of by key: can
    enough guesses, or just enough noise, ever satisfy a `frame_tag` neither
    verifies without the real pairwise secret?
    """
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
    sim.run(until_s=25.0)  # converge, and let victim issue its first real challenge

    victim_mac = sim.mac("victim")
    rng = random.Random(0xE7E)

    def forged_response() -> bytes:
        tag = bytes(rng.getrandbits(8) for _ in range(16))
        return forge.link_frame(victim_mac, hq_mac, forge.next_hop_response(tag))

    sim.flood("eve", forged_response, rate_hz=500, start_s=25.5, duration_s=10.0)
    sim.run(until_s=40.0)

    proven = sim.driver("victim").proof_current(hq_mac)
    return Finding(
        "Forged challenge-response flood",
        GAP if proven else HELD,
        (
            "5,000 forged responses, none computed over hq's real pairwise "
            "key, still satisfied an outstanding challenge"
            if proven
            else "every forged tag failed verification -- the pairwise key "
            "Eve does not hold is the only thing that can ever answer a "
            "challenge, however many guesses she sends"
        ),
    )


def attack_broadcast_addressed_challenge() -> Finding:
    """Eve, holding no credential, sends a next-hop-proof *challenge* to the
    broadcast address while spoofing hq as its source.

    The pairwise trailer that authenticates every directed frame is skipped
    for a multicast destination — broadcasts and OGMs carry their own
    signature instead — and the destination MAC is Eve's to choose. So a
    broadcast-addressed challenge reaches the proof handler having been
    authenticated by nothing at all. If victim answers it, an outsider has an
    unauthenticated reflection primitive: one forged frame in, one tagged
    response out, burning shared-medium airtime and a pairwise counter per
    frame, at whatever rate the medium allows.

    Measured by whether victim actually puts a response on Eve's link.
    """
    body, hq_mac = _capture_signed_ogm()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    # victim verifies hq's certificate off the relayed OGM, so it holds hq's
    # pairwise key — the precondition for `answer_challenge` to succeed at all.
    relayed = forge.link_frame(wf.PyMac.BROADCAST, hq_mac, body)
    for i in range(20):
        sim.inject("eve", relayed, at_s=0.5 + i * 0.3)
    sim.run(until_s=20.0)

    tap = sim.wiretap("victim-eve")  # fresh: only frames from here on
    rng = random.Random(0xB0A)
    nonce = bytes(rng.getrandbits(8) for _ in range(16))
    forged = forge.link_frame(
        wf.PyMac.BROADCAST, hq_mac, forge.next_hop_challenge(nonce)
    )
    for i in range(20):
        sim.inject("eve", forged, at_s=20.5 + i * 0.25)
    sim.run(until_s=28.0)

    victim_mac = sim.mac("victim")
    answered = [
        f for f in tap.of_type(forge.PACKET_NEXT_HOP_RESPONSE) if f.src == victim_mac
    ]
    return Finding(
        "Broadcast-addressed next-hop challenge",
        GAP if answered else HELD,
        (
            f"victim answered {len(answered)} of 20 unauthenticated broadcast "
            "challenges -- a keyless outsider can reflect a tagged response "
            "out of any member on demand"
            if answered
            else "every broadcast-addressed challenge was refused before it "
            "reached the proof handler -- a proof frame not addressed to this "
            "node is malformed by construction"
        ),
    )


def attack_challenge_response_replay() -> Finding:
    """Eve captures one genuine next-hop-proof response — bob answering
    victim's real challenge, over the real victim-bob link — and blasts
    those exact bytes at victim from her own, separate link.

    `verify_challenge_response` consumes the outstanding challenge on
    success, so a captured response is supposed to prove liveness exactly
    once (design doc §4): "accepting a replay would let an attacker that
    observed a single exchange keep a route alive without the neighbor ever
    participating again." Whether victim still reads hq as proven afterward
    can't tell the two apart — bob keeps answering for real regardless of
    what Eve does — so the sharper question is whether the replay ever gets
    *credited*: `note_proven` also records which interface answered, and
    egress trusts that over the (spoofable) link-quality table precisely
    because an answered challenge is supposed to be unforgeable. If Eve's
    replay were accepted, real traffic addressed to bob would follow it onto
    her link instead of bob's.
    """
    m = mesh()
    sim = Simulation(
        [
            Node("victim", credential=Credential()),
            Node("bob", credential=Credential()),
            Node("eve"),
        ],
        [pair("victim", "bob", PerfectWire()), pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    tap = sim.wiretap("victim-bob")
    sim.run(until_s=30.0)  # converge, and let a real challenge/response complete

    bob_mac = sim.mac("bob")
    responses = [
        f for f in tap.of_type(forge.PACKET_NEXT_HOP_RESPONSE) if f.src == bob_mac
    ]
    if not responses:
        raise RuntimeError(
            "captured no genuine next-hop response -- bob never proved itself"
        )
    captured = responses[-1].raw

    sim.flood("eve", lambda: captured, rate_hz=200, start_s=30.5, duration_s=5.0)
    sim.run(until_s=36.0)

    eve_tap = sim.wiretap("victim-eve")  # fresh: only frames from here on
    sim.send("victim", "bob", b"SENSITIVE TRAFFIC", at_s=36.5)
    sim.run(until_s=41.0)

    hijacked = bool(eve_tap.containing(b"SENSITIVE TRAFFIC"))
    delivered = sim.poll_local("bob") == b"SENSITIVE TRAFFIC"
    return Finding(
        "Next-hop challenge-response replay",
        GAP if hijacked else HELD,
        (
            "the replayed response got credited: real traffic addressed to "
            "bob followed it onto eve's link instead"
            if hijacked
            else f"1,000 replays of the exact captured bytes never got "
            f"credited -- traffic to bob still delivered over the real link: "
            f"{delivered}"
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
        verdict = HELD
        detail = (
            "outsider is still recorded as a path — discovery must keep "
            "working — but holds no pairwise key, so it can never answer a "
            "next-hop challenge and never wins best_next_hop"
        )
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

    if not routed and not data_flows and not still_admitted:
        verdict = HELD
        detail = (
            "expired member fully cut off: route purged, cert evicted from the "
            "neighbor cache, and no pairwise key left to carry its traffic"
        )
    else:
        verdict = GAP
        detail = (
            f"route purged: {not routed}, still admitted: {still_admitted}, "
            f"link-local data still delivered: {data_flows}"
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


def attack_proof_starvation_by_neighbour_count() -> Finding:
    """More concurrent proof candidates than the prover's table has slots.

    Every next hop must answer a challenge before it is selectable, and
    ``poll_due_challenges`` issues to *every* due candidate in one synchronous
    pass — no response can arrive until the pass ends. If the outstanding-proof
    table is smaller than the number of candidates in that pass,
    ``issue_challenge`` evicts the least-recently-issued entry, the earliest
    candidates lose their challenge before their answer comes back, the answer
    is refused as "nothing outstanding", and no route through that neighbour is
    ever selectable.

    Not attacker-driven — it needs no forged frame at all, only a mesh denser
    than the table. That is what makes it worth tracking: a dense but entirely
    legitimate deployment would silently lose routes, and the only evidence is
    trace-level lines on two different nodes that have to be correlated.

    The density is ``MAX_NEIGHBOR_KEYS``, not a literal: that is the most
    neighbours a node can hold verified keys for at all, so it is also the most
    proof candidates it can ever face at once — the worst case the table has to
    survive. ``MAX_IN_PROGRESS_PROOF`` is deliberately a quarter of it, so this
    density *does* evict; the assertion below states that relationship rather
    than assuming it.

    It has to be that dense to measure anything. Below it the mesh converges no
    matter how small the table is — with a *single* slot, 48 spokes and fewer
    all still route every neighbour — so a cheaper version of this scenario
    would report a pass having tested nothing. The cost is real and it is the
    flooding, not the crypto: a segment of mutual neighbours is a complete
    graph and a flood goes out every interface, so each node receives ~N²
    copies per round and the mesh carries ~N³.

    What is trimmed instead is the horizon. Starvation shows up early — by 20 s
    a single-slot table has left 4 of 64 neighbours unproven while the real
    table has proven all 64 — and running to 40 s only widens that to 11, for
    double the wall time. So the run stops at 20 s: enough for the signal, not
    for the margin.

    The mesh holds at this density because an evicted challenge is never
    answered and an unanswered challenge is retried on a backoff: eviction
    costs a round trip, not a route. What the table has to satisfy is only that
    concurrent proof throughput stay above the renewal rate, and this catches a
    table small enough to fall under it — nothing finer. Read a pass as "not
    grossly mis-sized", not as "this size is right".

    They must all be *mutual* neighbours of the prover simultaneously, so this
    is one shared segment rather than a star of point-to-point links: a star
    would need one router interface per spoke and ``MAX_INTERFACES`` is 8, so
    it would measure the interface table instead — which is what an earlier
    version of this scenario did, reporting a gap that had nothing to do with
    proofs.
    """
    hub = "hub"
    spokes = [f"spoke{i}" for i in range(wf.MAX_NEIGHBOR_KEYS)]
    assert len(spokes) > wf.MAX_IN_PROGRESS_PROOF, (
        "a density at or under MAX_IN_PROGRESS_PROOF evicts nothing, so this "
        "scenario would report a pass having tested nothing"
    )
    m = mesh()
    nodes = [Node(hub, credential=Credential())]
    nodes += [Node(s, credential=Credential()) for s in spokes]
    sim = Simulation(nodes, shared_lan([hub, *spokes], PerfectWire()), mesh=m)
    sim.run(until_s=20.0)

    starved = [s for s in spokes if not sim.has_route(hub, s)]
    return Finding(
        "Proof starvation by neighbour count",
        GAP if starved else HELD,
        (
            f"{len(starved)} of {len(spokes)} fully credentialed neighbours "
            f"never became usable next hops ({', '.join(starved[:4])}"
            f"{', …' if len(starved) > 4 else ''}) — more concurrent "
            "candidates than MAX_IN_PROGRESS_PROOF can hold, so in-flight "
            "challenges are evicted before their answers arrive"
            if starved
            else f"all {len(spokes)} neighbours — the most a node can hold "
            "keys for, so the most proofs it can ever owe at once — proved "
            "themselves and routed"
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


# ----------------------------------------------------------------------
# New attack batteries (2026-08 red-team sweep). Each battery attacks a
# distinct surface; every verdict is measured against the router's own
# state, and each attack's docstring is its hypothesis (what was attempted
# and why it should fail), rendered into the report alongside the result.
# ----------------------------------------------------------------------
# ======================================================================
# Battery 2 — certificate issuance, identity binding, enrollment
# ======================================================================

# --- the missing forge primitive ---------------------------------------

SIG_DOMAIN = b"wf-ogm-sig-v1"
"""`OgmAuth::SIG_DOMAIN` — the domain prefix bound into an OGM signature."""

TVLV_CERT = 0x80
TVLV_OGM_SIG = 0x81
"""`batman::wire::TvlvType::{Cert, OgmSig}` on-wire type bytes."""


def signed_ogm(
    keypair: wf.PyKeypair,
    cert: wf.PyMembershipCert,
    orig: wf.PyMac,
    seqno: int,
    *,
    ttl: int = 50,
    tq: int = 255,
) -> bytes:
    """A **fully verifying** OGM claiming `orig`, signed by `keypair`, carrying
    `cert`.

    `verify_ogm` accepts this iff `cert.node_mac == orig` and `keypair` is the
    key the cert binds — so `orig` is whatever MAC the CA was talked into
    naming, and the key is one the attacker holds (unlike a captured replay).
    The signed message mirrors `OgmAuth::signed_message`:
    `SIG_DOMAIN ‖ orig(6) ‖ seqno(4 BE) ‖ cert_bytes`.
    """
    cert_bytes = bytes(cert)
    signed = (
        SIG_DOMAIN
        + bytes(orig.bytes)
        + (seqno & 0xFFFF_FFFF).to_bytes(4, "big")
        + cert_bytes
    )
    sig = bytes(keypair.sign(signed))
    tail = forge.tvlv(TVLV_CERT, cert_bytes) + forge.tvlv(TVLV_OGM_SIG, sig)
    return forge.ogm(orig=orig, seqno=seqno, ttl=ttl, tq=tq, tvlv=tail)


# Attacker identity used across attacks (a key the attacker holds).
EVE_SEED = bytes([0xEE]) * 32


def _mint(m, claim_mac: wf.PyMac, seed: bytes = EVE_SEED, **window):
    """A CA-signed cert binding a key the attacker holds to `claim_mac`.

    `claim_mac != derive_mac(key)` is the misissuance (gap 4); the CA in this
    simulator will sign it, which is the whole precondition every attack here
    stands on. Returns `(keypair, cert)`.
    """
    kp = wf.PyKeypair.from_seed(seed)
    window.setdefault("valid_from_s", -1000.0)
    window.setdefault("valid_until_s", 100_000.0)
    cert = m.enroll(kp, claim_mac=claim_mac, **window)
    return kp, cert


# --- attacks ------------------------------------------------------------


def attack_reserved_address_originator() -> Finding:
    """A misissued cert binding an attacker key to a **reserved** address —
    the broadcast MAC, the all-zeros MAC, a multicast/group MAC — and a
    fully-signed OGM originating from it.

    None of these is a deliverable unicast host. The broadcast and multicast
    bits mean "every node / a group", and all-zeros is the null address; no
    node can *own* one, so no certificate should ever bind one, and even if a
    misissuing CA signs it (gap 4 lets it name any MAC) the verifier should
    refuse to admit a reserved address as a mesh member. `verify_cert` checks
    only version/mesh/signature/window and `verify_ogm` only that
    `cert.node_mac == orig` — neither asks whether the address is a legal
    unicast — so the concern is that a reserved address lands in the neighbor
    cache and the originator table, an address-type confusion the routing and
    flooding logic never expected to see as an *originator*.

    Measured by whether the victim admits the reserved MAC as a verified
    neighbour (`neighbor_macs`) — admission alone caches a pairwise key against
    it and would make a directed frame purporting to come from it verifiable.
    A usable route additionally needs a next-hop proof the injector cannot
    answer, so admission, not `has_route`, is the sharp signal.
    """
    reserved = {
        "broadcast": wf.PyMac.BROADCAST,
        "all-zeros": wf.PyMac(bytes(6)),
        "multicast": wf.PyMac(bytes([0x01, 0x00, 0x5E, 0x00, 0x00, 0x2A])),
    }
    admitted_names: list[str] = []
    routed_names: list[str] = []
    for i, (label, addr) in enumerate(reserved.items()):
        m = mesh()
        sim = Simulation(
            [Node("victim", credential=Credential()), Node("eve")],
            [pair("victim", "eve", PerfectWire())],
            mesh=m,
        )
        eve_kp, cert = _mint(m, addr, seed=bytes([0xE0 + i]) * 32)
        eve_mac = sim.mac("eve")
        for n in range(40):
            frame = forge.link_frame(
                wf.PyMac.BROADCAST, eve_mac, signed_ogm(eve_kp, cert, addr, n + 1)
            )
            sim.inject("eve", frame, at_s=0.5 + n * 0.3)
        sim.run(until_s=16.0)
        if addr in sim.driver("victim").neighbor_macs():
            admitted_names.append(label)
        if sim.has_route("victim", addr):
            routed_names.append(label)

    ok = not admitted_names
    return Finding(
        "Reserved-address originator (broadcast/zero/multicast)",
        HELD if ok else GAP,
        (
            f"victim admitted reserved addresses as verified members: "
            f"{', '.join(admitted_names)}"
            f"{f' (routable: {routed_names})' if routed_names else ''}"
            if admitted_names
            else "every reserved-address originator was refused admission"
        ),
    )


def attack_misissued_cert_overwrites_live_member() -> Finding:
    """Two live certificates for one MAC. `hq` is a real member routing to
    `field`; the attacker holds a *second* CA-signed cert for hq's own MAC
    over the attacker's key (gap-4 misissuance) and floods verifying OGMs from
    it on the same segment.

    `cache_neighbor` (auth.rs:1846) keys the neighbour cache by `cert.mac` and
    **overwrites in place**, so each accepted OGM for hq's MAC replaces the
    cached entry — and with it the pairwise key `field` derives for hq. hq's
    real OGMs restore hq's key; the attacker's flip it to the attacker's. The
    pairwise data-plane key between hq and field is symmetric ECDH, so the
    moment field's cache holds the attacker's key, a directed frame hq tagged
    (with the *real* key) fails `verify_directed` at field and is dropped — and
    the reverse too. Nothing here lets the attacker *read* hq's traffic (it
    would need to win the route and answer a proof), but it should not be able
    to sever a live member's authenticated data plane either: identity is
    supposed to be bound to the key, and two keys must not contend for one
    address.

    Measured two ways: whether field's cached identity for hq ever flips to the
    attacker's key (the overwrite happening at all), and the delivery ratio of
    hq→field directed sends during the flood against a clean baseline send.
    """
    m = mesh()
    sim = Simulation(
        [
            Node("hq", credential=Credential()),
            Node("field", credential=Credential()),
            Node("eve"),
        ],
        shared_lan(["hq", "field", "eve"], PerfectWire()),
        mesh=m,
    )
    sim.run(until_s=20.0)

    hq_mac = sim.mac("hq")
    eve_kp, cert = _mint(m, hq_mac)
    eve_ed = bytes(eve_kp.ed_pubkey)
    eve_mac = sim.mac("eve")

    # Positive control: a clean send delivers before the flood begins.
    sim.send("hq", "field", b"BASELINE", at_s=20.5)
    sim.run(until_s=22.0)
    baseline_ok = sim.poll_local("field") == b"BASELINE"

    # Sample which key field currently caches for hq's MAC, once per tick.
    def cached_is_eve(s: Simulation) -> bool:
        c = s.driver("field").neighbor_cert(hq_mac)
        return c is not None and bytes(c.ed_pubkey) == eve_ed

    sim.record("hijacked_key", cached_is_eve)

    seq = iter(range(1000, 10**9))
    sim.flood(
        "eve",
        lambda: forge.link_frame(
            wf.PyMac.BROADCAST, eve_mac, signed_ogm(eve_kp, cert, hq_mac, next(seq))
        ),
        rate_hz=40,
        start_s=22.0,
        duration_s=18.0,
    )

    delivered = 0
    attempts = 0
    for t in (24.0, 27.0, 30.0, 33.0, 36.0, 39.0):
        payload = f"MSG{int(t)}".encode()
        sim.send("hq", "field", payload, at_s=t)
        rec = sim.run(until_s=t + 2.0)
        attempts += 1
        if sim.poll_local("field") == payload:
            delivered += 1

    key_flipped = any(rec.column("hijacked_key"))
    # GAP if the attacker's key ever displaced hq's, or if delivery degraded
    # from the clean baseline while the flood ran.
    degraded = baseline_ok and delivered < attempts
    ok = not key_flipped and not degraded
    return Finding(
        "Misissued cert overwrites a live member's cached identity",
        GAP if not ok else HELD,
        (
            f"field's cached key for hq flipped to the attacker's: {key_flipped}; "
            f"hq→field delivery under flood: {delivered}/{attempts} "
            f"(baseline delivered: {baseline_ok})"
        ),
    )


def attack_unbounded_validity_window() -> Finding:
    """A member enrolled with an absurd far-future expiry (not_after ≈ 10^12
    simulation-seconds out). `verify_cert` bounds `now` to `[not_before,
    not_after]` but never bounds the *width* of that window, so nothing caps a
    certificate's lifetime.

    Short-lived certs are documented as the mesh's passive revocation
    mechanism — "what bounds the damage from a leaked key with no network."
    A cert that never passively expires has surrendered that mechanism
    entirely: the only remaining backstop is an *active*, flooded revocation.
    So this measures two things in sequence — that the over-long cert is
    accepted and routes at all (there is no maximum-lifetime guard), and that
    active revocation still cuts it off despite the window (the backstop the
    design leans on when expiry cannot). The first is by design; the finding is
    whether the second still holds when expiry has been defused.
    """
    m = mesh()
    nodes = [
        Node("hq", credential=Credential()),
        Node("immortal", credential=Credential(valid_until_s=1_000_000_000_000.0)),
    ]
    links = [pair("hq", "immortal", PerfectWire())]
    sim = Simulation(nodes, links, mesh=m)
    sim.run(until_s=20.0)
    accepted = "immortal" in sim.admitted("hq")
    routed_before = sim.has_route("hq", "immortal")

    sim.revoke("immortal")
    sim.run(until_s=60.0)
    cut_off = ("immortal" not in sim.admitted("hq")) and not sim.has_route(
        "hq", "immortal"
    )

    if accepted and routed_before and cut_off:
        verdict = BY_DESIGN
        detail = (
            "an unbounded-lifetime cert is accepted and routes (no maximum-"
            "lifetime guard — passive expiry is defused), but active revocation "
            "still cuts it off, which is the backstop the design relies on"
        )
    elif accepted and not cut_off:
        verdict = GAP
        detail = (
            "an unbounded-lifetime cert routes AND survives active revocation — "
            "neither passive expiry nor active revocation bounds it"
        )
    else:
        verdict = HELD
        detail = (
            f"immortal accepted: {accepted}, routed before revoke: "
            f"{routed_before}, cut off after revoke: {cut_off}"
        )
    return Finding("Unbounded certificate validity window", verdict, detail)


def attack_degenerate_validity_window() -> Finding:
    """Two malformed windows a misissuing CA could stamp: an **inverted** one
    (`not_before > not_after`) and a **zero-length** one (`not_before ==
    not_after`), each carried on a fully-signed OGM.

    `verify_cert` tests `now < not_before → NotYetValid` and `now > not_after →
    Expired` independently. An inverted window therefore admits *no* instant —
    every `now` fails one end or the other — and a zero-length window admits
    exactly one unix second. Both should be fail-closed at essentially all
    times; this is the control that proves the window checks are not
    accidentally an OR (where an inverted window would pass *both* ends for some
    `now`). A signed OGM whose cert has such a window must never be admitted.
    """
    results: dict[str, bool] = {}
    windows = {
        # not_before is far in the future, not_after in the past → inverted.
        "inverted": {"valid_from_s": 50_000.0, "valid_until_s": -50_000.0},
        # a single-instant window, essentially never live under a moving clock.
        "zero-length": {
            "valid_from_s": 10.0,
            "valid_until_s": 10.0,
        },
    }
    for i, (label, window) in enumerate(windows.items()):
        m = mesh()
        sim = Simulation(
            [Node("victim", credential=Credential()), Node("eve")],
            [pair("victim", "eve", PerfectWire())],
            mesh=m,
        )
        addr = wf.PyMac(bytes([0x02, 0, 0, 0, 0, 0xC0 + i]))
        eve_kp, cert = _mint(m, addr, seed=bytes([0xC0 + i]) * 32, **window)
        eve_mac = sim.mac("eve")
        for n in range(40):
            frame = forge.link_frame(
                wf.PyMac.BROADCAST, eve_mac, signed_ogm(eve_kp, cert, addr, n + 1)
            )
            sim.inject("eve", frame, at_s=0.5 + n * 0.3)
        sim.run(until_s=16.0)
        results[label] = addr in sim.driver("victim").neighbor_macs()

    admitted = [label for label, got_in in results.items() if got_in]
    ok = not admitted
    return Finding(
        "Degenerate validity window (inverted / zero-length)",
        HELD if ok else GAP,
        (
            f"admitted despite a malformed window: {', '.join(admitted)}"
            if admitted
            else "both malformed windows were fail-closed at every instant"
        ),
    )


def attack_fail_open_bridge_containment() -> Finding:
    """A misconfigured node between the authenticated core and an outsider.
    `bridge` is unenrolled with `require_auth=False`, so it falls back to an
    open, unauthenticated router (the fail-*open* posture). `intruder` is a
    bare open outsider; `hq` is a real member. Wiring is
    `hq — bridge — intruder`.

    The open bridge will happily learn routes to both sides — it verifies
    nothing. The question is the blast radius: can traffic laundered through
    the open bridge reach the authenticated member? It must not. hq requires
    auth, so bridge's own (unsigned) OGMs fail `verify_ogm` and hq never routes
    through it; and a directed frame the bridge relays from the intruder has no
    pairwise key hq holds, so `verify_directed` drops it. The fail-open
    misconfiguration should compromise only the node that made it, not the
    members that did not.

    Measured against hq's own state: that the open bridge did connect both
    sides (else the test proves nothing), that hq admits neither, has no route
    to the intruder, and never delivers a payload the intruder originates.
    """
    m = mesh()
    nodes = [
        Node("hq", credential=Credential()),
        Node("bridge", credential=Credential(enrolled=False, require_auth=False)),
        Node("intruder"),
    ]
    links = [
        pair("hq", "bridge", PerfectWire()),
        pair("bridge", "intruder", PerfectWire()),
    ]
    sim = Simulation(nodes, links, mesh=m)
    sim.run(until_s=30.0)

    # Precondition: the open bridge really did bridge both sides.
    bridge_connected = sim.has_route("bridge", "hq") and sim.has_route(
        "bridge", "intruder"
    )

    hq_admits = sim.admitted("hq")
    hq_routes_intruder = sim.has_route("hq", "intruder")

    # The intruder tries to reach hq through the open bridge.
    sim.send("intruder", "hq", b"LAUNDERED", at_s=31.0)
    sim.run(until_s=36.0)
    reached_hq = sim.poll_local("hq") == b"LAUNDERED"

    contained = (
        bridge_connected and not hq_admits and not hq_routes_intruder and not reached_hq
    )
    if not bridge_connected:
        verdict, detail = (
            HELD,
            (
                "inconclusive setup: the open bridge never connected both sides, "
                "so containment could not be exercised"
            ),
        )
    elif contained:
        verdict, detail = (
            HELD,
            (
                "a fail-open misconfigured bridge learns both sides, but the "
                "authenticated member admits neither, has no route to the "
                "outsider, and drops laundered traffic — the blast radius is the "
                "misconfigured node alone"
            ),
        )
    else:
        verdict, detail = (
            GAP,
            (
                f"authenticated core breached via an open bridge — hq admitted: "
                f"{hq_admits}, route to intruder: {hq_routes_intruder}, laundered "
                f"payload delivered: {reached_hq}"
            ),
        )
    return Finding("Fail-open bridge into an authenticated core", verdict, detail)


# ======================================================================
# Battery 3 — the directed data plane and its pairwise trailer
# ======================================================================

# --- forge helpers this module needs but forge.py does not provide ----------
#
# forge.py stops at OGM/keepalive/challenge/response/tvlv. The directed
# data-plane packet bodies (`BatmanUnicastPacket` etc., layouts in
# libs/batman/src/wire.rs) have no forger, so they live here. A real attacker
# reimplements the wire format from what it observed; these are that.

PACKET_UNICAST = 0x03  # BatmanPacketType::Unicast
PACKET_MCAST = 0x04  # BatmanPacketType::Mcast
PACKET_BCAST = 0x02  # BatmanPacketType::Bcast
OGM_VERSION = 5


def unicast_packet(dest: wf.PyMac, payload: bytes, *, ttl: int = 50) -> bytes:
    """`BatmanUnicastPacket` `[type][version][ttl][dest:6]` + inner payload."""
    return (
        bytes((PACKET_UNICAST, OGM_VERSION, ttl & 0xFF)) + bytes(dest.bytes) + payload
    )


def mcast_packet(dest: wf.PyMac, payload: bytes, *, ttl: int = 50) -> bytes:
    """`BatmanMcastPacket` — structurally a unicast, one copy per listener."""
    return bytes((PACKET_MCAST, OGM_VERSION, ttl & 0xFF)) + bytes(dest.bytes) + payload


def bcast_packet(
    orig: wf.PyMac, payload: bytes, *, ttl: int = 50, seqno: int = 1
) -> bytes:
    """`BatmanBroadcastPacket` `[type][version][ttl][seqno:4][orig:6]` + inner."""
    return (
        bytes((PACKET_BCAST, OGM_VERSION, ttl & 0xFF))
        + (seqno & 0xFFFF_FFFF).to_bytes(4, "big")
        + bytes(orig.bytes)
        + payload
    )


def a_multicast_mac() -> wf.PyMac:
    """A non-broadcast group MAC (I/G bit set) — an IPv4-multicast-derived
    address. Distinct from `PyMac.BROADCAST` so an attack can show the bypass
    is about the *multicast* bit, not the all-ones address specifically."""
    return wf.PyMac(bytes((0x01, 0x00, 0x5E, 0x00, 0x00, 0x2A)))


# --- attacks ----------------------------------------------------------------


def attack_multicast_addressed_directed_delivery() -> Finding:
    """Inject a `Unicast` (and `Mcast`) BATMAN packet whose *inner* dest is a
    member, but whose *link-layer* dst is a group address — so the pairwise-tag
    check is skipped, yet the frame is still delivered to the member's host.

    A directed frame is supposed to be authenticated by the pairwise trailer:
    an outsider holding no credential cannot compute one, so its unicast to a
    member must be dropped. But `strip_directed` gates the tag check on
    `frame.dst.is_multicast()`, while `handle_unicast` decides `DeliverLocal`
    from the *inner* `BatmanUnicastPacket.dest`. Eve sets the link dst to a
    group MAC (skipping the tag) and the inner dest to the victim (winning local
    delivery). If the victim hands the injected bytes to its host, an outsider
    has an unauthenticated injection primitive into the directed data plane —
    the exact thing the pairwise tag exists to prevent.

    Control: the same packet addressed honestly (link dst == victim's real MAC)
    must be dropped for want of a tag. The contrast is the proof.

    Measured by `poll_local(victim)`.
    """
    m = mesh()
    nodes = [Node("victim", credential=Credential()), Node("eve")]
    sim = Simulation(nodes, [pair("victim", "eve", PerfectWire())], mesh=m)
    sim.run(until_s=20.0)  # let victim install its cert / enable auth

    victim = sim.mac("victim")
    eve = sim.mac("eve")

    # 1. Control: honest unicast addressing (link dst == victim). strip_directed
    #    runs verify_directed, which fails (eve holds no pairwise key) -> drop.
    sim.poll_local("victim")  # drain anything prior
    honest = forge.link_frame(victim, eve, unicast_packet(victim, b"HONEST-UNICAST"))
    sim.inject("eve", honest, at_s=20.5)
    sim.run(until_s=22.0)
    honest_delivered = sim.poll_local("victim")

    # 2. The attack: link dst is a group MAC (tag check skipped), inner dest is
    #    the victim (local delivery). Try both a Unicast and an Mcast body, and
    #    both a non-broadcast group MAC and the all-ones broadcast.
    grp = a_multicast_mac()
    uni = forge.link_frame(grp, eve, unicast_packet(victim, b"UNI-VIA-MCAST-DST"))
    mca = forge.link_frame(
        wf.PyMac.BROADCAST, eve, mcast_packet(victim, b"MCAST-VIA-BCAST-DST")
    )
    sim.inject("eve", uni, at_s=22.5)
    sim.run(until_s=24.0)
    uni_delivered = sim.poll_local("victim")
    sim.inject("eve", mca, at_s=24.5)
    sim.run(until_s=26.0)
    mca_delivered = sim.poll_local("victim")

    injected = [d for d in (uni_delivered, mca_delivered) if d is not None]
    if injected:
        verdict = GAP
        detail = (
            f"honest tagless unicast dropped (delivered={honest_delivered!r}); but a "
            f"group-addressed frame with an inner unicast/mcast dest reached the "
            f"victim's host untagged: {[bytes(d) for d in injected]} — the tag check "
            f"keys on the link dst while local delivery keys on the inner dest"
        )
    else:
        verdict = HELD
        detail = (
            "a directed packet body carried under a group link-dst was refused "
            "before local delivery just as an honestly-addressed tagless one is"
        )
    return Finding("Multicast-addressed directed delivery", verdict, detail)


def attack_injected_directed_laundered_by_relay() -> Finding:
    """The same tag bypass, one hop deeper: get a *relay* to launder an
    outsider's untagged injection into a genuinely-tagged frame a *third*
    member accepts as authentic.

    Topology is a line eve -- victim -- bob, with no eve<->bob link, so bob can
    only ever hear a frame victim itself put on the wire. Eve injects a
    group-addressed `Unicast` whose inner dest is bob. `strip_directed` skips
    the tag (group link-dst); `handle_unicast` sees inner dest != victim and
    relays toward bob; and `plan_dispatch`/`tag_directed_into` then stamp
    victim's *real* pairwise tag for bob onto the relay. Bob verifies that tag
    against victim's key and delivers — so an outsider's unauthenticated bytes
    arrive at bob indistinguishable from data victim authored and vouched for.

    This is strictly worse than the direct-delivery gap: the injected content is
    laundered through a member's key onto a peer that never shared a medium with
    the attacker. Held only if the relay refuses to re-tag content it never
    authenticated on ingress.

    Measured by `poll_local(bob)`, with eve and bob provably not adjacent.
    """
    m = mesh()
    nodes = [
        Node("victim", credential=Credential()),
        Node("bob", credential=Credential()),
        Node("eve"),
    ]
    links = [pair("victim", "bob", PerfectWire()), pair("victim", "eve", PerfectWire())]
    sim = Simulation(nodes, links, mesh=m)
    sim.run(until_s=35.0)  # converge + let victim<->bob prove each other

    if not sim.has_route("victim", "bob"):
        raise RuntimeError("victim never learned a route to bob — setup failed")

    bob = sim.mac("bob")
    eve = sim.mac("eve")
    sim.poll_local("bob")  # drain

    # Eve injects on the victim-eve link only (bob is not on it). Link dst is a
    # group MAC; inner Unicast dest is bob.
    frame = forge.link_frame(
        wf.PyMac.BROADCAST, eve, unicast_packet(bob, b"LAUNDERED-BY-VICTIM")
    )
    for i in range(8):
        sim.inject("eve", frame, at_s=35.5 + i * 0.5, link="victim-eve")
    sim.run(until_s=42.0)

    at_bob = sim.poll_local("bob")
    victim_delivered = sim.poll_local("victim")  # victim must relay, not deliver
    if at_bob is not None:
        verdict = GAP
        detail = (
            f"bob delivered {bytes(at_bob)!r} carrying victim's genuine pairwise "
            "tag — an outsider two hops away injected data bob accepts as "
            "authenticated member traffic; victim re-tagged content it never "
            "authenticated on ingress (multicast link-dst skipped the check)"
        )
    else:
        verdict = HELD
        detail = (
            "the relay did not launder the injection: nothing reached bob "
            f"(victim local delivery: {victim_delivered!r})"
        )
    return Finding("Injected directed frame laundered by a relay", verdict, detail)


def _capture_tagged_unicast(sim: Simulation, tap, src_name: str) -> bytes:
    """Return the raw bytes of one genuine tagged `Unicast` frame from
    `src_name` seen on `tap`, or raise if none appeared (a broken attack)."""
    frames = [
        f
        for f in tap.of_type(PACKET_UNICAST)
        if f.src == sim.mac(src_name)
        # A real tagged unicast is header(9) + inner + trailer(24); the control
        # frames (CertReq/Reply) share the unicast *shape* but a different type
        # byte, already filtered by of_type.
        and len(f.payload) > 9
    ]
    if not frames:
        raise RuntimeError(
            f"captured no tagged unicast from {src_name} — the send never went "
            "out tagged, so the replay/forgery test set up nothing"
        )
    return frames[-1].raw


def attack_directed_unicast_replay() -> Finding:
    """Capture one genuine tagged unicast (alice -> bob) and replay the exact
    bytes at bob.

    The directed trailer carries an 8-byte monotonic per-neighbor counter, and
    `verify_directed` accepts a frame only if its counter is strictly newer than
    the last from that source. bob has already accepted the original, so its
    counter for alice has advanced past it: a byte-identical replay must be
    refused as stale. If bob delivered the replay a second time, the counter is
    not actually gating replays.

    Measured by draining bob's local queue after the genuine delivery, then
    replaying, then checking `poll_local(bob)` is empty.
    """
    m = mesh()
    nodes = [
        Node("alice", credential=Credential()),
        Node("bob", credential=Credential()),
        Node("eve"),
    ]
    sim = Simulation(nodes, shared_lan(["alice", "bob", "eve"], PerfectWire()), mesh=m)
    tap = sim.wiretap("alice-bob-eve")
    sim.run(until_s=30.0)  # converge + prove

    sim.send("alice", "bob", b"GENUINE-DIRECTED", at_s=30.5)
    sim.run(until_s=33.0)
    genuine = sim.poll_local("bob")  # the real delivery
    captured = _capture_tagged_unicast(sim, tap, "alice")

    sim.poll_local("bob")  # ensure the queue is empty before the replay
    for i in range(30):
        sim.inject("eve", captured, at_s=33.5 + i * 0.1)
    sim.run(until_s=38.0)
    replayed = sim.poll_local("bob")

    if replayed is not None:
        verdict = GAP
        detail = f"a byte-identical replay was delivered again: {bytes(replayed)!r}"
    else:
        verdict = HELD
        detail = (
            f"genuine frame delivered once ({genuine!r}); 30 byte-identical "
            "replays all refused by the monotonic pairwise counter"
        )
    return Finding("Directed unicast replay (stale counter)", verdict, detail)


def attack_cross_pair_tag_forgery() -> Finding:
    """Take a genuine tagged unicast (alice -> bob) and re-present it to bob
    under a *different* claimed link source (carol, another member bob holds a
    key for).

    The pairwise tag is keyed on the alice<->bob shared key and binds alice's
    MAC as the sender context (so a frame cannot be reflected or re-attributed).
    Re-presented as if from carol, it must be verified against the carol<->bob
    key and carol's MAC context — neither of which produced the tag — so it can
    never verify. A tag good for one (src,dst) pair is worthless for another.

    Measured by `poll_local(bob)` after injecting the source-swapped frame.
    """
    m = mesh()
    nodes = [
        Node("alice", credential=Credential()),
        Node("bob", credential=Credential()),
        Node("carol", credential=Credential()),
        Node("eve"),
    ]
    sim = Simulation(
        nodes, shared_lan(["alice", "bob", "carol", "eve"], PerfectWire()), mesh=m
    )
    tap = sim.wiretap("alice-bob-carol-eve")
    sim.run(until_s=35.0)

    sim.send("alice", "bob", b"ALICE-TO-BOB", at_s=35.5)
    sim.run(until_s=38.0)
    sim.poll_local("bob")  # drain the genuine delivery
    captured = bytearray(_capture_tagged_unicast(sim, tap, "alice"))

    # Rewrite the link source (bytes 6..12) from alice to carol; leave the inner
    # unicast dest (== bob) and the tag untouched.
    carol = sim.mac("carol")
    captured[6:12] = bytes(carol.bytes)
    forged = bytes(captured)

    for i in range(20):
        sim.inject("eve", forged, at_s=38.5 + i * 0.1)
    sim.run(until_s=42.0)
    delivered = sim.poll_local("bob")

    if delivered is not None:
        verdict = GAP
        detail = (
            f"a tag minted for the alice<->bob pair verified as carol's: "
            f"{bytes(delivered)!r}"
        )
    else:
        verdict = HELD
        detail = (
            "a genuine alice->bob tag re-presented as carol's was refused — the "
            "tag is bound to the pairwise key and the sender MAC, not portable "
            "across (src,dst) pairs"
        )
    return Finding("Cross-pair directed-tag forgery", verdict, detail)


def attack_directed_frame_parsing_robustness() -> Finding:
    """A battery of malformed/edge-length BATMAN directed frames, to see whether
    any of them panics the router (a crash reachable from arbitrary remote input
    is a critical gap).

    Zero-copy parsing (`zerocopy`, `read_from_prefix`) is defensive by
    construction, and the length fields (inner offset, trailer split, TTL) are
    all `checked_*`/`.get(..)` in the code read here. All frames are >= 14 bytes
    so they parse as a LinkFrame (shorter input is rejected at `push_rx`, before
    the router, proving nothing about the parser).

    Every body is *group-addressed* (link dst = broadcast) so it clears
    `strip_directed`'s tag gate and actually reaches the engine's unicast/mcast/
    bcast parsers and `inner_offset`, and *also* honestly re-addressed (link dst
    = victim) to exercise the sub-trailer split in `strip_directed`. Every
    directed body targets a *ghost* MAC that is not the victim, so nothing here
    should ever be delivered locally: this isolates the parser from the separate
    multicast-addressed-delivery gap, making any delivery unambiguous.

    Measured by: the simulation runs to completion without an exception
    propagating out of the Rust router, and `poll_local(victim)` stays empty.
    """
    m = mesh()
    nodes = [Node("victim", credential=Credential()), Node("eve")]
    sim = Simulation(nodes, [pair("victim", "eve", PerfectWire())], mesh=m)
    sim.run(until_s=15.0)

    victim = sim.mac("victim")
    eve = sim.mac("eve")
    ghost = wf.PyMac(bytes((0x02, 0x00, 0x00, 0x00, 0x00, 0x63)))  # not victim
    grp = wf.PyMac.BROADCAST
    rng = random.Random(0xDA7A)

    bodies = [
        bytes((PACKET_UNICAST,)),  # just a type byte, header truncated
        bytes((PACKET_UNICAST, OGM_VERSION)),  # header truncated mid-way
        unicast_packet(ghost, b""),  # valid header, zero inner, non-self dest
        unicast_packet(ghost, b"", ttl=0),  # ttl underflow candidate
        unicast_packet(ghost, b"", ttl=1),  # ttl == 1 boundary
        mcast_packet(ghost, b""),  # mcast, zero inner
        bytes((PACKET_MCAST, OGM_VERSION)),  # mcast header truncated
        bcast_packet(eve, b""),  # bcast, zero inner
        bytes((PACKET_BCAST, OGM_VERSION, 50)),  # bcast header truncated
        bytes((0xAA, OGM_VERSION, 5)) + bytes(ghost.bytes),  # reserved type byte
        bytes((0xFF,)) * 20,  # unknown type, junk
        unicast_packet(ghost, b"X" * 4000),  # inner larger than tx scratch
        unicast_packet(ghost, bytes(rng.getrandbits(8) for _ in range(2100))),
        bytes(rng.getrandbits(8) for _ in range(3)),  # 3-byte payload, junk type
    ]

    crashed = None
    t = 15.5
    delivered: list[bytes] = []
    try:
        for body in bodies:
            # group-addressed (reaches the parser) and honestly-addressed
            # (exercises strip_directed's short-payload trailer split).
            for dst in (grp, victim):
                sim.inject("eve", forge.link_frame(dst, eve, body), at_s=t)
                t += 0.2
            sim.run(until_s=t + 0.2)
            got = sim.poll_local("victim")
            if got is not None:
                delivered.append(bytes(got))
        # Confirm the victim still routes after the barrage.
        sim.run(until_s=t + 3.0)
        still_alive = sim.driver("victim").neighbor_macs() is not None
    except BaseException as exc:  # noqa: BLE001 — a router panic surfaces here
        crashed = f"{type(exc).__name__}: {exc}"
        still_alive = False

    # A broadcast body floods and delivers its inner to every host by design
    # (bcast is unauthenticated — ARP etc.), so an empty-inner broadcast
    # legitimately delivers b"". That is expected, not a parser failure. Only a
    # non-empty delivery (a directed body reaching the ghost-addressed host) or
    # a crash is a finding here.
    nonempty = [d for d in delivered if d != b""]
    if crashed is not None:
        verdict = GAP
        detail = f"CRASH from a malformed directed frame: {crashed}"
    elif nonempty:
        verdict = GAP
        detail = f"a ghost-addressed directed body was delivered locally: {nonempty}"
    else:
        verdict = HELD
        detail = (
            f"every one of {len(bodies)} malformed/edge directed frames (each sent "
            f"group- and honestly-addressed) dropped without panic; the only local "
            f"deliveries were {len(delivered)} empty-inner broadcast(s), which flood "
            f"by design; victim still routing: {still_alive}"
        )
    return Finding("Directed-frame parsing robustness", verdict, detail)


# ======================================================================
# Battery 4 — the next-hop proof challenge/response protocol
# ======================================================================

RESP = forge.PACKET_NEXT_HOP_RESPONSE
CHAL = forge.PACKET_NEXT_HOP_CHALLENGE

# A directed frame's pairwise trailer is [counter:8][tag:16]; a proof frame
# only reaches the proof handler once it clears `strip_directed`, which needs
# these 24 bytes present. Forgeries here append 24 (invalid) trailer bytes so
# they reach `verify_directed` rather than dying on the length check the
# shipped 18-byte forgeries hit.
DIRECTED_TRAILER_LEN = 24


def _capture_member_ogm() -> tuple[bytes, wf.PyMac]:
    """A genuine signed OGM plus the identity it *authenticates* — the
    originator MAC in its header (bytes 8..14), which is also the MAC its
    embedded certificate binds. That is the identity a receiver caches a
    pairwise key for, and it is NOT necessarily the frame's link-layer source:
    `_capture_signed_ogm` can return a re-flooded copy whose link
    source is a relayer while the authenticated originator is another node.
    Every attack keys off the authenticated identity, extracted here."""
    body, _link_src = _capture_signed_ogm()
    orig = wf.PyMac(bytes(body[8:14]))
    return body, orig


def _seed_victim_with_member_cert(
    sim: Simulation, attacker: str, victim: str, member_mac: wf.PyMac, body: bytes
) -> bool:
    """Have `attacker` replay `member`'s captured signed OGM at `victim` until
    `victim` has verified and cached the member's certificate — the
    precondition for the proof machinery to have a pairwise key at all.
    Injected *from the attacker* so it is delivered to victim rather than
    leaving on victim's own link. Returns whether the cert landed."""
    relayed = forge.link_frame(wf.PyMac.BROADCAST, member_mac, body)
    for i in range(20):
        sim.inject(attacker, relayed, at_s=0.5 + i * 0.3)
    sim.run(until_s=20.0)
    return member_mac in sim.driver(victim).neighbor_macs()


def _forged_directed(
    dst: wf.PyMac, src: wf.PyMac, inner: bytes, rng: random.Random
) -> bytes:
    """A directed BATMAN frame carrying `inner` plus a random, invalid 24-byte
    pairwise trailer — long enough to clear `strip_directed`'s length check and
    reach `verify_directed`, where it must fail for want of the pairwise key."""
    trailer = bytes(rng.getrandbits(8) for _ in range(DIRECTED_TRAILER_LEN))
    return forge.link_frame(dst, src, inner + trailer)


# --- attack 1 -------------------------------------------------------------


def attack_unicast_addressed_challenge_reflection() -> Finding:
    """`attack_broadcast_addressed_challenge` was refused by the proof arm's
    `frame.dst != self_ident` guard: a broadcast dst is not this node. That
    guard is the whole reason a broadcast challenge cannot reflect a response.

    A *unicast* dst passes it — the frame really is addressed to victim — so
    the question the broadcast attack could not ask is whether the reflection
    reopens over unicast. Eve, holding no credential, unicasts a
    `NextHopChallenge` at victim (`dst = victim`) spoofing a member `hq` as the
    link source, `hq` being one whose cert victim cached off a relayed OGM (so
    `answer_challenge`'s `live_neighbor(hq)` check would pass). She sends it
    *full length* — a real 24-byte pairwise trailer's worth of bytes appended —
    so it is not dismissed on length the way the shipped 18-byte forgeries are.

    It should still fail, and by a gate the broadcast attack never reached: a
    unicast proof frame is a *directed* frame, so `strip_directed` runs
    `verify_directed` on that trailer *before* the proof arm. Eve holds no
    pairwise key, so the tag cannot verify, and victim never answers. Measured
    by whether victim puts any response on Eve's link.
    """
    body, hq_mac = _capture_member_ogm()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    if not _seed_victim_with_member_cert(sim, "eve", "victim", hq_mac, body):
        raise RuntimeError("setup failed: victim never cached hq's cert")

    victim_mac = sim.mac("victim")
    tap = sim.wiretap("victim-eve")  # fresh: only frames from here on
    rng = random.Random(0x1234)
    for i in range(30):
        nonce = bytes(rng.getrandbits(8) for _ in range(16))
        forged = _forged_directed(
            victim_mac, hq_mac, forge.next_hop_challenge(nonce), rng
        )
        sim.inject("eve", forged, at_s=20.5 + i * 0.2)
    sim.run(until_s=28.0)

    answered = [f for f in tap.of_type(RESP) if f.src == victim_mac]
    return Finding(
        "Unicast-addressed challenge reflection",
        GAP if answered else HELD,
        (
            f"victim answered {len(answered)} of 30 full-length unicast "
            "challenges spoofing a member source -- the pairwise-trailer gate "
            "does not stop a keyless outsider reflecting a member's response"
            if answered
            else "every full-length unicast challenge spoofing a member source "
            "was refused at verify_directed (the pairwise-trailer gate) before "
            "the proof arm -- the unicast reflection the broadcast fix could not "
            "reach is closed by a second, independent guard"
        ),
    )


# --- attack 2 -------------------------------------------------------------


def attack_forged_response_reaches_proof_handler() -> Finding:
    """The shipped `attack_forged_challenge_response_flood` floods 18-byte
    forged *responses* at a unicast dst and concludes the proof handler refused
    them. It did not: an 18-byte unicast frame fails `strip_directed`'s
    `checked_sub(24)` length test and is dropped one layer *earlier*, so
    `verify_challenge_response` is never called. The HELD is real but the gate
    credited is the wrong one.

    This drives the flood one layer deeper. Victim is made to hold hq's cert
    (so it could answer/credit), and Eve floods *full-length* forged responses
    (`[type][ver][16-byte tag]` + a 24-byte random trailer) at victim while a
    real challenge to hq is perpetually outstanding (hq never appears, so
    victim keeps challenging it). Now the frame clears the length check and
    reaches `verify_directed` — which must refuse it for want of hq's pairwise
    key, so no proof is ever credited. Measured by `proof_current(hq)`.
    """
    body, hq_mac = _capture_member_ogm()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    if not _seed_victim_with_member_cert(sim, "eve", "victim", hq_mac, body):
        raise RuntimeError("setup failed: victim never cached hq's cert")

    victim_mac = sim.mac("victim")
    rng = random.Random(0xF00D)

    def forged_response() -> bytes:
        tag = bytes(rng.getrandbits(8) for _ in range(16))
        return _forged_directed(victim_mac, hq_mac, forge.next_hop_response(tag), rng)

    sim.flood("eve", forged_response, rate_hz=500, start_s=20.5, duration_s=10.0)
    sim.run(until_s=32.0)

    proven = sim.driver("victim").proof_current(hq_mac)
    return Finding(
        "Forged response reaches the proof handler",
        GAP if proven else HELD,
        (
            "5,000 full-length forged responses credited a proof without hq's "
            "pairwise key"
            if proven
            else "5,000 full-length forged responses (now clearing the length "
            "check the shipped 18-byte flood died on) still failed verify_directed "
            "-- no pairwise key, no proof credited; the shipped flood HELD one "
            "gate too early to have proven this"
        ),
    )


# --- attack 3 -------------------------------------------------------------


def attack_challenge_nonce_is_unpredictable() -> Finding:
    """Every replay defense in the proof protocol rests on one property: the
    challenge nonce is fresh and unpredictable, so a captured response (bound
    to an old nonce) can never satisfy a new challenge. The design derives the
    nonce from a PRF (`frame_tag`) over a monotonic counter keyed by this
    node's Diffie-Hellman with *itself* — claimed unpredictable to anyone else.

    That claim is measured here rather than trusted: a member issues real
    challenges to a live neighbour over a run; every nonce is lifted off the
    wire and checked to be (a) all distinct — no reuse across challenges — and
    (b) not a low-entropy sequence (consecutive counter, constant delta, or a
    tiny value set). A reused or predictable nonce would let an attacker
    pre-fetch or replay an answer; a control that fails here would invalidate
    the freshness the whole exchange depends on.
    """
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential()), Node("bob", credential=Credential())],
        [pair("victim", "bob", PerfectWire())],
        mesh=m,
    )
    tap = sim.wiretap("victim-bob")
    sim.run(until_s=60.0)

    victim_mac = sim.mac("victim")
    # A genuine challenge is [type][ver][nonce:16][trailer:24]; the nonce is
    # bytes 2..18 of the payload.
    nonces = [
        bytes(f.payload[2:18])
        for f in tap.of_type(CHAL)
        if f.src == victim_mac and len(f.payload) >= 18
    ]
    if len(nonces) < 3:
        raise RuntimeError(f"only {len(nonces)} challenges captured; need >= 3")

    all_distinct = len(set(nonces)) == len(nonces)
    as_ints = [int.from_bytes(n, "big") for n in nonces]
    deltas = {b - a for a, b in itertools.pairwise(as_ints)}
    constant_delta = len(deltas) == 1  # arithmetic sequence == predictable
    tiny_space = len(set(nonces)) <= 2
    unpredictable = all_distinct and not constant_delta and not tiny_space

    return Finding(
        "Challenge nonce is unpredictable",
        HELD if unpredictable else GAP,
        (
            f"{len(nonces)} nonces off the wire: all distinct={all_distinct}, "
            f"constant-delta sequence={constant_delta} -- fresh and "
            "non-sequential, so a captured response never matches a new challenge"
            if unpredictable
            else f"{len(nonces)} nonces show structure (distinct={all_distinct}, "
            f"constant-delta={constant_delta}, tiny-space={tiny_space}) -- the "
            "freshness the replay defense rests on is weaker than claimed"
        ),
    )


# --- attack 4 -------------------------------------------------------------


def attack_captured_challenge_replayed() -> Finding:
    """The shipped suite replays a captured *response*; nobody replays a
    captured *challenge*. A genuine challenge is a directed frame carrying a
    valid pairwise trailer (victim signed it under the victim-bob key), so
    unlike an outsider's forgery it is *not* refused for a bad tag — its tag is
    real. If the only thing standing between a replayed challenge and a fresh
    reflected response were the tag, Eve could capture one challenge and pump
    bob for responses forever.

    It is not the only thing: that trailer also carries a strictly-monotonic
    per-sender counter, and `verify_directed`'s `accept_recv_counter` refuses a
    counter that is not newer than the last accepted. Bob has already accepted
    the original challenge's counter, so every verbatim replay is a stale
    counter. Eve captures one genuine victim->bob challenge off a shared
    segment and floods it back at bob; bob must emit no fresh response for it.
    Measured by counting bob's responses during the replay burst against the
    handful its own renewal cadence would produce anyway.
    """
    m = mesh()
    sim = Simulation(
        [
            Node("victim", credential=Credential()),
            Node("bob", credential=Credential()),
            Node("eve"),
        ],
        shared_lan(["victim", "bob", "eve"], PerfectWire()),
        mesh=m,
    )
    tap = sim.wiretap("victim-bob-eve")
    sim.run(until_s=30.0)

    victim_mac = sim.mac("victim")
    bob_mac = sim.mac("bob")
    challenges = [f for f in tap.of_type(CHAL) if f.src == victim_mac]
    if not challenges:
        raise RuntimeError("captured no genuine challenge from victim")
    captured = challenges[-1].raw  # a full, valid-trailer challenge

    tap.reset()  # count only what follows
    sim.flood("eve", lambda: captured, rate_hz=200, start_s=30.5, duration_s=5.0)
    sim.run(until_s=36.0)

    # Bob's responses during the 5 s replay burst. Its own renewal cadence
    # (seed_interval, seconds) would produce at most a couple; 1,000 replays of
    # an accepted challenge would produce ~1,000.
    bob_responses = [f for f in tap.of_type(RESP) if f.src == bob_mac]
    replayed_credited = len(bob_responses) > 10
    return Finding(
        "Captured challenge replay",
        GAP if replayed_credited else HELD,
        (
            f"bob emitted {len(bob_responses)} responses under 1,000 replays -- "
            "a captured challenge is re-answerable, an outsider's reflection "
            "primitive"
            if replayed_credited
            else f"bob emitted {len(bob_responses)} responses under 1,000 replays "
            "of one captured challenge -- the pairwise counter makes each verbatim "
            "replay a stale counter, refused before it can re-answer"
        ),
    )


# --- attack 5 -------------------------------------------------------------


def attack_proof_survives_key_eviction_window() -> Finding:
    """Seed idea: the window between a proof going stale and being renewed —
    is traffic dropped, or does it fall back to the spoofable link-quality
    table? Here the window is opened not by time but by *certificate expiry*,
    which exposes an interplay the two halves of the fix do not obviously
    close together.

    When bob's cert lapses, `set_time` -> `evict_expired_neighbors` drops bob's
    pairwise key from `OgmAuth` (gap 3's fix). But the engine's `proven` table
    is separate and is *not* swept on expiry, so `proof_current(bob)` can stay
    true for up to `MAX_MISSED_PROOFS` intervals afterward. In that window the
    engine still *selects* bob as a next hop (selection gates on
    `proof_current`), while the data plane has no key to tag a frame to him
    (`tag_directed` -> `live_neighbor` -> None) — a route that reports healthy
    but silently drops. Renewal cannot rescue it either: `issue_challenge`
    fails closed for the now-keyless neighbour.

    Measured directly: after bob's cert expires, is there any sampled instant
    where victim still reports a route to bob *and* still reads his proof as
    current while his key is already gone from the neighbour cache? That triple
    is the untaggable-blackhole window; its width is the finding.
    """
    m = mesh()
    sim = Simulation(
        [
            Node("victim", credential=Credential()),
            Node("bob", credential=Credential(valid_until_s=15.0)),
        ],
        [pair("victim", "bob", PerfectWire())],
        mesh=m,
    )
    sim.run(until_s=14.0)
    bob_mac = sim.mac("bob")
    if not (
        bob_mac in sim.driver("victim").neighbor_macs()
        and sim.has_route("victim", bob_mac)
        and sim.driver("victim").proof_current(bob_mac)
    ):
        raise RuntimeError(
            "setup failed: victim never established a proven route to bob"
        )

    # Walk past expiry in fine steps, sampling the triple at each.
    window_samples: list[float] = []
    route_after: list[float] = []
    blackholed_send = False
    probed = False
    t = 15.0
    while t <= 40.0:
        sim.run(until_s=t)
        v = sim.driver("victim")
        cached = bob_mac in v.neighbor_macs()
        proven = v.proof_current(bob_mac)
        routed = sim.has_route("victim", bob_mac)
        if routed:
            route_after.append(t)
        # Untaggable-blackhole window: route selected + proof believed current,
        # but the key needed to actually tag a frame is already evicted.
        in_window = routed and proven and not cached
        if in_window:
            window_samples.append(t)
        # The impact, measured not inferred: the first instant we detect the
        # window, address a real payload to bob and confirm it never arrives
        # even though victim reports a usable route to him.
        if in_window and not probed:
            probed = True
            v.queue_local_send(bob_mac, b"BLACKHOLE-PROBE")
            sim.run(until_s=t + 1.0)
            t += 1.0
            delivered = sim.poll_local("bob") == b"BLACKHOLE-PROBE"
            still_routed = sim.has_route("victim", bob_mac)
            blackholed_send = (not delivered) and still_routed
        t += 1.0

    if window_samples:
        width = window_samples[-1] - window_samples[0] + 1.0
        verdict = GAP
        detail = (
            f"for ~{width:.0f}s after bob's cert expired ({window_samples[0]:.0f}-"
            f"{window_samples[-1]:.0f}s) proof_current(bob) and has_route stayed "
            "true after evict_expired_neighbors dropped his key; a real send in "
            f"the window was dropped at dispatch while the route reported usable "
            f"(blackholed_send={blackholed_send}). Transient (route purges once "
            "the proof lapses), single-neighbour, and the drop is metered -- but "
            "the engine's proven table is not swept on key eviction the way "
            "set_auth/revocation sweep it, so the route table lies for the window"
        )
    else:
        verdict = HELD
        detail = (
            f"no untaggable-blackhole window observed: route to bob cleared by "
            f"{(route_after[-1] if route_after else 15.0):.0f}s, and no sampled "
            "instant showed a current proof over an evicted key"
        )
    return Finding("Proof/expiry key-eviction window", verdict, detail)


# ======================================================================
# Battery 5 — revocation as a weapon
# ======================================================================

# MAX_REVOKED is not exported to Python; it is `MAX_REVOKED = 32` in
# `libs/wayfinder/src/auth.rs`. A flood only has to exceed it to prove a point
# about eviction, and 32 forged records that never pass verification never
# occupy a slot at all.
MAX_REVOKED = 32

# `forge.ogm` writes the fixed BATMAN OGM header as
# `[type,ver,ttl,flags](4) ‖ seqno(4) ‖ orig(6) ‖ [pad,tq](2) ‖ tvlv_len(2)`,
# mirroring `batman::wire::BatmanOgmPacket`. The last two header bytes are the
# big-endian TVLV-region length.
_OGM_HDR_LEN = 18
_TVLV_LEN_OFF = _OGM_HDR_LEN - 2
_TVLV_REVOKE = 0x82  # `batman::wire::TvlvType::Revoke`
_ORIG_OFF = 8  # byte offset of the 6-byte originator MAC in the OGM header


def _carrier() -> tuple[bytes, wf.PyMac]:
    """A genuine, full-cert-carrying signed OGM to splice into, plus **its
    originator's** MAC.

    ``_capture_signed_ogm`` returns the last frame whose *link* source
    is ``hq`` — which is often ``hq`` re-flooding a peer's OGM, so the link
    source and the OGM's own originator differ. Verification (and the neighbor
    cache) keys on the originator in the OGM header, so that is what proves the
    carrier was processed; the link source is just the forwarder.
    """
    body, _hq_link_src = _capture_signed_ogm()
    orig = wf.PyMac(bytes(body[_ORIG_OFF : _ORIG_OFF + 6]))
    return body, orig


def _splice_revocation(ogm_payload: bytes, record_bytes: bytes) -> bytes:
    """A genuinely-signed OGM `ogm_payload` with a `Revoke` TVLV carrying
    `record_bytes` appended to its tail — the exact splice the a20322a commit
    warns about.

    The OGM signature covers only `orig ‖ seqno ‖ cert` (see
    `OgmAuth::signed_message`), so appending to the tail leaves the signature
    valid. `find_tvlv`/`iter_tvlv` scan the whole tail rather than trusting the
    header length, so the record would be found even without the length bump —
    but we bump `tvlv_len` anyway so the frame is well-formed exactly as a real
    forwarder's `augment_ogm` would leave it.
    """
    if not ogm_payload or ogm_payload[0] != forge.PACKET_OGM:
        raise ValueError("carrier is not an OGM payload")
    tvlv = forge.tvlv(_TVLV_REVOKE, record_bytes)
    out = bytearray(ogm_payload)
    old_len = int.from_bytes(out[_TVLV_LEN_OFF : _TVLV_LEN_OFF + 2], "big")
    new_len = old_len + len(tvlv)
    out[_TVLV_LEN_OFF : _TVLV_LEN_OFF + 2] = new_len.to_bytes(2, "big")
    out.extend(tvlv)
    return bytes(out)


def _inject_carrier(sim: Simulation, src: str, frame: bytes, *, n: int = 12) -> None:
    """Replay one spliced frame from `src` a handful of times.

    Only the first copy carries a seqno the receiver has not seen, so only the
    first actually re-runs verification and the tail ingest — the rest are
    deduped. That is fine: a record that bites bites on the first, and one that
    does not never will however many copies arrive.
    """
    for i in range(n):
        sim.inject(src, frame, at_s=0.5 + i * 0.3)


# --- attacks ----------------------------------------------------------------


def attack_forged_self_revocation_killswitch() -> Finding:
    """The remote off switch. An attacker holding **no root key** forges a
    revocation naming the victim's own MAC and splices it into a captured,
    genuinely-signed OGM from an (absent) member — the tail rides for free,
    since the OGM signature does not cover it. If the victim goes inert, one
    frame from a keyless outsider has taken any node off the mesh at will.

    It must fail at ``TrustAnchor::verify_revocation``: the record is signed by
    a *foreign* root, so it verifies nowhere against the victim's anchor and is
    dropped before the self-revocation branch is ever reached. Measured by the
    victim staying unlocked while the carrier OGM is *proved* to have been
    processed (its originator is cached), so the forged record was genuinely
    judged and refused, not merely lost upstream.
    """
    body, carrier_mac = _carrier()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    victim_mac = sim.mac("victim")
    # A forged record: the attacker's own root, over the victim's real MAC and
    # its real issuance instant, so only the *signer* is wrong.
    forged = foreign_mesh().revoke(victim_mac, effective_s=0)
    frame = forge.link_frame(
        wf.PyMac.BROADCAST, carrier_mac, _splice_revocation(body, bytes(forged))
    )
    _inject_carrier(sim, "eve", frame)
    sim.run(until_s=20.0)

    locked = sim.driver("victim").auth_locked
    carrier_seen = carrier_mac in sim.driver("victim").neighbor_macs()
    ok = not locked and carrier_seen
    return Finding(
        "Forged self-revocation kill switch",
        HELD if ok else GAP,
        (
            "a keyless outsider spliced a foreign-signed revocation into a "
            "genuine OGM and took the node off the mesh"
            if locked
            else "forged revocation rejected at the trust anchor; node stayed "
            f"enrolled (carrier OGM processed: {carrier_seen})"
        ),
    )


def attack_self_revocation_replay_after_reenrollment() -> Finding:
    """The invalidity-date guarantee, from the self side. A member was revoked
    once and re-admitted with a fresh certificate; the attacker replays the
    **genuine** old revocation, spliced into a captured OGM. Modelled by a
    victim whose certificate was issued *after* the revocation instant
    (``valid_from_s=10`` against a revocation effective at the epoch) — the
    compressed shape of "revoked, then re-enrolled".

    It must fail at ``cancels_cert_for``: the record's instant predates the
    certificate the victim now runs under, so it describes a superseded
    membership and is dropped as "cancels only a superseded certificate". If it
    still bit, the off switch would be permanent — no re-admission could ever
    clear a revocation an attacker keeps replaying.
    """
    body, carrier_mac = _carrier()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential(valid_from_s=10.0)), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    stale = sim.mesh.revoke(sim.mac("victim"), effective_s=0.0)  # predates the cert
    frame = forge.link_frame(
        wf.PyMac.BROADCAST, carrier_mac, _splice_revocation(body, bytes(stale))
    )
    _inject_carrier(sim, "eve", frame)
    sim.run(until_s=25.0)

    locked = sim.driver("victim").auth_locked
    carrier_seen = carrier_mac in sim.driver("victim").neighbor_macs()
    ok = not locked and carrier_seen
    return Finding(
        "Self-revocation replay after re-enrollment",
        HELD if ok else GAP,
        (
            "a stale revocation replayed at a re-admitted node bricked it — "
            "re-admission cannot survive a replay"
            if locked
            else "stale revocation predates the current certificate and was "
            f"dropped as superseded; node stayed enrolled (carrier processed: {carrier_seen})"
        ),
    )


def attack_self_revocation_same_second_tie() -> Finding:
    """The tie the design resolves toward *revoked*. A revocation and a
    certificate stamped in the **same unix second** — the boundary case of the
    invalidity-date rule (``cert.not_before <= record.not_before``, inclusive).
    The attacker replays a genuine revocation whose instant equals the victim's
    own certificate instant (both at ``epoch+5``).

    Unlike the attack above, this one is expected to *succeed*, and by design:
    the field's docs say the tie resolves toward revoked because "an authority
    re-admitting a node can trivially stamp the new certificate a second
    later." So this is not a router break — but it *is* a real, narrow replay
    hazard worth surfacing: an operator who re-admits a node in the same second
    it was revoked hands an attacker a replayable brick. Measured, so a future
    change that flips the tie the other way turns this row from BY_DESIGN into
    a visible behaviour change rather than passing silently.
    """
    body, carrier_mac = _carrier()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential(valid_from_s=5.0)), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    tie = sim.mesh.revoke(sim.mac("victim"), effective_s=5.0)  # == cert.not_before
    frame = forge.link_frame(
        wf.PyMac.BROADCAST, carrier_mac, _splice_revocation(body, bytes(tie))
    )
    _inject_carrier(sim, "eve", frame)
    sim.run(until_s=25.0)

    locked = sim.driver("victim").auth_locked
    return Finding(
        "Self-revocation same-second tie",
        BY_DESIGN if locked else GAP,
        (
            "a revocation stamped in the same second as the certificate cancels "
            "it (tie resolves toward revoked, as documented) — replaying it "
            "bricks a node re-admitted without a one-second gap"
            if locked
            else "the same-second tie did NOT cancel — the documented rule "
            "(inclusive `<=`, tie toward revoked) has changed"
        ),
    )


def attack_foreign_root_revokes_member() -> Finding:
    """Evicting an honest third party. An attacker with a complete, structurally
    perfect mesh of its own (a foreign root) signs a revocation naming a genuine
    member and floods it — spliced into a captured OGM — at that member's peer.
    If accepted, anyone who can stand up a CA can evict anyone else's nodes.

    It must fail at ``verify_revocation``: the record is checked against the
    victim mesh's anchor, and a foreign root's signature does not verify there.
    Measured at the peer: the named member stays admitted and routable, while
    the carrier OGM is proved processed so the foreign record was actually
    judged and refused.
    """
    m = mesh()
    carrier_body, carrier_mac = _carrier()
    sim = Simulation(
        [*_members("peer", "target"), Node("eve")],
        [pair("peer", "target", PerfectWire()), pair("peer", "eve", PerfectWire())],
        mesh=m,
    )
    sim.run(until_s=20.0)  # let peer admit and route target normally
    admitted_before = "target" in sim.admitted("peer")

    forged = foreign_mesh().revoke(sim.mac("target"), effective_s=0)
    frame = forge.link_frame(
        wf.PyMac.BROADCAST, carrier_mac, _splice_revocation(carrier_body, bytes(forged))
    )
    for i in range(20):
        sim.inject("eve", frame, at_s=20.5 + i * 0.3)
    sim.run(until_s=35.0)

    admitted_after = "target" in sim.admitted("peer")
    routed = sim.has_route("peer", "target")
    carrier_seen = carrier_mac in sim.driver("peer").neighbor_macs()
    ok = admitted_before and admitted_after and routed and carrier_seen
    return Finding(
        "Foreign-root revocation of a member",
        HELD if ok else GAP,
        (
            f"a foreign-root revocation evicted an honest member "
            f"(admitted before: {admitted_before}, after: {admitted_after})"
            if not (admitted_after and routed)
            else "foreign-root revocation refused at the anchor; target stayed "
            f"admitted and routable (carrier processed: {carrier_seen})"
        ),
    )


def attack_forged_revocation_flood_evicts_genuine() -> Finding:
    """Table exhaustion. The local revocation set is bounded
    (``MAX_REVOKED = 32``). If a flood of forged revocations naming ghost MACs
    could push a *real* revocation out of that set, an attacker could quietly
    un-revoke a rogue by drowning its record. The attacker blasts far more than
    ``MAX_REVOKED`` foreign-signed ghost revocations, each spliced into a
    genuine carrier OGM so it actually reaches ``ingest_revocation``.

    It must fail because a forged record is refused at ``verify_revocation``
    *before* it is ever offered a slot — rejection happens above the bounded
    set, so no quantity of fakes can occupy or evict anything. Measured: the
    genuine revocation of the rogue is still held, and the rogue is still shunned
    (unadmitted, unroutable), after the storm.
    """
    m = mesh()
    carrier_body, carrier_mac = _carrier()
    sim = Simulation(
        [*_members("peer", "rogue"), Node("eve")],
        [pair("peer", "rogue", PerfectWire()), pair("peer", "eve", PerfectWire())],
        mesh=m,
    )
    sim.run(until_s=20.0)
    sim.revoke("rogue")  # the genuine record we must not be able to evict
    sim.run(until_s=25.0)
    shunned_before = "rogue" not in sim.admitted("peer") and not sim.has_route(
        "peer", "rogue"
    )

    attacker_root = foreign_mesh()
    ghost_counter = iter(range(1, 10**9))

    def ghost_revocation() -> bytes:
        n = next(ghost_counter)
        ghost_mac = wf.PyMac(bytes((0x02, 0x00, 0x00, 0x00, (n >> 8) & 0xFF, n & 0xFF)))
        rec = attacker_root.revoke(ghost_mac, effective_s=0)
        return forge.link_frame(
            wf.PyMac.BROADCAST,
            carrier_mac,
            _splice_revocation(carrier_body, bytes(rec)),
        )

    # Well past MAX_REVOKED, all forged, all riding a valid carrier.
    sim.flood("eve", ghost_revocation, rate_hz=200, start_s=25.5, duration_s=6.0)
    sim.run(until_s=33.0)

    rogue_still_revoked = sim.mac("rogue") in sim.driver("peer").revoked_macs()
    shunned_after = "rogue" not in sim.admitted("peer") and not sim.has_route(
        "peer", "rogue"
    )
    ok = shunned_before and rogue_still_revoked and shunned_after
    return Finding(
        "Forged revocation flood vs a genuine record",
        HELD if ok else GAP,
        (
            f"a flood of forged ghost revocations evicted the genuine one "
            f"(rogue still revoked: {rogue_still_revoked}, still shunned: {shunned_after})"
            if not (rogue_still_revoked and shunned_after)
            else f">{MAX_REVOKED} forged revocations were all refused above the "
            "bounded set; the genuine record survived and the rogue stayed shunned"
        ),
    )


def attack_stale_revocation_denies_readmission() -> Finding:
    """The invalidity-date guarantee, from the enforcement side. A peer *legitimately
    holds* a revocation of a rogue (delivered as an operator/flood push). The
    rogue is then re-admitted by the authority with a certificate issued after
    the revocation instant (``valid_from_s=10`` against a revocation effective at
    the epoch). The attacker keeps **replaying the old revocation** at the peer,
    trying to deny the re-admission and keep the rogue shunned forever.

    The whole reason revocations became invalidity-dated: a certificate issued
    after the record survives it, so the re-admitted rogue must become admitted
    and routable again even though the peer still holds — and the attacker keeps
    re-flooding — the old record. If the stale record still shunned the newer
    certificate, re-admission would be impossible for any node whose past
    revocation an attacker can replay (and on an nRF, whose MAC is fixed in FICR,
    that is *forever*). Measured at the peer after the replay storm.
    """
    m = mesh()
    carrier_body, carrier_mac = _carrier()
    sim = Simulation(
        # rogue re-admitted with a cert issued after the revocation instant.
        [
            Node("peer", credential=Credential()),
            Node("rogue", credential=Credential(valid_from_s=10.0)),
            Node("eve"),
        ],
        [pair("peer", "rogue", PerfectWire()), pair("peer", "eve", PerfectWire())],
        mesh=m,
    )
    # The peer legitimately learns the OLD revocation (instant at the epoch),
    # before the rogue's new certificate is even valid.
    old_record = sim.mesh.revoke(sim.mac("rogue"), effective_s=0.0)
    sim.driver("peer").ingest_revocation(old_record)
    held = sim.mac("rogue") in sim.driver("peer").revoked_macs()

    # Attacker keeps replaying that same old record at the peer throughout.
    frame = forge.link_frame(
        wf.PyMac.BROADCAST,
        carrier_mac,
        _splice_revocation(carrier_body, bytes(old_record)),
    )
    for i in range(40):
        sim.inject("eve", frame, at_s=1.0 + i * 0.5)
    sim.run(until_s=30.0)  # well past the rogue's valid_from at 10 s

    admitted = "rogue" in sim.admitted("peer")
    routed = sim.has_route("peer", "rogue")
    ok = held and admitted and routed
    return Finding(
        "Stale revocation denies re-admission",
        HELD if ok else GAP,
        (
            f"a re-admitted node was kept off the mesh by a replayed stale "
            f"revocation (record held: {held}, admitted: {admitted}, routed: {routed})"
            if not (admitted and routed)
            else "the newer certificate survived the earlier revocation the peer "
            "holds and the attacker keeps replaying; rogue re-admitted and routable"
        ),
    )


# ======================================================================
# Battery 6 — OGM semantics and the BATMAN routing engine
# ======================================================================

PACKET_BCAST = forge.PACKET_BCAST
OGM_VERSION = forge.OGM_VERSION


# --- extra forge primitives (would live in forge.py) --------------------


def _bcast_packet(
    orig: wf.PyMac, seqno: int, *, ttl: int = 50, inner: bytes = b""
) -> bytes:
    """A `BatmanBroadcastPacket`: `[type][version][ttl][seqno BE][orig][inner]`.

    Mirrors `batman::wire::BatmanBroadcastPacket`. `Bcast` frames carry no
    signature and are gated by nothing on ingress (only OGMs are auth-gated),
    so `orig` and `seqno` are entirely the attacker's to choose — which is the
    whole point of the two attacks that use this.
    """
    return b"".join(
        (
            bytes((PACKET_BCAST, OGM_VERSION, ttl & 0xFF)),
            (seqno & 0xFFFF_FFFF).to_bytes(4, "big"),
            bytes(orig.bytes),
            inner,
        )
    )


def _capture_signed_ogm_at_seqno(
    min_seqno: int, *, until_s: float
) -> tuple[bytes, wf.PyMac]:
    """Run a legitimate mesh until `hq` has emitted an OGM with seqno at least
    `min_seqno`, and return that genuine signed OGM body plus `hq`'s MAC.

    The attacker's raw material for the seqno-highwater attack: a signed OGM
    whose (signed) seqno is *higher* than the value a freshly-booted `hq` will
    be advertising. It costs nothing to obtain — the mesh floods it — and a
    node that ran for a while, or that the attacker heard on another segment,
    supplies an arbitrarily high one (seqno grows without bound and never
    persists across a reboot).
    """
    m = mesh()
    nodes = [*_members("hq", "relay"), Node("cap")]
    sim = Simulation(nodes, shared_lan(["hq", "relay", "cap"], PerfectWire()), mesh=m)
    tap = sim.wiretap("hq-relay-cap")
    sim.run(until_s=until_s)
    hq_mac = sim.mac("hq")
    # Filter on the OGM's own `orig` field (bytes 8..14), NOT the link-layer
    # `src`: hq also *relays* relay's OGMs (orig=relay, src=hq), so a src filter
    # would hand back a payload whose originator is not hq at all.
    ogms = [
        f
        for f in tap.of_type(forge.PACKET_OGM)
        if bytes(f.payload[8:14]) == bytes(hq_mac.bytes)
        and struct.unpack(">I", f.payload[4:8])[0] >= min_seqno
    ]
    if not ogms:
        raise RuntimeError(f"captured no signed OGM from hq with seqno >= {min_seqno}")
    return ogms[-1].payload, hq_mac


def _ogm_record(sim: Simulation, node: str, orig: wf.PyMac):
    for record in sim.driver(node).originator_table():
        if record.originator == orig:
            return record
    return None


# --- attacks ------------------------------------------------------------


def attack_ogm_seqno_highwater_jam() -> Finding:
    """Pin a receiver's per-originator sequence high-water above a member's
    *live* seqno with one captured, genuinely-signed OGM, and every genuine OGM
    that member emits afterwards is discarded as stale — a keyless outsider
    denies a present member's route without ever forging a signature.

    The engine tracks one `last_seqno` per originator and treats an OGM as
    fresh only when `incoming_seqno >= last_seqno` (engine.rs) — a strict,
    persistent high-water with no wraparound handling and no reordering window.
    The OGM signature covers `orig + seqno + cert` (auth.rs `signed_message`),
    so seqno cannot be *forged* to an arbitrary value... but it need not be:
    the attacker replays a real, higher seqno she captured earlier (from before
    a reboot, or off another segment where `hq` had been running longer). The
    counter starts at 0 on every fresh engine (`BatmanEngine::new`) and is never
    persisted, so a rebooted `hq` re-emits low seqnos that now sit *below* the
    replayed high-water.

    Should fail because the routing table must keep learning a live member's
    current topology. If it does not, an outsider gets a silent, targeted route
    denial on any member whose OGMs she once recorded — one forged frame, no
    credential.

    Construction: `hq` is given a slow initial Trickle so its first genuine OGM
    is not emitted until ~3 s, and the attacker pins the high-water during the
    window before that. This makes the ordering deterministic — the stale
    high-water is in place before `victim` ever processes one of `hq`'s current
    OGMs — which is exactly the real-world case: `victim` boots (or comes into
    range) into a segment where `eve` has pre-seeded a stale high-water for a
    member that has since rebooted and is now re-emitting low seqnos.

    Measured: whether `victim` — with `hq` directly adjacent and genuinely
    present — acquires a usable route to `hq`, against a control run with no
    attacker.
    """
    # A high seqno from a longer-lived hq: ~56 after 80 s, far above the handful
    # a freshly-booted hq re-emits before the run ends.
    body, hq_mac = _capture_signed_ogm_at_seqno(40, until_s=80.0)
    replayed_seqno = struct.unpack(">I", body[4:8])[0]
    # hq holds its first genuine OGM until ~3 s so the pin lands first.
    slow = (3000, 6000)

    def run(with_attacker: bool) -> tuple[bool, int | None, int]:
        m = mesh()
        nodes = [
            Node("victim", credential=Credential()),
            Node("hq", credential=Credential(), trickle=slow),
        ]
        links = [pair("victim", "hq", PerfectWire())]
        if with_attacker:
            nodes.append(Node("eve"))
            links.append(pair("victim", "eve", PerfectWire()))
        sim = Simulation(nodes, links, mesh=m)
        if with_attacker:
            # Replay under eve's OWN link-layer source: the pinned path is "hq
            # via eve", which eve (holding no credential) can never prove, so it
            # only advances the seqno high-water — it never becomes a usable
            # route the way spoofing src=hq would. Keep it refreshed so the
            # record never ages out (last_heard stays live via the replay while
            # last_seqno stays pinned above every genuine seqno hq re-emits).
            frame = forge.link_frame(wf.PyMac.BROADCAST, sim.mac("eve"), body)
            for i in range(120):
                sim.inject("eve", frame, at_s=0.2 + i * 0.2)
        sim.run(until_s=25.0)
        rec = _ogm_record(sim, "victim", hq_mac)
        return (
            sim.has_route("victim", hq_mac),
            rec.last_seqno if rec else None,
            replayed_seqno,
        )

    routed_clean, _seq_clean, _ = run(with_attacker=False)
    routed_attack, seq_attack, replayed = run(with_attacker=True)

    # The gap: hq is genuinely adjacent and present (control acquires a route),
    # yet the attack denies acquisition while pinning last_seqno at the replayed
    # value so hq's genuine current OGMs are all discarded as stale.
    jammed = routed_clean and not routed_attack
    return Finding(
        "OGM seqno high-water jam (stale replay denies route acquisition)",
        GAP if jammed else HELD,
        (
            f"hq adjacent and present routes cleanly ({routed_clean}); one "
            f"replayed signed OGM pins victim's last_seqno at {seq_attack} "
            f"(replayed {replayed}) so every genuine low-seqno OGM from the "
            f"rebooted hq is discarded as stale and no route forms "
            f"({routed_attack})"
            if jammed
            else f"clean route: {routed_clean}, route under attack: "
            f"{routed_attack}, pinned last_seqno: {seq_attack}"
        ),
    )


def attack_broadcast_seqno_blackhole() -> Finding:
    """One forged, unauthenticated `Bcast` frame carrying a member's address and
    a maxed sequence number silences that member's genuine broadcasts mesh-wide.

    Broadcast dedup is a strict per-originator high-water: a `Bcast` with
    `incoming_seqno <= entry` is dropped as a duplicate (engine.rs
    `handle_broadcast`). `Bcast` frames are authenticated by nothing on ingress
    (only OGMs are gated — auth.rs scope note), so the attacker chooses both the
    `orig` field and the seqno freely. She injects `orig = hq, seqno = 0xFFFF_
    FFFF`; hq's real broadcasts start at seqno 1 and are all `<=` the poisoned
    high-water, so every one is dropped before local delivery or re-flood.

    The auth scope note already concedes an outsider can *inject* a broadcast
    flood on an auth mesh — a nuisance. This is the sharper, unstated
    escalation: from injecting noise to silently and durably *suppressing* a
    named member's legitimate broadcasts with a single frame. Measured by
    whether `field` ever delivers hq's real broadcast payload to its local host.
    """
    m = mesh()
    nodes = [*_members("hq", "field"), Node("eve")]
    sim = Simulation(nodes, shared_lan(["hq", "field", "eve"], PerfectWire()), mesh=m)
    sim.run(until_s=15.0)

    # Control: hq's broadcast reaches field's local host with no attacker.
    sim.send("hq", "*", b"CLEAN-BCAST", at_s=15.5)
    sim.run(until_s=17.0)
    clean_delivered = _drain_contains(sim, "field", b"CLEAN-BCAST")

    # Poison field's dedup high-water for hq's address, then hq broadcasts.
    poison = forge.link_frame(
        wf.PyMac.BROADCAST,
        sim.mac("eve"),
        _bcast_packet(sim.mac("hq"), 0xFFFF_FFFF, ttl=1),
    )
    for i in range(5):
        sim.inject("eve", poison, at_s=17.5 + i * 0.1)
    sim.run(until_s=19.0)
    _drain(sim, "field")  # discard eve's (empty) poison delivery
    sim.send("hq", "*", b"REAL-BCAST", at_s=19.5)
    sim.run(until_s=22.0)
    suppressed = not _drain_contains(sim, "field", b"REAL-BCAST")

    blackholed = clean_delivered and suppressed
    return Finding(
        "Broadcast seqno high-water blackhole",
        GAP if blackholed else HELD,
        (
            "one forged Bcast (orig=hq, seqno=0xFFFFFFFF) pins field's dedup "
            "high-water so hq's genuine broadcasts are all dropped as stale "
            f"(clean delivery first: {clean_delivered}); a keyless outsider "
            "durably silences a named member's broadcasts"
            if blackholed
            else f"clean broadcast delivered: {clean_delivered}; real broadcast "
            f"suppressed after poison: {suppressed}"
        ),
    )


def attack_broadcast_dedup_table_exhaustion() -> Finding:
    """Flood `Bcast` frames under many distinct ghost originators to fill the
    receiver's fixed broadcast-dedup table, then a genuine member that has not
    broadcast yet can never get its first broadcast delivered.

    The dedup table is bounded (one entry per originator, capacity
    `MAX_ORIGINATORS`) and does *not* evict: once full, a `Bcast` from an
    originator not already present hits `push().is_err()` and is dropped
    (engine.rs `handle_broadcast`, "table full, drop packet"). Ghost-orig
    `Bcast` frames are unauthenticated, so the attacker mints as many distinct
    originators as she likes. After the table is saturated, `hq` — a real
    member whose address was never entered — broadcasts, and its packet is
    dropped for want of a table slot.

    Distinct mechanism from the high-water blackhole: that suppresses one named
    member; this denies broadcast to *every* originator not already in the
    table. Measured by whether `field` delivers hq's real broadcast after the
    table is flooded full, against a control with no flood.
    """
    m = mesh()
    nodes = [*_members("hq", "field"), Node("eve")]
    sim = Simulation(nodes, shared_lan(["hq", "field", "eve"], PerfectWire()), mesh=m)
    sim.run(until_s=15.0)

    # How many distinct ghost origs to mint. Overshoot any plausible
    # MAX_ORIGINATORS so the table is certainly saturated.
    ghost_count = 400
    t = 15.5
    for i in range(ghost_count):
        ghost = wf.PyMac(bytes((0x02, 0x00, (i >> 8) & 0xFF, i & 0xFF, 0x00, 0x01)))
        frame = forge.link_frame(
            wf.PyMac.BROADCAST, sim.mac("eve"), _bcast_packet(ghost, 1, ttl=1)
        )
        sim.inject("eve", frame, at_s=t)
        t += 0.01
    sim.run(until_s=t + 1.0)
    _drain(sim, "field")

    # hq (never previously a broadcast originator) now broadcasts.
    sim.send("hq", "*", b"POST-EXHAUSTION", at_s=t + 1.5)
    sim.run(until_s=t + 4.0)
    denied = not _drain_contains(sim, "field", b"POST-EXHAUSTION")

    return Finding(
        "Broadcast dedup-table exhaustion",
        GAP if denied else HELD,
        (
            f"{ghost_count} ghost-originator Bcasts saturate field's dedup "
            "table; hq's first genuine broadcast is then dropped for want of a "
            "slot — a keyless outsider denies broadcast to every not-yet-seen "
            "originator"
            if denied
            else f"hq's broadcast still delivered after {ghost_count} ghost "
            "origs — the dedup table is not exhaustible this way"
        ),
    )


def attack_relayed_tq_inflation() -> Finding:
    """An unauthenticated relay re-floods a member's genuine signed OGM with the
    advertised TQ maxed to 255, trying to make the path through *itself* look
    like the best route to that member.

    TQ is a per-hop mutable field, excluded from the OGM signature — so the
    inflated copy still verifies (its `orig+seqno+cert` are untouched). This is
    BATMAN-IV's classic metric-injection surface. Two defenses should neutralise
    it: (1) the engine attenuates advertised TQ by the per-hop penalty (−10) and
    then *clamps it by the locally-measured link quality* to the relayer
    (engine.rs), so a node cannot claim a path better than the link actually
    observed; and (2) the next-hop proof gate refuses to *select* an unproven
    relay however good its advertised metric. Eve holds no credential, so she
    can answer no challenge.

    Should hold: measured by the TQ the victim records for eve's path (must be
    the hop-penalised value, capped at 245, not the claimed 255) and by whether
    eve is ever chosen as best_next_hop for hq.
    """
    body, _ = _capture_signed_ogm()
    m = mesh()
    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=m,
    )
    # The genuine originator is whatever the captured body claims (bytes 8..14):
    # `_capture_signed_ogm` returns hq's MAC but the body may be a relayed OGM,
    # so read the orig straight off the bytes we are replaying.
    orig_mac = wf.PyMac(bytes(body[8:14]))
    inflated = bytearray(body)
    # tq is the byte right after `reserved`, at offset 15 in the OGM header
    # (type,ver,ttl,flags,seqno[4],orig[6],reserved,tq) — a per-hop field the
    # signature does not cover, so maxing it does not break verification.
    inflated[15] = 255
    frame = forge.link_frame(wf.PyMac.BROADCAST, sim.mac("eve"), bytes(inflated))
    for i in range(60):
        sim.inject("eve", frame, at_s=0.5 + i * 0.3)
    sim.run(until_s=25.0)

    rec = _ogm_record(sim, "victim", orig_mac)
    eve_mac = sim.mac("eve")
    eve_paths = [p for p in (rec.paths if rec else []) if p.neighbor == eve_mac]
    eve_tq = eve_paths[0].last_tq if eve_paths else None
    eve_is_next_hop = bool(rec and rec.best_next_hop == eve_mac)

    held = (eve_tq is None or eve_tq < 255) and not eve_is_next_hop
    return Finding(
        "Relayed OGM TQ inflation",
        HELD if held else GAP,
        (
            f"eve advertised tq=255 but victim recorded her path at tq={eve_tq} "
            "(hop-penalised and clamped to the measured link, not 255) and "
            "never selected her as best_next_hop — metric injection buys "
            "nothing past the proof gate and the local-quality clamp"
            if held
            else f"eve's inflated tq was accepted: recorded tq={eve_tq}, "
            f"selected as next hop: {eve_is_next_hop}"
        ),
    )


# --- small helpers ------------------------------------------------------


def _drain(sim: Simulation, node: str) -> list[bytes]:
    out = []
    while True:
        payload = sim.poll_local(node)
        if payload is None:
            return out
        out.append(payload)


def _drain_contains(sim: Simulation, node: str, needle: bytes) -> bool:
    return any(needle in p for p in _drain(sim, node))


ATTACKS: list[Callable[[], Finding]] = [
    attack_unauthenticated_joiner,
    attack_foreign_mesh,
    attack_forged_ogm,
    attack_revocation,
    attack_flood,
    attack_passive_eavesdrop,
    attack_expired_credential,
    attack_ogm_replay,
    attack_ogm_replay_hijacks_local_traffic,
    attack_forged_challenge_response_flood,
    attack_challenge_response_replay,
    attack_broadcast_addressed_challenge,
    attack_unauthenticated_relay,
    attack_ca_misissuance,
    attack_proof_starvation_by_neighbour_count,
    # --- 2026-08 sweep ---
    attack_reserved_address_originator,
    attack_misissued_cert_overwrites_live_member,
    attack_unbounded_validity_window,
    attack_degenerate_validity_window,
    attack_fail_open_bridge_containment,
    attack_multicast_addressed_directed_delivery,
    attack_injected_directed_laundered_by_relay,
    attack_directed_unicast_replay,
    attack_cross_pair_tag_forgery,
    attack_directed_frame_parsing_robustness,
    attack_unicast_addressed_challenge_reflection,
    attack_forged_response_reaches_proof_handler,
    attack_challenge_nonce_is_unpredictable,
    attack_captured_challenge_replayed,
    attack_proof_survives_key_eviction_window,
    attack_forged_self_revocation_killswitch,
    attack_self_revocation_replay_after_reenrollment,
    attack_self_revocation_same_second_tie,
    attack_foreign_root_revokes_member,
    attack_forged_revocation_flood_evicts_genuine,
    attack_stale_revocation_denies_readmission,
    attack_ogm_seqno_highwater_jam,
    attack_broadcast_seqno_blackhole,
    attack_broadcast_dedup_table_exhaustion,
    attack_relayed_tq_inflation,
]


def described(finding: Finding, attack: Callable[[], Finding]) -> Finding:
    """`finding` with `attack`'s own docstring attached as its description.

    The docstrings above are already the argument for why each attack should
    fail — several of them cite the design doc section that reasons it
    through. Reading them off the function is what lets the page carry that
    reasoning without a second, drifting copy of it living in a table
    somewhere.
    """
    return dataclasses.replace(finding, description=inspect.getdoc(attack) or "")


def run_all() -> list[Finding]:
    """Run every attack, each against its own freshly built mesh so no attack
    can contaminate the next."""
    return [described(attack(), attack) for attack in ATTACKS]


def finding_reports(findings: Sequence[Finding]) -> list[FindingReport]:
    """Findings as the rows `wayfinder_sim.report` renders.

    A deliberate translation rather than handing `Finding` straight to the
    report: the scenario's record of an attack and the page's row happen to
    carry the same four fields today, and nothing about the page should
    constrain what an attack is allowed to record tomorrow.
    """
    return [
        FindingReport(
            name=finding.name,
            verdict=finding.verdict,
            detail=finding.detail,
            description=finding.description,
        )
        for finding in findings
    ]


def write_report(findings: Sequence[Finding], out_path: Path) -> Path:
    """Write the whole battery to one self-contained HTML page."""
    gaps = sum(f.verdict == GAP for f in findings)
    # Spelled out rather than rendered as a numeral, because the sentence is
    # prose and "0 of them got through" is the one number on this page that
    # should read as a sentence rather than as data.
    got_through = {0: "None", 1: "One"}.get(gaps, str(gaps))
    return write_red_team_report(
        out_path,
        "Wayfinder red team",
        finding_reports(findings),
        subtitle=(
            f"{len(findings)} attacks against an authenticated mesh — a real mesh "
            "root, per-node membership certificates and signed OGMs — each run in "
            "its own isolated simulation against a freshly built mesh. Every "
            "verdict below was read off the router's own state rather than "
            f"assumed. {got_through} of them got through in a way the design does "
            "not intend to allow."
        ),
    )


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
    findings = run_all()
    print_report(findings)

    out_path = write_report(
        findings, Path(__file__).parent / "output" / "red_team_report.html"
    )
    print(f"Red team report written to {out_path}")


if __name__ == "__main__":
    main()
