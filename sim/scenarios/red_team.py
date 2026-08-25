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
