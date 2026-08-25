"""Red-team primitives: crafting frames by hand, putting them on a link
without a router's cooperation, and listening to everything that crosses one.

These deliberately sit *outside* `PyDriver`. An attacker does not call our
send path — it puts bytes on the medium.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
import wayfinder_py as wf
from wayfinder_sim import forge
from wayfinder_sim.adversary import Wiretap
from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.security import Credential, Mesh
from wayfinder_sim.topology import pair, shared_lan


def _mac(n: int) -> wf.PyMac:
    return wf.PyMac(bytes([0x02, 0, 0, 0, 0, n]))


# --- frame forging ------------------------------------------------------


def test_forged_link_frame_has_the_on_wire_layout():
    frame = forge.link_frame(_mac(1), _mac(2), b"body")
    assert frame[:6] == bytes([0x02, 0, 0, 0, 0, 1]), "dst first, as in Ethernet"
    assert frame[6:12] == bytes([0x02, 0, 0, 0, 0, 2])
    assert frame[12:14] == (0x4305).to_bytes(2, "big")
    assert frame[14:] == b"body"


def test_a_forged_ogm_is_accepted_by_an_open_router():
    """The baseline an attack is measured against: with no authentication, a
    hand-crafted OGM is indistinguishable from a real one and creates a route
    to a node that does not exist."""
    victim = wf.PyDriver(_mac(1), [(50, 500)])
    ghost = _mac(200)

    for seqno in range(1, 6):
        victim.push_rx(
            0,
            forge.link_frame(
                wf.PyMac.BROADCAST, ghost, forge.ogm(orig=ghost, seqno=seqno)
            ),
        )
        victim.tick(seqno * 100)

    assert ghost in [r.originator for r in victim.originator_table()], (
        "an open mesh believes anything it hears"
    )


def test_a_forged_ogm_is_rejected_by_an_authenticated_router():
    """The same bytes against an enrolled node: no signature, no route."""
    mesh = Mesh(mesh_id=0xABCD, root_seed=bytes([1]) * 32)
    keypair = mesh.keypair("victim")
    victim = wf.PyDriver(keypair.derived_mac, [(50, 500)])
    victim.set_epoch_unix(mesh.epoch_unix)
    victim.set_auth(keypair, mesh.enroll(keypair), mesh.trust_anchor)

    ghost = _mac(200)
    for seqno in range(1, 6):
        victim.push_rx(
            0,
            forge.link_frame(
                wf.PyMac.BROADCAST, ghost, forge.ogm(orig=ghost, seqno=seqno)
            ),
        )
        victim.tick(seqno * 100)

    assert ghost not in [r.originator for r in victim.originator_table()]


def test_garbage_is_not_mistaken_for_a_frame():
    """Random bytes shaped like a frame must be dropped, not parsed."""
    victim = wf.PyDriver(_mac(1), [(50, 500)])
    import random

    rng = random.Random(0)
    for i in range(200):
        victim.push_rx(0, forge.garbage(rng, min_len=14, max_len=200))
        victim.tick(i * 10)

    assert victim.originator_table() == []


def test_a_frame_too_short_to_parse_is_rejected_at_the_call():
    victim = wf.PyDriver(_mac(1), [(50, 500)])
    with pytest.raises(wf.MalformedFrameError):
        victim.push_rx(0, b"\x00" * 8)


# --- injection ----------------------------------------------------------


def test_injected_frames_reach_the_other_end_of_a_link():
    """`inject` bypasses the attacker's own router and puts bytes straight on
    the medium, through the same channel model a real frame crosses.

    Also pins the shape of the resulting hijack: the forged route appears on
    the first injected OGM and *lapses* once the attacker goes quiet, because
    nothing refreshes it. A route hijack has to be maintained, which is what
    makes it audible — an attacker holding one is transmitting continuously.
    """
    nodes = [Node("victim"), Node("attacker")]
    sim = Simulation(nodes, [pair("victim", "attacker", PerfectWire())])

    ghost = _mac(200)
    for seqno in range(1, 8):
        sim.inject(
            "attacker",
            forge.link_frame(
                wf.PyMac.BROADCAST, ghost, forge.ogm(orig=ghost, seqno=seqno)
            ),
            at_s=seqno * 0.5,
        )
    sim.record("hijacked", lambda s: s.has_route("victim", ghost))
    rec = sim.run(until_s=10.0)

    hijacked = rec.column("hijacked")
    assert any(hijacked), "an open victim routes to a node the attacker invented"
    assert not hijacked[-1], "and forgets it once the injection stops"


def test_injection_from_a_node_with_no_link_raises():
    sim = Simulation([Node("a"), Node("b")], [pair("a", "b", PerfectWire())])
    with pytest.raises(KeyError):
        sim.inject("nobody", b"\x00" * 20, at_s=0.0)


def test_flood_emits_at_the_requested_rate():
    """The blast primitive: sustained injection, for measuring what a storm of
    frames does to a mesh that must keep routing through it."""
    nodes = [Node("victim"), Node("attacker")]
    sim = Simulation(nodes, [pair("victim", "attacker", PerfectWire())])
    tap = sim.wiretap("victim-attacker")

    sim.flood(
        "attacker",
        lambda: forge.link_frame(wf.PyMac.BROADCAST, _mac(200), forge.ogm(_mac(200))),
        rate_hz=100,
        start_s=1.0,
        duration_s=2.0,
    )
    sim.run(until_s=5.0)

    injected = [f for f in tap.frames if f.src == _mac(200)]
    assert 180 <= len(injected) <= 220, f"~200 frames over 2 s, got {len(injected)}"
    assert all(1.0 <= f.t_s <= 3.05 for f in injected), "confined to the window"


# --- wiretapping --------------------------------------------------------


def test_a_wiretap_captures_every_frame_crossing_its_link():
    nodes = [Node("a"), Node("b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())])
    tap = sim.wiretap("a-b")

    sim.run(until_s=10.0)

    assert tap.frames, "OGM traffic alone fills a tap"
    assert {f.src for f in tap.frames} == {sim.mac("a"), sim.mac("b")}


def test_a_wiretap_reads_payloads_in_the_clear_even_on_an_authenticated_mesh():
    """The documented non-goal, asserted rather than assumed: wayfinder
    authenticates, it does not encrypt. A listener on the segment reads
    application payloads whether or not the mesh is authenticated — anything
    confidential must be encrypted above this layer.
    """
    mesh = Mesh(mesh_id=0xABCD, root_seed=bytes([1]) * 32)
    nodes = [
        Node("a", credential=Credential()),
        Node("b", credential=Credential()),
        Node("eve", credential=Credential()),
    ]
    sim = Simulation(nodes, shared_lan(["a", "b", "eve"], PerfectWire()), mesh=mesh)
    tap = sim.wiretap("a-b-eve")

    sim.run(until_s=20.0)
    sim.send("a", "b", b"MEETING AT DAWN", at_s=21.0)
    sim.run(until_s=25.0)

    assert any(b"MEETING AT DAWN" in f.raw for f in tap.frames), (
        "payloads are authenticated, never encrypted — this is by design"
    )


def test_a_wiretap_on_an_unknown_link_raises():
    sim = Simulation([Node("a"), Node("b")], [pair("a", "b", PerfectWire())])
    with pytest.raises(KeyError):
        sim.wiretap("nope")


# --- replay, and what authentication does not cover ---------------------


def _capture_signed_ogm(mesh: Mesh) -> tuple[bytes, wf.PyMac]:
    """One genuine signed OGM body from `hq`, plus `hq`'s MAC — the raw
    material for a replay, obtained by doing nothing but listening."""
    nodes = [
        Node("hq", credential=Credential()),
        Node("relay", credential=Credential()),
        Node("eve"),
    ]
    sim = Simulation(
        nodes, shared_lan(["hq", "relay", "eve"], PerfectWire()), mesh=mesh
    )
    tap = sim.wiretap("hq-relay-eve")
    sim.run(until_s=20.0)
    ogms = [f for f in tap.of_type(forge.PACKET_OGM) if f.src == sim.mac("hq")]
    assert ogms, "the mesh never converged, so nothing was captured"
    return ogms[-1].payload, sim.mac("hq")


def test_a_captured_signed_ogm_does_not_route_a_node_with_no_prior_state():
    """The narrowest form of the replay, and the first one found.

    The OGM signature covers `orig ‖ seqno ‖ cert` and binds no freshness — no
    timestamp, no nonce — so a captured OGM verifies forever, and seqno replay
    protection is per-receiver state that a just-booted or out-of-range node
    does not have. All of that is still true: the replay is still *accepted*.

    What stops it being a route is the next-hop proof. The address the attacker
    spoofs would have to answer a challenge with a pairwise key it does not
    hold, so the absent originator never becomes reachable however long the
    replay continues. Freshness was never the fix; proving the forwarder was.
    """
    mesh = Mesh(mesh_id=0xABCD, root_seed=bytes([1]) * 32)
    body, hq_mac = _capture_signed_ogm(mesh)

    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=mesh,
    )
    frame = forge.link_frame(wf.PyMac.BROADCAST, hq_mac, body)
    for i in range(60):
        sim.inject("eve", frame, at_s=0.5 + i * 0.3)
    sim.record("route", lambda s: s.has_route("victim", hq_mac))
    rec = sim.run(until_s=25.0)

    assert not any(rec.column("route")), (
        "a replayed OGM never yields a usable route to an absent originator"
    )
    record = next(
        (r for r in sim.driver("victim").originator_table() if r.originator == hq_mac),
        None,
    )
    assert record is not None and record.best_next_hop is None, (
        "it is still learned as a path — the signature is genuine — but is "
        "never selected"
    )


def _freshest_ogm_by(tap: Wiretap, orig: wf.PyMac) -> bytearray:
    """The highest-seqno OGM *originated* by `orig` that crossed `tap`.

    Selected on the OGM's own `orig` field rather than the frame's link-layer
    source, because the copy an attacker one segment away actually hears is
    the one a relay re-flooded under its own source.
    """
    ogms = sorted(
        (
            frame
            for frame in tap.of_type(forge.PACKET_OGM)
            if len(frame.payload) > 15 and frame.payload[8:14] == orig.bytes
        ),
        key=lambda frame: int.from_bytes(frame.payload[4:8], "big"),
    )
    assert ogms, "the attacker heard no OGM from the originator she is replaying"
    return bytearray(ogms[-1].payload)


def _next_hop(sim: Simulation, node: str, orig: wf.PyMac) -> str:
    """`node`'s currently chosen next hop toward `orig`."""
    for record in sim.driver(node).originator_table():
        if record.originator == orig:
            return str(record.best_next_hop)
    raise AssertionError(f"{node} has no route to {orig}")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda body: None,
        lambda body: body.__setitem__(15, 255),
    ],
    ids=["verbatim", "tq_maxed"],
)
def test_a_replayed_ogm_cannot_take_an_established_route(
    mutate: Callable[[bytearray], object],
):
    """The gap-1/gap-2 fix, measured against the attack that found it.

    This test asserted the *hijack* until the next-hop proof landed. The
    replayed OGM still verifies — it is genuinely signed, and the signature
    covers no freshness — and the engine still accepts it for path learning,
    since its seqno is current. What has changed is that a path can no longer
    be *selected* on the strength of the OGM alone: before it can win
    `best_next_hop` its relay must answer a challenge with the pairwise key for
    the address it claims. Eve holds no credential and cannot, so the victim
    keeps routing through the relay.

    Both parametrisations are kept from the attack: `verbatim` was the cheapest
    form of the hijack (nothing altered but the link-layer source) and
    `tq_maxed` the most forceful (the unsigned TQ field maxed). Neither moves
    the route now.

    See `docs/design/09-mesh-auth-gaps.md` §4.
    """
    mesh = Mesh(mesh_id=0xABCD, root_seed=bytes([1]) * 32)
    sim = Simulation(
        [
            Node("hq", credential=Credential()),
            Node("relay", credential=Credential()),
            Node("victim", credential=Credential()),
            Node("eve"),
        ],
        [
            pair("hq", "relay", PerfectWire()),
            *shared_lan(["relay", "victim", "eve"], PerfectWire()),
        ],
        mesh=mesh,
    )
    hq_mac, relay_mac = sim.mac("hq"), sim.mac("relay")
    segment = sim.wiretap("relay-victim-eve")
    backhaul = sim.wiretap("hq-relay")

    sim.run(until_s=40.0)
    assert _next_hop(sim, "victim", hq_mac) == str(relay_mac), (
        "the victim starts with a live, converged route through the relay"
    )

    now = 40.0
    while now < 70.0:
        body = _freshest_ogm_by(segment, hq_mac)
        mutate(body)
        sim.inject(
            "eve",
            forge.link_frame(wf.PyMac.BROADCAST, hq_mac, bytes(body)),
            at_s=now + 0.01,
            link="relay-victim-eve",
        )
        now += 0.25
        sim.run(until_s=now)

    assert _next_hop(sim, "victim", hq_mac) == str(relay_mac), (
        "30s of sustained replay does not move the route: the spoofed next hop "
        "never proved itself"
    )

    # The route is not merely unmoved, it still works — the gate must not cost
    # the victim the legitimate path it already had.
    backhaul.reset()
    sim.driver("victim").queue_local_send(hq_mac, b"SENSITIVE TRAFFIC")
    sim.run(until_s=76.0)
    assert backhaul.containing(b"SENSITIVE TRAFFIC"), (
        "traffic still reaches hq over the relay"
    )


def test_an_outsider_relaying_a_members_ogm_never_becomes_a_next_hop():
    """The other half of the same fix, and what changed about it.

    BATMAN's forwarding model has every relay re-flood a member's OGM under its
    own link-layer source, and authentication covers the *originator*, not the
    forwarder — so an outsider can re-flood a genuine OGM and be recorded as a
    path toward a member it cannot impersonate. That much still happens: the
    OGM is real, and discovery has to keep working or there would be nobody to
    challenge.

    What no longer happens is selection. Eve holds no credential, so she has no
    pairwise key, so she can never answer a challenge, so she can never win
    `best_next_hop`. Before the next-hop proof this was a silent blackhole —
    the victim believed it had a route and its traffic vanished at dispatch.
    Now the victim simply has no route to offer, which is the honest answer.
    """
    mesh = Mesh(mesh_id=0xABCD, root_seed=bytes([1]) * 32)
    body, hq_mac = _capture_signed_ogm(mesh)

    sim = Simulation(
        [Node("victim", credential=Credential()), Node("eve")],
        [pair("victim", "eve", PerfectWire())],
        mesh=mesh,
    )
    eve_mac = sim.mac("eve")
    relayed = bytearray(body)
    relayed[2] = 250  # TTL: a mutable per-hop field, outside the signature
    frame = forge.link_frame(wf.PyMac.BROADCAST, eve_mac, bytes(relayed))
    for i in range(80):
        sim.inject("eve", frame, at_s=0.5 + i * 0.3)
    sim.run(until_s=25.0)

    driver = sim.driver("victim")
    record = next(
        (r for r in driver.originator_table() if r.originator == hq_mac), None
    )
    assert record is not None, "the OGM is genuine, so the originator is learned"
    assert str(eve_mac) in {str(p.neighbor) for p in record.paths}, (
        "and eve is recorded as a path — discovery must keep working"
    )
    assert not driver.proof_current(eve_mac), (
        "but she holds no credential, so she can never prove herself"
    )
    assert record.best_next_hop is None, "and therefore never carries the route"
    assert eve_mac not in driver.neighbor_macs(), (
        "while never being admitted as a member either"
    )

    tap = sim.wiretap("victim-eve")
    driver.queue_local_send(hq_mac, b"SENSITIVE TRAFFIC")
    sim.run(until_s=31.0)
    assert not tap.containing(b"SENSITIVE TRAFFIC"), "and nothing is sent toward her"


def test_tq_and_ttl_are_mutable_but_the_signed_identity_fields_are_not():
    """The signature deliberately excludes the per-hop mutable fields (TTL,
    TQ) so it survives forwarding, and covers the identity fields so they
    cannot be rewritten. Pins both halves of that split."""
    mesh = Mesh(mesh_id=0xABCD, root_seed=bytes([1]) * 32)
    body, hq_mac = _capture_signed_ogm(mesh)

    def replay_accepted(mutate) -> bool:
        """Whether the replayed OGM is *accepted* — learned as a path.

        Deliberately not `has_route`: since the next-hop proof landed, no
        replay yields a usable route regardless of what it mutates, which would
        make every case below indistinguishable. What this test is about is
        which bytes the signature covers, and that shows in whether the OGM
        verifies at all.
        """
        b = bytearray(body)
        mutate(b)
        sim = Simulation(
            [Node("victim", credential=Credential()), Node("eve")],
            [pair("victim", "eve", PerfectWire())],
            mesh=mesh,
        )
        frame = forge.link_frame(wf.PyMac.BROADCAST, hq_mac, bytes(b))
        for i in range(40):
            sim.inject("eve", frame, at_s=0.5 + i * 0.3)
        sim.run(until_s=20.0)
        return any(
            r.originator == hq_mac for r in sim.driver("victim").originator_table()
        )

    # Offsets within the OGM header: [type][ver][ttl][flags][seqno:4][orig:6][rsv][tq]
    assert replay_accepted(lambda b: b.__setitem__(2, 255)), "TTL is not signed"
    assert replay_accepted(lambda b: b.__setitem__(15, 128)), "TQ is not signed"
    assert not replay_accepted(lambda b: b.__setitem__(8, b[8] ^ 0xFF)), (
        "the originator MAC is signed"
    )
    assert not replay_accepted(lambda b: b.__setitem__(-1, b[-1] ^ 0xFF)), (
        "and so is the signature itself"
    )
