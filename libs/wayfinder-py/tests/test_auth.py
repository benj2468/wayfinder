"""Mesh identity and OGM authentication, driven from Python.

These are the bindings a red-team scenario needs: mint a mesh root, issue
(or deliberately withhold) membership certificates, and watch an
authenticated node accept its own members while rejecting everyone else.
"""

import wayfinder_py as wf

# A wall-clock instant to anchor certificate validity on. The tick driver
# counts monotonic milliseconds from zero, so `epoch_unix` is what maps that
# onto the unix clock certificates are judged against.
EPOCH = 1_700_000_000
CERT_WINDOW = (EPOCH - 3600, EPOCH + 86_400)


def _drain_egress(src: wf.PyDriver, dst: wf.PyDriver, idx: int) -> None:
    frame = src.poll_egress(idx)
    while frame is not None:
        dst.push_rx(idx, frame)
        frame = src.poll_egress(idx)


def _converge(a: wf.PyDriver, b: wf.PyDriver, steps: int = 300) -> int:
    now = 0
    for _ in range(steps):
        now += 10
        a.tick(now)
        b.tick(now)
        _drain_egress(a, b, 0)
        _drain_egress(b, a, 0)
    return now


def _has_route(driver: wf.PyDriver, mac: wf.PyMac) -> bool:
    """Whether `driver` has actually learned a route to `mac`.

    Deliberately *not* `get_egress_interface`: that falls back to the
    link-quality table, which is populated on frame receipt before the auth
    verdict is reached — so it resolves an interface for a node whose every
    OGM was rejected. Membership questions must be asked of the routing and
    neighbor tables, which only a verified OGM writes to.
    """
    return any(record.originator == mac for record in driver.originator_table())


def _enrolled(
    authority: wf.PyAuthority, seed: bytes, trickle=(50, 500)
) -> tuple[wf.PyDriver, wf.PyKeypair]:
    """A driver whose MAC is derived from `seed`'s keypair, carrying a
    membership cert this authority issued for it."""
    keypair = wf.PyKeypair.from_seed(seed)
    driver = wf.PyDriver(keypair.derived_mac, [trickle])
    cert = authority.enroll(keypair, *CERT_WINDOW)
    driver.set_epoch_unix(EPOCH)
    driver.set_auth(keypair, cert, authority.trust_anchor())
    return driver, keypair


# --- identity primitives ------------------------------------------------


def test_keypair_derives_a_stable_mac_from_its_seed():
    a = wf.PyKeypair.from_seed(bytes([7]) * 32)
    b = wf.PyKeypair.from_seed(bytes([7]) * 32)
    assert a.derived_mac == b.derived_mac, "the MAC is a function of the seed"
    assert a.ed_pubkey == b.ed_pubkey
    assert a.x_pubkey == b.x_pubkey

    other = wf.PyKeypair.from_seed(bytes([8]) * 32)
    assert other.derived_mac != a.derived_mac


def test_generated_keypairs_are_distinct():
    assert wf.PyKeypair.generate().derived_mac != wf.PyKeypair.generate().derived_mac


def test_membership_cert_round_trips_through_bytes():
    authority = wf.PyAuthority.from_seed(bytes([1]) * 32, 0xABCD)
    keypair = wf.PyKeypair.from_seed(bytes([2]) * 32)
    cert = authority.enroll(keypair, *CERT_WINDOW)

    restored = wf.PyMembershipCert(bytes(cert))
    assert restored.node_mac == keypair.derived_mac
    assert restored.mesh_id == 0xABCD
    assert restored.fingerprint == cert.fingerprint
    assert restored.not_before == CERT_WINDOW[0]
    assert restored.not_after == CERT_WINDOW[1]


def test_trust_anchor_round_trips_through_bytes():
    authority = wf.PyAuthority.from_seed(bytes([1]) * 32, 0x1234)
    anchor = authority.trust_anchor()
    restored = wf.PyTrustAnchor(bytes(anchor))
    assert restored.mesh_id == 0x1234
    assert restored.root_pubkey == anchor.root_pubkey


# --- what auth actually buys -------------------------------------------


def test_two_enrolled_nodes_converge():
    """Authentication must not break the happy path: two members of the same
    mesh still learn a route to each other."""
    authority = wf.PyAuthority.from_seed(bytes([1]) * 32, 0xABCD)
    a, a_kp = _enrolled(authority, bytes([10]) * 32)
    b, b_kp = _enrolled(authority, bytes([11]) * 32)

    assert not a.auth_locked, "a valid cert unlocks the router"
    _converge(a, b)

    assert _has_route(a, b_kp.derived_mac)
    assert _has_route(b, a_kp.derived_mac)
    assert b_kp.derived_mac in a.neighbor_macs(), "and each verified the other"


def test_unauthenticated_node_is_not_admitted_by_an_enrolled_node():
    """An outsider running a stock, open router alongside an authenticated
    mesh: its OGMs carry no signature, so the member must never route to it."""
    authority = wf.PyAuthority.from_seed(bytes([1]) * 32, 0xABCD)
    member, member_kp = _enrolled(authority, bytes([10]) * 32)

    outsider_mac = wf.PyMac(b"\x02\x00\x00\x00\x00\x99")
    outsider = wf.PyDriver(outsider_mac, [(50, 500)])

    _converge(member, outsider)

    assert not _has_route(member, outsider_mac), (
        "an unsigned OGM must not create a route"
    )
    assert outsider_mac not in member.neighbor_macs(), (
        "and the outsider is never admitted as a verified neighbor"
    )
    # The reverse direction is deliberately *not* asserted: the member's OGMs
    # are signed but not encrypted, so an open router happily learns a route
    # to it. Authentication segregates the mesh's trust, not its radio.
    assert member_kp.derived_mac in [
        record.originator for record in outsider.originator_table()
    ], "an open outsider still hears the mesh — signatures are not secrecy"


def test_foreign_mesh_credentials_are_rejected():
    """A node with a perfectly valid certificate — signed by the *wrong* root.
    Mesh segregation is the whole point of the trust anchor."""
    ours = wf.PyAuthority.from_seed(bytes([1]) * 32, 0xABCD)
    theirs = wf.PyAuthority.from_seed(bytes([2]) * 32, 0xABCD)

    member, _ = _enrolled(ours, bytes([10]) * 32)
    intruder, intruder_kp = _enrolled(theirs, bytes([11]) * 32)

    _converge(member, intruder)

    assert not _has_route(member, intruder_kp.derived_mac), (
        "a cert from a foreign root must not admit a node"
    )
    assert intruder_kp.derived_mac not in member.neighbor_macs()


def test_require_auth_locks_a_node_with_no_certificate():
    """Fail-closed: a node told to require auth, with nothing installed, must
    be completely inert on the mesh rather than falling back to open mode."""
    mac = wf.PyMac(b"\x02\x00\x00\x00\x00\x01")
    node = wf.PyDriver(mac, [(50, 500)])
    node.set_require_auth(True)

    assert node.auth_locked

    now = 0
    for _ in range(300):
        now += 10
        node.tick(now)
    assert node.poll_egress(0) is None, "a locked node emits nothing at all"


def test_revocation_ejects_a_former_member():
    """A legitimate member turns bad. The root signs a revocation; once a peer
    ingests it, the revoked node's route is gone."""
    authority = wf.PyAuthority.from_seed(bytes([1]) * 32, 0xABCD)
    good, _ = _enrolled(authority, bytes([10]) * 32)
    rogue, rogue_kp = _enrolled(authority, bytes([11]) * 32)

    now = _converge(good, rogue)
    assert _has_route(good, rogue_kp.derived_mac), (
        "the rogue is a member in good standing to begin with"
    )

    record = authority.revoke(rogue_kp.derived_mac, *CERT_WINDOW)
    assert good.ingest_revocation(record), "a root-signed revocation is accepted"
    assert rogue_kp.derived_mac in good.revoked_macs()

    for _ in range(300):
        now += 10
        good.tick(now)
        rogue.tick(now)
        _drain_egress(good, rogue, 0)
        _drain_egress(rogue, good, 0)

    assert not _has_route(good, rogue_kp.derived_mac), (
        "a revoked node must be purged and must not be re-learned"
    )


def test_revocation_record_round_trips_through_bytes():
    authority = wf.PyAuthority.from_seed(bytes([1]) * 32, 0xABCD)
    target = wf.PyMac(b"\x02\x00\x00\x00\x00\x07")
    record = authority.revoke(target, *CERT_WINDOW)

    restored = wf.PyRevocationRecord(bytes(record))
    assert restored.node_mac == target
    assert restored.mesh_id == 0xABCD


def test_auth_status_reports_neighbor_certificates():
    """The security view: an authenticated node knows which peers it has
    verified, so a scenario can assert on membership directly rather than
    inferring it from routes."""
    authority = wf.PyAuthority.from_seed(bytes([1]) * 32, 0xABCD)
    a, _ = _enrolled(authority, bytes([10]) * 32)
    b, b_kp = _enrolled(authority, bytes([11]) * 32)

    assert a.auth_enabled
    assert a.neighbor_macs() == []

    _converge(a, b)

    assert b_kp.derived_mac in a.neighbor_macs()


def test_no_payload_reaches_a_node_that_failed_verification():
    """The consequence that actually matters. A member's `get_egress_interface`
    *does* resolve an interface toward a rejected node — link quality is
    recorded on receipt, before the auth verdict — so the guarantee cannot rest
    on route resolution. It rests on the directed data plane: with no verified
    cert there is no pairwise key, so the frame is dropped at dispatch rather
    than emitted in the clear.
    """
    ours = wf.PyAuthority.from_seed(bytes([1]) * 32, 0xABCD)
    theirs = wf.PyAuthority.from_seed(bytes([2]) * 32, 0xABCD)

    member, _ = _enrolled(ours, bytes([10]) * 32)
    intruder, intruder_kp = _enrolled(theirs, bytes([11]) * 32)

    now = _converge(member, intruder)
    assert member.get_egress_interface(intruder_kp.derived_mac) is not None, (
        "link quality alone resolves an interface — this is why it is the "
        "wrong question to ask about membership"
    )

    member.queue_local_send(intruder_kp.derived_mac, b"TOP SECRET PAYLOAD")
    now += 10
    member.tick(now)

    emitted = []
    frame = member.poll_egress(0)
    while frame is not None:
        emitted.append(frame)
        frame = member.poll_egress(0)

    assert not any(b"TOP SECRET PAYLOAD" in frame for frame in emitted), (
        "an untaggable unicast is dropped, never emitted unauthenticated"
    )

    for frame in emitted:
        intruder.push_rx(0, frame)
    now += 10
    intruder.tick(now)
    assert intruder.poll_local() is None
