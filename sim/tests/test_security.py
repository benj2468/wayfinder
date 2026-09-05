"""Mesh identity in the simulation engine: enrolling nodes against a mesh
root, and the credentials a red-team scenario deliberately gets wrong."""

from __future__ import annotations

import pytest
from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.security import Credential, Mesh
from wayfinder_sim.topology import pair


def _mesh(seed: int = 1) -> Mesh:
    return Mesh(mesh_id=0xABCD, root_seed=bytes([seed]) * 32)


def test_mesh_derives_a_stable_keypair_per_node_name():
    mesh = _mesh()
    assert mesh.keypair("alice").derived_mac == mesh.keypair("alice").derived_mac
    assert mesh.keypair("alice").derived_mac != mesh.keypair("bob").derived_mac


def test_two_meshes_with_the_same_id_have_different_anchors():
    """Mesh id is a label; the root key is the actual boundary."""
    assert _mesh(1).trust_anchor.root_pubkey != _mesh(2).trust_anchor.root_pubkey
    assert _mesh(1).mesh_id == _mesh(2).mesh_id


def test_an_enrolled_node_takes_its_key_derived_mac():
    """A certificate binds key to MAC, so an enrolled node cannot be given an
    address it holds no key for."""
    mesh = _mesh()
    nodes = [Node("a", credential=Credential()), Node("b", credential=Credential())]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], mesh=mesh)

    assert sim.mac("a") == mesh.keypair("a").derived_mac
    assert sim.driver("a").auth_enabled


def test_an_explicit_mac_on_an_enrolled_node_is_rejected():
    mesh = _mesh()
    import wayfinder_py as wf

    nodes = [
        Node("a", credential=Credential(), mac=wf.PyMac(b"\x02\x00\x00\x00\x00\x01")),
        Node("b", credential=Credential()),
    ]
    with pytest.raises(ValueError, match="derived from its key"):
        Simulation(nodes, [pair("a", "b", PerfectWire())], mesh=mesh)


def test_enrolled_nodes_converge():
    """The happy path: authentication must not stop a real mesh working."""
    mesh = _mesh()
    nodes = [Node("a", credential=Credential()), Node("b", credential=Credential())]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], mesh=mesh)
    sim.run(until_s=20.0)

    assert sim.admitted("a") == ("b",), "a verified b's certificate"
    assert sim.admitted("b") == ("a",)
    assert sim.has_route("a", "b")


def test_an_unenrolled_node_is_never_admitted():
    """A node with no credential at all, alongside an authenticated mesh."""
    mesh = _mesh()
    nodes = [
        Node("a", credential=Credential()),
        Node("intruder"),  # no credential
    ]
    sim = Simulation(nodes, [pair("a", "intruder", PerfectWire())], mesh=mesh)
    sim.run(until_s=20.0)

    assert sim.admitted("a") == ()
    assert not sim.has_route("a", "intruder")


def test_a_foreign_mesh_credential_is_never_admitted():
    """Valid certificate, wrong root — the segregation guarantee."""
    ours, theirs = _mesh(1), _mesh(2)
    nodes = [
        Node("a", credential=Credential()),
        Node("intruder", credential=Credential(mesh=theirs)),
    ]
    sim = Simulation(nodes, [pair("a", "intruder", PerfectWire())], mesh=ours)
    sim.run(until_s=20.0)

    assert sim.admitted("a") == ()
    assert not sim.has_route("a", "intruder")


def test_an_expired_credential_loses_its_route():
    """Certificate expiry is the passive revocation mechanism: a node whose
    window closes mid-run stops being verifiable, with no network involved.

    The control plane is where that bites. Every OGM's certificate is
    re-checked against the clock, so once the window closes nothing from that
    node verifies, and its route lapses when the last accepted OGM goes stale
    — noticeably later than the expiry instant itself.
    """
    mesh = _mesh()
    nodes = [
        Node("a", credential=Credential()),
        Node("b", credential=Credential(valid_until_s=10.0)),
    ]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], mesh=mesh)

    sim.record("route", lambda s: s.has_route("a", "b"))
    rec = sim.run(until_s=60.0)

    route = rec.column("route")
    assert any(route), "b is routable while its certificate is valid"
    assert not route[-1], "and unroutable once it expires and goes stale"


def test_expiry_cuts_off_an_already_cached_neighbor():
    """Certificate expiry is the mesh's *passive* revocation mechanism, so a
    lapsed member must lose the data plane too, not just its route.

    Verifying an OGM caches the peer's certificate and the pairwise key derived
    from it. Once that certificate expires the cache entry is evicted, so there
    is no key left to tag a frame to it or to accept one from it — the link
    goes quiet without anyone having to issue a revocation.
    """
    mesh = _mesh()
    nodes = [
        Node("a", credential=Credential()),
        Node("b", credential=Credential(valid_until_s=10.0)),
    ]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], mesh=mesh)
    sim.run(until_s=40.0)

    assert not sim.has_route("a", "b"), "the route is gone"
    assert sim.admitted("a") == (), "and the expired cert is out of the cache"

    sim.send("a", "b", b"POST-EXPIRY", at_s=41.0)
    sim.run(until_s=45.0)
    assert sim.poll_local("b") is None, (
        "and the link-local data plane no longer authenticates with its key"
    )


def test_require_auth_locks_a_node_holding_no_certificate():
    """Fail-closed: told to require auth with nothing installed, a node is
    inert rather than falling back to open operation."""
    mesh = _mesh()
    nodes = [
        Node("a", credential=Credential()),
        Node("b", credential=Credential(enrolled=False)),
    ]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], mesh=mesh)
    assert sim.driver("b").auth_locked
    sim.run(until_s=20.0)

    assert sim.admitted("a") == ()
    assert not sim.has_route("b", "a"), "a locked node learns nothing either"


def test_revoking_a_member_ejects_it():
    """The active purge: the root signs a revocation and the mesh drops the
    named node, without waiting for its certificate to expire."""
    mesh = _mesh()
    nodes = [
        Node("a", credential=Credential()),
        Node("b", credential=Credential()),
        Node("rogue", credential=Credential()),
    ]
    links = [
        pair("a", "b", PerfectWire()),
        pair("a", "rogue", PerfectWire()),
        pair("b", "rogue", PerfectWire()),
    ]
    sim = Simulation(nodes, links, mesh=mesh)
    sim.run(until_s=20.0)
    assert "rogue" in sim.admitted("a")

    sim.revoke("rogue")
    sim.run(until_s=60.0)

    assert "rogue" not in sim.admitted("a")
    assert "rogue" not in sim.admitted("b"), "the revocation floods to b as well"
    assert not sim.has_route("a", "rogue")


def test_a_mesh_is_optional_and_absent_leaves_every_node_open():
    """Existing scenarios declare no mesh and must be unaffected."""
    nodes = [Node("a"), Node("b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())])
    sim.run(until_s=20.0)

    assert not sim.driver("a").auth_enabled
    assert sim.has_route("a", "b")


def test_a_certificate_naming_a_mac_its_key_does_not_derive_is_refused():
    """`verify_cert` binds a certificate's subject to its identity key.

    This was gap 4 (design 09 §5), and the assertion below used to run the
    other way: verification checked the root's signature, the mesh id and the
    validity window, but never that `node_mac` was the address `ed_pubkey`
    derives — so a certificate binding a key to somebody else's address
    verified perfectly, and impersonation resistance rested entirely on the
    authority refusing to issue one.

    Now every node enforces it for itself. That is the half that holds even
    against a *compromised* authority: minting such a credential would need a
    `derive_mac` preimage, which a signing key does not provide.
    """
    mesh = _mesh()
    # An address the mesh knows but that no node in this run holds, so the
    # *only* way it can reach `field`'s neighbour cache is the misissuance.
    # (An earlier version of this fixture also ran hq, which cached the address
    # legitimately and made the assertion vacuous either way.)
    victim_mac = mesh.keypair("hq").derived_mac
    nodes = [
        Node("field", credential=Credential()),
        Node("imposter", credential=Credential(claim_mac=victim_mac)),
        # The positive control. Every other assertion here is an *absence*, and
        # an absence is also what a simulation that never converged produces —
        # so without a neighbour that must be present, this test would pass just
        # as happily if nothing ran at all.
        Node("neighbour", credential=Credential()),
    ]
    links = [
        pair("field", "imposter", PerfectWire()),
        pair("field", "neighbour", PerfectWire()),
    ]
    sim = Simulation(nodes, links, mesh=mesh)
    sim.run(until_s=30.0)

    admitted = sim.driver("field").neighbor_macs()
    assert sim.mac("neighbour") in admitted, (
        "the control was not admitted, so this run proves nothing about the "
        "refusals below"
    )
    assert victim_mac not in admitted, (
        "a certificate naming an address its key does not derive was admitted"
    )
    # The imposter holds *only* the misissued certificate, so being refused the
    # address it claimed leaves it with no address at all.
    assert sim.mac("imposter") not in admitted, (
        "the imposter should be admitted at no address at all"
    )
