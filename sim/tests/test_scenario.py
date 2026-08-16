import pytest

pytest.importorskip("simpy")

import wayfinder_py as wf
from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.link import Link
from wayfinder_sim.node import Node
from wayfinder_sim.scenario import Simulation
from wayfinder_sim.topology import diamond, pair


def test_two_node_route_converges():
    wf.init_tracing()
    nodes = [Node("a", trickle=(50, 500)), Node("b", trickle=(50, 500))]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=3.0, sample_interval_ms=50)

    assert sim.route_via("a", "b") == "a-b"
    assert sim.route_via("b", "a") == "a-b"


def test_no_route_before_convergence():
    nodes = [Node("a", trickle=(50, 500)), Node("b", trickle=(50, 500))]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    assert sim.route_via("a", "b") is None


def test_probe_recording_tracks_route_transition():
    wf.init_tracing()
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)
    sim.record("route", lambda s: s.route_via("a", "b"))

    rec = sim.run(until_s=3.0, sample_interval_ms=50)

    transitions = rec.transitions("route")
    assert transitions
    assert transitions[0][1] == "a-b"


def test_local_send_is_delivered_end_to_end():
    wf.init_tracing()
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)
    sim.send("a", "b", b"hello", at_s=2.5)

    sim.run(until_s=4.0)

    assert sim.poll_local("b") == b"hello"


def test_diamond_multihop_route_converges():
    wf.init_tracing()
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c", "d")]
    links = diamond("a", "b", "c", "d", PerfectWire())
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=5.0, sample_interval_ms=50)

    assert sim.route_via("a", "d") in ("a-b", "a-c")
    assert sim.route_via("d", "a") in ("b-d", "c-d")


def test_rejects_link_to_unknown_node():
    nodes = [Node("a")]
    links = [pair("a", "ghost", PerfectWire())]
    with pytest.raises(ValueError):
        Simulation(nodes, links, seed=0)


def test_rejects_duplicate_node_names():
    nodes = [Node("a"), Node("a")]
    with pytest.raises(ValueError):
        Simulation(nodes, [], seed=0)


# The BATMAN sub-type tag (the first payload byte) for a keep-alive
# heartbeat — see `libs/batman/src/wire.rs`'s `BatmanPacketType::Keepalive`.
_PKT_KEEPALIVE = 0x07


def _is_keepalive_frame(frame: bytes) -> bool:
    return len(frame) > 14 and frame[14] == _PKT_KEEPALIVE


def _drain_until_keepalive(driver: wf.PyDriver, iface: int, until_ms: int) -> bool:
    """Tick `driver` up to `until_ms` (in 100ms steps), draining `iface`'s
    egress queue after each tick, until a keep-alive heartbeat appears.
    Bypasses `Simulation`'s own tick loop (which hands egress straight to
    channel delivery) so the test can inspect the raw frame directly."""
    now = 0
    while now < until_ms:
        now += 100
        driver.tick(now)
        frame = driver.poll_egress(iface)
        while frame is not None:
            if _is_keepalive_frame(frame):
                return True
            frame = driver.poll_egress(iface)
    return False


def test_node_keepalive_config_is_threaded_into_its_driver():
    nodes = [
        Node("a", trickle=(50, 500)),
        Node("b", trickle=(50, 500), tx_keepalive_interval_ms=1000),
    ]
    links = [pair("a", "b", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    assert _drain_until_keepalive(sim._states["b"].driver, 0, 60_000), (
        "node b's tx_keepalive_interval_ms must arm its interface's heartbeat"
    )
    assert not _drain_until_keepalive(sim._states["a"].driver, 0, 60_000), (
        "node a has no keep-alive configured and must never emit one"
    )


def test_link_keepalive_override_wins_over_node_default():
    # Node "a" has no keep-alive default at all; the link explicitly arms
    # one for the interface it creates on "a" — same override direction
    # `Link.trickle` already supports over `Node.trickle`.
    nodes = [
        Node("a", trickle=(50, 500)),
        Node("b", trickle=(50, 500)),
    ]
    links = [
        Link(("a", "b"), PerfectWire(), tx_keepalive_interval_ms=500),
    ]
    sim = Simulation(nodes, links, seed=0)

    assert _drain_until_keepalive(sim._states["a"].driver, 0, 60_000), (
        "the link's tx_keepalive_interval_ms must override node a's "
        "(absent) default, same as the existing trickle override"
    )


def test_node_names_lists_every_node_in_declaration_order():
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    assert sim.node_names == ("a", "b")


def test_driver_exposes_the_underlying_router():
    """Feature extraction reads router state directly, so the real `PyDriver`
    has to be reachable rather than only its route resolution."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    sim.run(until_s=3.0, sample_interval_ms=50)

    table = sim.driver("a").originator_table()
    assert [r.originator for r in table] == [sim.mac("b")]


def test_driver_rejects_an_unknown_node():
    sim = Simulation([Node("a")], [], seed=0)
    with pytest.raises(KeyError):
        sim.driver("nope")


def test_node_for_mac_inverts_the_mac_assignment():
    """Router state is keyed by MAC; the oracle works in node names, so the
    generator needs the inverse of the auto-derived MAC mapping."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    assert sim.node_for_mac(sim.mac("b")) == "b"
    assert sim.node_for_mac(wf.PyMac(b"\xff\xff\xff\xff\xff\xfe")) is None


# --- reachability -----------------------------------------------------------


def test_reachable_lists_every_node_with_a_route():
    """A coverage study asks "is this node in touch with *anything*", not
    "what is its route to one named peer", so the engine has to answer the
    set question directly."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c")]
    links = [pair("a", "b", PerfectWire()), pair("b", "c", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=5.0, sample_interval_ms=50)

    assert sim.reachable("a") == ("b", "c")


def test_reachable_is_empty_before_anything_converges():
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    assert sim.reachable("a") == ()


def test_reachable_never_includes_the_source_itself():
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    sim.run(until_s=3.0, sample_interval_ms=50)

    assert "a" not in sim.reachable("a")


def test_reachable_can_be_restricted_to_named_targets():
    """The question is usually "in touch with a *gateway*", not "in touch with
    any node at all" — a drone routable only via another drone is not
    connected to the ground."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c")]
    links = [pair("a", "b", PerfectWire()), pair("b", "c", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=5.0, sample_interval_ms=50)

    assert sim.reachable("a", ("c",)) == ("c",)


def test_reachable_preserves_the_order_of_the_targets_given():
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c")]
    links = [pair("a", "b", PerfectWire()), pair("b", "c", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=5.0, sample_interval_ms=50)

    assert sim.reachable("a", ("c", "b")) == ("c", "b")


def test_reachable_rejects_an_unknown_node():
    sim = Simulation([Node("a")], [], seed=0)
    with pytest.raises(KeyError):
        sim.reachable("nope")


# --- neighbour link quality --------------------------------------------------


def test_link_quality_reports_a_live_neighbours_estimate():
    """ "Is this hop alive right now" is a different question from "is this
    where traffic goes" — a link can be carrying frames while the route
    ignores it, and a render that can only ask the second one draws a live
    relay as absent."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    sim.run(until_s=3.0, sample_interval_ms=50)

    assert sim.link_quality("a", "b") > 0


def test_link_quality_is_none_for_a_neighbour_never_heard_from():
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    assert sim.link_quality("a", "b") is None


def test_link_quality_is_none_across_a_node_that_is_not_a_neighbour():
    """Two hops apart is not a link: `a` hears `c` only through `b`, so it has
    no local estimate for it however well the route works."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c")]
    links = [pair("a", "b", PerfectWire()), pair("b", "c", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=5.0, sample_interval_ms=50)

    assert sim.route_via("a", "c") is not None
    assert sim.link_quality("a", "c") is None


def test_link_quality_rejects_an_unknown_node():
    sim = Simulation([Node("a")], [], seed=0)
    with pytest.raises(KeyError):
        sim.link_quality("nope", "a")


def test_link_age_reports_how_long_since_the_neighbour_was_heard():
    """Quality alone cannot say whether a link is still *there*: the estimate
    is an EWMA over frames that arrived, so it holds its last value for as
    long as nothing arrives at all. Only the timestamp goes stale."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    sim.run(until_s=3.0, sample_interval_ms=50)

    age_ms = sim.link_age_ms("a", "b")
    assert 0 <= age_ms <= 1000


def test_link_age_is_none_for_a_neighbour_never_heard_from():
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b")]
    sim = Simulation(nodes, [pair("a", "b", PerfectWire())], seed=0)

    assert sim.link_age_ms("a", "b") is None


def test_link_age_is_none_across_a_node_that_is_not_a_neighbour():
    """`a` hears `c` only through `b`, so there is no direct link whose age
    could be reported — however fresh the route through `b` is."""
    nodes = [Node(n, trickle=(50, 500)) for n in ("a", "b", "c")]
    links = [pair("a", "b", PerfectWire()), pair("b", "c", PerfectWire())]
    sim = Simulation(nodes, links, seed=0)

    sim.run(until_s=5.0, sample_interval_ms=50)

    assert sim.route_via("a", "c") is not None
    assert sim.link_age_ms("a", "c") is None


def test_link_age_rejects_an_unknown_node():
    sim = Simulation([Node("a")], [], seed=0)
    with pytest.raises(KeyError):
        sim.link_age_ms("nope", "a")
