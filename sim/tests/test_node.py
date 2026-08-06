from wayfinder_sim.mobility import Static, Vec3, Waypoints
from wayfinder_sim.node import DEFAULT_TRICKLE, Node


def test_node_defaults_to_static_origin_and_default_trickle():
    n = Node("gcsa")
    assert n.mobility == Static(Vec3(0, 0, 0))
    assert n.trickle == DEFAULT_TRICKLE
    assert n.mac is None
    assert n.tick_interval_ms is None


def test_node_accepts_custom_mobility_and_trickle():
    mobility = Waypoints((Vec3(0, 0, 0), Vec3(100, 0, 0)), speed_m_s=10.0)
    n = Node("drone", mobility=mobility, trickle=(50, 500), tick_interval_ms=10)
    assert n.mobility is mobility
    assert n.trickle == (50, 500)
    assert n.tick_interval_ms == 10


def test_node_keepalive_defaults_to_disabled():
    n = Node("gcsa")
    assert n.tx_keepalive_interval_ms is None


def test_node_accepts_custom_keepalive_interval():
    n = Node("drone", tx_keepalive_interval_ms=1000)
    assert n.tx_keepalive_interval_ms == 1000
