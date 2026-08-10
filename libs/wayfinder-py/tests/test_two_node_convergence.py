import wayfinder_py as wf


def _drain_egress(src: wf.PyDriver, dst: wf.PyDriver, idx: int):
    frame = src.poll_egress(idx)
    while frame is not None:
        dst.push_rx(idx, frame)
        frame = src.poll_egress(idx)


def test_two_node_ogm_convergence():
    wf.init_tracing()
    mac_a = wf.PyMac(b"\x02\x00\x00\x00\x00\x01")
    mac_b = wf.PyMac(b"\x02\x00\x00\x00\x00\x02")
    a = wf.PyDriver(mac_a, [(50, 500)])
    b = wf.PyDriver(mac_b, [(50, 500)])

    assert a.get_egress_interface(mac_b) is None, "no route before any OGM exchange"

    now = 0
    for _ in range(300):
        now += 10
        a.tick(now)
        b.tick(now)
        _drain_egress(a, b, 0)
        _drain_egress(b, a, 0)

    route_a_to_b = a.get_egress_interface(mac_b)
    route_b_to_a = b.get_egress_interface(mac_a)
    assert route_a_to_b is not None, "a resolves a route to b"
    assert route_b_to_a is not None, "b resolves a route to a"
    assert route_a_to_b.all is False
    assert route_a_to_b.interface == 0


# The BATMAN sub-type tag (the first payload byte) for a keep-alive heartbeat.
_PKT_KEEPALIVE = 0x07


def _is_keepalive_frame(frame: bytes) -> bool:
    """Whether a raw on-wire frame (`[dst:6][src:6][proto:2 BE][payload]`) is
    a keep-alive heartbeat, by its BATMAN sub-type tag at payload offset 14."""
    return len(frame) > 14 and frame[14] == _PKT_KEEPALIVE


def test_keepalive_heartbeat_is_transmitted_when_configured():
    wf.init_tracing()
    mac_a = wf.PyMac(b"\x02\x00\x00\x00\x00\x01")
    features = wf.PyLinkFeatures(tx_keepalive_interval_ms=1000)
    a = wf.PyDriver(mac_a, [(50, 500)], [features])

    now = 0
    keepalive = None
    while now < 60_000 and keepalive is None:
        now += 100
        a.tick(now)
        frame = a.poll_egress(0)
        while frame is not None:
            if _is_keepalive_frame(frame):
                keepalive = frame
                break
            frame = a.poll_egress(0)

    assert keepalive is not None, "keep-alive heartbeat never appeared on the wire"


def test_keepalive_not_transmitted_when_unconfigured():
    wf.init_tracing()
    mac_a = wf.PyMac(b"\x02\x00\x00\x00\x00\x01")
    a = wf.PyDriver(mac_a, [(50, 500)])  # no tx_keepalive_interval_ms set

    now = 0
    for _ in range(600):
        now += 100
        a.tick(now)
        frame = a.poll_egress(0)
        while frame is not None:
            assert not _is_keepalive_frame(frame), (
                "no interface has tx_keepalive_interval_ms configured"
            )
            frame = a.poll_egress(0)
