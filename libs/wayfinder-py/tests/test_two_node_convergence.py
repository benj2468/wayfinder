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
