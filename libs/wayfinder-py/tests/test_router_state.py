"""Read-only introspection of a driver's routing state.

This is what dataset generation for the learned-routing pipeline (`ml/`) reads
to build features: the same state a real node holds, so nothing trains on a
signal that would be unavailable at inference time.
"""

import wayfinder_py as wf

_MAC_A = wf.PyMac(b"\x02\x00\x00\x00\x00\x01")
_MAC_B = wf.PyMac(b"\x02\x00\x00\x00\x00\x02")
_MAC_C = wf.PyMac(b"\x02\x00\x00\x00\x00\x03")


def _drain_egress(src, dst, src_idx, dst_idx=None, metrics=None):
    frame = src.poll_egress(src_idx)
    while frame is not None:
        dst.push_rx(dst_idx if dst_idx is not None else src_idx, frame, metrics)
        frame = src.poll_egress(src_idx)


def _converge_pair(metrics=None, ticks=300):
    """Run two directly-linked nodes until routing converges; return both."""
    a = wf.PyDriver(_MAC_A, [(50, 500)])
    b = wf.PyDriver(_MAC_B, [(50, 500)])
    now = 0
    for _ in range(ticks):
        now += 10
        a.tick(now)
        b.tick(now)
        _drain_egress(a, b, 0, metrics=metrics)
        _drain_egress(b, a, 0, metrics=metrics)
    return a, b


def test_originator_table_is_empty_before_convergence():
    a = wf.PyDriver(_MAC_A, [(50, 500)])
    assert a.originator_table() == []


def test_originator_table_reports_the_learned_destination():
    a, _ = _converge_pair()

    table = a.originator_table()

    assert len(table) == 1
    record = table[0]
    # `originator` is the destination this record describes. It is named
    # `neighbor_ident` on the Rust `OriginatorRecord`, which is a confusing
    # name for a destination — renamed at this boundary rather than carried
    # across.
    assert record.originator == _MAC_B
    assert record.best_next_hop == _MAC_B, "directly linked, so it relays itself"


def test_originator_record_carries_its_metric_and_freshness():
    a, _ = _converge_pair()
    record = a.originator_table()[0]

    assert 0 < record.max_tq <= 255
    assert record.last_seqno > 0
    assert record.last_heard_ms > 0


def test_paths_expose_per_candidate_stats():
    """The ≤4 candidate paths are what the model ranks, so each must carry its
    own metric, freshness and cadence — not just the winner's."""
    a, _ = _converge_pair()
    paths = a.originator_table()[0].paths

    assert len(paths) == 1
    path = paths[0]
    assert path.neighbor == _MAC_B
    assert 0 < path.last_tq <= 255
    assert path.last_seqno > 0
    assert path.last_heard_ms > 0
    # Peak-hold cadence estimate; non-zero once a second OGM gives a gap.
    assert path.interval_estimate_ms > 0


def test_link_quality_records_reflect_pushed_metrics():
    """Link quality is stamped from the carrier's physical-layer metrics."""
    a, _ = _converge_pair(metrics=wf.PyLinkMetrics(quality=200))

    records = a.link_quality_records()

    assert len(records) == 1
    record = records[0]
    assert record.neighbor == _MAC_B
    assert record.iface_idx == 0
    assert 0 < record.ewma_quality <= 255
    assert record.sample_count > 0


def test_link_quality_record_exists_but_reads_none_without_metrics():
    """A row is stamped for every neighbor/interface pair seen, even absent
    real `LinkMetrics` — the row is present but its quality is unknown.

    `None`, not 0: a carrier that reports no signal has nothing to measure,
    whereas 0 is a real reading a radio can produce on a genuinely dead link.
    Conflating them made every wired neighbor read as the worst possible link.
    """
    a, _ = _converge_pair()

    records = a.link_quality_records()

    assert len(records) == 1
    assert records[0].ewma_quality is None
    # Still evidence the neighbor is there, even with no quality to report.
    assert records[0].sample_count > 0


def test_neighbor_count_counts_direct_neighbors():
    a, _ = _converge_pair()
    assert a.neighbor_count() == 1


def test_originator_occupancy_reports_used_and_capacity():
    a, _ = _converge_pair()

    used, capacity = a.originator_occupancy()

    assert used == 1
    assert capacity >= used, "capacity is the fixed table bound"


def test_introspection_does_not_disturb_routing():
    """These accessors feed dataset generation while a simulation runs, so
    they must not perturb the run they are describing."""
    a, _ = _converge_pair()
    before = a.get_egress_interface(_MAC_B)

    for _ in range(5):
        a.originator_table()
        a.link_quality_records()
        a.neighbor_count()
        a.originator_occupancy()

    after = a.get_egress_interface(_MAC_B)
    assert (before.all, before.interface) == (after.all, after.interface)


def test_multi_hop_originator_reports_the_relay_not_itself_as_next_hop():
    """`best_next_hop` (the relay) must differ from `originator` (the
    destination itself) once the destination is more than one hop away —
    exactly the distinction `OriginatorRecord::neighbor_ident`'s doc fix is
    about (`libs/batman/src/lib.rs`): the field misleadingly reads as though
    it names a relay, but it is the destination, and `best_next_hop ==
    originator` is precisely the "reached directly" test. A two-node pair
    (as `_converge_pair` builds) can never exercise the `!=` branch."""
    a = wf.PyDriver(_MAC_A, [(50, 500)])
    b = wf.PyDriver(_MAC_B, [(50, 500), (50, 500)])
    c = wf.PyDriver(_MAC_C, [(50, 500)])

    now = 0
    for _ in range(300):
        now += 10
        a.tick(now)
        b.tick(now)
        c.tick(now)
        _drain_egress(a, b, 0, 0)
        _drain_egress(b, a, 0, 0)
        _drain_egress(b, c, 1, 0)
        _drain_egress(c, b, 0, 1)

    record = next(r for r in a.originator_table() if r.originator == _MAC_C)

    assert record.best_next_hop == _MAC_B
    assert record.best_next_hop != record.originator
    assert [p.neighbor for p in record.paths] == [_MAC_B]


def test_multi_interface_node_reports_per_interface_link_quality():
    """A node with two links must attribute quality to the interface each
    neighbor was heard on — the feature is per (neighbor, interface)."""
    hub = wf.PyDriver(_MAC_A, [(50, 500), (50, 500)])
    left = wf.PyDriver(_MAC_B, [(50, 500)])
    right = wf.PyDriver(_MAC_C, [(50, 500)])

    now = 0
    for _ in range(300):
        now += 10
        hub.tick(now)
        left.tick(now)
        right.tick(now)
        _drain_egress(hub, left, 0, 0, wf.PyLinkMetrics(quality=200))
        _drain_egress(hub, right, 1, 0, wf.PyLinkMetrics(quality=100))
        _drain_egress(left, hub, 0, 0, wf.PyLinkMetrics(quality=200))
        _drain_egress(right, hub, 0, 1, wf.PyLinkMetrics(quality=100))

    by_neighbor = {r.neighbor: r for r in hub.link_quality_records()}

    assert by_neighbor[_MAC_B].iface_idx == 0
    assert by_neighbor[_MAC_C].iface_idx == 1
