"""Feature extraction turns one router's observable state into training rows.

These tests are written against the snapshot dataclasses rather than a live
`PyDriver`, to isolate the pure state -> row transform from the native
extension: no PyO3 build required to run this file, and the transform's
behavior is pinned down independent of `generate.router_snapshot`'s mapping
from the real bindings (covered separately in `test_generate.py` and
`test_end_to_end.py`).
"""

from __future__ import annotations

import math

import numpy as np
from wayfinder_ml import features, schema
from wayfinder_ml.features import (
    LinkObservation,
    OriginatorObservation,
    PathObservation,
    RouterSnapshot,
)


def _path(neighbor: str, tq: int, seqno: int = 100, heard_ms: int = 9_000):
    return PathObservation(
        neighbor=neighbor,
        last_tq=tq,
        last_seqno=seqno,
        last_heard_ms=heard_ms,
        interval_estimate_ms=1_000,
    )


def _snapshot(*paths: PathObservation) -> RouterSnapshot:
    return RouterSnapshot(
        node="a",
        now_ms=10_000,
        originators=(
            OriginatorObservation(
                originator="d",
                last_heard_ms=9_000,
                last_seqno=100,
                max_tq=max((p.last_tq for p in paths), default=0),
                best_next_hop=paths[0].neighbor if paths else "",
                paths=paths,
            ),
        ),
        links=tuple(
            LinkObservation(
                neighbor=p.neighbor, iface_idx=0, ewma_quality=200, sample_count=50
            )
            for p in paths
        ),
        neighbor_count=len(paths),
        originator_occupancy=(1, 32),
    )


def test_one_row_per_originator() -> None:
    batch = features.build_batch(
        _snapshot(_path("b", 200), _path("c", 100)),
        best_next_hop={"d": "b"},
        cost_via={("d", "b"): 2.0, ("d", "c"): 5.0},
    )
    assert batch.rows == 1
    batch.validate()


def test_mask_marks_only_populated_slots() -> None:
    """BATMAN often knows fewer than four paths; the unused slots must be
    masked out rather than trained on as zero-valued candidates."""
    batch = features.build_batch(
        _snapshot(_path("b", 200), _path("c", 100)),
        best_next_hop={"d": "b"},
        cost_via={("d", "b"): 2.0, ("d", "c"): 5.0},
    )
    np.testing.assert_array_equal(batch.mask[0], [True, True, False, False])


def test_label_points_at_the_oracle_chosen_slot() -> None:
    batch = features.build_batch(
        _snapshot(_path("b", 200), _path("c", 100)),
        best_next_hop={"d": "c"},
        cost_via={("d", "b"): 5.0, ("d", "c"): 2.0},
    )
    assert batch.label[0] == 1  # slot 1 is neighbor "c"


def test_label_is_absent_when_oracle_hop_is_not_a_candidate() -> None:
    """The router can only choose among paths it knows. When the truly-best
    next hop is not one of them, no slot is correct — the row is unlabelled,
    not mislabelled onto the closest slot."""
    batch = features.build_batch(
        _snapshot(_path("b", 200), _path("c", 100)),
        best_next_hop={"d": "zz"},
        cost_via={},
    )
    assert batch.label[0] == schema.NO_LABEL
    batch.validate()


def test_unroutable_originator_is_unlabelled() -> None:
    batch = features.build_batch(
        _snapshot(_path("b", 200)),
        best_next_hop={"d": None},
        cost_via={},
    )
    assert batch.label[0] == schema.NO_LABEL


def test_tq_feature_is_normalized_quality() -> None:
    batch = features.build_batch(
        _snapshot(_path("b", 255), _path("c", 0)),
        best_next_hop={"d": "b"},
        cost_via={("d", "b"): 1.0, ("d", "c"): 9.0},
    )
    tq = schema.CANDIDATE_FEATURES.index("tq")
    assert batch.candidates[0, 0, tq] == 1.0
    assert batch.candidates[0, 1, tq] == 0.0


def test_age_ratio_is_measured_against_the_paths_own_cadence() -> None:
    """Staleness relative to a path's learned interval, matching how
    `purge_stale` ages it — not against a fixed wall-clock timeout."""
    batch = features.build_batch(
        _snapshot(_path("b", 200, heard_ms=8_000)),  # 2000ms old, interval 1000ms
        best_next_hop={"d": "b"},
        cost_via={("d", "b"): 1.0},
    )
    age = schema.CANDIDATE_FEATURES.index("age_ratio")
    assert batch.candidates[0, 0, age] == 2.0


def test_age_ratio_is_clipped_so_a_stale_path_cannot_blow_up_training() -> None:
    """Unlike `seqno_lag`, staleness has no natural ceiling of its own — a
    path with a tiny learned cadence that's gone very quiet could otherwise
    produce an arbitrarily large ratio. Clip it, matching the same finite
    bound `interval` and every other candidate feature observe."""
    batch = features.build_batch(
        _snapshot(_path("b", 200, heard_ms=0)),  # 10_000ms old, interval 1000ms
        best_next_hop={"d": "b"},
        cost_via={("d", "b"): 1.0},
    )
    age = schema.CANDIDATE_FEATURES.index("age_ratio")
    assert batch.candidates[0, 0, age] == schema.AGE_RATIO_CLIP


def test_seqno_lag_is_relative_to_the_freshest_path() -> None:
    snapshot = _snapshot(_path("b", 200, seqno=100), _path("c", 100, seqno=90))
    batch = features.build_batch(
        snapshot, best_next_hop={"d": "b"}, cost_via={("d", "b"): 1.0}
    )
    lag = schema.CANDIDATE_FEATURES.index("seqno_lag")
    assert batch.candidates[0, 0, lag] == 0.0
    assert batch.candidates[0, 1, lag] == 10.0 / schema.SEQNO_LAG_SCALE


def test_missing_link_record_reads_as_zero_confidence() -> None:
    """A candidate neighbor with no link-quality row yet must not inherit
    another neighbor's quality; it reads as unknown with zero samples."""
    snapshot = _snapshot(_path("b", 200))
    snapshot = RouterSnapshot(**{**vars(snapshot), "links": ()})
    batch = features.build_batch(
        snapshot, best_next_hop={"d": "b"}, cost_via={("d", "b"): 1.0}
    )
    quality = schema.CANDIDATE_FEATURES.index("link_quality")
    samples = schema.CANDIDATE_FEATURES.index("link_samples")
    assert batch.candidates[0, 0, quality] == 0.0
    assert batch.candidates[0, 0, samples] == 0.0


def test_masked_slots_carry_infinite_cost() -> None:
    """So a cost-weighted loss can never prefer an empty slot."""
    batch = features.build_batch(
        _snapshot(_path("b", 200)),
        best_next_hop={"d": "b"},
        cost_via={("d", "b"): 3.0},
    )
    assert batch.cost[0, 0] == 3.0
    assert all(math.isinf(c) for c in batch.cost[0, 1:])


def test_originator_with_no_paths_is_skipped() -> None:
    """Nothing to rank, so nothing to learn from."""
    batch = features.build_batch(_snapshot(), best_next_hop={"d": None}, cost_via={})
    assert batch.rows == 0
    batch.validate()
