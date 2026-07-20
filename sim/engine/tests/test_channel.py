from random import Random

import pytest

from engine.channel import FreeSpacePathLoss, PerfectWire
from engine.mobility import Vec3


def test_perfect_wire_always_delivers():
    ch = PerfectWire()
    sample = ch.evaluate(Vec3(0, 0, 0), Vec3(1000, 0, 0), t_s=0.0, rng=Random(0))
    assert sample.delivery_probability == 1.0
    assert sample.metrics.quality == 255
    assert sample.latency_ms == 0.0


def test_perfect_wire_custom_quality_and_latency():
    ch = PerfectWire(quality=200, latency_ms=5.0)
    sample = ch.evaluate(Vec3(0, 0, 0), Vec3(0, 0, 0), t_s=0.0, rng=Random(0))
    assert sample.metrics.quality == 200
    assert sample.latency_ms == 5.0


def test_fspl_quality_decreases_with_distance():
    ch = FreeSpacePathLoss(noise_sigma_db=0.0)
    near = ch.evaluate(Vec3(0, 0, 0), Vec3(10, 0, 0), 0.0, Random(0))
    far = ch.evaluate(Vec3(0, 0, 0), Vec3(5000, 0, 0), 0.0, Random(0))
    assert near.metrics.quality is not None
    assert far.metrics.quality is not None
    assert near.metrics.quality > far.metrics.quality


def test_fspl_quality_clamped_to_valid_range():
    ch = FreeSpacePathLoss(noise_sigma_db=0.0)
    very_far = ch.evaluate(Vec3(0, 0, 0), Vec3(1_000_000, 0, 0), 0.0, Random(0))
    assert very_far.metrics.quality == 0

    very_near = ch.evaluate(Vec3(0, 0, 0), Vec3(0, 0, 0), 0.0, Random(0))
    assert very_near.metrics.quality == 255


def test_fspl_delivery_probability_waterfall():
    ch = FreeSpacePathLoss(noise_sigma_db=0.0)
    near = ch.evaluate(Vec3(0, 0, 0), Vec3(10, 0, 0), 0.0, Random(0))
    far = ch.evaluate(Vec3(0, 0, 0), Vec3(5000, 0, 0), 0.0, Random(0))
    assert near.delivery_probability > 0.9
    assert far.delivery_probability < 0.1


def test_fspl_midpoint_crossover_near_500m():
    # Tuned so a ~1km GCS separation puts the crossover mid-flight — see
    # FreeSpacePathLoss's docstring for the derivation.
    ch = FreeSpacePathLoss(noise_sigma_db=0.0)
    sample = ch.evaluate(Vec3(0, 0, 0), Vec3(500, 0, 0), 0.0, Random(0))
    assert sample.delivery_probability == pytest.approx(0.5, abs=0.05)


def test_fspl_reports_rssi_on_metrics():
    ch = FreeSpacePathLoss(noise_sigma_db=0.0)
    sample = ch.evaluate(Vec3(0, 0, 0), Vec3(500, 0, 0), 0.0, Random(0))
    assert sample.metrics.rssi_dbm is not None


def test_fspl_noise_is_reproducible_from_seeded_rng():
    ch = FreeSpacePathLoss(noise_sigma_db=5.0)
    a = ch.evaluate(Vec3(0, 0, 0), Vec3(500, 0, 0), 0.0, Random(42))
    b = ch.evaluate(Vec3(0, 0, 0), Vec3(500, 0, 0), 0.0, Random(42))
    assert a.metrics.rssi_dbm == b.metrics.rssi_dbm


def test_fspl_max_range_default_is_unbounded():
    ch = FreeSpacePathLoss(noise_sigma_db=0.0)
    far = ch.evaluate(Vec3(0, 0, 0), Vec3(5000, 0, 0), 0.0, Random(0))
    assert far.delivery_probability > 0.0


def test_fspl_max_range_blocks_delivery_beyond_cutoff():
    # A small telemetry radio's fixed link-budget limit, distinct from the
    # gradual RSSI waterfall: past this distance there's no signal at all,
    # not just a weak one.
    ch = FreeSpacePathLoss(noise_sigma_db=0.0, max_range_m=700.0)
    within = ch.evaluate(Vec3(0, 0, 0), Vec3(600, 0, 0), 0.0, Random(0))
    beyond = ch.evaluate(Vec3(0, 0, 0), Vec3(800, 0, 0), 0.0, Random(0))
    assert within.delivery_probability > 0.0
    assert beyond.delivery_probability == 0.0
    assert beyond.metrics.quality == 0
    assert beyond.metrics.rssi_dbm is None


def test_fspl_max_range_boundary_is_inclusive():
    ch = FreeSpacePathLoss(noise_sigma_db=0.0, max_range_m=700.0)
    at_boundary = ch.evaluate(Vec3(0, 0, 0), Vec3(700, 0, 0), 0.0, Random(0))
    just_beyond = ch.evaluate(Vec3(0, 0, 0), Vec3(700.001, 0, 0), 0.0, Random(0))
    assert at_boundary.delivery_probability > 0.0
    assert just_beyond.delivery_probability == 0.0
