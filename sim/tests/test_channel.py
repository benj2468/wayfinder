import math
from random import Random

import pytest
from wayfinder_sim.channel import (
    EarthOccluded,
    FreeSpacePathLoss,
    PerfectWire,
    TerrainMasked,
    knife_edge_loss_db,
)
from wayfinder_sim.mobility import EARTH_RADIUS_M, Vec3
from wayfinder_sim.terrain import FlatGround, GaussianPeak, MountainRange


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


# --- knife-edge diffraction loss --------------------------------------------


def test_knife_edge_loss_is_zero_for_a_well_cleared_path():
    assert knife_edge_loss_db(-3.0) == 0.0
    assert knife_edge_loss_db(-0.78) == 0.0
    # The 60%-first-Fresnel-zone rule of thumb sits just inside the free zone.
    assert knife_edge_loss_db(-0.6 * math.sqrt(2)) == 0.0


def test_knife_edge_loss_at_grazing_is_about_6_db():
    """v = 0 is the line of sight exactly skimming the obstacle — already a
    ~6 dB penalty, which is why a bare line-of-sight test overstates a
    grazing path's quality."""
    assert knife_edge_loss_db(0.0) == pytest.approx(6.0, abs=0.1)


def test_knife_edge_loss_grows_monotonically_with_obstruction():
    losses = [knife_edge_loss_db(v) for v in (-0.5, 0.0, 1.0, 3.0, 10.0)]
    assert losses == sorted(losses)
    assert losses[0] < losses[-1]


# --- TerrainMasked ----------------------------------------------------------

# A single steep summit at x=2000 astride a 4 km east-west path.
_RIDGE = MountainRange((GaussianPeak(x=2000.0, y=0.0, height_m=900.0, sigma_m=400.0),))
_WEST = Vec3(0.0, 0.0, 60.0)
_EAST = Vec3(4000.0, 0.0, 60.0)


def _base_radio() -> FreeSpacePathLoss:
    return FreeSpacePathLoss(noise_sigma_db=0.0, tx_power_dbm=40.0)


def test_terrain_masked_is_a_no_op_over_clear_ground():
    base = _base_radio()
    masked = TerrainMasked(base, FlatGround(0.0))

    plain = base.evaluate(_WEST, _EAST, 0.0, Random(0))
    through = masked.evaluate(_WEST, _EAST, 0.0, Random(0))

    assert through.metrics.rssi_dbm == plain.metrics.rssi_dbm
    assert through.metrics.quality == plain.metrics.quality
    assert through.delivery_probability == pytest.approx(plain.delivery_probability)


def test_terrain_masked_attenuates_a_path_through_a_mountain():
    base = _base_radio()
    masked = TerrainMasked(base, _RIDGE)

    plain = base.evaluate(_WEST, _EAST, 0.0, Random(0))
    through = masked.evaluate(_WEST, _EAST, 0.0, Random(0))

    assert through.metrics.rssi_dbm is not None
    assert plain.metrics.rssi_dbm is not None
    assert through.metrics.rssi_dbm < plain.metrics.rssi_dbm
    assert through.delivery_probability < plain.delivery_probability


def test_terrain_masked_kills_a_deeply_obstructed_path():
    """The whole point of the model: two nodes in adjacent valleys, well
    inside each other's free-space range, cannot hear each other at all."""
    masked = TerrainMasked(_base_radio(), _RIDGE)
    sample = masked.evaluate(_WEST, _EAST, 0.0, Random(0))
    assert sample.delivery_probability < 0.01
    assert sample.metrics.quality == 0


def test_terrain_masked_restores_the_link_from_above_the_ridge():
    """Same two ground positions, same distance — but flown over the summit,
    so only the geometry differs."""
    masked = TerrainMasked(_base_radio(), _RIDGE)
    blocked = masked.evaluate(_WEST, _EAST, 0.0, Random(0))
    over = masked.evaluate(
        Vec3(0.0, 0.0, 1400.0), Vec3(4000.0, 0.0, 1400.0), 0.0, Random(0)
    )
    assert over.delivery_probability > 0.9
    assert over.delivery_probability > blocked.delivery_probability


def test_terrain_masked_is_symmetric_between_the_two_endpoints():
    masked = TerrainMasked(_base_radio(), _RIDGE)
    forward = masked.evaluate(_WEST, _EAST, 0.0, Random(0))
    reverse = masked.evaluate(_EAST, _WEST, 0.0, Random(0))
    assert forward.metrics.rssi_dbm == reverse.metrics.rssi_dbm


def test_terrain_masked_inherits_the_base_radios_frequency():
    """Evaluating the Fresnel geometry at a different frequency than the path
    loss would be a silent modelling error, so the frequency comes from the
    base radio unless deliberately overridden."""
    masked = TerrainMasked(FreeSpacePathLoss(freq_hz=900e6), _RIDGE)
    assert masked.effective_freq_hz() == 900e6


def test_terrain_masked_frequency_can_be_overridden():
    masked = TerrainMasked(FreeSpacePathLoss(freq_hz=900e6), _RIDGE, freq_hz=2.4e9)
    assert masked.effective_freq_hz() == 2.4e9


def test_terrain_masked_honours_the_base_radios_hard_range_cutoff():
    base = FreeSpacePathLoss(noise_sigma_db=0.0, max_range_m=1000.0)
    masked = TerrainMasked(base, FlatGround(0.0))
    sample = masked.evaluate(Vec3(0, 0, 500), Vec3(3000, 0, 500), 0.0, Random(0))
    assert sample.delivery_probability == 0.0
    assert sample.metrics.quality == 0


def test_terrain_masked_caps_the_excess_loss():
    """Diffraction loss grows without bound as an obstacle rises; the cap
    keeps a deeply-shadowed link's reported RSSI a plausible number rather
    than an arbitrarily large negative one."""
    deep = MountainRange(
        (GaussianPeak(x=2000.0, y=0.0, height_m=9000.0, sigma_m=400.0),)
    )
    base = _base_radio()
    masked = TerrainMasked(base, deep, max_loss_db=20.0)

    plain = base.evaluate(_WEST, _EAST, 0.0, Random(0))
    through = masked.evaluate(_WEST, _EAST, 0.0, Random(0))
    assert plain.metrics.rssi_dbm is not None
    assert through.metrics.rssi_dbm == plain.metrics.rssi_dbm - 20


def test_terrain_masked_rejects_a_base_channel_without_rssi():
    masked = TerrainMasked(PerfectWire(), _RIDGE, freq_hz=2.4e9)  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValueError, match="rssi"):
        masked.evaluate(_WEST, _EAST, 0.0, Random(0))


def test_terrain_masked_repeats_itself_exactly():
    """The geometry memo must be a pure cache: a second evaluation of the
    same pair, off an identically seeded RNG, has to match the first."""
    masked = TerrainMasked(FreeSpacePathLoss(noise_sigma_db=3.0), _RIDGE)
    first = masked.evaluate(_WEST, _EAST, 0.0, Random(7))
    second = masked.evaluate(_WEST, _EAST, 0.0, Random(7))
    assert first.metrics.rssi_dbm == second.metrics.rssi_dbm
    assert first.delivery_probability == second.delivery_probability


# --- receive gain -----------------------------------------------------------


def test_receive_gain_adds_straight_into_the_link_budget():
    """A satellite link closes on antenna gain, not transmit power alone: a
    Starlink terminal's dish is worth ~35 dB, more than the difference
    between every power in the old sweep."""
    plain = FreeSpacePathLoss(tx_power_dbm=30.0)
    dish = FreeSpacePathLoss(tx_power_dbm=30.0, rx_gain_dbi=35.0)
    rng = Random(0)
    assert dish.rssi_dbm(1000.0, Random(0)) == pytest.approx(
        plain.rssi_dbm(1000.0, rng) + 35.0
    )


def test_without_receive_gain_the_budget_is_unchanged():
    """The default has to leave every existing scenario's numbers exactly
    where they were."""
    ch = FreeSpacePathLoss(tx_power_dbm=14.0)
    assert ch.rx_gain_dbi == 0.0
    assert ch.rssi_dbm(500.0, Random(0)) == pytest.approx(
        14.0 - ch.path_loss_db(500.0) + Random(0).gauss(0.0, ch.noise_sigma_db)
    )


# --- the horizon ------------------------------------------------------------


def _sat(altitude_m: float, downrange_m: float) -> Vec3:
    """A point at `altitude_m` above the surface, `downrange_m` of arc away
    from the scene origin — i.e. on the curved Earth, not on a flat plane."""
    angle = downrange_m / EARTH_RADIUS_M
    r = EARTH_RADIUS_M + altitude_m
    return Vec3(r * math.sin(angle), 0.0, r * math.cos(angle) - EARTH_RADIUS_M)


def test_a_satellite_overhead_is_not_occluded():
    ch = EarthOccluded(FreeSpacePathLoss(tx_power_dbm=60.0, rx_gain_dbi=35.0))
    sample = ch.evaluate(Vec3(0, 0, 0), _sat(550_000.0, 0.0), t_s=0.0, rng=Random(0))
    assert sample.delivery_probability > 0.5


def test_a_satellite_beyond_the_horizon_is_blocked_outright():
    """The planet is in the way. No link budget fixes that, which is exactly
    what a flat-plane orbit could never express."""
    ch = EarthOccluded(FreeSpacePathLoss(tx_power_dbm=200.0, rx_gain_dbi=100.0))
    sample = ch.evaluate(
        Vec3(0, 0, 0), _sat(550_000.0, 6_000_000.0), t_s=0.0, rng=Random(0)
    )
    assert sample.delivery_probability == 0.0
    assert sample.metrics.quality == 0


def test_a_minimum_elevation_mask_cuts_off_before_the_horizon_does():
    """A terminal that has to track a satellite gives up well above the
    geometric horizon — Starlink's own mask is around 25 degrees."""
    low = _sat(550_000.0, 1_800_000.0)
    base = FreeSpacePathLoss(tx_power_dbm=60.0, rx_gain_dbi=35.0)
    assert (
        EarthOccluded(base)
        .evaluate(Vec3(0, 0, 0), low, t_s=0.0, rng=Random(0))
        .delivery_probability
        > 0.0
    )
    assert (
        EarthOccluded(base, min_elevation_deg=25.0)
        .evaluate(Vec3(0, 0, 0), low, t_s=0.0, rng=Random(0))
        .delivery_probability
        == 0.0
    )


def test_elevation_is_judged_from_the_lower_end_of_the_link():
    """Between two satellites the only question is whether the planet is in
    the way; measuring the angle at the higher end would call a perfectly
    clear cross-link blocked."""
    ch = EarthOccluded(FreeSpacePathLoss(tx_power_dbm=60.0, rx_gain_dbi=35.0))
    a, b = _sat(550_000.0, 0.0), _sat(550_000.0, 1_500_000.0)
    assert ch.evaluate(a, b, t_s=0.0, rng=Random(0)).delivery_probability > 0.0
    assert ch.evaluate(b, a, t_s=0.0, rng=Random(0)).delivery_probability > 0.0


def test_occlusion_leaves_a_clear_path_to_the_base_model():
    """Unblocked, the wrapper must not touch the budget — otherwise every
    scenario's tuning shifts the moment a horizon is added."""
    base = FreeSpacePathLoss(tx_power_dbm=60.0, rx_gain_dbi=35.0)
    at = _sat(550_000.0, 100_000.0)
    assert (
        EarthOccluded(base)
        .evaluate(Vec3(0, 0, 0), at, t_s=0.0, rng=Random(0))
        .metrics.quality
        == base.evaluate(Vec3(0, 0, 0), at, t_s=0.0, rng=Random(0)).metrics.quality
    )
