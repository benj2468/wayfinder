import math

import pytest
from wayfinder_sim.mobility import Static, Vec3, Waypoints
from wayfinder_sim.terrain import (
    Bounds,
    FlatGround,
    GaussianPeak,
    Heightmap,
    MountainRange,
    TerrainFollowing,
    elevation_profile,
    fresnel_parameter,
    fresnel_radius_m,
    has_line_of_sight,
    max_fresnel_parameter,
    peak_sites,
    valley_sites,
)

# --- Bounds -----------------------------------------------------------------


def test_bounds_reports_extent_and_center():
    b = Bounds(0.0, 0.0, 100.0, 50.0)
    assert b.width_m == pytest.approx(100.0)
    assert b.depth_m == pytest.approx(50.0)
    assert b.center == Vec3(50.0, 25.0, 0.0)


def test_bounds_rejects_inverted_extent():
    with pytest.raises(ValueError):
        Bounds(100.0, 0.0, 0.0, 50.0)


# --- FlatGround -------------------------------------------------------------


def test_flat_ground_is_the_same_everywhere():
    t = FlatGround(elevation_m=12.0)
    assert t.elevation(0.0, 0.0) == 12.0
    assert t.elevation(-9999.0, 9999.0) == 12.0


# --- MountainRange ----------------------------------------------------------


def test_gaussian_peak_is_tallest_at_its_center():
    t = MountainRange((GaussianPeak(x=0.0, y=0.0, height_m=1000.0, sigma_m=500.0),))
    assert t.elevation(0.0, 0.0) == pytest.approx(1000.0)
    assert t.elevation(500.0, 0.0) < 1000.0
    assert t.elevation(5000.0, 0.0) == pytest.approx(0.0, abs=1e-6)


def test_gaussian_peak_falls_off_by_one_sigma_as_expected():
    # A Gaussian is at exp(-1/2) ~ 0.6065 of its peak one sigma out.
    t = MountainRange((GaussianPeak(x=0.0, y=0.0, height_m=1000.0, sigma_m=500.0),))
    assert t.elevation(500.0, 0.0) == pytest.approx(1000.0 * math.exp(-0.5))


def test_mountain_range_sums_overlapping_peaks_onto_the_base():
    t = MountainRange(
        (
            GaussianPeak(x=0.0, y=0.0, height_m=100.0, sigma_m=100.0),
            GaussianPeak(x=0.0, y=0.0, height_m=200.0, sigma_m=100.0),
        ),
        base_elevation_m=50.0,
    )
    assert t.elevation(0.0, 0.0) == pytest.approx(350.0)


def test_mountain_range_with_no_peaks_is_its_base():
    t = MountainRange((), base_elevation_m=25.0)
    assert t.elevation(123.0, -456.0) == pytest.approx(25.0)


def test_gaussian_peak_rejects_non_positive_sigma():
    with pytest.raises(ValueError):
        GaussianPeak(x=0.0, y=0.0, height_m=100.0, sigma_m=0.0)


# --- Heightmap --------------------------------------------------------------


def test_heightmap_reads_back_its_grid_nodes_exactly():
    hm = Heightmap.from_rows([[0.0, 10.0], [20.0, 30.0]], cell_size_m=100.0)
    assert hm.elevation(0.0, 0.0) == pytest.approx(0.0)
    assert hm.elevation(100.0, 0.0) == pytest.approx(10.0)
    assert hm.elevation(0.0, 100.0) == pytest.approx(20.0)
    assert hm.elevation(100.0, 100.0) == pytest.approx(30.0)


def test_heightmap_interpolates_bilinearly_between_nodes():
    hm = Heightmap.from_rows([[0.0, 10.0], [20.0, 30.0]], cell_size_m=100.0)
    assert hm.elevation(50.0, 0.0) == pytest.approx(5.0)
    assert hm.elevation(0.0, 50.0) == pytest.approx(10.0)
    assert hm.elevation(50.0, 50.0) == pytest.approx(15.0)


def test_heightmap_clamps_outside_its_extent():
    hm = Heightmap.from_rows([[0.0, 10.0], [20.0, 30.0]], cell_size_m=100.0)
    assert hm.elevation(-500.0, -500.0) == pytest.approx(0.0)
    assert hm.elevation(500.0, 500.0) == pytest.approx(30.0)


def test_heightmap_honours_its_origin_offset():
    hm = Heightmap.from_rows(
        [[0.0, 10.0], [20.0, 30.0]], cell_size_m=100.0, origin_x=1000.0, origin_y=2000.0
    )
    assert hm.elevation(1000.0, 2000.0) == pytest.approx(0.0)
    assert hm.elevation(1100.0, 2100.0) == pytest.approx(30.0)
    assert hm.bounds == Bounds(1000.0, 2000.0, 1100.0, 2100.0)


def test_heightmap_rejects_a_ragged_grid():
    with pytest.raises(ValueError):
        Heightmap.from_rows([[0.0, 1.0], [2.0]], cell_size_m=10.0)


def test_heightmap_rejects_an_empty_grid():
    with pytest.raises(ValueError):
        Heightmap.from_rows([], cell_size_m=10.0)


def test_mountain_range_rasterizes_to_a_matching_heightmap():
    """`to_heightmap` is how an analytic terrain gets drawn or searched for
    sites; its grid nodes must agree with the analytic `elevation`."""
    t = MountainRange((GaussianPeak(x=500.0, y=500.0, height_m=800.0, sigma_m=300.0),))
    bounds = Bounds(0.0, 0.0, 1000.0, 1000.0)
    hm = t.to_heightmap(bounds, cell_size_m=250.0)

    assert hm.bounds == bounds
    for x, y in ((0.0, 0.0), (500.0, 500.0), (1000.0, 750.0)):
        assert hm.elevation(x, y) == pytest.approx(t.elevation(x, y))


# --- elevation profile / line of sight --------------------------------------


def test_profile_over_flat_ground_is_all_clearance():
    t = FlatGround(0.0)
    profile = elevation_profile(t, Vec3(0, 0, 100), Vec3(1000, 0, 100), samples=9)
    assert len(profile) == 9
    assert all(p.clearance_m == pytest.approx(100.0) for p in profile)
    assert profile[0].distance_m > 0.0
    assert profile[-1].distance_m < 1000.0


def test_profile_interpolates_the_line_of_sight_between_endpoints():
    t = FlatGround(0.0)
    # 0m up at the start, 1000m up at the end: the LOS height at the midpoint
    # must be 500m, whatever the ground does.
    profile = elevation_profile(t, Vec3(0, 0, 0), Vec3(1000, 0, 1000), samples=3)
    mid = profile[1]
    assert mid.distance_m == pytest.approx(500.0)
    assert mid.los_z_m == pytest.approx(500.0)


def test_profile_clearance_goes_negative_through_a_mountain():
    t = MountainRange((GaussianPeak(x=500.0, y=0.0, height_m=1000.0, sigma_m=200.0),))
    profile = elevation_profile(t, Vec3(0, 0, 50), Vec3(1000, 0, 50), samples=21)
    assert min(p.clearance_m for p in profile) < 0.0


def test_line_of_sight_is_blocked_by_a_peak_between_the_endpoints():
    t = MountainRange((GaussianPeak(x=500.0, y=0.0, height_m=1000.0, sigma_m=200.0),))
    assert not has_line_of_sight(t, Vec3(0, 0, 50), Vec3(1000, 0, 50), samples=64)


def test_line_of_sight_is_clear_when_flying_over_the_peak():
    t = MountainRange((GaussianPeak(x=500.0, y=0.0, height_m=1000.0, sigma_m=200.0),))
    assert has_line_of_sight(t, Vec3(0, 0, 1500), Vec3(1000, 0, 1500), samples=64)


def test_line_of_sight_is_clear_when_the_peak_is_off_to_the_side():
    """The profile follows the great-circle-ish ground track between the two
    endpoints, so a mountain 5 km off the path must not block it."""
    t = MountainRange(
        (GaussianPeak(x=500.0, y=5000.0, height_m=1000.0, sigma_m=200.0),)
    )
    assert has_line_of_sight(t, Vec3(0, 0, 50), Vec3(1000, 0, 50), samples=64)


def test_profile_of_a_vertically_stacked_pair_is_empty():
    """Two nodes at the same ground position have no horizontal track to
    sample, and nothing can be between them."""
    t = MountainRange((GaussianPeak(x=0.0, y=0.0, height_m=1000.0, sigma_m=200.0),))
    assert elevation_profile(t, Vec3(0, 0, 1100), Vec3(0, 0, 2000), samples=9) == []
    assert has_line_of_sight(t, Vec3(0, 0, 1100), Vec3(0, 0, 2000))


# --- Fresnel geometry -------------------------------------------------------


def test_fresnel_radius_is_widest_at_midpoint():
    # 2.4 GHz over a 1 km path.
    mid = fresnel_radius_m(500.0, 500.0, 2.4e9)
    off_centre = fresnel_radius_m(100.0, 900.0, 2.4e9)
    assert mid > off_centre
    # lambda = c/f ~ 0.125m; F1 = sqrt(lambda*d1*d2/d) = sqrt(0.125*500*500/1000)
    assert mid == pytest.approx(math.sqrt(0.124913 * 500 * 500 / 1000), rel=1e-3)


def test_fresnel_parameter_is_zero_at_grazing():
    assert fresnel_parameter(0.0, 500.0, 500.0, 2.4e9) == pytest.approx(0.0)


def test_fresnel_parameter_is_negative_when_clear_and_positive_when_blocked():
    assert fresnel_parameter(50.0, 500.0, 500.0, 2.4e9) < 0.0
    assert fresnel_parameter(-50.0, 500.0, 500.0, 2.4e9) > 0.0


def test_fresnel_parameter_matches_the_60_percent_clearance_rule():
    """The classic engineering rule — 60% of the first Fresnel zone clear is
    effectively unobstructed — must land at v = -0.6*sqrt(2) ~ -0.85, just
    past the v = -0.78 point where knife-edge diffraction loss vanishes."""
    f1 = fresnel_radius_m(500.0, 500.0, 2.4e9)
    v = fresnel_parameter(0.6 * f1, 500.0, 500.0, 2.4e9)
    assert v == pytest.approx(-0.6 * math.sqrt(2), rel=1e-6)
    assert v < -0.78


def test_max_fresnel_parameter_grows_as_an_obstacle_rises():
    low = MountainRange((GaussianPeak(x=500.0, y=0.0, height_m=100.0, sigma_m=200.0),))
    high = MountainRange((GaussianPeak(x=500.0, y=0.0, height_m=900.0, sigma_m=200.0),))
    a, b = Vec3(0, 0, 50), Vec3(1000, 0, 50)
    assert max_fresnel_parameter(high, a, b, 2.4e9) > max_fresnel_parameter(
        low, a, b, 2.4e9
    )


def test_max_fresnel_parameter_of_a_clear_high_path_is_well_negative():
    t = FlatGround(0.0)
    v = max_fresnel_parameter(t, Vec3(0, 0, 500), Vec3(1000, 0, 500), 2.4e9)
    assert v < -0.78


# --- TerrainFollowing -------------------------------------------------------


def test_terrain_following_flies_at_a_fixed_height_above_ground():
    t = MountainRange((GaussianPeak(x=500.0, y=0.0, height_m=600.0, sigma_m=300.0),))
    route = Waypoints((Vec3(0, 0, 0), Vec3(1000, 0, 0)), speed_m_s=100.0, loop="once")
    m = TerrainFollowing(route, t, agl_m=50.0)

    start = m.position(0.0)
    assert start.x == pytest.approx(0.0)
    assert start.z == pytest.approx(t.elevation(0.0, 0.0) + 50.0)

    over_peak = m.position(5.0)
    assert over_peak.x == pytest.approx(500.0)
    assert over_peak.z == pytest.approx(600.0 + 50.0)


def test_terrain_following_ignores_the_base_track_altitude():
    """The route supplies the ground track; the terrain plus `agl_m` supplies
    the height, so a route written at z=0 flies the mountains correctly."""
    t = FlatGround(200.0)
    m = TerrainFollowing(Static(Vec3(10, 10, 999)), t, agl_m=30.0)
    assert m.position(0.0) == Vec3(10, 10, 230.0)


# --- site selection ---------------------------------------------------------


def _range_of_three_peaks() -> MountainRange:
    return MountainRange(
        (
            GaussianPeak(x=1000.0, y=1000.0, height_m=900.0, sigma_m=300.0),
            GaussianPeak(x=4000.0, y=1000.0, height_m=700.0, sigma_m=300.0),
            GaussianPeak(x=2500.0, y=4000.0, height_m=800.0, sigma_m=300.0),
        )
    )


def test_peak_sites_finds_the_summits_highest_first():
    t = _range_of_three_peaks()
    bounds = Bounds(0.0, 0.0, 5000.0, 5000.0)
    sites = peak_sites(t, bounds, count=3, spacing_m=100.0, min_separation_m=800.0)

    assert len(sites) == 3
    # Ordered by elevation, highest first.
    assert [round(s.z) for s in sites] == sorted(
        (round(s.z) for s in sites), reverse=True
    )
    # Each returned site sits on (within one grid cell of) a distinct summit.
    for site, peak in zip(sites, (900.0, 800.0, 700.0)):
        assert site.z == pytest.approx(peak, rel=0.05)


def test_peak_sites_carries_the_terrain_elevation_as_z():
    t = _range_of_three_peaks()
    sites = peak_sites(t, Bounds(0.0, 0.0, 5000.0, 5000.0), count=1, spacing_m=100.0)
    assert sites[0].z == pytest.approx(t.elevation(sites[0].x, sites[0].y))


def test_peak_sites_respects_the_minimum_separation():
    t = _range_of_three_peaks()
    sites = peak_sites(
        t,
        Bounds(0.0, 0.0, 5000.0, 5000.0),
        count=3,
        spacing_m=100.0,
        min_separation_m=2000.0,
    )
    for i, a in enumerate(sites):
        for b in sites[i + 1 :]:
            assert math.dist((a.x, a.y), (b.x, b.y)) >= 2000.0


def test_peak_sites_returns_fewer_than_asked_when_separation_forbids_more():
    t = _range_of_three_peaks()
    sites = peak_sites(
        t,
        Bounds(0.0, 0.0, 5000.0, 5000.0),
        count=10,
        spacing_m=200.0,
        min_separation_m=9000.0,
    )
    assert len(sites) == 1


def test_valley_sites_finds_the_low_ground_lowest_first():
    t = _range_of_three_peaks()
    bounds = Bounds(0.0, 0.0, 5000.0, 5000.0)
    valleys = valley_sites(t, bounds, count=3, spacing_m=100.0, min_separation_m=800.0)
    peaks = peak_sites(t, bounds, count=3, spacing_m=100.0, min_separation_m=800.0)

    assert len(valleys) == 3
    assert [round(v.z) for v in valleys] == sorted(round(v.z) for v in valleys)
    assert max(v.z for v in valleys) < min(p.z for p in peaks)


def test_site_search_rejects_a_non_positive_spacing():
    t = _range_of_three_peaks()
    with pytest.raises(ValueError):
        peak_sites(t, Bounds(0.0, 0.0, 100.0, 100.0), count=1, spacing_m=0.0)
