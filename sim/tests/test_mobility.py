import math

import pytest
from wayfinder_sim.mobility import (
    EARTH_RADIUS_M,
    EarthOrbit,
    GreatCircle,
    Orbit,
    Static,
    Vec3,
    Waypoints,
)


def test_vec3_distance_to():
    assert Vec3(0, 0, 0).distance_to(Vec3(3, 4, 0)) == pytest.approx(5.0)
    assert Vec3(1, 1, 1).distance_to(Vec3(1, 1, 1)) == 0.0


def test_static_never_moves():
    m = Static(Vec3(10, 20, 30))
    assert m.position(0.0) == Vec3(10, 20, 30)
    assert m.position(999.0) == Vec3(10, 20, 30)


def test_waypoints_single_point_behaves_like_static():
    m = Waypoints((Vec3(5, 5, 5),), speed_m_s=1.0)
    assert m.position(0.0) == Vec3(5, 5, 5)
    assert m.position(100.0) == Vec3(5, 5, 5)


def test_waypoints_two_point_linear_interpolation():
    m = Waypoints((Vec3(0, 0, 0), Vec3(100, 0, 0)), speed_m_s=10.0)
    assert m.duration_s() == pytest.approx(10.0)
    assert m.position(0.0) == Vec3(0, 0, 0)
    assert m.position(5.0) == Vec3(50, 0, 0)
    assert m.position(10.0) == Vec3(100, 0, 0)


def test_waypoints_multi_segment_interpolation():
    # (0,0,0) -> (100,0,0) -> (100,100,0), each leg 100m, speed 10 m/s.
    m = Waypoints((Vec3(0, 0, 0), Vec3(100, 0, 0), Vec3(100, 100, 0)), speed_m_s=10.0)
    assert m.duration_s() == pytest.approx(20.0)
    assert m.position(15.0) == Vec3(100, 50, 0)


def test_waypoints_loop_once_clamps_at_end():
    m = Waypoints((Vec3(0, 0, 0), Vec3(100, 0, 0)), speed_m_s=10.0, loop="once")
    assert m.position(15.0) == Vec3(100, 0, 0)
    assert m.position(1000.0) == Vec3(100, 0, 0)


def test_waypoints_loop_pingpong_reverses():
    m = Waypoints((Vec3(0, 0, 0), Vec3(100, 0, 0)), speed_m_s=10.0, loop="pingpong")
    # period is 2 * duration_s = 20s; at t=15 we're 5s into the return leg.
    assert m.position(15.0) == Vec3(50, 0, 0)
    assert m.position(20.0) == Vec3(0, 0, 0)
    # second out-leg repeats the first
    assert m.position(25.0) == Vec3(50, 0, 0)


def test_waypoints_loop_cycle_restarts_from_beginning():
    m = Waypoints((Vec3(0, 0, 0), Vec3(100, 0, 0)), speed_m_s=10.0, loop="cycle")
    # period is duration_s = 10s; t=15 is 5s into the second lap.
    assert m.position(15.0) == Vec3(50, 0, 0)
    assert m.position(10.0) == Vec3(0, 0, 0)


def test_waypoints_rejects_empty_points():
    with pytest.raises(ValueError):
        Waypoints((), speed_m_s=1.0)


def test_waypoints_rejects_unknown_loop_mode():
    with pytest.raises(ValueError):
        Waypoints(
            (Vec3(0, 0, 0), Vec3(1, 0, 0)),
            speed_m_s=1.0,
            loop="bogus",  # pyright: ignore[reportArgumentType]
        )


def _approx_vec3(v: Vec3) -> object:
    return pytest.approx((v.x, v.y, v.z), abs=1e-9)


def _as_tuple(v: Vec3) -> tuple[float, float, float]:
    return (v.x, v.y, v.z)


def test_orbit_starts_at_angle_zero():
    m = Orbit(center=Vec3(0, 0, 0), radius_m=100.0, altitude_m=50.0, period_s=60.0)
    assert _as_tuple(m.position(0.0)) == _approx_vec3(Vec3(100, 0, 50))


def test_orbit_quarter_period_is_90_degrees():
    m = Orbit(center=Vec3(0, 0, 0), radius_m=100.0, altitude_m=50.0, period_s=60.0)
    assert _as_tuple(m.position(15.0)) == _approx_vec3(Vec3(0, 100, 50))


def test_orbit_half_period_is_the_opposite_point():
    m = Orbit(center=Vec3(0, 0, 0), radius_m=100.0, altitude_m=50.0, period_s=60.0)
    assert _as_tuple(m.position(30.0)) == _approx_vec3(Vec3(-100, 0, 50))


def test_orbit_wraps_after_a_full_period():
    m = Orbit(center=Vec3(10, 20, 0), radius_m=100.0, altitude_m=50.0, period_s=60.0)
    assert _as_tuple(m.position(60.0)) == _approx_vec3(m.position(0.0))
    assert _as_tuple(m.position(75.0)) == _approx_vec3(m.position(15.0))


def test_orbit_centered_away_from_origin():
    m = Orbit(center=Vec3(1000, 0, 0), radius_m=100.0, altitude_m=50.0, period_s=60.0)
    assert _as_tuple(m.position(0.0)) == _approx_vec3(Vec3(1100, 0, 50))


def test_orbit_phase_offset_shifts_the_start():
    unphased = Orbit(
        center=Vec3(0, 0, 0), radius_m=100.0, altitude_m=50.0, period_s=60.0
    )
    phased = Orbit(
        center=Vec3(0, 0, 0),
        radius_m=100.0,
        altitude_m=50.0,
        period_s=60.0,
        phase_s=15.0,
    )
    assert _as_tuple(phased.position(0.0)) == _approx_vec3(unphased.position(15.0))


def test_orbit_zero_radius_is_a_fixed_point_above_center():
    m = Orbit(center=Vec3(5, 5, 0), radius_m=0.0, altitude_m=50.0, period_s=60.0)
    assert m.position(0.0) == Vec3(5, 5, 50)
    assert m.position(999.0) == Vec3(5, 5, 50)


def test_orbit_rejects_non_positive_period():
    with pytest.raises(ValueError):
        Orbit(center=Vec3(0, 0, 0), radius_m=100.0, altitude_m=50.0, period_s=0.0)
    with pytest.raises(ValueError):
        Orbit(center=Vec3(0, 0, 0), radius_m=100.0, altitude_m=50.0, period_s=-10.0)


# --- real orbits ------------------------------------------------------------


def test_orbital_period_follows_from_the_altitude():
    """A real orbit has no free period: Kepler's third law fixes it from the
    radius, which is why a 550 km shell circles in ~95 minutes and cannot be
    made to loiter."""
    orbit = EarthOrbit(altitude_m=550_000.0)
    assert orbit.period_s == pytest.approx(95.5 * 60, rel=0.01)
    assert EarthOrbit(altitude_m=1_200_000.0).period_s > orbit.period_s


def test_orbit_starts_overhead_when_its_track_passes_over_the_origin():
    """The scene's frame is ENU with its origin on the surface, so a
    satellite directly above it sits at (0, 0, altitude) — the same reading a
    flat-plane orbit would give, which is what makes the two comparable."""
    at = EarthOrbit(altitude_m=550_000.0).position(0.0)
    assert at.x == pytest.approx(0.0, abs=1.0)
    assert at.y == pytest.approx(0.0, abs=1.0)
    assert at.z == pytest.approx(550_000.0, abs=1.0)


def test_orbit_keeps_a_constant_distance_from_the_earths_centre():
    """Circular means circular about the *planet*, not about a point in the
    scene — the property a flat-plane orbit at fixed altitude gets wrong."""
    orbit = EarthOrbit(altitude_m=550_000.0, heading_deg=42.0)
    centre = Vec3(0.0, 0.0, -EARTH_RADIUS_M)
    radii = [centre.distance_to(orbit.position(t)) for t in range(0, 5000, 250)]
    for r in radii:
        assert r == pytest.approx(EARTH_RADIUS_M + 550_000.0, rel=1e-9)


def test_half_an_orbit_later_the_satellite_is_on_the_far_side_of_the_earth():
    """The whole reason to leave the flat plane: a satellite does not stay
    overhead at constant altitude, it goes round the back and its ENU
    altitude becomes hugely negative."""
    orbit = EarthOrbit(altitude_m=550_000.0)
    antipode = orbit.position(orbit.period_s / 2)
    assert antipode.z == pytest.approx(-(2 * EARTH_RADIUS_M + 550_000.0), rel=1e-6)


def test_heading_sets_the_direction_the_ground_track_runs():
    """A constellation is planes at different headings; without this every
    plane would be the same plane."""
    north = EarthOrbit(altitude_m=550_000.0, heading_deg=0.0).position(60.0)
    east = EarthOrbit(altitude_m=550_000.0, heading_deg=90.0).position(60.0)
    assert north.y > abs(north.x)
    assert east.x > abs(east.y)


def test_ground_offset_moves_the_track_sideways():
    """A satellite whose track passes to one side never comes overhead — the
    reason a handful of satellites cannot cover a point continuously.

    The offset is the *ground track's*, measured as an arc along the surface,
    so the satellite itself sits further out than that (its own displacement
    scales with orbital radius) and correspondingly lower in the ENU frame —
    the curvature this class exists to keep.
    """
    at = EarthOrbit(altitude_m=550_000.0, ground_offset_m=400_000.0).position(0.0)

    arc_m = EARTH_RADIUS_M * math.acos(
        (at.z + EARTH_RADIUS_M) / (EARTH_RADIUS_M + 550_000.0)
    )
    assert arc_m == pytest.approx(400_000.0, rel=1e-6)
    assert at.z < 550_000.0
    assert math.hypot(at.x, at.y) > 400_000.0


def test_phase_staggers_satellites_around_one_shared_track():
    """Satellites in a plane are the same orbit at different phases — that is
    what makes them a ring rather than a formation."""
    plane = {"altitude_m": 550_000.0, "heading_deg": 0.0}
    lead = EarthOrbit(**plane)
    trail = EarthOrbit(**plane, phase_s=-lead.period_s / 3)
    assert trail.position(lead.period_s / 3).distance_to(lead.position(0.0)) < 1.0


def test_orbit_rejects_an_altitude_inside_the_earth():
    with pytest.raises(ValueError):
        EarthOrbit(altitude_m=-1.0)


# --- travel over a curved Earth ---------------------------------------------


def test_a_great_circle_starts_at_the_scene_origin():
    flight = GreatCircle(range_m=9_000_000.0, speed_m_s=250.0, altitude_m=10_000.0)
    at = flight.position(0.0)
    assert (at.x, at.y) == pytest.approx((0.0, 0.0))
    assert at.z == pytest.approx(10_000.0)


def test_a_great_circle_holds_its_altitude_the_whole_way():
    """The bug this exists to prevent: a straight line in the tangent plane
    keeps its `z` and climbs away from the planet, so a 9,000 km "airliner"
    ends up thousands of kilometres above the constellation it is supposed to
    be under."""
    flight = GreatCircle(range_m=9_000_000.0, speed_m_s=250.0, altitude_m=10_000.0)
    centre = Vec3(0.0, 0.0, -EARTH_RADIUS_M)
    for t in range(0, 36_000, 1_200):
        assert centre.distance_to(flight.position(t)) == pytest.approx(
            EARTH_RADIUS_M + 10_000.0, rel=1e-9
        )


def test_a_great_circle_covers_its_range_along_the_surface():
    """Range is measured as an arc over the ground, not as a straight-line
    chord — that is what makes it comparable to a satellite's footprint."""
    flight = GreatCircle(range_m=9_000_000.0, speed_m_s=250.0, loop="once")
    at = flight.position(9_000_000.0 / 250.0)
    arc_m = EARTH_RADIUS_M * math.acos((at.z + EARTH_RADIUS_M) / EARTH_RADIUS_M)
    assert arc_m == pytest.approx(9_000_000.0, rel=1e-6)


def test_heading_points_the_flight():
    north = GreatCircle(range_m=1e6, speed_m_s=250.0, heading_deg=0.0).position(1000.0)
    east = GreatCircle(range_m=1e6, speed_m_s=250.0, heading_deg=90.0).position(1000.0)
    assert north.y > 0 and north.x == pytest.approx(0.0, abs=1.0)
    assert east.x > 0 and east.y == pytest.approx(0.0, abs=1.0)


def test_a_short_leg_still_agrees_with_the_flat_plane_answer():
    """Curvature has to be a refinement, not a change of behaviour: over the
    few kilometres the older scenarios fly, this must match `Waypoints` to
    within centimetres, or every one of their tuned numbers moves."""
    curved = GreatCircle(range_m=2000.0, speed_m_s=20.0, altitude_m=30.0, loop="once")
    flat = Waypoints((Vec3(0, 0, 30), Vec3(0, 2000, 30)), speed_m_s=20.0, loop="once")
    for t in (0.0, 25.0, 50.0, 100.0):
        assert curved.position(t).distance_to(flat.position(t)) < 0.5


def test_a_great_circle_pingpongs_back_to_where_it_started():
    flight = GreatCircle(range_m=1e6, speed_m_s=250.0, loop="pingpong")
    out = flight.duration_s()
    assert flight.position(2 * out).distance_to(flight.position(0.0)) < 1.0
    assert flight.position(1.5 * out).distance_to(flight.position(0.5 * out)) < 1.0


def test_a_great_circle_rejects_a_standstill():
    with pytest.raises(ValueError):
        GreatCircle(range_m=1e6, speed_m_s=0.0)
