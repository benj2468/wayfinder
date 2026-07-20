import pytest

from engine.mobility import Orbit, Static, Vec3, Waypoints


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
