import pytest
from wayfinder_sim.connectivity import (
    ConnectivityStats,
    Outage,
    connectivity_stats,
    outage_windows,
)
from wayfinder_sim.recorder import Recorder


def _recorder(values: list[object], *, interval_ms: int = 100) -> Recorder:
    """A `Recorder` holding one column, `link`, sampled every `interval_ms`."""
    rec = Recorder(interval_ms=interval_ms)
    for i, value in enumerate(values):
        rec.append(i * interval_ms / 1000.0, {"link": value})
    return rec


def _pairs(windows: object) -> list[tuple[float, float]]:
    """Outage bounds rounded to the millisecond, so a comparison isn't at the
    mercy of 0.1 + 0.2 in binary floating point."""
    return [(round(o.start_s, 6), round(o.end_s, 6)) for o in windows]  # pyright: ignore[reportGeneralTypeIssues]


# --- Outage -----------------------------------------------------------------


def test_outage_reports_its_own_duration():
    assert Outage(start_s=1.0, end_s=3.5).duration_s == pytest.approx(2.5)


# --- outage_windows ---------------------------------------------------------


def test_no_outages_when_always_connected():
    rec = _recorder(["a-b"] * 5)
    assert outage_windows(rec, "link") == ()


def test_one_outage_spanning_everything_when_never_connected():
    rec = _recorder([None] * 5)
    assert _pairs(outage_windows(rec, "link")) == [(0.0, 0.5)]


def test_outage_runs_from_first_lost_sample_to_first_recovered_one():
    rec = _recorder(["a-b", "a-b", None, None, "a-b"])
    assert _pairs(outage_windows(rec, "link")) == [(0.2, 0.4)]


def test_a_trailing_outage_closes_one_interval_past_the_last_sample():
    """The last sample stands for a whole interval of time like any other, so
    an outage still in progress at the end is not silently shortened."""
    rec = _recorder(["a-b", None, None])
    assert _pairs(outage_windows(rec, "link")) == [(0.1, 0.3)]


def test_separate_outages_are_reported_separately():
    rec = _recorder(["a-b", None, "a-b", None, None, "a-b"])
    assert _pairs(outage_windows(rec, "link")) == [(0.1, 0.2), (0.3, 0.5)]


def test_an_empty_reachable_set_counts_as_disconnected():
    """A `reachable`-style probe reports a tuple of node names, so "connected
    to nothing" arrives as `()` rather than `None`."""
    rec = _recorder([("r1",), (), (), ("r2", "r3")])
    assert _pairs(outage_windows(rec, "link")) == [(0.1, 0.3)]


def test_a_custom_predicate_can_redefine_connected():
    """Being routable is not always being *usefully* routable — a scenario
    may want a quality floor, or a specific peer, to count."""
    rec = _recorder([255, 40, 30, 200])
    windows = outage_windows(rec, "link", predicate=lambda q: q >= 128)
    assert _pairs(windows) == [(0.1, 0.3)]


def test_outage_windows_on_an_empty_recording_is_empty():
    assert outage_windows(Recorder(interval_ms=100), "link") == ()


def test_outage_windows_rejects_an_unrecorded_column():
    rec = _recorder(["a-b"])
    with pytest.raises(KeyError):
        outage_windows(rec, "nope")


# --- connectivity_stats -----------------------------------------------------


def test_stats_of_a_fully_connected_run():
    stats = connectivity_stats(_recorder(["a-b"] * 4), "link")
    assert stats.total_s == pytest.approx(0.4)
    assert stats.connected_s == pytest.approx(0.4)
    assert stats.disconnected_s == pytest.approx(0.0)
    assert stats.connected_fraction == pytest.approx(1.0)
    assert stats.outage_count == 0
    assert stats.longest_outage_s == 0.0


def test_stats_of_a_fully_disconnected_run():
    stats = connectivity_stats(_recorder([None] * 4), "link")
    assert stats.connected_s == pytest.approx(0.0)
    assert stats.disconnected_s == pytest.approx(0.4)
    assert stats.connected_fraction == pytest.approx(0.0)
    assert stats.outage_count == 1
    assert stats.longest_outage_s == pytest.approx(0.4)


def test_stats_split_a_mixed_run_by_sample_count():
    # 3 of 4 samples connected.
    stats = connectivity_stats(_recorder(["a-b", "a-b", None, "a-b"]), "link")
    assert stats.connected_fraction == pytest.approx(0.75)
    assert stats.connected_s == pytest.approx(0.3)
    assert stats.disconnected_s == pytest.approx(0.1)


def test_outage_durations_account_for_all_disconnected_time():
    """The window view and the fraction view must agree — they're the same
    samples counted two ways, and a scenario reports both side by side."""
    rec = _recorder(["a-b", None, None, "a-b", None, "a-b", None, None])
    stats = connectivity_stats(rec, "link")
    assert sum(o.duration_s for o in stats.outages) == pytest.approx(
        stats.disconnected_s
    )


def test_longest_outage_picks_the_worst_one():
    rec = _recorder(["a-b", None, "a-b", None, None, None, "a-b"])
    stats = connectivity_stats(rec, "link")
    assert stats.outage_count == 2
    assert stats.longest_outage_s == pytest.approx(0.3)


def test_stats_of_an_empty_recording_are_all_zero():
    """A run that recorded nothing is reported as an empty run, not a
    division by zero."""
    stats = connectivity_stats(Recorder(interval_ms=100), "link")
    assert stats == ConnectivityStats(total_s=0.0, connected_s=0.0, outages=())
    assert stats.connected_fraction == 0.0


def test_stats_honour_the_recorders_own_sample_interval():
    stats = connectivity_stats(_recorder(["a-b", None], interval_ms=500), "link")
    assert stats.total_s == pytest.approx(1.0)
    assert stats.connected_s == pytest.approx(0.5)


def test_stats_carry_a_custom_predicate_through_to_the_windows():
    rec = _recorder([255, 40, 200])
    stats = connectivity_stats(rec, "link", predicate=lambda q: q >= 128)
    assert stats.connected_fraction == pytest.approx(2 / 3)
    assert _pairs(stats.outages) == [(0.1, 0.2)]
