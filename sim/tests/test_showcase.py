"""The JSON a scenario exports for the website's results page."""

import json

from wayfinder_sim.showcase import Chart, Headline, Series, Showcase, write_showcase


def _showcase() -> Showcase:
    return Showcase(
        slug="failover",
        title="Kill a node, watch it heal",
        question="How long does traffic stop when a relay dies?",
        headlines=[Headline(value="2.1 s", label="to reroute")],
        summary="A relay is powered off mid-stream.",
        charts=[
            Chart(
                title="Delivery",
                x_label="time (s)",
                y_label="delivered",
                series=[Series(name="a→d", x=[0.0, 1.0], y=[1.0, 0.0])],
            )
        ],
        params={"rate_hz": 20},
    )


def test_write_showcase_round_trips(tmp_path):
    path = write_showcase(_showcase(), tmp_path)
    assert path == tmp_path / "failover.json"
    data = json.loads(path.read_text())
    assert data["slug"] == "failover"
    assert data["headlines"] == [{"value": "2.1 s", "label": "to reroute", "detail": None}]
    assert data["charts"][0]["series"][0]["kind"] == "line"
    assert data["params"] == {"rate_hz": 20}
    assert data["schema"] == 1


def test_series_lengths_must_match():
    import pytest

    with pytest.raises(ValueError):
        Series(name="bad", x=[1.0], y=[1.0, 2.0])


def test_floats_are_rounded_to_keep_the_page_small(tmp_path):
    showcase = _showcase()
    showcase.charts[0].series[0].y[0] = 0.123456789
    data = json.loads(write_showcase(showcase, tmp_path).read_text())
    assert data["charts"][0]["series"][0]["y"][0] == 0.1235


def test_downsample_keeps_every_edge_of_a_step_signal():
    from wayfinder_sim.showcase import downsample

    x = [float(i) for i in range(5000)]
    y = [1 if 1000 <= i < 1200 or i == 4321 else 0 for i in range(5000)]
    xs, ys = downsample(x, y, max_points=300)
    assert len(xs) <= 5000 and len(xs) < 1000
    for edge in (999.0, 1000.0, 1199.0, 1200.0, 4320.0, 4321.0, 4322.0):
        assert edge in xs
    assert xs == sorted(xs)
    assert dict(zip(xs, ys))[4321.0] == 1


def test_downsample_leaves_short_series_alone():
    from wayfinder_sim.showcase import downsample

    assert downsample([1.0, 2.0], [3, 4]) == ([1.0, 2.0], [3, 4])
