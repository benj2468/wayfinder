import base64
import json
import re

import pytest
from wayfinder_sim.report import (
    ImagePanel,
    RunReport,
    ScenePanel,
    sweep_report_html,
    write_sweep_report,
)

# The smallest valid PNG, so a test can exercise image embedding without
# depending on a rendering stack to produce one.
_PNG_BYTES = base64.b64decode(
    b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def _png(tmp_path, name="chart.png"):
    path = tmp_path / name
    path.write_bytes(_PNG_BYTES)
    return path


def _runs() -> list[RunReport]:
    return [
        RunReport(
            label="summits",
            params={"relays": 3, "siting": "peak"},
            metrics={"outages": 3},
            headline=0.808,
        ),
        RunReport(
            label="valley floor",
            params={"relays": 3, "siting": "valley"},
            metrics={"outages": 6},
            headline=0.601,
        ),
    ]


# --- document shape ---------------------------------------------------------


def test_report_is_a_complete_html_document():
    html = sweep_report_html("Mountain relay sweep", _runs())
    assert html.lstrip().startswith("<!doctype html>")
    assert "</html>" in html.rstrip()


def test_report_carries_the_title_into_the_page_and_the_tab():
    html = sweep_report_html("Mountain relay sweep", _runs())
    assert "<title>Mountain relay sweep</title>" in html
    assert html.count("Mountain relay sweep") >= 2


def test_report_renders_a_section_per_run():
    html = sweep_report_html("Sweep", _runs())
    assert "summits" in html
    assert "valley floor" in html


def test_report_renders_parameters_and_metrics():
    html = sweep_report_html("Sweep", _runs())
    for fragment in ("relays", "siting", "peak", "outages"):
        assert fragment in html


def test_a_subtitle_is_included_when_given():
    html = sweep_report_html("Sweep", _runs(), subtitle="Four sitings, one route")
    assert "Four sitings, one route" in html


# --- ranking ----------------------------------------------------------------


def test_runs_are_ranked_by_their_headline_figure():
    """The page exists to answer "which setting won", so the ranking is the
    first thing on it — best first, whatever order the sweep ran in."""
    html = sweep_report_html("Sweep", list(reversed(_runs())))
    summary = html[html.index("data-summary") : html.index("data-runs")]
    assert summary.index("summits") < summary.index("valley floor")


def test_headline_fractions_are_rendered_as_percentages():
    html = sweep_report_html("Sweep", _runs())
    assert "80.8%" in html
    assert "60.1%" in html


def test_a_headline_label_describes_what_the_figure_measures():
    html = sweep_report_html("Sweep", _runs(), headline_label="connected")
    assert "connected" in html


def test_runs_without_a_headline_still_render():
    """Not every sweep reduces to one number; the page must degrade to plain
    parameter/metric blocks rather than fail."""
    runs = [
        RunReport(label="a", params={"x": 1}),
        RunReport(label="b", params={"x": 2}),
    ]
    html = sweep_report_html("Sweep", runs)
    assert "data-runs" in html
    assert "%" not in html.split("data-runs")[1]


def test_report_rejects_an_empty_sweep():
    with pytest.raises(ValueError):
        sweep_report_html("Sweep", [])


# --- embedded panels --------------------------------------------------------


def test_images_are_embedded_rather_than_linked(tmp_path):
    """The page has to survive being copied somewhere else on its own, so a
    chart is bytes in the document, not a path into someone's checkout."""
    runs = [
        RunReport(
            label="summits",
            headline=0.8,
            panels=[ImagePanel(_png(tmp_path), caption="Coverage map")],
        )
    ]
    html = sweep_report_html("Sweep", runs)
    assert "data:image/png;base64," in html
    assert str(tmp_path) not in html
    assert "Coverage map" in html


def test_summary_panels_render_above_the_runs(tmp_path):
    runs = _runs()
    html = sweep_report_html(
        "Sweep",
        runs,
        summary_panels=[ImagePanel(_png(tmp_path), caption="Placement comparison")],
    )
    assert html.index("Placement comparison") < html.index("data-runs")


def test_a_missing_image_is_reported_rather_than_silently_dropped(tmp_path):
    runs = [RunReport(label="a", panels=[ImagePanel(tmp_path / "nope.png")])]
    with pytest.raises(FileNotFoundError):
        sweep_report_html("Sweep", runs)


def test_report_pulls_in_no_remote_resources(tmp_path):
    runs = [RunReport(label="a", panels=[ImagePanel(_png(tmp_path))])]
    html = sweep_report_html("Sweep", runs)
    assert '<script src="http' not in html
    assert '<link rel="stylesheet" href="http' not in html
    assert "@import url(http" not in html


def test_labels_are_escaped_rather_than_injected():
    runs = [RunReport(label="<script>alert(1)</script>", params={"a": "<b>"})]
    html = sweep_report_html("Sweep", runs)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --- plotly scenes ----------------------------------------------------------


def test_scene_panels_embed_the_plotly_runtime_exactly_once():
    """Every scene shares one copy of the runtime — four bundled copies would
    quadruple a page that is already several megabytes."""
    plotly = pytest.importorskip("plotly.graph_objects")
    runs = [
        RunReport(label="a", panels=[ScenePanel(plotly.Figure(), caption="Scene A")]),
        RunReport(label="b", panels=[ScenePanel(plotly.Figure(), caption="Scene B")]),
    ]
    html = sweep_report_html("Sweep", runs)
    assert "Scene A" in html and "Scene B" in html
    from plotly.offline import get_plotlyjs

    # One plot div per scene, and exactly one copy of the runtime — compared
    # against the real bundle, since counting a token like "Plotly.newPlot"
    # would also match the bundle's own definition of it.
    assert html.count('class="plotly-graph-div"') == 2
    assert html.count(get_plotlyjs()[:2000]) == 1


def test_an_embedded_scene_keeps_its_scrubber():
    """A scene panel carries a timeline as often as not, and the report is
    where a reader actually meets it — so the frames must survive embedding,
    not just standalone `write_html`."""
    pytest.importorskip("plotly.graph_objects")
    from wayfinder_sim.interactive import Timeline, track_scene
    from wayfinder_sim.mobility import Vec3

    scene = track_scene(
        tracks={"Drone": [Vec3(0, 0, 30), Vec3(1000, 0, 30)]},
        timeline=Timeline(
            times_s=[0.0, 1.0], positions={"Drone": [Vec3(0, 0, 30), Vec3(1000, 0, 30)]}
        ),
    )
    html = sweep_report_html(
        "Sweep", [RunReport(label="a", panels=[ScenePanel(scene)])]
    )
    assert "addFrames" in html


def test_scenes_span_the_full_width_while_images_share_a_row(tmp_path):
    """A rotatable 3D scene needs room; a static chart reads fine at half
    width beside its neighbour."""
    plotly = pytest.importorskip("plotly.graph_objects")
    runs = [
        RunReport(
            label="a",
            panels=[ImagePanel(_png(tmp_path)), ScenePanel(plotly.Figure())],
        )
    ]
    html = sweep_report_html("Sweep", runs)
    assert 'class="wf-figure wf-wide"' in html
    assert 'class="wf-figure"' in html


def test_a_report_without_scenes_omits_the_plotly_runtime(tmp_path):
    runs = [RunReport(label="a", panels=[ImagePanel(_png(tmp_path))])]
    html = sweep_report_html("Sweep", runs)
    assert "Plotly.newPlot" not in html


# --- writing ----------------------------------------------------------------


def test_write_creates_parent_directories_and_returns_the_path(tmp_path):
    out = write_sweep_report(tmp_path / "nested" / "report.html", "Sweep", _runs())
    assert out.exists()
    assert out.read_text().startswith("<!doctype html>")


# --- expandable scenes ------------------------------------------------------


def _scene(caption="Scene", **kwargs):
    pytest.importorskip("plotly.graph_objects")
    from wayfinder_sim.interactive import Timeline, track_scene
    from wayfinder_sim.mobility import Vec3

    figure = track_scene(
        tracks={"Drone": [Vec3(0, 0, 30), Vec3(1000, 0, 30)]},
        timeline=Timeline(
            times_s=[0.0, 1.0],
            positions={"Drone": [Vec3(0, 0, 30), Vec3(1000, 0, 30)]},
        ),
    )
    return ScenePanel(figure, caption=caption, **kwargs)


def test_a_collapsed_scene_is_wrapped_in_a_closed_disclosure():
    """Seven scenes open at once is seven WebGL contexts and a page nobody can
    scroll; each run's scene belongs behind its own toggle."""
    html = sweep_report_html(
        "Sweep", [RunReport(label="a", panels=[_scene(collapsed=True)])]
    )
    assert "<details" in html
    assert "<summary" in html
    assert "<details open" not in html


def test_a_collapsed_scene_is_not_plotted_until_it_is_opened():
    """A plot built inside a closed `<details>` has no size to lay out in, and
    every scene on the page would claim a WebGL context at load whether or not
    anyone looks at it. The spec is parked as inert JSON instead."""
    html = sweep_report_html(
        "Sweep", [RunReport(label="a", panels=[_scene(collapsed=True)])]
    )
    assert 'type="application/json"' in html
    assert 'addEventListener("toggle"' in html
    # The eager path emits a `newPlot` call carrying the figure's data inline;
    # the deferred one reads it back out of the JSON block on open.
    assert "Plotly.newPlot(id, spec.data" in html
    assert 'Plotly.newPlot("wf-scene' not in html


def test_an_opened_scene_still_gets_its_frames():
    html = sweep_report_html(
        "Sweep", [RunReport(label="a", panels=[_scene(collapsed=True)])]
    )
    assert "addFrames" in html


def test_every_collapsed_scene_gets_its_own_target():
    """Two scenes sharing a div id would render one and blank the other."""
    runs = [
        RunReport(label="a", panels=[_scene("A", collapsed=True)]),
        RunReport(label="b", panels=[_scene("B", collapsed=True)]),
    ]
    html = sweep_report_html("Sweep", runs)
    ids = re.findall(r'id="(wf-scene-\d+)"', html)
    assert len(ids) == len(set(ids)) == 2


def test_a_collapsed_scenes_caption_labels_the_toggle():
    """A closed section shows only its summary, so the caption has to be on
    it — left in the figure it would be invisible until opened."""
    html = sweep_report_html(
        "Sweep", [RunReport(label="a", panels=[_scene("Fly the pass", collapsed=True)])]
    )
    summary = html[html.index("<summary") : html.index("</summary>")]
    assert "Fly the pass" in summary


def test_scene_data_cannot_break_out_of_its_json_block():
    """The spec is inlined into a script element, so a `<` anywhere in the
    figure — a title, a caption, an axis label — must not be able to close it
    early. plotly's own encoder escapes those, and `_scene_spec` escapes them
    again rather than depend on that silently continuing to be true."""
    plotly = pytest.importorskip("plotly.graph_objects")
    figure = plotly.Figure()
    figure.update_layout(title={"text": "</script><script>alert(1)</script>"})
    html = sweep_report_html(
        "Sweep",
        [RunReport(label="a", panels=[ScenePanel(figure, collapsed=True)])],
    )

    opening = 'id="wf-scene-0-spec">'
    block = html[html.index(opening) + len(opening) :]
    block = block[: block.index("</script>")]
    assert "<" not in block
    # Escaped, not mangled: it still parses back to what went in.
    assert (
        json.loads(block)["layout"]["title"]["text"]
        == "</script><script>alert(1)</script>"
    )


def test_collapsed_scenes_still_share_one_runtime():
    runs = [
        RunReport(label="a", panels=[_scene("A", collapsed=True)]),
        RunReport(label="b", panels=[_scene("B", collapsed=True)]),
    ]
    html = sweep_report_html("Sweep", runs)
    from plotly.offline import get_plotlyjs

    assert html.count(get_plotlyjs()[:2000]) == 1


def test_an_expanded_scene_is_unchanged():
    """The default stays eager: a single hero scene should render without a
    click."""
    html = sweep_report_html("Sweep", [RunReport(label="a", panels=[_scene()])])
    assert "<details" not in html
    assert 'class="plotly-graph-div"' in html
