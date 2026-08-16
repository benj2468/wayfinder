import itertools

import pytest

pytest.importorskip("plotly")

from wayfinder_sim.interactive import Timeline, terrain_scene, track_scene, write_html
from wayfinder_sim.mobility import Vec3
from wayfinder_sim.terrain import Bounds, GaussianPeak, MountainRange


def _terrain() -> MountainRange:
    return MountainRange(
        (GaussianPeak(x=500.0, y=500.0, height_m=800.0, sigma_m=300.0),)
    )


_BOUNDS = Bounds(0.0, 0.0, 1000.0, 1000.0)


def _trace_names(fig) -> list[str]:
    return [t.name for t in fig.data]


def test_scene_of_bare_terrain_is_a_single_surface():
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=8)
    assert len(fig.data) == 1
    assert fig.data[0].type == "surface"


def test_surface_samples_the_terrain_at_the_requested_resolution():
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=8)
    surface = fig.data[0]
    assert len(surface.x) == 8
    assert len(surface.y) == 8
    assert len(surface.z) == 8
    assert len(surface.z[0]) == 8


def test_surface_z_matches_the_terrain_it_was_built_from():
    terrain = _terrain()
    fig = terrain_scene(terrain, _BOUNDS, resolution=5)
    surface = fig.data[0]
    for j, y in enumerate(surface.y):
        for i, x in enumerate(surface.x):
            assert surface.z[j][i] == pytest.approx(terrain.elevation(x, y))


def test_scene_rejects_a_degenerate_resolution():
    with pytest.raises(ValueError):
        terrain_scene(_terrain(), _BOUNDS, resolution=1)


def test_tracks_become_named_line_traces():
    fig = terrain_scene(
        _terrain(),
        _BOUNDS,
        resolution=6,
        tracks={"Drone": [Vec3(0, 0, 100), Vec3(500, 500, 900)]},
    )
    assert "Drone" in _trace_names(fig)
    track = next(t for t in fig.data if t.name == "Drone")
    assert track.type == "scatter3d"
    assert track.x == (0, 500)
    assert track.z == (100, 900)


def test_sites_become_one_labelled_marker_trace():
    """Relays are one kind of thing, so they share a trace (and a hue) and are
    told apart by their labels — not by one legend entry each."""
    fig = terrain_scene(
        _terrain(),
        _BOUNDS,
        resolution=6,
        sites={"r1": Vec3(100, 100, 250), "r2": Vec3(900, 900, 260)},
    )
    sites = next(t for t in fig.data if t.name == "Relay site")
    assert sites.mode is not None and "markers" in sites.mode
    assert sorted(sites.text) == ["r1", "r2"]


def test_markers_become_their_own_highlight_trace():
    fig = terrain_scene(
        _terrain(),
        _BOUNDS,
        resolution=6,
        markers={"No route": [Vec3(10, 10, 210)]},
    )
    assert "No route" in _trace_names(fig)


def test_empty_track_and_marker_sets_add_no_traces():
    fig = terrain_scene(
        _terrain(), _BOUNDS, resolution=6, tracks={"Drone": []}, markers={"Gap": []}
    )
    assert _trace_names(fig) == [None]


def test_title_is_carried_onto_the_figure():
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, title="Mountain relay")
    assert fig.layout.title.text == "Mountain relay"


def test_scene_is_rotatable_rather_than_pinned_to_one_projection():
    """The whole point of this renderer over a static PNG: the camera is a
    live control, so the scene must not be locked to a fixed aspect or drag
    mode that disables orbiting."""
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6)
    assert fig.layout.scene.dragmode == "orbit"
    assert fig.layout.scene.aspectmode == "manual"


def test_legend_and_colorbar_do_not_share_a_corner():
    """Plotly parks both in the top right by default, where the surface's
    colorbar and the trace legend overlap into an unreadable pile. They have
    to be given separate homes explicitly."""
    fig = terrain_scene(
        _terrain(),
        _BOUNDS,
        resolution=6,
        tracks={"Drone": [Vec3(0, 0, 100), Vec3(500, 500, 900)]},
        markers={"No route": [Vec3(10, 10, 210)]},
        sites={"r1": Vec3(100, 100, 250)},
        title="Mountain relay",
    )

    # The legend sits in the top margin, laid out as a row.
    assert fig.layout.legend.orientation == "h"
    assert fig.layout.legend.y is not None and fig.layout.legend.y >= 1.0
    # The colorbar sits outside the plot area on the right.
    colorbar = fig.data[0].colorbar
    assert colorbar.x is not None and colorbar.x >= 1.0
    assert colorbar.len is not None and colorbar.len < 1.0


def test_a_titled_scene_reserves_room_above_the_plot():
    """The title and the legend row both live in the top margin, so it has to
    be deep enough for the two of them."""
    titled = terrain_scene(_terrain(), _BOUNDS, resolution=6, title="Mountain relay")
    untitled = terrain_scene(_terrain(), _BOUNDS, resolution=6)
    assert titled.layout.margin.t > untitled.layout.margin.t


def test_the_surface_itself_stays_out_of_the_legend():
    """One surface with a colorbar already says "this is the ground"; a
    legend swatch for it would be a second, redundant key."""
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6)
    assert fig.data[0].showlegend is False


def test_write_html_produces_a_self_contained_file(tmp_path):
    """A viewer opens this by double-clicking it, offline — so the plotly
    runtime has to be in the file, not fetched from a CDN."""
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6)
    out = write_html(fig, tmp_path / "scene.html")

    assert out.exists()
    text = out.read_text()
    assert "<div" in text
    # No remotely-sourced script: the runtime is inlined, not linked. (The
    # bundle does mention plotly's topojson CDN as a default config value,
    # but that is only fetched for geo/choropleth traces, which a terrain
    # scene never builds — so the string appearing in the page is not
    # evidence of a network dependency; a remote <script src> would be.)
    assert '<script src="http' not in text
    # The bundled runtime makes this large; a CDN-linked stub would be tiny.
    assert out.stat().st_size > 500_000


def test_written_scene_fills_the_viewport(tmp_path):
    """Plotly's 450px default letterboxes a terrain scene in the middle of an
    otherwise empty page — the opposite of what a dedicated 3D view is for."""
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6)
    out = write_html(fig, tmp_path / "scene.html")
    assert "100vh" in out.read_text()


def test_write_html_creates_missing_parent_directories(tmp_path):
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6)
    out = write_html(fig, tmp_path / "nested" / "dir" / "scene.html")
    assert out.exists()


# --- the timeline scrubber ---------------------------------------------------


def _timeline(samples: int = 4, **kwargs) -> Timeline:
    return Timeline(
        times_s=[float(i) for i in range(samples)],
        positions={"Drone": [Vec3(100.0 * i, 0.0, 300.0) for i in range(samples)]},
        **kwargs,
    )


def _moving(fig) -> list:
    """The scrubbed position markers: labelled in place rather than in the
    legend, so they are exactly the text-marker traces kept out of it."""
    return [
        t
        for t in fig.data
        if t.type == "scatter3d" and t.mode == "markers+text" and t.showlegend is False
    ]


def test_timeline_rejects_a_position_series_of_the_wrong_length():
    with pytest.raises(ValueError):
        Timeline(times_s=[0.0, 1.0], positions={"Drone": [Vec3(0, 0, 0)]})


def test_timeline_rejects_captions_of_the_wrong_length():
    with pytest.raises(ValueError):
        Timeline(
            times_s=[0.0, 1.0],
            positions={"Drone": [Vec3(0, 0, 0), Vec3(1, 1, 1)]},
            captions=["only one"],
        )


def test_timeline_rejects_an_empty_recording():
    with pytest.raises(ValueError):
        Timeline(times_s=[], positions={})


def test_a_scene_without_a_timeline_has_no_scrubber():
    """The controls are only meaningful with frames behind them — an empty
    slider under a static scene is chrome that does nothing."""
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6)
    assert fig.frames == ()
    assert not fig.layout.sliders
    assert not fig.layout.updatemenus


def test_timeline_becomes_one_frame_per_sample():
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    assert len(fig.frames) == 4


def test_scrubber_adds_a_slider_step_per_frame():
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    (slider,) = fig.layout.sliders
    assert len(slider.steps) == len(fig.frames)
    # Each step drives its own frame by name, so dragging the handle is a
    # seek rather than a restart.
    assert [s.args[0][0] for s in slider.steps] == [f.name for f in fig.frames]


def test_every_slider_step_keeps_its_time_label():
    """The readout above the handle shows the *active step's label*, so a
    step left unlabelled to unclutter the track takes the readout with it —
    plotly already thins the printed ticks on its own."""
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    (slider,) = fig.layout.sliders
    assert [s.label for s in slider.steps] == ["0s", "1s", "2s", "3s"]


def test_scrubber_offers_playback_as_well_as_seeking():
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    (menu,) = fig.layout.updatemenus
    assert [b.label for b in menu.buttons] == ["Play", "Pause"]


def test_moving_entity_gets_a_position_marker_starting_at_the_first_sample():
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    (marker,) = _moving(fig)
    assert marker.x == (0.0,)
    assert marker.z == (300.0,)
    assert marker.text == ("Drone",)


def test_each_frame_moves_the_marker_to_that_sample():
    timeline = _timeline(4)
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    marker_index = list(fig.data).index(_moving(fig)[0])

    for i, frame in enumerate(fig.frames):
        # The marker leads the animated traces; whatever else the frame
        # redraws follows it.
        assert frame.traces[0] == marker_index
        assert frame.data[0].x == (timeline.positions["Drone"][i].x,)


def test_position_marker_shares_its_track_colour():
    """The marker is the same entity as the line it runs along, so it must
    not read as a second series."""
    fig = terrain_scene(
        _terrain(),
        _BOUNDS,
        resolution=6,
        tracks={"Drone": [Vec3(0, 0, 300), Vec3(300, 0, 300)]},
        timeline=_timeline(4),
    )
    track = next(t for t in fig.data if t.name == "Drone" and t.mode == "lines")
    (marker,) = _moving(fig)
    assert marker.marker.color == track.line.color


def test_frames_are_decimated_to_the_frame_budget():
    """A run sampled every 50 ms for three minutes is thousands of samples;
    one frame each would bloat the page for motion no one can see."""
    fig = terrain_scene(
        _terrain(), _BOUNDS, resolution=6, timeline=_timeline(500), max_frames=25
    )
    assert len(fig.frames) == 25


def test_decimation_keeps_the_first_and_last_sample():
    """Scrubbing to either end must land on the run's real endpoints, not on
    whatever the sampling stride happened to leave behind."""
    timeline = _timeline(500)
    fig = terrain_scene(
        _terrain(), _BOUNDS, resolution=6, timeline=timeline, max_frames=25
    )
    assert fig.frames[0].data[0].x == (timeline.positions["Drone"][0].x,)
    assert fig.frames[-1].data[0].x == (timeline.positions["Drone"][-1].x,)


def test_captions_ride_along_with_the_frames():
    """The scrubber answers "what was the mesh doing at this instant", which
    positions alone can't say — so the per-sample state travels with it."""
    timeline = _timeline(3, captions=["direct", "via satellite", "no route"])
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)

    assert "direct" in fig.layout.annotations[0].text
    assert [f.layout.annotations[0].text for f in fig.frames] == [
        c for c in timeline.captions
    ]


def test_links_become_one_route_trace_broken_between_segments():
    """A two-hop route is two disjoint segments; drawn as one trace they need
    a `None` break between them or plotly joins the far end back to the near
    one."""
    timeline = _timeline(
        2,
        links=[
            [(Vec3(0, 0, 0), Vec3(0, 0, 500))],
            [(Vec3(0, 0, 0), Vec3(0, 0, 500)), (Vec3(0, 0, 500), Vec3(900, 0, 30))],
        ],
    )
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)

    route = next(t for t in fig.data if t.name == "Active route")
    assert route.mode == "lines"

    two_hop = fig.frames[1].data[-1]
    assert two_hop.z == (0.0, 500.0, None, 500.0, 30.0)


def test_a_sample_with_no_route_draws_no_route_line():
    timeline = _timeline(2, links=[[], [(Vec3(0, 0, 0), Vec3(0, 0, 500))]])
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    assert fig.frames[0].data[-1].x == ()


# --- links that exist vs the one route in use --------------------------------


def _named(fig, name: str):
    return next(t for t in fig.data if t.name == name)


def test_timeline_rejects_usable_links_of_the_wrong_length():
    with pytest.raises(ValueError):
        Timeline(
            times_s=[0.0, 1.0],
            positions={"Drone": [Vec3(0, 0, 0), Vec3(1, 1, 1)]},
            usable_links=[[]],
        )


def test_usable_links_are_drawn_alongside_the_route_in_use():
    """The route is one path through the links that exist, not all of them —
    a scene that draws only the chosen hops says a link is absent when it is
    merely unused, which is a different claim about the mesh."""
    timeline = _timeline(
        2,
        links=[[(Vec3(0, 0, 0), Vec3(100, 0, 300))], []],
        usable_links=[
            [(Vec3(0, 0, 0), Vec3(100, 0, 300)), (Vec3(0, 0, 0), Vec3(0, 0, 900))],
            [(Vec3(0, 0, 0), Vec3(0, 0, 900))],
        ],
    )
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    assert "Usable link" in _trace_names(fig)
    assert "Active route" in _trace_names(fig)


def test_a_usable_link_is_still_drawn_when_no_route_is_in_use():
    """The state this whole distinction exists for: every hop is carrying
    frames and the mesh still has no end-to-end path. Drawing nothing there
    reads as "the satellite is out of contact", which is the opposite of what
    happened."""
    timeline = _timeline(
        2,
        links=[[], []],
        usable_links=[[(Vec3(0, 0, 0), Vec3(0, 0, 900))]] * 2,
    )
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    usable_index = list(fig.data).index(_named(fig, "Usable link"))
    frame_usable = fig.frames[0].data[fig.frames[0].traces.index(usable_index)]
    assert frame_usable.z == (0.0, 900.0)


def test_usable_links_recede_behind_the_route_in_use():
    """Both are drawn at once, so they have to be told apart at a glance —
    the one carrying traffic is the one that reads first."""
    timeline = _timeline(
        2,
        links=[[(Vec3(0, 0, 0), Vec3(100, 0, 300))]] * 2,
        usable_links=[[(Vec3(0, 0, 0), Vec3(0, 0, 900))]] * 2,
    )
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    usable, route = _named(fig, "Usable link"), _named(fig, "Active route")
    assert usable.line.width < route.line.width
    assert usable.opacity < 1.0


def test_usable_links_are_thinned_with_the_rest_of_the_timeline():
    """Every per-sample series rides the same frame budget; one left at full
    length would pair a frame's positions with some other instant's links."""
    timeline = _timeline(500, usable_links=[[(Vec3(0, 0, 0), Vec3(0, 0, 900))]] * 500)
    thinned = timeline.decimated(25)
    assert len(thinned.usable_links) == len(thinned.times_s) == 25


# --- trails ------------------------------------------------------------------


def _trail(fig, label: str):
    """The travelled-so-far line: the entity's second line trace, kept out of
    the legend because it is the same entity as its track."""
    return next(
        t
        for t in fig.data
        if t.name == label and t.mode == "lines" and t.showlegend is False
    )


def test_each_entity_trails_where_it_has_already_been():
    """A track drawn whole cannot say which way along it the node is going —
    and a flight that doubles back on itself covers every dropout twice, once
    in each direction."""
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    trail = _trail(fig, "Drone")
    assert trail.x == (0.0,)


def test_the_trail_grows_a_sample_at_a_time():
    timeline = _timeline(4)
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    trail_index = list(fig.data).index(_trail(fig, "Drone"))

    for i, frame in enumerate(fig.frames):
        drawn = frame.data[frame.traces.index(trail_index)]
        assert drawn.x == tuple(p.x for p in timeline.positions["Drone"][: i + 1])


def test_the_whole_track_recedes_behind_the_trail_when_scrubbed():
    """Scrubbed, the full track stops being the subject and becomes the
    context the trail advances through — otherwise the two overdraw in the
    same colour and neither reads."""
    tracks = {"Drone": [Vec3(100.0 * i, 0.0, 300.0) for i in range(4)]}
    scrubbed = terrain_scene(
        _terrain(), _BOUNDS, resolution=6, tracks=tracks, timeline=_timeline(4)
    )
    static = terrain_scene(_terrain(), _BOUNDS, resolution=6, tracks=tracks)

    # The track proper, not the trail drawn along it: the trail is the one
    # kept out of the legend.
    dimmed = next(
        t for t in scrubbed.data if t.name == "Drone" and t.showlegend is not False
    )
    assert dimmed.opacity < 1.0
    assert next(t for t in static.data if t.name == "Drone").opacity in (None, 1.0)


def test_trails_can_be_left_off():
    """A scene whose entities barely move gains nothing from a trail and
    pays for it in frame size."""
    fig = terrain_scene(
        _terrain(), _BOUNDS, resolution=6, timeline=_timeline(4), trails=False
    )
    with pytest.raises(StopIteration):
        _trail(fig, "Drone")


def test_a_wrapped_title_reserves_room_for_every_line():
    """plotly renders a title as written and lets an over-long one run off
    the edge, so a caller that wraps it has to be given the space — otherwise
    the extra lines land on the legend."""
    one = terrain_scene(_terrain(), _BOUNDS, resolution=6, title="Scene")
    two = terrain_scene(_terrain(), _BOUNDS, resolution=6, title="Scene<br>and why")
    assert two.layout.margin.t > one.layout.margin.t


def test_a_scrubbed_scene_reserves_room_below_the_plot():
    """The slider and its buttons live in the bottom margin; without one they
    are drawn over the scene."""
    scrubbed = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    static = terrain_scene(_terrain(), _BOUNDS, resolution=6)
    assert scrubbed.layout.margin.b > static.layout.margin.b


def test_written_scrubbed_scene_carries_its_frames_into_the_file(tmp_path):
    """The scrubber is only real in the written page if the frames made it
    across: plotly emits them as a separate `addFrames` call after the plot,
    so a page that lost them still renders — as a scene with a dead slider."""
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    out = write_html(fig, tmp_path / "scene.html")
    assert "addFrames" in out.read_text()


# --- terrain-free scenes -----------------------------------------------------


def test_track_scene_has_no_ground_surface():
    """Not every scenario has terrain — a satellite pass over flat ground is
    tracks in empty space, and inventing a surface for it would draw a
    landscape the model never had."""
    fig = track_scene(tracks={"Drone": [Vec3(0, 0, 30), Vec3(2000, 0, 30)]})
    assert [t.type for t in fig.data] == ["scatter3d"]


def test_track_scene_needs_something_to_show():
    with pytest.raises(ValueError):
        track_scene()


def test_track_scene_sizes_its_box_to_the_data():
    """With no bounds to be handed, the extent of everything drawn is the
    only thing that can set the aspect — otherwise a 4 km orbit and a 30 m
    cruise altitude share one cube."""
    fig = track_scene(
        tracks={"Drone": [Vec3(0, 0, 0), Vec3(4000, 0, 0)]},
        sites={"GCS": Vec3(0, 2000, 0)},
    )
    aspect = fig.layout.scene.aspectratio
    assert aspect.x == pytest.approx(1.0)
    assert aspect.y == pytest.approx(0.5)


def test_track_scene_takes_a_scrubber_too():
    fig = track_scene(
        tracks={"Drone": [Vec3(0, 0, 30), Vec3(2000, 0, 30)]},
        timeline=_timeline(4),
    )
    assert len(fig.frames) == 4
    assert fig.layout.sliders


def test_sites_can_be_named_for_what_they_are():
    """ "Relay site" is the mountain scenario's word; a ground control station
    is not one, and the legend should not claim it is."""
    fig = track_scene(sites={"GCSA": Vec3(0, 0, 0)}, site_label="Ground station")
    assert [t.name for t in fig.data] == ["Ground station"]


# --- reading a long run ------------------------------------------------------


def _slider_labels(fig) -> list[str]:
    (slider,) = fig.layout.sliders
    return [s.label for s in slider.steps]


def test_a_short_run_is_labelled_in_seconds():
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=_timeline(4))
    assert _slider_labels(fig) == ["0s", "1s", "2s", "3s"]


def test_a_long_run_is_labelled_in_a_unit_a_reader_can_hold():
    """A nine-hour orbital run labelled in seconds gives a slider reading
    "31680s", which no one can place in the flight."""
    timeline = Timeline(
        times_s=[i * 275.0 for i in range(120)],
        positions={"Sat": [Vec3(i, 0, 0) for i in range(120)]},
    )
    fig = terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    assert not any(label.endswith("s") for label in _slider_labels(fig))


def test_one_unit_is_chosen_for_the_whole_track():
    """Mixed units across the steps would make the readout jump scale as the
    handle moves."""
    timeline = Timeline(
        times_s=[i * 275.0 for i in range(120)],
        positions={"Sat": [Vec3(i, 0, 0) for i in range(120)]},
    )
    labels = _slider_labels(
        terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    )
    assert len({label[-1] for label in labels}) == 1


def test_no_two_neighbouring_steps_share_a_label():
    """The readout shows the active step's label, so two adjacent steps
    reading the same thing makes a working scrubber look stuck — which is
    exactly what a six-minute run did when the unit came from the total span
    ("0m 0m 0m 1m 1m 1m") rather than from the step between samples."""
    timeline = Timeline(
        times_s=[i * 384.0 / 119 for i in range(120)],
        positions={"Drone": [Vec3(i, 0, 0) for i in range(120)]},
    )
    labels = _slider_labels(
        terrain_scene(_terrain(), _BOUNDS, resolution=6, timeline=timeline)
    )
    assert all(a != b for a, b in itertools.pairwise(labels))


def test_a_terrain_free_box_takes_its_height_from_the_data():
    """`VERTICAL_EXAGGERATION` exists because terrain is far wider than it is
    tall. An orbit is not: squashing 14,000 km of vertical extent into a third
    of the box draws the planet-crossing dive as a shallow dip."""
    tall = track_scene(
        tracks={"Sat": [Vec3(-1000, 0, -1000), Vec3(1000, 0, 1000)]},
    )
    assert tall.layout.scene.aspectratio.z == pytest.approx(1.0, rel=0.01)


def test_a_flat_terrain_free_scene_still_gets_a_readable_height():
    """Data with no vertical extent at all must not collapse the box to a
    zero-height sliver."""
    flat = track_scene(tracks={"Track": [Vec3(0, 0, 5), Vec3(1000, 500, 5)]})
    assert flat.layout.scene.aspectratio.z > 0


def test_the_scrub_camera_pulls_back_for_a_box_that_is_not_cube_ish():
    """`SCRUB_CAMERA` is framed for a roughly cubic box. An orbital scene is
    1 : 2.7 : 2.8, and holding the camera at the same distance crops it to a
    fragment — the eye has to move out with the box's own diagonal."""
    flat = track_scene(
        tracks={"T": [Vec3(-1000, -1000, 0), Vec3(1000, 1000, 10)]},
        timeline=Timeline(
            times_s=[0.0, 1.0], positions={"T": [Vec3(0, 0, 0), Vec3(1, 1, 1)]}
        ),
    )
    tall = track_scene(
        tracks={"T": [Vec3(-1000, -8000, -8000), Vec3(1000, 8000, 8000)]},
        timeline=Timeline(
            times_s=[0.0, 1.0], positions={"T": [Vec3(0, 0, 0), Vec3(1, 1, 1)]}
        ),
    )
    assert tall.layout.scene.camera.eye.x > 2 * flat.layout.scene.camera.eye.x
