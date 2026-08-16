"""Rotatable, scrubbable 3D scenes, written to self-contained HTML.

Terrain is the case where a static projection actively hides the answer: a
route through a valley disappears behind the ridge beside it, and which ridge
blocks which link depends entirely on the angle you happen to have picked.
`plotting.terrain_contour` solves that by flattening to a plan view; this
module solves it the other way, by handing the camera to the reader.

Time is the second thing a static render flattens. A track drawn whole says
where a node went but not *when* it was where, so a dropout marked on the
line can't be lined up against the position of everything else at that
instant. `Timeline` restores that axis: it turns a recorded run into frames
under a slider, so the scene can be scrubbed sample by sample — with the
moving nodes at their positions for that instant, the route they were
actually using drawn between them, and the run's own state caption alongside.

Backed by plotly (the `interactive` extra) rather than matplotlib because the
output is a file, not a window: `write_html` bundles the runtime into the
page, so it opens by double-click, works offline, and can be sent to someone
who has no Python at all. For a live window in an interactive session
instead, matplotlib's own GUI backend already rotates — see
`sim/README.sim.md`.

Colors come from `palette`, shared verbatim with the static charts, so the
two renderings of the same scenario agree on what every entity looks like.
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .mobility import Vec3
from .palette import PALETTE, TERRAIN_RAMP, Palette
from .terrain import Bounds, Terrain

if TYPE_CHECKING:
    from plotly.graph_objects import Figure

VERTICAL_EXAGGERATION = 0.35
"""Height of the z axis relative to the scene's x extent.

Real terrain is far wider than it is tall — this scenario's range spans 8 km
horizontally and 1.5 km vertically — so a true-to-scale box renders as an
almost flat plate in which nothing blocks anything. This is the conventional
relief exaggeration: read heights off the axis, not off the picture.
"""

DEFAULT_MAX_FRAMES = 120
"""How many frames a scrubber gets, however many samples the run has.

A run recorded every 50 ms for three minutes is ~4000 samples; a frame each
would multiply the page size by the number of moving entities for motion no
one can resolve by dragging a slider. The frames are thinned to this many,
evenly, keeping both endpoints.
"""

FRAME_DURATION_MS = 80
"""Playback pace of the Play button. Not real time — a run's own sample
interval varies by scenario and a faithful replay of a five-minute flight is
five minutes of watching — just fast enough to read as motion."""

SCRUB_CAMERA = {"eye": {"x": 1.05, "y": -1.15, "z": 0.62}}
"""Where the camera starts on a scrubbed scene, framed for a roughly cubic box.

Closer in than plotly's default (which frames the box from far enough away
to leave most of the page empty) and lower, since what a scrubber is watched
for — a link forming or breaking between two moving nodes — happens across
the ground plane rather than above it. Still a starting point only: the
scene is orbitable from the first frame.

Scaled by `_scrub_camera` for boxes that are not cube-ish, which is most of
them once the data sets the shape.
"""

REFERENCE_DIAGONAL = math.sqrt(1 + 1 + VERTICAL_EXAGGERATION**2)
"""The box `SCRUB_CAMERA`'s distance was chosen against — a terrain scene,
square in plan and flattened in height."""


def _scrub_camera(y_ratio: float, z_ratio: float) -> dict[str, Any]:
    """`SCRUB_CAMERA` moved out to suit a box of this shape.

    The eye is in units of the box, not of the data, so a scene that is nearly
    three times as deep and as tall as it is wide — an orbit, once the height
    comes from the data — puts most of itself outside a frame that was chosen
    for a cube. Scaling the eye by the box's own diagonal keeps the whole
    thing on screen at any shape, and leaves a cube-ish box exactly where it
    was.
    """
    diagonal = math.sqrt(1 + y_ratio**2 + z_ratio**2)
    scale = max(1.0, diagonal / REFERENCE_DIAGONAL)
    eye = SCRUB_CAMERA["eye"]
    return {"eye": {axis: value * scale for axis, value in eye.items()}}


@dataclasses.dataclass(frozen=True)
class Timeline:
    """A recorded run's time axis, as the scrubber needs it.

    - `times_s` is the sample grid, and sets the length everything else must
      match.
    - `positions` are the moving entities, one position per sample. A label
      shared with a track in the same scene is drawn in that track's colour,
      so the marker reads as the same entity rather than a new series.
    - `captions` is the run's state at each sample, in words — "via
      satellite", "no route". Positions alone can't say what the mesh was
      doing, which is usually the reason to scrub at all.
    - `links` are the segments carrying traffic at each sample: one
      `(from, to)` pair per hop, so a two-hop relay is two pairs and a
      dropout is an empty list.
    - `usable_links` are the segments that *could* carry traffic at each
      sample, whether or not the route uses them. The route is one path
      through the mesh, not the mesh: a scene drawing only `links` says a
      relay is out of contact whenever it happens to be unused, and — worse —
      draws nothing at all during a dropout, when the interesting question is
      precisely which hops were alive while there was still no path.

    Every sequence is validated against `times_s` on construction: a
    silently short column would otherwise show up as a scene that stops
    moving partway along the slider, which reads as a simulation result
    rather than as a bug.
    """

    times_s: Sequence[float]
    positions: Mapping[str, Sequence[Vec3]]
    captions: Sequence[str] | None = None
    links: Sequence[Sequence[tuple[Vec3, Vec3]]] | None = None
    usable_links: Sequence[Sequence[tuple[Vec3, Vec3]]] | None = None

    def __post_init__(self) -> None:
        if not self.times_s:
            raise ValueError("a timeline needs at least one sample")
        expected = len(self.times_s)
        for label, series in self.positions.items():
            if len(series) != expected:
                raise ValueError(
                    f"timeline entity {label!r} has {len(series)} positions "
                    f"for {expected} samples"
                )
        for name, series in (
            ("captions", self.captions),
            ("links", self.links),
            ("usable_links", self.usable_links),
        ):
            if series is not None and len(series) != expected:
                raise ValueError(
                    f"timeline {name} has {len(series)} entries for {expected} samples"
                )

    def __len__(self) -> int:
        return len(self.times_s)

    def decimated(self, max_frames: int) -> Timeline:
        """This timeline thinned to at most `max_frames` samples, evenly
        spaced and keeping the first and last — so scrubbing to either end
        lands on the run's real endpoints rather than wherever the stride
        stopped."""
        if max_frames < 2:
            raise ValueError(f"max_frames must be at least 2, got {max_frames!r}")
        total = len(self)
        if total <= max_frames:
            return self
        keep = sorted(
            {round(i * (total - 1) / (max_frames - 1)) for i in range(max_frames)}
        )
        return Timeline(
            times_s=[self.times_s[i] for i in keep],
            positions={
                label: [series[i] for i in keep]
                for label, series in self.positions.items()
            },
            captions=None
            if self.captions is None
            else [self.captions[i] for i in keep],
            links=None if self.links is None else [self.links[i] for i in keep],
            usable_links=None
            if self.usable_links is None
            else [self.usable_links[i] for i in keep],
        )


def _colorscale(ramp: Sequence[str]) -> list[list[Any]]:
    """`ramp` as plotly's normalised [position, color] colorscale form."""
    if len(ramp) < 2:
        raise ValueError(f"a colorscale needs at least two stops, got {len(ramp)}")
    return [[i / (len(ramp) - 1), color] for i, color in enumerate(ramp)]


TRACK_CONTEXT_OPACITY = 0.3
"""How far the full track fades once a scrubber advances a trail along it.

Unscrubbed, the track is the subject. Scrubbed, it is the route *not yet
flown* — context behind the trail, which is drawn along it in the same hue
and would otherwise be indistinguishable from it.
"""

USABLE_LINK_OPACITY = 0.45
"""How far a link that exists but carries no traffic recedes behind the one
that does. Both are drawn at the same instant, so the distinction has to
survive a glance."""


def _track_traces(
    tracks: Mapping[str, Sequence[Vec3]], palette: Palette, *, dimmed: bool
) -> tuple[list[Any], dict[str, str]]:
    """The line trace per named track, plus the colour each was given — so a
    scrubbed position marker can be drawn in its own track's hue."""
    import plotly.graph_objects as go

    traces: list[Any] = []
    colors: dict[str, str] = {}
    for i, (label, positions) in enumerate(tracks.items()):
        color = palette.series[i % len(palette.series)]
        colors[label] = color
        positions = list(positions)
        if not positions:
            continue
        traces.append(
            go.Scatter3d(
                x=[p.x for p in positions],
                y=[p.y for p in positions],
                z=[p.z for p in positions],
                mode="lines",
                name=label,
                opacity=TRACK_CONTEXT_OPACITY if dimmed else 1.0,
                line={"color": color, "width": 3 if dimmed else 5},
                hovertemplate=(
                    f"{label}<br>x %{{x:.0f}}m<br>y %{{y:.0f}}m"
                    "<br>altitude %{z:.0f}m<extra></extra>"
                ),
            )
        )
    return traces, colors


def _marker_traces(
    markers: Mapping[str, Sequence[Vec3]], palette: Palette
) -> list[Any]:
    import plotly.graph_objects as go

    traces: list[Any] = []
    for label, positions in markers.items():
        positions = list(positions)
        if not positions:
            continue
        traces.append(
            go.Scatter3d(
                x=[p.x for p in positions],
                y=[p.y for p in positions],
                z=[p.z for p in positions],
                mode="markers",
                name=label,
                # Red: these call out a loss of service, not another series.
                marker={"color": palette.series[5], "size": 3},
                hovertemplate=f"{label}<br>altitude %{{z:.0f}}m<extra></extra>",
            )
        )
    return traces


def _site_trace(sites: Mapping[str, Vec3], label: str, palette: Palette) -> Any:
    """Fixed installations as one labelled marker trace: they are all the
    same *kind* of thing, so they share a hue and are told apart by their
    labels rather than by a legend of near-identical entries."""
    import plotly.graph_objects as go

    names = list(sites)
    return go.Scatter3d(
        x=[sites[n].x for n in names],
        y=[sites[n].y for n in names],
        z=[sites[n].z for n in names],
        mode="markers+text",
        name=label,
        text=names,
        textposition="top center",
        textfont={"color": palette.ink_primary, "size": 11},
        marker={"color": palette.series[3], "size": 6, "symbol": "diamond"},
        hovertemplate="%{text}<br>elevation %{z:.0f}m<extra></extra>",
    )


def _caption_annotation(text: str, palette: Palette) -> dict[str, Any]:
    """The run's state at the scrubbed instant, parked in the scene's
    top-left corner — under the legend row, and well clear of the slider in
    the bottom margin."""
    return {
        "text": text,
        "xref": "paper",
        "yref": "paper",
        "x": 0,
        "xanchor": "left",
        "y": 1,
        "yanchor": "top",
        "showarrow": False,
        "align": "left",
        "font": {"color": palette.ink_primary, "size": 13},
    }


def _position_marker(label: str, at: Vec3, color: str) -> Any:
    """One moving entity at one instant. Kept out of the legend: it is the
    same entity as its track, labelled in place like a site rather than
    claiming a second legend entry."""
    import plotly.graph_objects as go

    return go.Scatter3d(
        x=[at.x],
        y=[at.y],
        z=[at.z],
        mode="markers+text",
        name=label,
        text=[label],
        textposition="top center",
        showlegend=False,
        textfont={"color": color, "size": 11},
        marker={"color": color, "size": 7, "line": {"color": "#ffffff", "width": 1}},
        hovertemplate=f"{label}<br>x %{{x:.0f}}m<br>y %{{y:.0f}}m<br>altitude %{{z:.0f}}m<extra></extra>",
    )


def _trail_trace(label: str, flown: Sequence[Vec3], color: str) -> Any:
    """Where an entity has already been, up to the scrubbed instant.

    The full track says where a node goes but not which way along it it is
    going, and a flight that doubles back covers every event on it twice —
    once outbound, once inbound — with nothing to tell the two apart. The
    trail is that missing arrow: it advances with the slider, so the direction
    of travel is in the picture rather than only in the caption.

    Out of the legend: the track above it already names this entity.
    """
    import plotly.graph_objects as go

    flown = list(flown)
    return go.Scatter3d(
        x=[p.x for p in flown],
        y=[p.y for p in flown],
        z=[p.z for p in flown],
        mode="lines",
        name=label,
        showlegend=False,
        line={"color": color, "width": 5},
        hoverinfo="skip",
    )


def _segments_trace(
    segments: Sequence[tuple[Vec3, Vec3]],
    *,
    name: str,
    color: str,
    width: int,
    dash: str,
    opacity: float,
) -> Any:
    """A set of hops at one instant, as a single broken line.

    Each segment is separated by a `None` vertex: a two-hop relay is two
    disjoint links, and without the break plotly would join the far end of
    one back to the near end of the next, drawing a path that does not
    exist.
    """
    import plotly.graph_objects as go

    xs: list[float | None] = []
    ys: list[float | None] = []
    zs: list[float | None] = []
    for i, (start, end) in enumerate(segments):
        if i:
            xs.append(None)
            ys.append(None)
            zs.append(None)
        xs += [start.x, end.x]
        ys += [start.y, end.y]
        zs += [start.z, end.z]

    return go.Scatter3d(
        x=xs,
        y=ys,
        z=zs,
        mode="lines",
        name=name,
        opacity=opacity,
        line={"color": color, "width": width, "dash": dash},
        hoverinfo="skip",
    )


def _route_trace(segments: Sequence[tuple[Vec3, Vec3]], palette: Palette) -> Any:
    """The hops actually carrying traffic at one instant."""
    return _segments_trace(
        segments,
        name="Active route",
        color=palette.series[7],
        width=5,
        dash="dot",
        opacity=1.0,
    )


def _usable_link_trace(segments: Sequence[tuple[Vec3, Vec3]], palette: Palette) -> Any:
    """The hops that would carry traffic if the route asked them to.

    Drawn thinner and dimmer than the route on purpose: the point is that the
    link is *there*, not that it is in use — and during a dropout it is the
    only thing drawn, which is the whole reason it exists.
    """
    return _segments_trace(
        segments,
        name="Usable link",
        color=palette.ink_muted,
        width=2,
        dash="solid",
        opacity=USABLE_LINK_OPACITY,
    )


def _time_labels(times_s: Sequence[float]) -> list[str]:
    """Slider tick labels in one unit sized to the run.

    The unit comes from the *step* between samples, not the total span. Span
    alone picks a unit the run is long enough to justify and then rounds every
    step into it — a six-minute transit sliced 120 ways reads "0m 0m 0m 1m 1m
    1m", which makes a working scrubber look broken. Sizing by the step
    guarantees neighbouring labels differ, which is the only property the
    readout above the handle actually needs.

    Seconds stay seconds for anything short; a nine-hour orbital run reads in
    minutes rather than "31680s".
    """
    if len(times_s) < 2:
        return [f"{t:.0f}s" for t in times_s]
    step = (max(times_s) - min(times_s)) / (len(times_s) - 1)
    # The largest unit this step is still resolvable in.
    for suffix, size in (("h", 3600.0), ("m", 60.0)):
        if step >= 0.1 * size:
            places = 0 if step >= size else 1
            return [f"{t / size:.{places}f}{suffix}" for t in times_s]
    return [f"{t:.0f}s" for t in times_s]


def _add_scrubber(
    figure: Figure,
    timeline: Timeline,
    colors: Mapping[str, str],
    palette: Palette,
    *,
    trails: bool,
) -> None:
    """Append the scrubbed traces to `figure`, build a frame per sample, and
    put the slider and playback controls under it.

    Frames address traces by index, so the moving traces are appended last
    and their indices captured here — anything added to the figure afterwards
    would shift them out from under the animation.
    """
    import plotly.graph_objects as go

    labels = list(timeline.positions)
    default = {
        label: colors.get(label, palette.series[i % len(palette.series)])
        for i, label in enumerate(labels)
    }

    def _animated(i: int) -> list[Any]:
        """Every trace the frame at sample `i` redraws, in the order their
        indices were captured below."""
        data = [
            _position_marker(label, timeline.positions[label][i], default[label])
            for label in labels
        ]
        if trails:
            data += [
                _trail_trace(label, timeline.positions[label][: i + 1], default[label])
                for label in labels
            ]
        if timeline.usable_links is not None:
            data.append(_usable_link_trace(timeline.usable_links[i], palette))
        if timeline.links is not None:
            data.append(_route_trace(timeline.links[i], palette))
        return data

    indices: list[int] = []
    for trace in _animated(0):
        indices.append(len(figure.data))
        figure.add_trace(trace)

    frames = []
    for i, t_s in enumerate(timeline.times_s):
        data = _animated(i)
        layout = (
            go.Layout(annotations=[_caption_annotation(timeline.captions[i], palette)])
            if timeline.captions is not None
            else None
        )
        frames.append(
            go.Frame(name=f"{t_s:.3f}", data=data, traces=indices, layout=layout)
        )
    figure.frames = frames

    labels_by_step = _time_labels(timeline.times_s)
    steps = [
        {
            # Every step keeps its time, however crowded the track gets:
            # plotly thins the printed ticks itself, and the readout above
            # the handle shows the *active step's label* — so blanking labels
            # to unclutter the track would blank the readout with them.
            "label": labels_by_step[i],
            "method": "animate",
            # Named-frame seek rather than a replay from the start: dragging
            # the handle has to land on that instant, not run there.
            "args": [
                [frame.name],
                {
                    "mode": "immediate",
                    "frame": {"duration": 0, "redraw": True},
                    "transition": {"duration": 0},
                },
            ],
        }
        for i, frame in enumerate(frames)
    ]

    figure.update_layout(
        annotations=[_caption_annotation(timeline.captions[0], palette)]
        if timeline.captions is not None
        else [],
        scene_camera=_scrub_camera(
            figure.layout.scene.aspectratio.y or 1.0,
            figure.layout.scene.aspectratio.z or VERTICAL_EXAGGERATION,
        ),
        sliders=[
            {
                "active": 0,
                "steps": steps,
                "x": 0.08,
                "len": 0.9,
                "y": 0,
                "yanchor": "top",
                "pad": {"t": 34, "b": 10},
                "currentvalue": {
                    "prefix": "t = ",
                    "xanchor": "left",
                    "font": {"color": palette.ink_secondary, "size": 13},
                },
                "font": {"color": palette.ink_muted, "size": 10},
                "bgcolor": palette.gridline,
                "bordercolor": palette.axis,
                "activebgcolor": palette.series[0],
                "tickcolor": palette.axis,
                "transition": {"duration": 0},
            }
        ],
        updatemenus=[
            {
                "type": "buttons",
                "direction": "left",
                "showactive": False,
                "x": 0.06,
                "xanchor": "right",
                "y": 0,
                "yanchor": "top",
                "pad": {"t": 40, "r": 8},
                "bgcolor": palette.surface,
                "bordercolor": palette.axis,
                "font": {"color": palette.ink_secondary, "size": 11},
                "buttons": [
                    {
                        "label": "Play",
                        "method": "animate",
                        "args": [
                            None,
                            {
                                "mode": "immediate",
                                "fromcurrent": True,
                                "frame": {
                                    "duration": FRAME_DURATION_MS,
                                    "redraw": True,
                                },
                                "transition": {"duration": 0},
                            },
                        ],
                    },
                    {
                        "label": "Pause",
                        "method": "animate",
                        "args": [
                            [None],
                            {
                                "mode": "immediate",
                                "frame": {"duration": 0, "redraw": False},
                                "transition": {"duration": 0},
                            },
                        ],
                    },
                ],
            }
        ],
    )


def _apply_layout(
    figure: Figure,
    bounds: Bounds,
    *,
    title: str | None,
    scrubbed: bool,
    palette: Palette,
    reserve_colorbar: bool,
    z_ratio: float = VERTICAL_EXAGGERATION,
) -> None:
    figure.update_layout(
        title={"text": title, "x": 0, "xanchor": "left", "y": 0.97, "yanchor": "top"}
        if title
        else None,
        paper_bgcolor=palette.surface,
        font={"color": palette.ink_secondary},
        # The top margin holds the title and, under it, the legend row; the
        # right margin holds the colorbar, and the bottom one the scrubber.
        # All have to be reserved explicitly, or the scene expands under
        # them. A title is never wrapped for us — plotly renders it as one
        # line per `<br>` and lets the rest run off the edge — so each break
        # the caller wrote has to be paid for here.
        margin={
            "l": 0,
            "r": 80 if reserve_colorbar else 20,
            "t": 90 + 22 * title.count("<br>") if title else 50,
            "b": 90 if scrubbed else 0,
        },
        # A row in the top margin, left-aligned under the title — the one
        # place it cannot collide with the colorbar on the right.
        legend={
            "orientation": "h",
            "x": 0,
            "xanchor": "left",
            "y": 1.0,
            "yanchor": "bottom",
            "bgcolor": palette.surface,
            "borderwidth": 0,
        },
        scene={
            "xaxis": {"title": {"text": "x (m)"}, "backgroundcolor": palette.surface},
            "yaxis": {"title": {"text": "y (m)"}, "backgroundcolor": palette.surface},
            "zaxis": {
                "title": {"text": "elevation (m)"},
                "backgroundcolor": palette.surface,
            },
            # Orbit rather than plotly's default turntable: terrain is looked
            # at from above as often as from the side, and turntable pins the
            # up axis in a way that makes a top-down look awkward.
            "dragmode": "orbit",
            "aspectmode": "manual",
            "aspectratio": {
                "x": 1.0,
                "y": bounds.depth_m / bounds.width_m if bounds.width_m else 1.0,
                "z": z_ratio,
            },
        },
    )


def _entity_traces(
    figure: Figure,
    tracks: Mapping[str, Sequence[Vec3]] | None,
    markers: Mapping[str, Sequence[Vec3]] | None,
    sites: Mapping[str, Vec3] | None,
    site_label: str,
    palette: Palette,
    dimmed: bool,
) -> dict[str, str]:
    """Add the static entity traces every scene shares, and report the colour
    each track was given."""
    track_traces, colors = _track_traces(dict(tracks or {}), palette, dimmed=dimmed)
    for trace in track_traces:
        figure.add_trace(trace)
    for trace in _marker_traces(dict(markers or {}), palette):
        figure.add_trace(trace)
    if sites:
        figure.add_trace(_site_trace(sites, site_label, palette))
    return colors


MIN_Z_RATIO = 0.05
"""Floor on a data-shaped box's height, so a scene whose contents are exactly
flat still gets a visible z axis rather than collapsing to a sliver."""


def _data_points(
    tracks: Mapping[str, Sequence[Vec3]] | None,
    markers: Mapping[str, Sequence[Vec3]] | None,
    sites: Mapping[str, Vec3] | None,
    timeline: Timeline | None,
) -> list[Vec3]:
    """Every point the scene draws, for sizing the box around it.

    Only needed where there is no terrain to take bounds from: without a
    surface, the data itself is the only thing that can set the box, and
    letting plotly cube it would put a 4 km orbit and a 30 m cruise altitude
    on the same scale.
    """
    points: list[Vec3] = []
    for group in (tracks, markers):
        for series in (group or {}).values():
            points.extend(series)
    points.extend((sites or {}).values())
    if timeline is not None:
        for series in timeline.positions.values():
            points.extend(series)
        for per_sample in (timeline.links, timeline.usable_links):
            for segments in per_sample or ():
                for start, end in segments:
                    points.extend((start, end))
    if not points:
        raise ValueError("a scene needs at least one track, marker, site or timeline")
    return points


def _data_bounds(points: Sequence[Vec3]) -> Bounds:
    return Bounds(
        min_x=min(p.x for p in points),
        min_y=min(p.y for p in points),
        max_x=max(p.x for p in points),
        max_y=max(p.y for p in points),
    )


def _data_z_ratio(points: Sequence[Vec3], bounds: Bounds) -> float:
    """The box's height, taken from the data rather than assumed.

    `VERTICAL_EXAGGERATION` is a terrain convention: real relief is far wider
    than it is tall, so a true-to-scale box renders as a flat plate. Nothing
    guarantees that off the ground — an orbit's 14,000 km plunge round the
    back of the planet is as tall as the scene is wide, and squashing it into
    a third of the box draws the defining feature of the geometry as a shallow
    dip.
    """
    if not bounds.width_m:
        return VERTICAL_EXAGGERATION
    height = max(p.z for p in points) - min(p.z for p in points)
    return max(MIN_Z_RATIO, height / bounds.width_m)


def terrain_scene(
    terrain: Terrain,
    bounds: Bounds,
    *,
    tracks: Mapping[str, Sequence[Vec3]] | None = None,
    markers: Mapping[str, Sequence[Vec3]] | None = None,
    sites: Mapping[str, Vec3] | None = None,
    timeline: Timeline | None = None,
    max_frames: int = DEFAULT_MAX_FRAMES,
    trails: bool = True,
    resolution: int = 90,
    title: str | None = None,
    site_label: str = "Relay site",
    palette: Palette = PALETTE,
    ramp: Sequence[str] = TERRAIN_RAMP,
) -> Figure:
    """Build a rotatable scene of `terrain` over `bounds`.

    - `tracks` are moving nodes' paths, one named line each, coloured from
      the categorical palette in iteration order.
    - `markers` are point sets called out against those paths — the natural
      use being the samples where a drone had no route, so the gaps are
      visible on the track itself rather than only on a timeline.
    - `sites` are fixed installations, drawn as one labelled marker trace and
      named in the legend by `site_label`.
    - `timeline`, when given, adds the scrubber: a slider and playback
      controls stepping the scene through the run, thinned to `max_frames`.
      `trails` draws each moving entity's travelled-so-far path along its
      track, which is what tells an out-and-back leg from its return; turn it
      off for a scene whose entities barely move.

    An empty track or marker set contributes no trace, so a caller can pass
    its signals unconditionally without special-casing the runs where one of
    them never occurred.
    """
    import plotly.graph_objects as go

    if resolution < 2:
        raise ValueError(f"resolution must be at least 2, got {resolution!r}")

    xs = [
        bounds.min_x + bounds.width_m * i / (resolution - 1) for i in range(resolution)
    ]
    ys = [
        bounds.min_y + bounds.depth_m * j / (resolution - 1) for j in range(resolution)
    ]
    grid_z = [[terrain.elevation(x, y) for x in xs] for y in ys]

    figure = go.Figure(
        go.Surface(
            x=xs,
            y=ys,
            z=grid_z,
            colorscale=_colorscale(ramp),
            # Parked on the right, clear of the plot area and clear of the
            # legend (see the layout below) — plotly's defaults put both in
            # the same top-right corner, where they overlap into a pile.
            colorbar={
                "title": {"text": "Ground (m)", "side": "right"},
                "thickness": 14,
                "len": 0.72,
                "x": 1.02,
                "xanchor": "left",
                "y": 0.5,
                "yanchor": "middle",
            },
            # The colorbar already says "this is the ground"; a legend swatch
            # for the same trace would be a second, redundant key.
            showlegend=False,
            hovertemplate="x %{x:.0f}m<br>y %{y:.0f}m<br>ground %{z:.0f}m<extra></extra>",
        )
    )

    colors = _entity_traces(
        figure, tracks, markers, sites, site_label, palette, dimmed=timeline is not None
    )
    _apply_layout(
        figure,
        bounds,
        title=title,
        scrubbed=timeline is not None,
        palette=palette,
        reserve_colorbar=True,
    )
    if timeline is not None:
        _add_scrubber(
            figure, timeline.decimated(max_frames), colors, palette, trails=trails
        )
    return figure


def track_scene(
    *,
    tracks: Mapping[str, Sequence[Vec3]] | None = None,
    markers: Mapping[str, Sequence[Vec3]] | None = None,
    sites: Mapping[str, Vec3] | None = None,
    timeline: Timeline | None = None,
    max_frames: int = DEFAULT_MAX_FRAMES,
    trails: bool = True,
    title: str | None = None,
    site_label: str = "Site",
    palette: Palette = PALETTE,
) -> Figure:
    """The same scene without a ground surface, for a scenario that has no
    terrain model — a satellite pass over flat ground is tracks in empty
    space, and inventing a surface for it would draw a landscape the model
    never had.

    Takes the same entities as `terrain_scene`, and the same `timeline`
    scrubber. With no `bounds` to be handed, the box is sized to the extent
    of everything drawn.
    """
    import plotly.graph_objects as go

    figure = go.Figure()
    colors = _entity_traces(
        figure, tracks, markers, sites, site_label, palette, dimmed=timeline is not None
    )
    points = _data_points(tracks, markers, sites, timeline)
    bounds = _data_bounds(points)
    _apply_layout(
        figure,
        bounds,
        title=title,
        scrubbed=timeline is not None,
        palette=palette,
        reserve_colorbar=False,
        z_ratio=_data_z_ratio(points, bounds),
    )
    if timeline is not None:
        _add_scrubber(
            figure, timeline.decimated(max_frames), colors, palette, trails=trails
        )
    return figure


def write_html(figure: Figure, out_path: Path, *, include_runtime: bool = True) -> Path:
    """Write `figure` to `out_path` and return that path.

    `include_runtime` bundles plotly's JavaScript into the page (the default),
    which is what makes the result openable offline by double-click at the
    cost of a few MB. Set it `False` only when embedding many scenes in one
    place that loads the runtime itself.

    The scene is sized to the viewport rather than plotly's fixed 450px
    default: this is a whole page holding one 3D view, and a terrain scene
    shown in a letterbox is exactly the problem the interactive render exists
    to solve.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    figure.write_html(
        out_path,
        include_plotlyjs=bool(include_runtime),
        default_width="100%",
        default_height="100vh",
    )
    return out_path
