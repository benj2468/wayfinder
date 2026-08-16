"""One self-contained HTML page for a whole parameter sweep.

A sweep produces N runs that differ in one controlled way, and the question
is always the same: *which setting won, and what did the losers look like?*
Answering that from N separate PNG files and a column of console output means
holding the comparison in your head. This module puts it on one page — a
ranked outcome list first, then every run with the parameters that produced
it and the charts it produced — and writes the whole thing, images and all,
into a single file that can be copied elsewhere and opened offline.

Design notes, since this is a page and not a chart:

- The palette is `palette.PALETTE`, unchanged. The page is a *frame* for
  figures that already carry a validated palette; inventing a second one
  would have the chrome competing with its own content. The page surface is
  the chart surface, so a figure sits on the page with no visible seam.
- Light only, deliberately. Every panel is a light-surface raster, and a dark
  page would leave them glaring out of it like windows.
- No webfonts: the page must render identically with no network, so the
  personality comes from scale and from one rule held absolutely — every
  number on the page is monospace, so figures line up in columns and read as
  data rather than prose.
- Rank is encoded twice: as a numeral, and as a chip filled from the same
  terrain ramp the maps use — highest ground is the run that won. That is
  the page's one ornament, and it carries information.

`ImagePanel` needs nothing beyond the standard library; `ScenePanel` needs
plotly (the `interactive` extra), and only when one is actually used.
"""

from __future__ import annotations

import base64
import dataclasses
import html as html_lib
import itertools
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from .palette import PALETTE, TERRAIN_RAMP, Palette

DEFAULT_SCENE_HEIGHT_PX = 560
"""Tall enough to rotate a terrain scene in without the mountains clipping,
short enough that several runs stay scannable on one page."""


@dataclasses.dataclass(frozen=True)
class ImagePanel:
    """A rendered raster chart (a matplotlib PNG), embedded into the page as
    a data URI so the report travels as one file."""

    path: Path
    caption: str = ""


@dataclasses.dataclass(frozen=True)
class ScenePanel:
    """A live plotly figure — a `interactive.terrain_scene`, typically —
    embedded so it stays rotatable inside the report."""

    figure: Any
    caption: str = ""
    height_px: int = DEFAULT_SCENE_HEIGHT_PX
    collapsed: bool = False
    """Put the scene behind a closed disclosure, and build it only when that
    is first opened.

    What makes a scene-per-run affordable. A sweep of seven runs with a scene
    each is seven WebGL contexts claimed at load — past what a browser will
    grant, so the earliest ones get dropped and those scenes go blank — on a
    page nobody can scroll anyway. Deferring also sidesteps the sizing bug
    that comes with the obvious alternative: a plot built inside a hidden
    element has no box to lay out in and comes back zero-sized when shown.

    `caption` becomes the toggle's label, since a closed section shows
    nothing else.
    """


Panel = ImagePanel | ScenePanel


@dataclasses.dataclass(frozen=True)
class RunReport:
    """One instance of a sweep: the parameters that defined it, the metrics
    it produced, and its charts.

    `headline` is the single figure the runs are ranked by, as a fraction in
    `[0, 1]` (a connected share, a success rate). Leave it `None` when a
    sweep has no single winner — the page then drops the ranking rather than
    inventing one.
    """

    label: str
    params: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    metrics: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    headline: float | None = None
    panels: Sequence[Panel] = ()


def _esc(value: Any) -> str:
    return html_lib.escape(str(value), quote=True)


def _fmt(value: Any) -> str:
    """Render a parameter or metric value for a data column."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.4g}"
    if isinstance(value, (list, tuple)):
        return ", ".join(_fmt(v) for v in value)
    return str(value)


def _slug(label: str, index: int) -> str:
    keep = "".join(c if c.isalnum() else "-" for c in label.lower()).strip("-")
    return f"run-{index + 1}-{keep}" if keep else f"run-{index + 1}"


def _data_uri(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"report panel image not found: {path}")
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _chip_color(rank: int, total: int, ramp: Sequence[str]) -> str:
    """Rank as ground height: first place gets the darkest (highest) step."""
    if total <= 1:
        return ramp[-1]
    position = (total - 1 - rank) / (total - 1)
    return ramp[min(len(ramp) - 1, int(position * (len(ramp) - 1) + 0.5))]


def _definition_grid(title: str, items: Mapping[str, Any]) -> str:
    if not items:
        return ""
    rows = "".join(
        f'<div class="wf-dt">{_esc(key)}</div>'
        f'<div class="wf-dd">{_esc(_fmt(value))}</div>'
        for key, value in items.items()
    )
    return (
        f'<div class="wf-block"><p class="wf-eyebrow">{_esc(title)}</p>'
        f'<div class="wf-grid">{rows}</div></div>'
    )


def _scene_spec(figure: Any) -> str:
    """A figure as inert JSON, safe to park inside a `<script>` element.

    Every `<` becomes its JSON unicode escape — legal JSON, identical once
    parsed, and unable to close the element early. plotly's own encoder
    already does this, so in practice the replacement finds nothing; it is
    here so that a caption containing `</script>` stays inert if that ever
    stops being true, rather than silently depending on it.
    """
    return figure.to_json().replace("<", "\\u003c")


def _deferred_scene(panel: ScenePanel, scene_id: str) -> str:
    """A collapsed scene: an empty target, its spec alongside, and a summary
    to open it by."""
    label = panel.caption or "Interactive scene"
    return (
        f'<details class="wf-details" data-wf-scene="{scene_id}">'
        f'<summary class="wf-summary">{_esc(label)}</summary>'
        f'<figure class="wf-figure wf-wide">'
        f'<div id="{scene_id}" class="plotly-graph-div" '
        f'style="width:100%;height:{panel.height_px}px"></div>'
        f"</figure></details>"
        f'<script type="application/json" id="{scene_id}-spec">'
        f"{_scene_spec(panel.figure)}</script>"
    )


SCENE_BOOTSTRAP = """<script>
document.querySelectorAll("details[data-wf-scene]").forEach(function (section) {
  section.addEventListener("toggle", function () {
    if (!section.open || section.dataset.wfPlotted) { return; }
    section.dataset.wfPlotted = "1";
    var id = section.dataset.wfScene;
    var spec = JSON.parse(document.getElementById(id + "-spec").textContent);
    Plotly.newPlot(id, spec.data, spec.layout, { responsive: true });
    if (spec.frames) { Plotly.addFrames(id, spec.frames); }
  });
});
</script>"""
"""Builds each collapsed scene the first time its section is opened.

Once only — reopening a section must not replot it, which would discard the
camera angle and the scrubber position the reader had left it at.
"""


def _render_panels(
    panels: Sequence[Panel], scene_ids: Iterator[str] | None = None
) -> tuple[str, bool]:
    """Returns the panels' markup and whether any needed the plotly runtime."""
    if not panels:
        return "", False

    ids = scene_ids if scene_ids is not None else _scene_ids()
    chunks: list[str] = []
    uses_plotly = False
    for panel in panels:
        if isinstance(panel, ScenePanel) and panel.collapsed:
            uses_plotly = True
            chunks.append(_deferred_scene(panel, next(ids)))
            continue
        if isinstance(panel, ImagePanel):
            body = f'<img class="wf-img" loading="lazy" alt="{_esc(panel.caption)}" src="{_data_uri(panel.path)}">'
            classes = "wf-figure"
        else:
            uses_plotly = True
            body = panel.figure.to_html(
                include_plotlyjs=False,
                full_html=False,
                default_width="100%",
                default_height=f"{panel.height_px}px",
            )
            # A scene is there to be rotated and read; sharing a row with a
            # static chart leaves it too narrow to do either.
            classes = "wf-figure wf-wide"
        caption = (
            f'<figcaption class="wf-caption">{_esc(panel.caption)}</figcaption>'
            if panel.caption
            else ""
        )
        chunks.append(f'<figure class="{classes}">{body}{caption}</figure>')
    return f'<div class="wf-panels">{"".join(chunks)}</div>', uses_plotly


def _scene_ids() -> Iterator[str]:
    """Unique target ids: two scenes sharing one would render into the same
    div, leaving the other blank."""
    return (f"wf-scene-{i}" for i in itertools.count())


def _stylesheet(palette: Palette) -> str:
    return f"""
:root {{
  --ground: {palette.surface};
  --ink: {palette.ink_primary};
  --ink-2: {palette.ink_secondary};
  --ink-3: {palette.ink_muted};
  --rule: {palette.gridline};
  --contour: {palette.axis};
  --accent: {palette.series[0]};
  --alert: {palette.series[5]};
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
  margin: 0;
  background: var(--ground);
  color: var(--ink);
  font-family: var(--sans);
  font-size: 15px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}}
.wf-wrap {{ max-width: 1200px; margin: 0 auto; padding: 0 32px 96px; }}

.wf-eyebrow {{
  margin: 0 0 10px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--ink-3);
}}
.wf-h1 {{
  margin: 0 0 12px;
  font-size: clamp(34px, 5.2vw, 62px);
  line-height: 1.02;
  font-weight: 700;
  letter-spacing: -0.035em;
}}
.wf-lede {{
  margin: 0;
  max-width: 62ch;
  font-size: 17px;
  color: var(--ink-2);
}}
.wf-head {{ padding: 72px 0 44px; }}

/* The ranked outcome: the answer the page exists to give, first. */
.wf-rank {{ margin: 0; padding: 0; list-style: none; border-top: 1px solid var(--rule); }}
.wf-rank-row {{
  display: grid;
  grid-template-columns: 26px 18px minmax(140px, 1fr) 3fr auto;
  gap: 16px;
  align-items: center;
  padding: 14px 0;
  border-bottom: 1px solid var(--rule);
}}
.wf-rank-n {{
  font-family: var(--mono);
  font-size: 13px;
  color: var(--ink-3);
  font-variant-numeric: tabular-nums;
}}
.wf-chip {{
  width: 14px; height: 14px;
  border: 1px solid rgba(0, 0, 0, 0.14);
}}
.wf-rank-label {{ font-weight: 600; }}
.wf-rank-label a {{ color: inherit; text-decoration: none; border-bottom: 1px solid var(--rule); }}
.wf-rank-label a:hover {{ border-bottom-color: var(--accent); }}
.wf-bar {{ height: 8px; background: var(--rule); position: relative; }}
.wf-bar-fill {{ position: absolute; inset: 0 auto 0 0; background: var(--accent); }}
.wf-rank-value {{
  font-family: var(--mono);
  font-size: 15px;
  font-variant-numeric: tabular-nums;
  min-width: 5.5ch;
  text-align: right;
}}

.wf-section {{ padding-top: 64px; }}
.wf-section-head {{
  display: flex;
  align-items: baseline;
  gap: 14px;
  padding-bottom: 12px;
  border-bottom: 2px solid var(--ink);
}}
.wf-section-title {{ margin: 0; font-size: 24px; font-weight: 700; letter-spacing: -0.02em; }}
.wf-section-meta {{
  margin-left: auto;
  font-family: var(--mono);
  font-size: 14px;
  color: var(--ink-2);
  font-variant-numeric: tabular-nums;
}}

.wf-blocks {{ display: flex; flex-wrap: wrap; gap: 40px; padding: 22px 0 4px; }}
.wf-block {{ min-width: 220px; }}
.wf-grid {{
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 5px 20px;
  font-family: var(--mono);
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}}
.wf-dt {{ color: var(--ink-3); }}
.wf-dd {{ color: var(--ink); }}

.wf-panels {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(440px, 1fr));
  gap: 24px;
  padding-top: 24px;
}}
.wf-figure {{ margin: 0; min-width: 0; border: 1px solid var(--rule); background: var(--ground); }}
/* A disclosure is a panel-grid item like any other, and a scene inside one
   needs the full width just as much as an expanded scene does. */
.wf-details {{
  grid-column: 1 / -1;
  margin: 0;
  border: 1px solid var(--rule);
  background: var(--ground);
}}
.wf-summary {{
  cursor: pointer;
  padding: 12px 16px;
  font-size: 13px;
  color: var(--ink-2);
  list-style-position: inside;
}}
.wf-summary:hover {{ color: var(--ink); }}
.wf-details[open] .wf-summary {{ border-bottom: 1px solid var(--rule); }}
.wf-details .wf-figure {{ border: 0; }}
.wf-img {{ display: block; width: 100%; height: auto; }}
.wf-caption {{
  padding: 10px 14px;
  border-top: 1px solid var(--rule);
  font-size: 12px;
  color: var(--ink-2);
}}
.wf-wide {{ grid-column: 1 / -1; }}

.wf-foot {{
  margin-top: 72px;
  padding-top: 18px;
  border-top: 1px solid var(--rule);
  font-size: 12px;
  color: var(--ink-3);
}}

a:focus-visible, .wf-rank-label a:focus-visible {{
  outline: 2px solid var(--accent);
  outline-offset: 3px;
}}
@media (prefers-reduced-motion: reduce) {{
  html {{ scroll-behavior: auto; }}
}}
@media (max-width: 720px) {{
  .wf-wrap {{ padding: 0 18px 64px; }}
  .wf-rank-row {{ grid-template-columns: 24px 14px 1fr auto; }}
  .wf-bar {{ display: none; }}
  .wf-panels {{ grid-template-columns: 1fr; }}
}}
"""


def sweep_report_html(
    title: str,
    runs: Sequence[RunReport],
    *,
    subtitle: str | None = None,
    headline_label: str = "",
    summary_panels: Sequence[Panel] = (),
    palette: Palette = PALETTE,
    ramp: Sequence[str] = TERRAIN_RAMP,
) -> str:
    """Render a whole sweep as one self-contained HTML document.

    `runs` keep their given order in the body — a sweep over a parameter
    reads best in parameter order — while the summary at the top is ranked by
    `headline`, so both "how does it trend" and "which one won" are
    answerable without scrolling twice.
    """
    if not runs:
        raise ValueError("a sweep report needs at least one run")

    ranked = sorted(
        (r for r in runs if r.headline is not None),
        key=lambda r: r.headline or 0.0,
        reverse=True,
    )
    rank_of = {id(run): i for i, run in enumerate(ranked)}
    slugs = {id(run): _slug(run.label, i) for i, run in enumerate(runs)}

    uses_plotly = False

    summary_rows: list[str] = []
    for rank, run in enumerate(ranked):
        fraction = run.headline or 0.0
        chip = _chip_color(rank, len(ranked), ramp)
        summary_rows.append(
            f'<li class="wf-rank-row">'
            f'<span class="wf-rank-n">{rank + 1:02d}</span>'
            f'<span class="wf-chip" style="background:{chip}"></span>'
            f'<span class="wf-rank-label"><a href="#{slugs[id(run)]}">{_esc(run.label)}</a></span>'
            f'<span class="wf-bar"><span class="wf-bar-fill" style="width:{fraction * 100:.1f}%"></span></span>'
            f'<span class="wf-rank-value">{fraction * 100:.1f}%</span>'
            f"</li>"
        )

    summary_markup = ""
    if summary_rows:
        heading = "Ranked outcome"
        if headline_label:
            heading = f"Ranked by {headline_label}"
        summary_markup = (
            f'<p class="wf-eyebrow">{_esc(heading)}</p>'
            f'<ol class="wf-rank">{"".join(summary_rows)}</ol>'
        )

    scene_ids = _scene_ids()
    summary_panel_markup, summary_used_plotly = _render_panels(
        summary_panels, scene_ids
    )
    uses_plotly = uses_plotly or summary_used_plotly

    sections: list[str] = []
    for index, run in enumerate(runs):
        panels_markup, run_used_plotly = _render_panels(run.panels, scene_ids)
        uses_plotly = uses_plotly or run_used_plotly

        meta = ""
        if run.headline is not None:
            rank = rank_of[id(run)]
            suffix = f" {_esc(headline_label)}" if headline_label else ""
            meta = (
                f'<span class="wf-section-meta">'
                f"{run.headline * 100:.1f}%{suffix} &middot; rank {rank + 1:02d}"
                f"</span>"
            )

        blocks = _definition_grid("Parameters", run.params) + _definition_grid(
            "Results", run.metrics
        )
        blocks_markup = f'<div class="wf-blocks">{blocks}</div>' if blocks else ""

        sections.append(
            f'<section class="wf-section" id="{slugs[id(run)]}">'
            f'<div class="wf-section-head">'
            f'<h2 class="wf-section-title">{_esc(run.label)}</h2>{meta}</div>'
            f"{blocks_markup}{panels_markup}</section>"
        )

    runtime = ""
    if uses_plotly:
        from plotly.offline import get_plotlyjs

        runtime = f"<script>{get_plotlyjs()}</script>"

    # After the sections, so the disclosures it binds to already exist.
    bootstrap = (
        SCENE_BOOTSTRAP
        if "data-wf-scene" in "".join(sections)
        or ("data-wf-scene" in summary_panel_markup)
        else ""
    )

    lede = f'<p class="wf-lede">{_esc(subtitle)}</p>' if subtitle else ""
    run_word = "run" if len(runs) == 1 else "runs"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>{_stylesheet(palette)}</style>
{runtime}
</head>
<body>
<div class="wf-wrap">
<header class="wf-head">
<p class="wf-eyebrow">Sweep report &middot; {len(runs)} {run_word}</p>
<h1 class="wf-h1">{_esc(title)}</h1>
{lede}
</header>
<div data-summary>{summary_markup}{summary_panel_markup}</div>
<main data-runs>{"".join(sections)}</main>
<footer class="wf-foot">Generated by wayfinder-sim. Every chart and the page itself are embedded here; this file needs no network to open.</footer>
</div>
{bootstrap}
</body>
</html>
"""


def write_sweep_report(
    out_path: Path,
    title: str,
    runs: Sequence[RunReport],
    **kwargs: Any,
) -> Path:
    """Render `runs` with `sweep_report_html` and write them to `out_path`,
    creating parent directories as needed. Returns the path written."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(sweep_report_html(title, runs, **kwargs), encoding="utf-8")
    return out_path
