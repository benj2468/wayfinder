"""The chart palette, as plain data.

Kept separate from `plotting.py` so that every renderer shares one validated
set of colors without also sharing a rendering dependency: `plotting` draws
static figures with matplotlib, `interactive` builds rotatable scenes with
plotly, and neither should have to import the other's stack to agree on what
blue means.

Palette per the dataviz skill's validated reference instance
(`references/palette.md`): the full 8-hue categorical set (blue, aqua,
yellow, green, violet, red, magenta, orange, in that order), light chart
surface, muted ink for axes/gridlines. Reused verbatim (not re-derived),
since these are the pre-validated default hues — ordered to maximize the
minimum adjacent CVD-safe color distance — rather than a new brand palette.
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class Palette:
    """A small, ordered set of categorical series hues plus the ink/surface
    colors every panel in a chart shares."""

    series: tuple[str, ...]
    surface: str
    ink_primary: str
    ink_secondary: str
    ink_muted: str
    gridline: str
    axis: str


PALETTE = Palette(
    series=(
        "#2a78d6",  # blue
        "#1baf7a",  # aqua
        "#eda100",  # yellow
        "#008300",  # green
        "#4a3aa7",  # violet
        "#e34948",  # red
        "#e87ba4",  # magenta
        "#eb6834",  # orange
    ),
    surface="#fcfcfb",
    ink_primary="#0b0b0b",
    ink_secondary="#52514e",
    ink_muted="#898781",
    gridline="#e1e0d9",
    axis="#c3c2b7",
)

# Elevation is a *sequential* encoding (continuous magnitude), which the
# categorical `PALETTE.series` cannot express — cycling hues across a height
# range is the rainbow anti-pattern. This is a single-hue light->dark ramp
# built from the palette's own warm neutrals, chosen over the reference
# sequential blue for two reasons: terrain is the base layer rather than a
# series competing for identity, and a neutral ground leaves all eight
# categorical hues free and unambiguous for the entities drawn on top of it.
TERRAIN_RAMP = ("#e1e0d9", "#c3c2b7", "#898781", "#52514e")
"""Low ground -> high ground."""
