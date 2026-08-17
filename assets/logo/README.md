# Wayfinder logo

Vector rebuild of the "Wi" mark: a monoline **W** whose final upstroke doubles
as the stem of the **i**, topped by a red dot.

| File | Artboard | Use |
| --- | --- | --- |
| `wayfinder-mark.svg` | `775 × 530`, tight to the mark | Primary. README headers, docs, the web UI. |
| `wayfinder-mark-mono.svg` | `775 × 530` | Single-colour, `fill="currentColor"`. Dark backgrounds, one-ink printing, tinting. |
| `wayfinder-icon.svg` | `1000 × 1000` square | Favicon / app icon. Same geometry, centred with padding. **Adapts to the viewer's colour scheme** — see below. |

## Colours

| Role | Hex |
| --- | --- |
| Ink | `#0A0A0A` |
| Dot | `#D43735` |
| Reference background | `#E4E2DE` |

The mark is drawn on transparency — the background above is only what the
source artwork used, not part of the asset.

`wayfinder-icon.svg` is the exception to those fixed values: it carries a
`prefers-color-scheme: dark` rule that swaps the ink to `#F2F2F2` and the dot to
`#E8483F`. It is the only asset that lands on a background we neither control
nor can see — a browser tab strip, an OS dock — and at 16px a near-black mark on
a dark strip disappears entirely, leaving the dot floating on its own. Do not
"simplify" it back to a flat `fill`; a unit test in `logo.rs` fails if you do.

## Geometry

All paths are straight lines plus one arc; there are no traced Béziers, so the
mark stays crisp at any scale.

- Cap height is exactly `500` units (glyph top `y=30`, baseline `y=530`).
- Strokes run at a constant slope of `0.352` (run over rise), horizontal width
  `~70`, all four cut flat on the baseline and at cap height.
- The dot is a true circle: `r=49.5` at `(725.5, 49)`.
- The scoop at the top of the i-stem is a circular arc of `r=86` **concentric
  with the dot**, leaving a uniform `36.5`-unit gap around it. Keep the two
  concentric if you ever rescale one of them independently.

## Where it is used

`bins/wayfinder-web` consumes both files in this directory:

- **Favicon** — `wayfinder-icon.svg` is `include_str!`'d by
  `src/components/logo.rs` and served from the crate's own `/favicon.svg` route
  (`src/server.rs`). It is *not* served off disk: the static-file fallback reads
  `site-root`, which only `cargo leptos` populates, so a plain `cargo build` of
  the `ssr` binary would 404 its own icon.
- **Header mark** — `src/components/logo.rs` carries the same outline again as
  a `Logo` component, so the ink can follow the dashboard's theme while the dot
  keeps the brand red. An `<img>` cannot do this: `currentColor` in a referenced
  SVG resolves against the image's own document, not the host page.

**Replacing the logo means editing this directory *and* `logo.rs`.** The unit
tests in `logo.rs` read `wayfinder-mark.svg` and fail if the two diverge, so the
drift is caught rather than shipped — but the fix is still a two-file edit.

## Notes

- **`currentColor` only resolves when the SVG is inlined.** Referenced through
  `<img src>` or `background-image`, the browser renders it in its own document
  context and the mark falls back to black. Inline the markup, or use a CSS
  `mask-image` with `background-color`.
- **Below roughly 24px the dot stops reading** — at 16px it is a single pixel
  and the mark degrades to a plain `W`. If a true 16px favicon is needed, draw a
  hinted bitmap rather than downscaling `wayfinder-icon.svg`.
