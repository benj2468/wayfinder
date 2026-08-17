//! The Wayfinder mark.
//!
//! A monoline **W** whose final upstroke doubles as the stem of the **i**,
//! topped by a dot. The geometry is straight lines plus one arc — no traced
//! curves — so it stays crisp from a 16px tab icon to a page header.
//!
//! # Why the geometry is duplicated here
//!
//! `assets/logo/` holds the standalone brand assets, with literal colours, for
//! use outside this crate (docs, README, anywhere a file is what is wanted).
//! This module holds the same outline again so the header can draw it *themed*:
//! the ink follows the dashboard's text colour through light and dark mode while
//! the dot keeps the brand red. A file with `currentColor` baked in could not
//! also serve as a standalone asset, and a file referenced through `<img>` never
//! inherits `currentColor` at all — it is resolved in the image's own document,
//! not the host page's.
//!
//! The unit tests below read `assets/logo/wayfinder-mark.svg` and assert it
//! still matches, so replacing the logo cannot silently update one and not the
//! other.

use leptos::prelude::*;

/// The mark's coordinate space: cap height is exactly 500 units, with the glyph
/// top at `y=30` and the baseline at `y=530`.
pub const MARK_VIEWBOX: &str = "0 0 775 530";

/// The outline of the W, including the arc that cuts the i-stem clear of the
/// dot. Expressed in [`MARK_VIEWBOX`] units.
pub const MARK_PATH: &str = "M 0 30 L 72 30 L 213 433 L 354 30 L 420 30 L 561 432 L 673 116 \
                             A 86 86 0 0 0 736 135 L 597 530 L 528 530 L 387 126 L 245 530 \
                             L 178 530 Z";

/// Centre of the dot, x. Concentric with the arc in [`MARK_PATH`], which clears
/// a uniform gap around it — move one and the other has to move with it.
pub const DOT_CX: &str = "725.5";

/// Centre of the dot, y.
pub const DOT_CY: &str = "49";

/// Radius of the dot.
pub const DOT_R: &str = "49.5";

/// The square-artboard mark, served verbatim as the site's favicon.
///
/// Read from `assets/logo/` at compile time rather than copied into this crate:
/// there is then one file to replace, and moving the asset breaks the build
/// loudly instead of leaving a stale icon behind.
pub const FAVICON_SVG: &str = include_str!("../../../../assets/logo/wayfinder-icon.svg");

/// The Wayfinder mark, as an inline SVG that inherits the surrounding text
/// colour.
///
/// Inline rather than an `<img>` so the ink can follow the theme; see the module
/// docs. Decorative by default — the header pairs it with the wordmark, so a
/// screen reader announcing both would just stutter "Wayfinder Wayfinder".
#[component]
pub fn Logo(
    /// Extra classes for the `<svg>` element, on top of `wf-logo`.
    #[prop(default = "")]
    class: &'static str,
    /// Accessible name. Empty (the default) marks the mark decorative, for the
    /// usual case where visible text alongside it already says "Wayfinder".
    #[prop(default = "")]
    label: &'static str,
) -> impl IntoView {
    view! {
        <svg
            class=format!("wf-logo {class}")
            viewBox=MARK_VIEWBOX
            role=if label.is_empty() { "presentation" } else { "img" }
            aria-hidden=if label.is_empty() { "true" } else { "false" }
            aria-label=label
        >
            <path class="wf-logo-ink" d=MARK_PATH />
            <circle class="wf-logo-dot" cx=DOT_CX cy=DOT_CY r=DOT_R />
        </svg>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pull the value of an attribute out of the brand asset, so the tests read
    /// the shipped SVG rather than a transcription of it.
    fn attr(svg: &str, name: &str) -> String {
        let needle = format!(" {name}=\"");
        let start = svg
            .find(&needle)
            .map(|i| i + needle.len())
            .unwrap_or_else(|| panic!("`{name}` present in the asset"));
        let rest = &svg[start..];
        let end = rest.find('"').expect("attribute is terminated");
        rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The mark drawn in the header is the same geometry as the brand asset in
    /// `assets/logo/`.
    ///
    /// The two exist separately on purpose — the asset is a standalone file with
    /// literal colours, the component is themed against the dashboard's palette
    /// — so nothing but this test stops them drifting when the logo is replaced.
    #[test]
    fn mark_path_matches_the_brand_asset() {
        let asset = include_str!("../../../../assets/logo/wayfinder-mark.svg");
        assert_eq!(
            MARK_PATH,
            attr(asset, "d"),
            "the header mark and assets/logo/wayfinder-mark.svg have diverged"
        );
    }

    /// The dot, likewise, and the viewBox that positions both.
    #[test]
    fn dot_and_viewbox_match_the_brand_asset() {
        let asset = include_str!("../../../../assets/logo/wayfinder-mark.svg");
        assert_eq!(MARK_VIEWBOX, attr(asset, "viewBox"));
        assert_eq!(DOT_CX, attr(asset, "cx"));
        assert_eq!(DOT_CY, attr(asset, "cy"));
        assert_eq!(DOT_R, attr(asset, "r"));
    }

    /// The favicon is a real SVG document — it is served verbatim, so a broken
    /// asset would only show up as a missing tab icon.
    #[test]
    fn favicon_asset_is_an_svg_document() {
        assert!(FAVICON_SVG.contains("<svg"), "favicon is an svg document");
        assert!(
            FAVICON_SVG.contains("viewBox"),
            "favicon scales to any tab size"
        );
    }

    /// The favicon draws the same mark as everything else. It is a third copy of
    /// the outline, on a square artboard, and drifts just as easily.
    #[test]
    fn favicon_geometry_matches_the_brand_asset() {
        assert_eq!(
            MARK_PATH,
            attr(FAVICON_SVG, "d"),
            "assets/logo/wayfinder-icon.svg has drifted from the mark"
        );
        assert_eq!(DOT_CX, attr(FAVICON_SVG, "cx"));
        assert_eq!(DOT_CY, attr(FAVICON_SVG, "cy"));
        assert_eq!(DOT_R, attr(FAVICON_SVG, "r"));
    }

    /// The favicon adapts to the viewer's colour scheme.
    ///
    /// It is the one asset that lands on a background we neither control nor can
    /// see. Flattened back to a single fill — the obvious "simplification" — the
    /// near-black mark disappears into a dark tab strip and leaves the dot
    /// hanging there alone, which no test that only checks it parses would
    /// notice.
    #[test]
    fn favicon_adapts_to_a_dark_tab_strip() {
        assert!(
            FAVICON_SVG.contains("prefers-color-scheme: dark"),
            "favicon carries a dark-scheme rule"
        );
        assert!(
            !FAVICON_SVG.contains("fill=\""),
            "and paints via those classes, not a hard-coded fill attribute that \
             would override them"
        );
    }
}
