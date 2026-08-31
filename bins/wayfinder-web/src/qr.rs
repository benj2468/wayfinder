//! A QR code as inline SVG, for the one value on this dashboard somebody has to
//! carry to a *different* device.
//!
//! # Why the encoder is here rather than the value being retyped
//!
//! The registration page hands over an `otpauth://` URI: a base32 secret inside
//! a URL, shown once, which has to end up inside an authenticator app. Where
//! that app is on the same machine the copy button is enough. Where it is on a
//! phone and the page is on a laptop — the ordinary case, and the case design
//! 12 §11 left open — the alternatives are retyping 30-odd characters of base32
//! by hand or mailing a shared secret to yourself. A camera is the path that
//! neither transcribes nor transmits it.
//!
//! # Drawn, not fetched
//!
//! The SVG is written into the page's own markup: no image request, no data
//! URI, nothing for a proxy or an access log to see, and no second round trip
//! carrying the secret. It is also what lets the server render and the browser
//! hydrate the *same* bytes — see the note on `qrcodegen` in `Cargo.toml`.
//!
//! # Black on white, in both themes
//!
//! The one piece of this dashboard that does not follow the reader's theme.
//! Inverting a QR code (light modules on a dark ground) is legal and plenty of
//! scanners read it, but plenty do not, and the failure is a person holding a
//! phone at a screen wondering what they did wrong. So the quiet zone is an
//! explicit white rectangle and the modules are explicit black, whatever the
//! page around them is doing.

use core::fmt::Write as _;

use qrcodegen::QrCode;
use qrcodegen::QrCodeEcc;

/// The quiet zone, in modules. Four is what the specification requires, and a
/// scanner that fails on a code drawn flush to its container fails silently —
/// it simply never locks on.
const QUIET_ZONE: i32 = 4;

/// Encode `data` as a QR code and return it as a self-contained `<svg>`
/// element, or `None` if it will not fit in a QR code at all.
///
/// `label` becomes the element's accessible name: the code is an image with no
/// text in it, so a screen reader has nothing else to announce. It is written
/// into the attribute exactly as given, and the result is handed to
/// `inner_html` — so it is `&'static str` rather than `&str`, which is what
/// makes a caller-supplied string a compile error instead of an escaping
/// question. That also stops the two arguments being transposed: `data` is the
/// one carrying a secret, and `svg(label, data)` would put it in the
/// accessibility tree.
///
/// The returned markup carries no width or height, only a `viewBox`, so the
/// stylesheet decides how large it is drawn — a QR code is scale-free and
/// hard-coding a pixel size here would be this module guessing at a layout it
/// cannot see. It does carry `class="wf-qr"`, which is the seam `main.css`
/// sizes it through; output taken outside the dashboard has no size at all.
pub fn svg(data: &str, label: &'static str) -> Option<String> {
    // Medium: the level every authenticator's own enrolment code uses. Low
    // makes a smaller code that a camera at an angle recovers less often, and
    // high makes a denser one for a redundancy nothing here needs — this code
    // is read once, from a screen, at arm's length.
    let code = QrCode::encode_text(data, QrCodeEcc::Medium).ok()?;
    let side = code.size() + 2 * QUIET_ZONE;

    // One `<path>` of `M x y h1 v1 h-1 z` subpaths rather than a `<rect>` per
    // module: a code this size is several hundred modules, and several hundred
    // elements is markup the server serialises, the browser parses and the
    // hydration bundle walks. The path is one node.
    let mut modules = String::new();
    for y in 0..code.size() {
        for x in 0..code.size() {
            if code.get_module(x, y) {
                let _ = write!(modules, "M{} {}h1v1h-1z", x + QUIET_ZONE, y + QUIET_ZONE);
            }
        }
    }

    Some(format!(
        "<svg class=\"wf-qr\" viewBox=\"0 0 {side} {side}\" role=\"img\" \
         aria-label=\"{label}\" xmlns=\"http://www.w3.org/2000/svg\">\
         <rect width=\"{side}\" height=\"{side}\" fill=\"#ffffff\"/>\
         <path d=\"{modules}\" fill=\"#000000\"/></svg>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative `otpauth://` URI — the shape the registration page
    /// actually hands over, secret length included.
    const URI: &str = "otpauth://totp/Wayfinder:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
                       &issuer=Wayfinder&algorithm=SHA1&digits=6&period=30";

    #[test]
    fn an_enrolment_uri_encodes_to_a_drawable_code() {
        let svg = svg(URI, "Authenticator setup code").expect("a URI this short always fits");

        assert!(svg.starts_with("<svg "), "a bare element: {svg}");
        assert!(svg.ends_with("</svg>"), "closed: {svg}");
        assert!(
            svg.contains("<path d=\"M"),
            "at least one dark module: {svg}"
        );
    }

    /// The quiet zone is part of the code, not something a stylesheet is
    /// trusted to leave around it. A code drawn flush to its container is not
    /// read at all, and it fails by simply never scanning.
    #[test]
    fn the_code_carries_its_own_quiet_zone() {
        let svg = svg(URI, "code").expect("fits");
        let code = QrCode::encode_text(URI, QrCodeEcc::Medium).expect("fits");
        let side = code.size() + 2 * QUIET_ZONE;

        assert!(
            svg.contains(&format!("viewBox=\"0 0 {side} {side}\"")),
            "the viewBox is the code plus {QUIET_ZONE} modules each side: {svg}"
        );

        // Every module, on both axes, not just the first subpath. Checking the
        // leading `M0 ` catches an x-axis regression and silently misses the
        // y-axis one, which draws a code that no scanner locks on to.
        let drawn: Vec<(i32, i32)> = modules_of(&svg);
        assert!(!drawn.is_empty(), "some modules are drawn: {svg}");
        let last = side - QUIET_ZONE - 1;
        for (x, y) in drawn {
            assert!(
                (QUIET_ZONE..=last).contains(&x) && (QUIET_ZONE..=last).contains(&y),
                "module ({x}, {y}) is outside the {QUIET_ZONE}-module quiet zone \
                 of a {side}-module canvas"
            );
        }
    }

    /// The `(x, y)` of every module drawn in an SVG this module produced, read
    /// back out of the single `<path>`'s `d` attribute.
    fn modules_of(svg: &str) -> Vec<(i32, i32)> {
        let d = svg
            .split_once("<path d=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .expect("the modules path")
            .0;

        d.split('M')
            .filter(|sub| !sub.is_empty())
            .map(|sub| {
                let coords = sub.trim_end_matches("h1v1h-1z");
                let (x, y) = coords.split_once(' ').expect("an `M x y` subpath");
                (x.parse().expect("an x"), y.parse().expect("a y"))
            })
            .collect()
    }

    /// Neither colour is a CSS variable or `currentColor`: see the module docs.
    /// A dark-theme page that inverted this would produce a code some scanners
    /// silently refuse.
    #[test]
    fn the_code_is_black_on_white_whatever_the_page_is() {
        let svg = svg(URI, "code").expect("fits");

        assert!(svg.contains("fill=\"#ffffff\""), "a white ground: {svg}");
        assert!(svg.contains("fill=\"#000000\""), "black modules: {svg}");
        assert!(
            !svg.contains("currentColor"),
            "the code does not follow the theme: {svg}"
        );
    }

    /// The server renders this page and the wasm bundle hydrates it, so the
    /// same input has to produce the same bytes — a code that differed between
    /// the two would be a hydration mismatch.
    #[test]
    fn the_same_uri_always_encodes_to_the_same_markup() {
        assert_eq!(svg(URI, "code"), svg(URI, "code"));
    }

    /// The accessible name reaches the element: a QR code has no text in it, so
    /// without one a screen reader announces an unlabelled image.
    #[test]
    fn the_label_becomes_the_accessible_name() {
        let svg = svg(URI, "Authenticator setup code").expect("fits");

        assert!(
            svg.contains("role=\"img\"") && svg.contains("aria-label=\"Authenticator setup code\""),
            "labelled as an image: {svg}"
        );
    }

    /// Nothing is promised for input that will not fit, and the caller is told
    /// rather than handed an empty code. At the Medium correction this module
    /// encodes at, the ceiling is 2,331 bytes — not the 2,953 a QR code reaches
    /// at Low, which is the number it is easy to reach for. This is well past
    /// either.
    #[test]
    fn data_too_large_for_any_qr_code_is_refused() {
        assert_eq!(svg(&"x".repeat(10_000), "code"), None);
    }
}
