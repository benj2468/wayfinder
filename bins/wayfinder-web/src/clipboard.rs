//! Putting a value on the viewer's clipboard.
//!
//! One function, and the whole of the browser-specific code in this crate
//! outside `hydrate()`. It exists so the Security tab can hand an operator a
//! provider key and an enrollment token without ever drawing them: copying is
//! the only way *out* of a masked field, so it has to actually work.
//!
//! # Why `execCommand`, which is deprecated
//!
//! The modern replacement, `navigator.clipboard.writeText`, is only defined in
//! a [secure context] — HTTPS or a loopback host. This dashboard binds loopback
//! by default, but it is routinely reached over plain HTTP at a LAN address
//! (that is what pointing a browser at a node on the mesh looks like), and
//! there `navigator.clipboard` is simply `undefined`. Calling into it would
//! throw, and a `wasm-bindgen` call that throws aborts — taking the whole page
//! down to the panic banner, in the middle of an operator copying a token.
//!
//! `document.execCommand("copy")` has neither problem: it is defined
//! everywhere, it is synchronous so its `false` return is a usable answer
//! rather than a rejected promise, and it needs no permission prompt because
//! the click that ran it *is* the user gesture authorizing it. Deprecated, but
//! every current browser still implements it. Revisit if one stops — the
//! replacement would be to try the async API first and keep this as the
//! fallback, which is more machinery than the situation currently earns.
//!
//! [secure context]: https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts

/// Copy `value` to the system clipboard, reporting whether the browser took it.
///
/// `false` means the value is *not* on the clipboard — every failure path leads
/// here rather than to a panic, because this runs inside a click handler in a
/// dashboard whose other panels are still live. The caller is expected to say
/// so rather than claim a copy that did not happen.
#[cfg(feature = "hydrate")]
pub fn copy(value: &str) -> bool {
    use wasm_bindgen::JsCast;

    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return false;
    };
    let Some(body) = document.body() else {
        return false;
    };
    let Ok(element) = document.create_element("textarea") else {
        return false;
    };
    // Off-screen rather than hidden: the copy command acts on the *selection*,
    // and a `display:none` element cannot hold one. Also read-only-ish by
    // being gone before the next frame — it is appended, selected, copied and
    // removed inside this one synchronous call, so it is never focusable,
    // never tab-reachable, and never on screen.
    let _ = element.set_attribute("style", "position:fixed;top:-9999px;opacity:0");
    let Ok(area) = element.dyn_into::<web_sys::HtmlTextAreaElement>() else {
        return false;
    };
    area.set_value(value);
    if body.append_child(&area).is_err() {
        return false;
    }
    area.select();
    // `execCommand` hangs off `HtmlDocument` in web-sys, not `Document` — the
    // runtime object is the same one, so this cast is a type-level formality
    // that still has to be spelled out.
    let Ok(html_document) = document.clone().dyn_into::<web_sys::HtmlDocument>() else {
        let _ = body.remove_child(&area);
        return false;
    };
    let copied = html_document.exec_command("copy").unwrap_or(false);
    // Removed whichever way the copy went: leaving a textarea holding the
    // enrollment token in the document is exactly what this module exists to
    // avoid.
    let _ = body.remove_child(&area);
    copied
}

/// The server build's stand-in.
///
/// Server-rendered markup carries no event handlers, so nothing calls this —
/// but the click handler still has to *compile* into the `ssr` binary, and a
/// `cfg` at each call site would put a `#[cfg]` in the middle of a `view!`.
/// Answers `false`, the same as a browser that refused: no path may report a
/// copy that did not happen.
#[cfg(not(feature = "hydrate"))]
pub fn copy(_value: &str) -> bool {
    false
}
