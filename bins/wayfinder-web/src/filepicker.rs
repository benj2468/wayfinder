//! Reading the file a viewer chose in a `<input type="file">`.
//!
//! The counterpart to [`crate::clipboard`], and the second of the two places
//! this crate touches a browser API directly. It exists for one thing: the
//! sign-in form's `.wfauth` credential file, which has to reach the server as
//! text before anything can be done with it.
//!
//! # What is deliberately *not* here
//!
//! No parsing, no validation, no look inside the file at all. The browser hands
//! over bytes and this hands those bytes to a `#[server]` function; whether they
//! are a credential, whose it is and whether it still works is decided
//! server-side (`session::SessionStore::login_with_bundle`) and ultimately by
//! the node. Anything else would put a second, weaker copy of that judgement in
//! the wasm bundle, where it could disagree with the real one — and where the
//! only thing it could actually achieve is refusing a file the node would have
//! accepted.
//!
//! # Why a callback rather than an `async fn`
//!
//! `FileReader` is event-driven, and the alternative — `Blob::text()`, which
//! returns a promise — needs `js-sys` and `wasm-bindgen-futures` in the bundle
//! to await. A single `onloadend` closure costs neither, and the reactive
//! runtime is the thing waiting anyway: the callback sets a signal and the view
//! follows.

/// Read the file chosen in a file input, handing its text to `deliver`.
///
/// `deliver` receives the file's name and contents, or a message to show. It is
/// called from the browser's event loop, after this function has returned, so
/// its job is to set a signal rather than to return anything.
///
/// A `change` that *cleared* the selection delivers nothing at all: there is no
/// file, no failure, and nothing worth saying about it.
#[cfg(feature = "hydrate")]
pub fn read_chosen_file(
    ev: &leptos::ev::Event,
    deliver: impl Fn(Result<(String, String), String>) + 'static,
) {
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;

    // Shared rather than moved, because there are two ways this ends and both
    // have to be able to speak: the read's own callback, and the synchronous
    // refusal below when the browser will not start the read at all.
    let deliver = std::rc::Rc::new(deliver);

    let Some(input) = ev
        .target()
        .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
    else {
        deliver(Err(
            "this browser did not report which file was chosen".into()
        ));
        return;
    };
    let Some(file) = input.files().and_then(|files| files.get(0)) else {
        return;
    };
    let name = file.name();
    let Ok(reader) = web_sys::FileReader::new() else {
        deliver(Err("this browser cannot read a file from a form".into()));
        return;
    };

    // `onloadend` rather than `onload` plus `onerror`: it fires either way, and
    // "the result is not a string" is exactly the condition both failure paths
    // land in — so one closure covers a read that failed, a file that vanished
    // between choosing and reading, and a binary that is not text.
    let finished = {
        let reader = reader.clone();
        let deliver = std::rc::Rc::clone(&deliver);
        Closure::<dyn FnMut()>::new(move || {
            match reader.result().ok().and_then(|value| value.as_string()) {
                Some(text) => deliver(Ok((name.clone(), text))),
                None => deliver(Err(
                    "this file could not be read as text — a credential file is a text file".into(),
                )),
            }
        })
    };
    reader.set_onloadend(Some(finished.as_ref().unchecked_ref()));

    // Leaked on purpose, and it is what keeps the `FileReader` alive: the
    // closure holds the only remaining reference to it once this function
    // returns, and dropping it here would leave the read with nothing to call
    // back into. The cost is one small closure per file a person picks, which
    // is an action measured in single digits per session.
    finished.forget();

    if reader.read_as_text(&file).is_err() {
        deliver(Err("this browser refused to read the chosen file".into()));
    }
}

/// The server build's stand-in.
///
/// Server-rendered markup carries no event handlers, so nothing calls this —
/// but the `on:change` handler still has to *compile* into the `ssr` binary,
/// and a `#[cfg]` at the call site would put one in the middle of a `view!`.
/// The same arrangement `clipboard::copy` uses, for the same reason.
#[cfg(not(feature = "hydrate"))]
pub fn read_chosen_file(
    _ev: &leptos::ev::Event,
    _deliver: impl Fn(Result<(String, String), String>) + 'static,
) {
}
