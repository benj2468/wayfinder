//! Python exception hierarchy for `wayfinder_py`.
//!
//! An [`Option`]/`bool` outcome on the Rust side (a dropped frame, no route
//! yet, an out-of-range runtime-config index) stays `None`/`False` in
//! Python — those are normal, expected outcomes, not exceptions. Only a
//! genuine `Result::Err` or malformed caller input raises.

use pyo3::create_exception;
use pyo3::exceptions::PyException;

create_exception!(
    wayfinder_py,
    WayfinderError,
    PyException,
    "Base exception for all wayfinder_py errors."
);

create_exception!(
    wayfinder_py,
    MalformedFrameError,
    WayfinderError,
    "Bytes passed to push_rx do not parse as a well-formed on-wire link frame."
);
