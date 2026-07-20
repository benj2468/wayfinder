//! Bridges wayfinder's `tracing` events out to the process.
//!
//! `wayfinder`/`wayfinder-tick-driver` log via `tracing`'s
//! `trace!`/`debug!`/`info!`/`warn!`/`error!` macros, same as every other
//! crate in the workspace (see the root `CLAUDE.md`'s Logging section) — but
//! a library never installs its own subscriber, so without one those records
//! are silently dropped. [`init_tracing`] installs the same
//! `tracing_subscriber::fmt` setup `wayfinder-tap`/`rylr998-cli` use.

use pyo3::prelude::*;
use tracing_subscriber::EnvFilter;

/// Install a `tracing_subscriber::fmt` subscriber (writing to stdout) so the
/// mesh stack's `trace!`/`debug!`/`info!`/`warn!`/`error!` records become
/// visible — mirroring `wayfinder-tap`'s own setup.
///
/// `filter` is an [`EnvFilter`] directive string (e.g.
/// `"wayfinder=debug,wayfinder_tick_driver=trace"`); when `None`, falls back
/// to the `RUST_LOG` environment variable, same as every other wayfinder
/// binary (`tracing`'s own default applies when that's unset too: only
/// `warn!`/`error!` show).
///
/// Safe to call more than once — e.g. a notebook re-running a cell, or
/// several tests each importing the module — a global subscriber can only be
/// installed once per process, so a repeat call is silently ignored rather
/// than panicking.
///
/// Note: this writes straight to the process's stdout file descriptor, which
/// bypasses any *Python-level* redirection of `sys.stdout` (e.g.
/// `contextlib.redirect_stdout`, `pytest`'s default output capture) — it
/// still shows up in a real terminal or a Jupyter cell, both of which
/// redirect the underlying file descriptor rather than the Python object.
#[pyfunction]
#[pyo3(signature = (filter=None))]
pub fn init_tracing(filter: Option<&str>) {
    let env_filter = match filter {
        Some(directives) => EnvFilter::new(directives),
        None => EnvFilter::from_default_env(),
    };
    // `try_init` (not `init`, which panics) so a second call — or a
    // subscriber some embedding application already installed — is a no-op.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();
}
