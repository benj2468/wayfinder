//! PyO3 bindings over wayfinder's tick-based mesh routing driver
//! (`wayfinder_tick_driver`), for driving simulated wayfinder nodes from
//! Python — e.g. a game-engine or physics-based radio-propagation
//! simulation. Distinct from, and complementary to, `sim/`'s docker-compose
//! multi-container simulator: that drives real `wayfinder-tap` binaries over
//! virtual networks; this drives the routing core in-process, with no
//! containers or sockets at all.
#![allow(clippy::clone_on_copy)]

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod auth;
mod driver;
mod errors;
mod state;
mod tracing_init;
mod types;

pub use auth::PyAuthority;
pub use auth::PyKeypair;
pub use auth::PyMembershipCert;
pub use auth::PyRevocationRecord;
pub use auth::PyTrustAnchor;
pub use driver::PyDriver;
pub use errors::MalformedFrameError;
pub use errors::WayfinderError;
pub use state::PyLinkQualityRecord;
pub use state::PyNeighborStats;
pub use state::PyOriginatorRecord;
pub use tracing_init::init_tracing;
pub use types::PyEgressInterface;
pub use types::PyLinkFeatures;
pub use types::PyLinkMetrics;
pub use types::PyMac;

/// `wayfinder_py` module init.
#[pymodule]
fn wayfinder_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMac>()?;
    m.add_class::<PyLinkFeatures>()?;
    m.add_class::<PyLinkMetrics>()?;
    m.add_class::<PyEgressInterface>()?;
    m.add_class::<PyNeighborStats>()?;
    m.add_class::<PyOriginatorRecord>()?;
    m.add_class::<PyLinkQualityRecord>()?;
    m.add_class::<PyDriver>()?;
    m.add_class::<PyKeypair>()?;
    m.add_class::<PyTrustAnchor>()?;
    m.add_class::<PyMembershipCert>()?;
    m.add_class::<PyRevocationRecord>()?;
    m.add_class::<PyAuthority>()?;
    // The BATMAN protocol version this build speaks, so the simulator's frame
    // forge stamps the same one the router accepts rather than duplicating the
    // number. A version bump used to leave the forge behind, and every forged
    // frame was then dropped on the ingress version check — the whole red-team
    // battery reporting HELD because nothing it sent was ever parsed.
    m.add("BATMAN_VERSION", wayfinder::batman::wire::BATMAN_VERSION)?;
    m.add_function(wrap_pyfunction!(init_tracing, m)?)?;
    m.add("WayfinderError", m.py().get_type::<WayfinderError>())?;
    m.add(
        "MalformedFrameError",
        m.py().get_type::<MalformedFrameError>(),
    )?;
    m.add("MAX_INTERFACES", wayfinder::MAX_INTERFACES)?;
    m.add("MAX_NEIGHBOR_KEYS", wayfinder::auth::MAX_NEIGHBOR_KEYS)?;
    m.add(
        "MAX_IN_PROGRESS_PROOF",
        wayfinder::auth::MAX_IN_PROGRESS_PROOF,
    )?;
    m.add("MAX_LINK_FRAME_LEN", interfaces::frame::MAX_LINK_FRAME_LEN)?;
    Ok(())
}
