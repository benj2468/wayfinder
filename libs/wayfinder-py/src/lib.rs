//! PyO3 bindings over wayfinder's tick-based mesh routing driver
//! (`wayfinder_tick_driver`), for driving simulated wayfinder nodes from
//! Python — e.g. a game-engine or physics-based radio-propagation
//! simulation. Distinct from, and complementary to, `sim/`'s docker-compose
//! multi-container simulator: that drives real `wayfinder-tap` binaries over
//! virtual networks; this drives the routing core in-process, with no
//! containers or sockets at all.

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod driver;
mod errors;
mod tracing_init;
mod types;

pub use driver::PyDriver;
pub use errors::{MalformedFrameError, WayfinderError};
pub use tracing_init::init_tracing;
pub use types::{PyEgressInterface, PyLinkFeatures, PyLinkMetrics, PyMac};

/// `wayfinder_py` module init.
#[pymodule]
fn wayfinder_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMac>()?;
    m.add_class::<PyLinkFeatures>()?;
    m.add_class::<PyLinkMetrics>()?;
    m.add_class::<PyEgressInterface>()?;
    m.add_class::<PyDriver>()?;
    m.add_function(wrap_pyfunction!(init_tracing, m)?)?;
    m.add("WayfinderError", m.py().get_type::<WayfinderError>())?;
    m.add(
        "MalformedFrameError",
        m.py().get_type::<MalformedFrameError>(),
    )?;
    m.add("MAX_INTERFACES", wayfinder::MAX_INTERFACES)?;
    m.add("MAX_LINK_FRAME_LEN", interfaces::frame::MAX_LINK_FRAME_LEN)?;
    Ok(())
}
