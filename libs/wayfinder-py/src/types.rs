//! Python-visible mirrors of the plain data types that cross the
//! `wayfinder_tick_driver` boundary.

use interfaces::frame::Mac;
use interfaces::link::LinkMetrics;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use wayfinder::features::LinkFeatures;

/// A 6-byte mesh MAC address — the identifier every wayfinder node, route,
/// and frame destination is keyed on.
#[pyclass(frozen, eq, hash, from_py_object, module = "wayfinder_py")]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PyMac(pub(crate) Mac);

#[pymethods]
impl PyMac {
    /// Build a `PyMac` from exactly 6 address bytes.
    #[new]
    fn new(addr: &[u8]) -> PyResult<Self> {
        let mac = Mac::try_from(addr)
            .map_err(|_| PyValueError::new_err("a MAC address is exactly 6 bytes"))?;
        Ok(Self(mac))
    }

    /// The 6 address bytes.
    #[getter]
    fn bytes(&self) -> Vec<u8> {
        Vec::from(self.0.0)
    }

    /// `PyMac(aa:bb:cc:dd:ee:ff)`.
    fn __repr__(&self) -> String {
        format!("PyMac({})", self.0)
    }

    /// `aa:bb:cc:dd:ee:ff`.
    fn __str__(&self) -> String {
        format!("{}", self.0)
    }

    /// The reserved all-ones broadcast/flood address.
    #[classattr]
    #[allow(non_snake_case)]
    fn BROADCAST() -> Self {
        Self(Mac::BROADCAST)
    }
}

/// Per-link participation gates: one send/receive gate for each of the OGM
/// (topology) and data planes. Mirrors `wayfinder::features::LinkFeatures`;
/// every flag defaults to `True` (full participation).
#[pyclass(module = "wayfinder_py", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyLinkFeatures {
    /// Send OGMs (own emission and re-floods) on this link.
    #[pyo3(get, set)]
    pub tx_ogm: bool,
    /// Receive and learn routes from OGMs heard on this link.
    #[pyo3(get, set)]
    pub rx_ogm: bool,
    /// Send data-plane traffic (unicast/multicast/broadcast) on this link.
    #[pyo3(get, set)]
    pub tx_data: bool,
    /// Receive data-plane traffic on this link.
    #[pyo3(get, set)]
    pub rx_data: bool,
}

#[pymethods]
impl PyLinkFeatures {
    /// Build a feature set; every flag defaults to full participation.
    #[new]
    #[pyo3(signature = (tx_ogm=true, rx_ogm=true, tx_data=true, rx_data=true))]
    fn new(tx_ogm: bool, rx_ogm: bool, tx_data: bool, rx_data: bool) -> Self {
        Self {
            tx_ogm,
            rx_ogm,
            tx_data,
            rx_data,
        }
    }
}

impl From<PyLinkFeatures> for LinkFeatures {
    fn from(f: PyLinkFeatures) -> Self {
        LinkFeatures {
            tx_ogm: f.tx_ogm,
            rx_ogm: f.rx_ogm,
            tx_data: f.tx_data,
            rx_data: f.rx_data,
        }
    }
}

/// A received frame's physical-layer quality, as measured by whatever
/// simulated (or real) carrier delivered it. Mirrors
/// `interfaces::link::LinkMetrics`; every field defaults to `None` (no signal
/// information available).
#[pyclass(module = "wayfinder_py", from_py_object)]
#[derive(Clone, Copy, Default)]
pub struct PyLinkMetrics {
    /// Received signal strength, in dBm.
    #[pyo3(get, set)]
    pub rssi_dbm: Option<i16>,
    /// Signal-to-noise ratio, in dB.
    #[pyo3(get, set)]
    pub snr_db: Option<i8>,
    /// A carrier-defined link quality figure (e.g. 0-255).
    #[pyo3(get, set)]
    pub quality: Option<u8>,
}

#[pymethods]
impl PyLinkMetrics {
    /// Build a metrics value; every field defaults to `None`.
    #[new]
    #[pyo3(signature = (rssi_dbm=None, snr_db=None, quality=None))]
    fn new(rssi_dbm: Option<i16>, snr_db: Option<i8>, quality: Option<u8>) -> Self {
        Self {
            rssi_dbm,
            snr_db,
            quality,
        }
    }
}

impl From<PyLinkMetrics> for LinkMetrics {
    fn from(m: PyLinkMetrics) -> Self {
        LinkMetrics {
            rssi_dbm: m.rssi_dbm,
            snr_db: m.snr_db,
            quality: m.quality,
        }
    }
}

/// Which interface(s) a planned frame should egress on, as resolved by
/// `CentralRouter::get_egress_interface`. Read-only introspection: the send
/// path itself never needs a caller to resolve this, `PyDriver::tick`
/// already does it internally.
#[pyclass(module = "wayfinder_py", get_all, from_py_object)]
#[derive(Clone, Copy)]
pub struct PyEgressInterface {
    /// `True` when the frame should flood every interface (a broadcast).
    pub all: bool,
    /// The single interface index to use, when `all` is `False`.
    pub interface: Option<usize>,
}
