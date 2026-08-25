//! `PyDriver` — a thin PyO3 shim over `wayfinder_tick_driver::Driver`.

use core::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use wayfinder::EgressInterface;
use wayfinder::auth::OgmAuth;
use wayfinder::config::TrickleConfig;
use wayfinder_tick_driver::Driver;

use crate::auth::PyKeypair;
use crate::auth::PyMembershipCert;
use crate::auth::PyRevocationRecord;
use crate::auth::PyTrustAnchor;
use crate::errors::MalformedFrameError;
use crate::state::PyLinkQualityRecord;
use crate::state::PyOriginatorRecord;
use crate::types::PyEgressInterface;
use crate::types::PyLinkFeatures;
use crate::types::PyLinkMetrics;
use crate::types::PyMac;

/// A tick-based, queue-backed wayfinder router. Push received frames onto
/// whichever interface index carried them
/// ([`push_rx`](PyDriver::push_rx)), optionally queue host-originated data
/// ([`queue_local_send`](PyDriver::queue_local_send)), call
/// [`tick`](PyDriver::tick) once per simulation step, then drain whatever
/// landed in each interface's egress queue
/// ([`poll_egress`](PyDriver::poll_egress)) or the local-delivery queue
/// ([`poll_local`](PyDriver::poll_local)).
#[pyclass(module = "wayfinder_py")]
pub struct PyDriver {
    inner: Driver,
    /// The most recent `now` passed to [`tick`](PyDriver::tick), reused by
    /// read-only introspection methods (e.g.
    /// [`get_egress_interface`](PyDriver::get_egress_interface)) that need a
    /// current time but aren't themselves driven by the simulation step.
    last_now: Duration,
}

#[pymethods]
impl PyDriver {
    /// Build a driver for `mac` with `len(trickle)` interfaces. `trickle[idx]`
    /// is that interface's `(i_min_ms, i_max_ms)` adaptive OGM schedule;
    /// `features[idx]` its participation gates, defaulting to full
    /// participation for any interface `features` doesn't cover; `names[idx]`
    /// its display name for the management API, left unnamed when absent.
    #[new]
    #[pyo3(signature = (mac, trickle, features=None, names=None))]
    fn new(
        mac: PyMac,
        trickle: Vec<(u64, u64)>,
        features: Option<Vec<PyLinkFeatures>>,
        names: Option<Vec<String>>,
    ) -> Self {
        let trickle: Vec<TrickleConfig> = trickle
            .into_iter()
            .map(|(i_min_ms, i_max_ms)| TrickleConfig { i_min_ms, i_max_ms })
            .collect();
        let features: Vec<wayfinder::features::LinkFeatures> = features
            .unwrap_or_default()
            .into_iter()
            .map(Into::into)
            .collect();
        let names = names.unwrap_or_default();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        Self {
            inner: Driver::new(mac.0, &trickle, &features, &names),
            last_now: Duration::ZERO,
        }
    }

    /// The number of mesh interfaces this driver was constructed with.
    fn num_interfaces(&self) -> usize {
        self.inner.num_interfaces()
    }

    /// Enqueue a frame received on interface `idx` (with its carrier's
    /// physical-layer `metrics`, defaulting to all-`None`), processed on the
    /// next [`tick`](Self::tick). Raises `MalformedFrameError` if `frame`
    /// doesn't parse as a well-formed on-wire link frame.
    #[pyo3(signature = (idx, frame, metrics=None))]
    fn push_rx(
        &mut self,
        idx: usize,
        frame: &[u8],
        metrics: Option<PyLinkMetrics>,
    ) -> PyResult<()> {
        let metrics = metrics.unwrap_or_default().into();
        self.inner.push_rx(idx, metrics, frame).map_err(|_| {
            MalformedFrameError::new_err("frame does not parse as a well-formed on-wire link frame")
        })
    }

    /// Enqueue host-originated data destined for `dest` (or
    /// `PyMac.BROADCAST` to flood), processed on the next
    /// [`tick`](Self::tick).
    fn queue_local_send(&mut self, dest: PyMac, payload: &[u8]) {
        self.inner.queue_local_send(dest.0, payload);
    }

    /// Non-blocking: drain every currently queued received frame and local
    /// send, run whatever per-interface OGM maintenance is due as of
    /// `now_ms`, and stage the results for `poll_egress`/`poll_local`. Call
    /// once per simulation step.
    fn tick(&mut self, now_ms: u64) {
        self.last_now = Duration::from_millis(now_ms);
        self.inner.tick(self.last_now);
    }

    /// Pop the next frame staged for transmission on interface `idx`, if any
    /// (on-wire bytes, ready to hand to whatever carries that interface).
    fn poll_egress<'py>(&mut self, py: Python<'py>, idx: usize) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .poll_egress(idx)
            .map(|bytes| PyBytes::new(py, &bytes))
    }

    /// Pop the next payload delivered to the local host, if any.
    fn poll_local<'py>(&mut self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .poll_local()
            .map(|bytes| PyBytes::new(py, &bytes))
    }

    /// Every known destination and its candidate paths, in no particular
    /// order (the table is keyed by MAC for O(1) lookup).
    ///
    /// Read-only: building a snapshot must not perturb the run it describes,
    /// since feature extraction happens alongside a live simulation.
    fn originator_table(&self) -> Vec<PyOriginatorRecord> {
        self.inner
            .router()
            .originator_table()
            .map(PyOriginatorRecord::from)
            .collect()
    }

    /// Per-`(neighbor, interface)` local link-quality estimates.
    ///
    /// Populated for every neighbor/interface pair a frame has been received
    /// on, whether or not that frame carried `LinkMetrics` — a caller that
    /// never passes `metrics` to [`push_rx`](Self::push_rx) still gets one
    /// entry per pair, with `ewma_quality` set to `None` rather than the row
    /// being absent. `None` means the link was never measurable, which is
    /// distinct from a radio reporting a genuine `Some(0)`.
    fn link_quality_records(&self) -> Vec<PyLinkQualityRecord> {
        self.inner
            .router()
            .link_quality_records()
            .iter()
            .map(PyLinkQualityRecord::from)
            .collect()
    }

    /// How many originators are reachable directly (best next hop is the
    /// destination itself), as opposed to through a relay.
    fn neighbor_count(&self) -> usize {
        self.inner.router().neighbor_count()
    }

    /// `(used, capacity)` of the originator table. At capacity the
    /// least-recently-heard originator is evicted to admit a new one, so a
    /// saturated table changes what the candidate set means.
    fn originator_occupancy(&self) -> (usize, usize) {
        self.inner.router().originator_occupancy()
    }

    // --- mesh authentication --------------------------------------------

    /// Enable mesh authentication with this node's `keypair`, the
    /// `cert` attesting its membership, and the mesh `anchor` every peer's
    /// credentials are verified against.
    ///
    /// From here the router signs the OGMs it emits and rejects incoming ones
    /// that do not verify — an unsigned OGM, or one signed under a foreign
    /// anchor, never becomes a route. Installing auth deliberately resets
    /// learned routing state: it was learned under a different (or no) trust
    /// regime.
    ///
    /// Pair this with [`set_epoch_unix`](Self::set_epoch_unix). Certificate
    /// validity is judged in unix seconds while `tick` counts monotonic
    /// milliseconds from zero, so without an epoch the auth clock never leaves
    /// 0 and every validity window is judged against the wrong time.
    fn set_auth(&mut self, keypair: &PyKeypair, cert: &PyMembershipCert, anchor: &PyTrustAnchor) {
        self.inner
            .router_mut()
            .set_auth(OgmAuth::new(keypair.to_keypair(), cert.0, anchor.0));
    }

    /// Pin the wall-clock unix time that `tick(0)` corresponds to, so
    /// certificate validity is judged against a real clock while the caller
    /// keeps driving a monotonic `now` from zero. Each `tick` then advances
    /// the auth clock to `epoch_unix + now`.
    fn set_epoch_unix(&mut self, epoch_unix: u64) {
        self.inner.set_epoch_unix(epoch_unix);
    }

    /// Set the fail-closed policy: with `require` true and no certificate
    /// installed, the node goes `auth_locked` — completely inert on the mesh —
    /// rather than falling back to open, unauthenticated operation.
    fn set_require_auth(&mut self, require: bool) {
        self.inner.router_mut().set_require_auth(require);
    }

    /// Whether mesh authentication is installed on this node.
    #[getter]
    fn auth_enabled(&self) -> bool {
        self.inner.router().auth().is_some()
    }

    /// Whether this node is required to authenticate but holds no certificate
    /// — inert on the mesh until one is installed.
    #[getter]
    fn auth_locked(&self) -> bool {
        self.inner.router().auth_locked()
    }

    /// This node's own membership certificate, if auth is enabled.
    fn own_cert(&self) -> Option<PyMembershipCert> {
        self.inner
            .router()
            .auth()
            .map(|auth| PyMembershipCert(*auth.own_cert()))
    }

    /// Ingest a root-signed revocation, returning whether it was newly
    /// recorded. From here the named node's frames are dropped and its routes
    /// purged, and this node re-floods the record on its own OGMs until its
    /// budget is spent. A no-op returning `False` when auth is disabled.
    fn ingest_revocation(&mut self, record: &PyRevocationRecord) -> bool {
        self.inner
            .router_mut()
            .ingest_revocation(&record.0, self.last_now)
    }

    /// Every MAC this node currently enforces a revocation against.
    fn revoked_macs(&self) -> Vec<PyMac> {
        self.inner
            .router()
            .auth()
            .map(|auth| auth.revoked_macs().map(PyMac).collect())
            .unwrap_or_default()
    }

    /// Every neighbor whose membership certificate this node has verified and
    /// cached — the peers it has actually admitted to the mesh, as distinct
    /// from the ones it merely has a route to.
    fn neighbor_macs(&self) -> Vec<PyMac> {
        self.inner
            .router()
            .auth()
            .map(|auth| auth.neighbors().iter().map(|n| PyMac(n.cert.mac)).collect())
            .unwrap_or_default()
    }

    /// Whether `mac` currently holds a valid next-hop proof — it answered a
    /// challenge with the pairwise key for the address it claims, recently
    /// enough that the proof has not lapsed.
    ///
    /// Only a proven neighbor can be selected as a next hop, so this is how a
    /// probe tells "still being challenged" apart from "unreachable" when
    /// `best_next_hop` is `None` but `paths` is not empty. Always `True` on an
    /// unauthenticated mesh, which has no pairwise keys to prove with.
    ///
    /// Evaluated at the driver's last-ticked clock, the same instant the
    /// routing tables were last recomputed at.
    fn proof_current(&self, mac: PyMac) -> bool {
        self.inner.router().proof_current(self.last_now, mac.0)
    }

    /// The verified certificate this node holds for neighbor `mac`, if it has
    /// admitted it at all.
    fn neighbor_cert(&self, mac: PyMac) -> Option<PyMembershipCert> {
        self.inner
            .router()
            .auth()?
            .neighbor_cert(mac.0)
            .map(|(cert, _fp)| PyMembershipCert(cert))
    }

    /// Resolve the current egress interface(s) for `dest`, if routable —
    /// read-only introspection; `tick` already resolves this internally on
    /// the send path.
    fn get_egress_interface(&mut self, dest: PyMac) -> Option<PyEgressInterface> {
        match self
            .inner
            .router_mut()
            .get_egress_interface(self.last_now, dest.0)
        {
            Some(EgressInterface::All) => Some(PyEgressInterface {
                all: true,
                interface: None,
            }),
            Some(EgressInterface::Interface(idx)) => Some(PyEgressInterface {
                all: false,
                interface: Some(idx),
            }),
            None => None,
        }
    }
}
