//! Python-visible mirrors of the router's *observable* routing state.
//!
//! Read-only projections of what a live `CentralRouter` holds, for driving a
//! simulated node's feature extraction from Python. Deliberately the same set
//! `wayfinder_server::RouterAdapter` projects for the management API: a real
//! node can serve exactly these fields over the wire, so anything derived from
//! them here is also derivable on hardware at inference time.
//!
//! `Duration` fields are flattened to whole milliseconds, matching the
//! `now_ms` the simulation already ticks on.

use interfaces::frame::Mac;
use pyo3::prelude::*;
use wayfinder::LinkQualityRecord;
use wayfinder::batman::NeighborStats;
use wayfinder::batman::OriginatorRecord;

use crate::types::PyMac;

/// One candidate path to an originator, via a particular relaying neighbor —
/// mirrors `batman::NeighborStats`.
///
/// BATMAN keeps up to four of these per originator and forwards over the
/// best-TQ one; they are the alternatives any route-selection policy chooses
/// between.
#[pyclass(module = "wayfinder_py", get_all, frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyNeighborStats {
    /// The immediate neighbor relaying OGMs for this path.
    pub neighbor: PyMac,
    /// Transmission quality (0..=255) of the most recent OGM on this path,
    /// after per-hop penalty and any local-link clamp.
    pub last_tq: u8,
    /// Sequence number of the most recent OGM accepted on this path.
    pub last_seqno: u32,
    /// Engine clock, in ms, when this path was last refreshed.
    pub last_heard_ms: u64,
    /// Slow-decaying peak hold of the interval between successive OGMs on this
    /// path, in ms — the cadence staleness is judged against. Zero until a
    /// second OGM provides a first gap to measure.
    pub interval_estimate_ms: u64,
}

impl From<&NeighborStats> for PyNeighborStats {
    fn from(stats: &NeighborStats) -> Self {
        // Destructured (not field-accessed) so a field added to
        // `NeighborStats` is a compile error here instead of silently never
        // reaching Python.
        let NeighborStats {
            neighbor_ident,
            last_tq,
            last_seqno,
            last_heard,
            interval_estimate,
        } = stats;
        Self {
            neighbor: PyMac(*neighbor_ident),
            last_tq: *last_tq,
            last_seqno: *last_seqno,
            last_heard_ms: last_heard.as_millis() as u64,
            interval_estimate_ms: interval_estimate.as_millis() as u64,
        }
    }
}

/// A known destination and every candidate path to it — mirrors
/// `batman::OriginatorRecord`.
#[pyclass(module = "wayfinder_py", get_all, frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyOriginatorRecord {
    /// The destination this record describes.
    ///
    /// Named `neighbor_ident` on the Rust `OriginatorRecord`, which reads as
    /// though it were a relay; it is in fact the originator's own address (see
    /// `BatmanEngine`'s insertion site, and `neighbor_count`, which tests
    /// `best_next_hop == neighbor_ident` to mean "reached directly"). Renamed
    /// at this boundary rather than propagating the confusion into Python.
    pub originator: PyMac,
    /// The next hop packets for this originator are currently forwarded to —
    /// the relay of the best-TQ path. Equal to `originator` when the
    /// destination is a direct neighbor.
    pub best_next_hop: PyMac,
    /// The highest transmission quality (0..=255) across all known paths; the
    /// metric `best_next_hop` is selected by.
    pub max_tq: u8,
    /// Sequence number of the freshest OGM accepted via *any* path. Per-path
    /// lag is measured against this.
    pub last_seqno: u32,
    /// Engine clock, in ms, when this originator was last heard via any path.
    pub last_heard_ms: u64,
    /// The candidate paths, at most four. Includes the selected one.
    pub paths: Vec<PyNeighborStats>,
}

impl From<&OriginatorRecord> for PyOriginatorRecord {
    fn from(record: &OriginatorRecord) -> Self {
        // Destructured for the same reason as `PyNeighborStats::from`: a new
        // `OriginatorRecord` field must fail to compile here, not vanish.
        let OriginatorRecord {
            last_heard,
            neighbor_ident,
            best_next_hop,
            max_tq,
            last_seqno,
            paths,
        } = record;
        Self {
            originator: PyMac(*neighbor_ident),
            best_next_hop: PyMac(*best_next_hop),
            max_tq: *max_tq,
            last_seqno: *last_seqno,
            last_heard_ms: last_heard.as_millis() as u64,
            paths: paths.iter().map(PyNeighborStats::from).collect(),
        }
    }
}

/// Local link quality to one neighbor on one interface — mirrors
/// `wayfinder::link_quality::LinkQualityRecord`.
///
/// Distinct from a path's TQ, which is end-to-end to an originator: this is
/// the physical-layer health of the single hop to that neighbor. A row
/// exists for every neighbor/interface pair a frame has been received on,
/// but `ewma_quality` is `None` unless the carrier supplied real
/// `LinkMetrics` on receive — a metric-less link (raw L2, UDP, Unix) has no
/// signal to measure, which is not the same as measuring zero.
#[pyclass(module = "wayfinder_py", get_all, frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyLinkQualityRecord {
    /// The neighbor this row describes.
    pub neighbor: PyMac,
    /// The interface index the neighbor was observed on.
    pub iface_idx: usize,
    /// EWMA-smoothed quality on the 0..=255 scale, or `None` on a link that
    /// has never carried a physical-layer measurement.  `None` is *unknown*,
    /// not zero: treat it as missing data rather than a bad link.
    pub ewma_quality: Option<u8>,
    /// How many frames have been received on this pair, including unmeasured
    /// ones — so it can be non-zero while `ewma_quality` is `None`.
    pub sample_count: u32,
}

impl From<&LinkQualityRecord<Mac>> for PyLinkQualityRecord {
    fn from(record: &LinkQualityRecord<Mac>) -> Self {
        // Destructured for the same reason as `PyNeighborStats::from`.
        let LinkQualityRecord {
            neighbor,
            iface_idx,
            ewma_quality,
            sample_count,
        } = record;
        Self {
            neighbor: PyMac(*neighbor),
            iface_idx: *iface_idx,
            ewma_quality: *ewma_quality,
            sample_count: *sample_count,
        }
    }
}
