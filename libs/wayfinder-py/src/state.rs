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

use core::time::Duration;

use interfaces::frame::Mac;
use pyo3::prelude::*;
use wayfinder::LinkQualityRecord;
use wayfinder::batman::NeighborStats;
use wayfinder::batman::OriginatorRecord;
use wayfinder::interfaces::time::Millis;

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

impl PyNeighborStats {
    /// Project one path, as of the driver's `now`.
    ///
    /// **`now` is not decoration.** The engine stores `last_heard` as a
    /// `Millis` — a four-byte stamp that wraps every 49.7 days — and this
    /// field is a *non-wrapping* millisecond count that Python does arithmetic
    /// on (`ml`'s feature extractor computes `now_ms - last_heard_ms`, and
    /// `sim` takes `max()` over it). Handing out the raw stamp would move a
    /// hazard Rust's type system now catches into a language that cannot,
    /// under a name and a docstring that both still promise the old meaning.
    ///
    /// So it is reconstructed rather than read: `elapsed_since` is
    /// wrap-correct, and subtracting it from the driver's own full-width clock
    /// recovers exactly the value this field carried before the stamp shrank.
    fn project(stats: &NeighborStats, now: Duration) -> Self {
        // Destructured (not field-accessed) so a field added to
        // `NeighborStats` is a compile error here instead of silently never
        // reaching Python.
        let NeighborStats {
            neighbor_ident,
            last_tq,
            last_seqno,
            last_heard,
            interval_estimate_ms,
        } = stats;
        Self {
            neighbor: PyMac(*neighbor_ident),
            last_tq: *last_tq,
            last_seqno: *last_seqno,
            last_heard_ms: absolute_ms(now, *last_heard),
            interval_estimate_ms: u64::from(*interval_estimate_ms),
        }
    }
}

/// Recover the absolute, non-wrapping millisecond reading a `Millis` stamp was
/// taken at, given the driver's current full-width clock.
///
/// Saturates at zero, which is only reachable for a stamp from before this
/// driver's clock started — there is no such stamp in a live table.
fn absolute_ms(now: Duration, stamp: Millis) -> u64 {
    let elapsed = u64::from(Millis::from_duration(now).elapsed_since(stamp));
    (now.as_millis().min(u128::from(u64::MAX)) as u64).saturating_sub(elapsed)
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
    /// the relay of the best-TQ path — or `None` when no path is currently
    /// usable. Equal to `originator` when the destination is a direct
    /// neighbor.
    ///
    /// `None` with a non-empty `paths` means every known relay is still
    /// unproven: on an authenticated mesh a next hop must answer a challenge
    /// before it can carry traffic. Probe it with `PyDriver.proof_current`.
    pub best_next_hop: Option<PyMac>,
    /// Transmission quality (0..=255) of the currently selected path — the
    /// best among *selectable* paths, not across all known ones; the metric
    /// `best_next_hop` is selected by.  Zero when nothing is selectable,
    /// including while every path's neighbor is still unproven.
    pub max_tq: u8,
    /// Sequence number of the freshest OGM accepted via *any* path. Per-path
    /// lag is measured against this.
    pub last_seqno: u32,
    /// Engine clock, in ms, when this originator was last heard via any path.
    pub last_heard_ms: u64,
    /// The candidate paths, at most four. Includes the selected one.
    pub paths: Vec<PyNeighborStats>,
}

impl PyOriginatorRecord {
    /// Project one originator and its paths, as of the driver's `now`. See
    /// [`PyNeighborStats::project`] for why the clock is a parameter.
    pub(crate) fn project(record: &OriginatorRecord, now: Duration) -> Self {
        // Destructured for the same reason as `PyNeighborStats::project`: a new
        // `OriginatorRecord` field must fail to compile here, not vanish.
        let OriginatorRecord {
            last_heard,
            neighbor_ident,
            best_next_hop,
            max_tq,
            last_seqno,
            // Re-flood dedup bookkeeping, not routing state a sim inspects.
            resync_watch: _,
            paths,
        } = record;
        Self {
            originator: PyMac(*neighbor_ident),
            best_next_hop: best_next_hop.map(PyMac),
            max_tq: *max_tq,
            last_seqno: *last_seqno,
            last_heard_ms: absolute_ms(now, *last_heard),
            paths: paths
                .iter()
                .map(|p| PyNeighborStats::project(p, now))
                .collect(),
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
