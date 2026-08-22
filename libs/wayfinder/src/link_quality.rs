//! Per-(neighbor, interface) link-quality tracking used to bias the egress
//! interface decision toward the radio with the best observed signal.
//!
//! The table maintains a single exponentially-weighted moving average of
//! normalized quality (0..=255) for each `(neighbor, iface_idx)` pair the
//! router has seen.  On every received frame the router calls [`update`]
//! with a normalized sample; on every egress decision it calls
//! [`best_interface_for`] to pick the strongest path.
//!
//! Quality is normalized at the point of update: drivers that already know
//! how to produce a 0..=255 quality can set [`LinkMetrics::quality`]
//! directly, and otherwise [`normalize_quality`] maps RSSI/SNR into the same
//! space.
//!
//! [`update`]: LinkQualityTable::update
//! [`best_interface_for`]: LinkQualityTable::best_interface_for

use heapless::Vec as HVec;
use interfaces::frame::MeshIdentifier;
use interfaces::link::LinkMetrics;
use tracing::debug;

/// Maximum number of distinct `(neighbor, iface_idx)` entries tracked.
///
/// Sized to comfortably cover small mesh deployments while keeping the
/// per-router footprint bounded for embedded targets.
pub const LINK_QUALITY_CAPACITY: usize = 64;

/// EWMA blending weight as a power-of-two divisor.  With `EWMA_SHIFT = 2`
/// the update is `new = (sample + 3 * prev) / 4`, i.e. alpha = 1/4 — heavy
/// smoothing while still responding to sustained signal changes within a
/// few OGM intervals.
const EWMA_SHIFT: u16 = 2;

/// One row in the link-quality table.
#[derive(Debug, Clone, Copy)]
pub struct LinkQualityRecord<Ident> {
    /// The neighbor whose link quality this row describes.
    pub neighbor: Ident,
    /// The physical interface this neighbor was observed on.
    pub iface_idx: usize,
    /// EWMA-smoothed quality on the 0..=255 scale, or `None` when this link
    /// has never carried a physical-layer measurement.
    ///
    /// `None` is not "quality zero": a metric-less transport (raw L2, UDP,
    /// Unix) has no signal to report on any frame, and a wired neighbor is
    /// typically excellent. Callers must render it as *unknown* and must not
    /// substitute a number for it — the row still exists, so a neighbor heard
    /// only over such a link is listed rather than hidden.
    ///
    /// Ordering does the right thing for the egress decision without extra
    /// care at the call sites: `None < Some(0)`, so an unmeasurable link never
    /// outranks one that reported a real value.
    pub ewma_quality: Option<u8>,
    /// Number of frames received on this `(neighbor, interface)` pair,
    /// counting those that carried no measurement.  Saturates at `u32::MAX`.
    ///
    /// Not the number of samples in the EWMA — an unmeasured frame is evidence
    /// the neighbor is *there*, which is worth reporting even though it moves
    /// no average.
    pub sample_count: u32,
}

/// Fixed-capacity table of per-(neighbor, interface) link-quality estimates.
pub struct LinkQualityTable<Ident: MeshIdentifier, const CAP: usize = LINK_QUALITY_CAPACITY> {
    entries: HVec<LinkQualityRecord<Ident>, CAP>,
}

impl<Ident: MeshIdentifier, const CAP: usize> Default for LinkQualityTable<Ident, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Ident: MeshIdentifier, const CAP: usize> LinkQualityTable<Ident, CAP> {
    /// Create an empty table at this profile's capacity.
    pub fn new() -> Self {
        Self {
            entries: HVec::new(),
        }
    }

    /// Drop every `(neighbor, interface)` quality record, restoring an empty
    /// table.  Used when routing state is invalidated wholesale, e.g. on a
    /// runtime authentication change.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drop every row whose neighbor `is_live` reports `false` for, taking all
    /// of that neighbor's `(neighbor, iface_idx)` entries with it.  Called
    /// after the routing engine purges stale originators, so a neighbor's
    /// link-quality rows can never outlive its presence in the routing table
    /// (otherwise inspection APIs would keep reporting a neighbor as reachable
    /// long after the routing table has forgotten it).
    pub fn retain_live(&mut self, mut is_live: impl FnMut(Ident) -> bool) {
        self.entries.retain(|e| {
            let live = is_live(e.neighbor);
            if !live {
                debug!(
                    neighbor = ?e.neighbor,
                    iface_idx = e.iface_idx,
                    sample_count = e.sample_count,
                    "dropping link-quality entry: neighbor has no live route in the routing table"
                );
            }
            live
        });
    }

    /// Fold a new normalized quality sample for `(neighbor, iface_idx)` into
    /// the table.  Creates a fresh entry if the pair has not been seen
    /// before, evicting the weakest existing entry when the table is at
    /// capacity.
    ///
    /// `sample` is `None` when the frame carried no physical-layer
    /// measurement.  Such a frame still counts toward `sample_count` — it
    /// proves the neighbor is reachable on this interface — but leaves the
    /// quality estimate untouched, so a metric-less link reports *unknown*
    /// rather than a fabricated zero, and one metric-less frame on a radio
    /// link cannot wipe out an estimate built from real samples.
    pub fn update(&mut self, neighbor: Ident, iface_idx: usize, sample: Option<u8>) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.neighbor == neighbor && e.iface_idx == iface_idx)
        {
            e.sample_count = e.sample_count.saturating_add(1);
            if let Some(sample) = sample {
                e.ewma_quality = Some(match e.ewma_quality {
                    // EWMA: new = (sample + (2^k - 1) * prev) / 2^k, k = EWMA_SHIFT.
                    Some(prev) => {
                        let alpha_denom: u16 = 1 << EWMA_SHIFT;
                        ((sample as u16 + (alpha_denom - 1) * prev as u16) / alpha_denom) as u8
                    }
                    // First real measurement on a link that had none: seed the
                    // average verbatim.  Blending against an absent prior would
                    // have to invent one, dragging the estimate toward a value
                    // the radio never reported.
                    None => sample,
                });
            }
            return;
        }

        let new_entry = LinkQualityRecord {
            neighbor,
            iface_idx,
            ewma_quality: sample,
            sample_count: 1,
        };

        if self.entries.push(new_entry).is_err() {
            // Capacity reached — replace the weakest entry.  This biases the
            // table toward retaining links that are actually useful.
            if let Some((idx, _)) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.ewma_quality)
            {
                self.entries[idx] = new_entry;
            }
        }
    }

    /// Return the interface with the highest EWMA quality currently
    /// observed for `neighbor`, or `None` if no entry exists.
    pub fn best_interface_for(&self, neighbor: Ident) -> Option<usize> {
        self.entries
            .iter()
            .filter(|e| e.neighbor == neighbor)
            .max_by_key(|e| e.ewma_quality)
            .map(|e| e.iface_idx)
    }

    /// The current EWMA-smoothed quality (0..=255) for `(neighbor,
    /// iface_idx)`.  Used to clamp an OGM's advertised TQ by the link we
    /// actually measure to the relaying neighbor (the `local_quality` argument
    /// to `BatmanEngine::handle_rx`).
    ///
    /// `None` covers both "the pair has not been observed" and "observed, but
    /// never measurable" — which the caller wants to treat identically, as *no
    /// clamp*.  Clamping by a metric-less link's fabricated 0 would zero every
    /// TQ that passes through it.
    pub fn quality_for(&self, neighbor: Ident, iface_idx: usize) -> Option<u8> {
        self.entries
            .iter()
            .find(|e| e.neighbor == neighbor && e.iface_idx == iface_idx)
            .and_then(|e| e.ewma_quality)
    }

    /// Borrow the table as a contiguous slice of records.  Used by
    /// inspection APIs (e.g. the management RPC) that need to expose the
    /// full link-quality snapshot to external callers.
    pub fn records(&self) -> &[LinkQualityRecord<Ident>] {
        &self.entries
    }
}

/// Map raw [`LinkMetrics`] to a 0..=255 normalized quality score, or `None`
/// when the frame carried no physical-layer measurement at all.
///
/// When `metrics.quality` is `Some`, it is returned verbatim — the driver
/// has already done the mapping.  Otherwise the function applies a default
/// curve tuned for LoRa-like radios:
///
/// * RSSI is mapped linearly across `-120..=-50 dBm` into `0..=255`.
/// * SNR adds a small bias (≈3 quality units per dB, clamped to ±60).
/// * One missing field (but not both) defaults to the worst credible value
///   (`-120 dBm` / `0 dB`), so a partial measurement still scores.
///
/// **All three fields absent returns `None`, not `0`.** That is the case for
/// every frame on a metric-less transport — raw L2, UDP, Unix — where there is
/// no signal to measure rather than a bad one. Scoring it `0` made those links
/// report 0% quality on the management API while carrying traffic perfectly,
/// and would clamp every OGM's TQ through them to zero. `None` also keeps such
/// a link ranked below any real measurement in the egress decision, which is
/// what the old `-120 dBm` floor was reaching for.
pub fn normalize_quality(metrics: &LinkMetrics) -> Option<u8> {
    if let Some(q) = metrics.quality {
        return Some(q);
    }

    if metrics.rssi_dbm.is_none() && metrics.snr_db.is_none() {
        return None;
    }

    let rssi = metrics.rssi_dbm.unwrap_or(-120);
    let snr = metrics.snr_db.unwrap_or(0);

    let rssi_offset = (rssi as i32 + 120).clamp(0, 70);
    let rssi_score = (rssi_offset * 255 / 70) as i16;

    let snr_bias = ((snr as i16) * 3).clamp(-60, 60);

    Some((rssi_score + snr_bias).clamp(0, 255) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl<Ident: MeshIdentifier> LinkQualityTable<Ident> {
        /// Invariant checks for tests: no two rows describe the same
        /// `(neighbor, iface_idx)` pair, and the length matches the
        /// underlying vector.
        fn assert_invariants(&self) {
            for (i, a) in self.entries.iter().enumerate() {
                for b in self.entries.iter().skip(i + 1) {
                    assert!(
                        !(a.neighbor == b.neighbor && a.iface_idx == b.iface_idx),
                        "duplicate (neighbor, iface_idx) entry in table"
                    );
                }
            }
        }

        /// The stored quality cell for a pair: the outer `Option` is "row
        /// exists", the inner one "the row has a measurement".
        fn ewma_for(&self, neighbor: Ident, iface_idx: usize) -> Option<Option<u8>> {
            self.entries
                .iter()
                .find(|e| e.neighbor == neighbor && e.iface_idx == iface_idx)
                .map(|e| e.ewma_quality)
        }

        fn sample_count_for(&self, neighbor: Ident, iface_idx: usize) -> Option<u32> {
            self.entries
                .iter()
                .find(|e| e.neighbor == neighbor && e.iface_idx == iface_idx)
                .map(|e| e.sample_count)
        }
    }

    // ── LinkQualityTable behaviour ────────────────────────────────────────

    #[test]
    fn empty_table_returns_none() {
        let table: LinkQualityTable<u8> = LinkQualityTable::new();
        assert_eq!(table.best_interface_for(1), None);
        table.assert_invariants();
    }

    #[test]
    fn single_update_then_lookup() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, Some(200));
        assert_eq!(table.best_interface_for(2), Some(0));
        assert_eq!(table.ewma_for(2, 0), Some(Some(200)));
        assert_eq!(table.sample_count_for(2, 0), Some(1));
        table.assert_invariants();
    }

    #[test]
    fn best_interface_picks_highest_quality_for_neighbor() {
        let mut table = LinkQualityTable::<u8>::new();
        // Three interfaces all carrying neighbor 5, varying qualities.
        table.update(5, 0, Some(100));
        table.update(5, 1, Some(250));
        table.update(5, 2, Some(50));
        assert_eq!(table.best_interface_for(5), Some(1));
        table.assert_invariants();
    }

    #[test]
    fn ewma_smooths_repeated_samples() {
        let mut table = LinkQualityTable::<u8>::new();
        // First sample inserts verbatim.
        table.update(2, 0, Some(0));
        assert_eq!(table.ewma_for(2, 0), Some(Some(0)));

        // Subsequent identical-value samples don't move the average.
        for _ in 0..10 {
            table.update(2, 0, Some(0));
        }
        assert_eq!(table.ewma_for(2, 0), Some(Some(0)));

        // A sudden high sample only moves the EWMA by a fraction of the
        // delta — alpha = 1/4, so 0 + (200 - 0)/4 = 50.
        table.update(2, 0, Some(200));
        assert_eq!(table.ewma_for(2, 0), Some(Some(50)));

        // Several more high samples should converge toward the new level.
        for _ in 0..20 {
            table.update(2, 0, Some(200));
        }
        let q = table.ewma_for(2, 0).flatten().unwrap();
        assert!(
            q > 195,
            "EWMA should converge toward 200 after sustained high samples, got {q}"
        );
        table.assert_invariants();
    }

    #[test]
    fn sample_count_increments_on_each_update() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(7, 1, Some(128));
        table.update(7, 1, Some(128));
        table.update(7, 1, Some(128));
        assert_eq!(table.sample_count_for(7, 1), Some(3));
    }

    #[test]
    fn different_neighbors_do_not_interfere() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, Some(200));
        table.update(3, 0, Some(50));
        // Neighbor 2 on iface 0 stays strong; neighbor 3 on iface 0 stays weak.
        assert_eq!(table.ewma_for(2, 0), Some(Some(200)));
        assert_eq!(table.ewma_for(3, 0), Some(Some(50)));
        assert_eq!(table.best_interface_for(2), Some(0));
        assert_eq!(table.best_interface_for(3), Some(0));
        table.assert_invariants();
    }

    #[test]
    fn lookup_for_unknown_neighbor_returns_none() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, Some(200));
        assert_eq!(table.best_interface_for(99), None);
    }

    // ── unmeasured links ──────────────────────────────────────────────────
    //
    // A metric-less transport (raw L2, UDP, Unix) reports no physical-layer
    // signal at all.  That is categorically different from a radio measuring
    // a genuinely terrible link, and the table must not conflate the two:
    // scoring "no data" as 0 made every wired neighbor read 0% on the
    // management API's link-quality view.

    #[test]
    fn unmeasured_sample_records_presence_without_quality() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, None);
        // The row exists — the neighbor *was* heard on this interface, and an
        // inspection API should still list it …
        assert_eq!(table.sample_count_for(2, 0), Some(1));
        assert_eq!(table.best_interface_for(2), Some(0));
        // … but it carries no quality, rather than a fabricated zero.
        assert_eq!(table.ewma_for(2, 0), Some(None));
        table.assert_invariants();
    }

    #[test]
    fn unmeasured_samples_never_synthesize_a_quality() {
        let mut table = LinkQualityTable::<u8>::new();
        for _ in 0..20 {
            table.update(2, 0, None);
        }
        assert_eq!(table.ewma_for(2, 0), Some(None));
        assert_eq!(table.sample_count_for(2, 0), Some(20));
        table.assert_invariants();
    }

    #[test]
    fn measured_sample_seeds_ewma_after_unmeasured_history() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, None);
        table.update(2, 0, None);
        // The first real measurement seeds the average verbatim; blending it
        // against an absent prior would drag it toward a value never observed.
        table.update(2, 0, Some(200));
        assert_eq!(table.ewma_for(2, 0), Some(Some(200)));
        assert_eq!(table.sample_count_for(2, 0), Some(3));
        table.assert_invariants();
    }

    #[test]
    fn unmeasured_sample_does_not_erase_a_measured_estimate() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, Some(200));
        // One metric-less frame on an otherwise-measured radio link must not
        // discard the estimate built from real samples.
        table.update(2, 0, None);
        assert_eq!(table.ewma_for(2, 0), Some(Some(200)));
        assert_eq!(table.sample_count_for(2, 0), Some(2));
        table.assert_invariants();
    }

    #[test]
    fn quality_for_is_none_on_an_unmeasured_link() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, None);
        // `quality_for` feeds the OGM TQ clamp.  An unmeasured link must yield
        // no clamp at all — clamping by a synthesized 0 would zero every TQ.
        assert_eq!(table.quality_for(2, 0), None);
    }

    #[test]
    fn best_interface_prefers_a_measured_link_over_an_unmeasured_one() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(5, 0, None);
        table.update(5, 1, Some(10));
        // Even a weak *measurement* beats no measurement: an unmeasurable
        // link must not win the egress decision on a fabricated score.
        assert_eq!(table.best_interface_for(5), Some(1));
        table.assert_invariants();
    }

    #[test]
    fn best_interface_still_resolves_when_every_link_is_unmeasured() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(5, 0, None);
        table.update(5, 1, None);
        // The all-wired host case: no link is measurable, but the neighbor is
        // still reachable and egress must resolve to *some* interface.
        assert!(table.best_interface_for(5).is_some());
        table.assert_invariants();
    }

    #[test]
    fn retain_live_drops_dead_neighbor() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, Some(200));
        table.update(3, 0, Some(200));
        table.retain_live(|neighbor| neighbor == 2);
        assert_eq!(table.best_interface_for(2), Some(0));
        assert_eq!(table.best_interface_for(3), None);
        table.assert_invariants();
    }

    #[test]
    fn retain_live_drops_all_ifaces_of_dead_neighbor() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(5, 0, Some(200));
        table.update(5, 1, Some(150));
        table.update(5, 2, Some(100));
        table.retain_live(|neighbor| neighbor != 5);
        assert_eq!(table.quality_for(5, 0), None);
        assert_eq!(table.quality_for(5, 1), None);
        assert_eq!(table.quality_for(5, 2), None);
        table.assert_invariants();
    }

    #[test]
    fn retain_live_keeps_all_ifaces_of_live_neighbor() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(5, 0, Some(200));
        table.update(5, 1, Some(150));
        table.update(5, 2, Some(100));
        table.retain_live(|neighbor| neighbor == 5);
        assert_eq!(table.quality_for(5, 0), Some(200));
        assert_eq!(table.quality_for(5, 1), Some(150));
        assert_eq!(table.quality_for(5, 2), Some(100));
        table.assert_invariants();
    }

    #[test]
    fn retain_live_on_empty_is_noop() {
        let mut table = LinkQualityTable::<u8>::new();
        table.retain_live(|_| false);
        assert_eq!(table.best_interface_for(1), None);
        table.assert_invariants();
    }

    #[test]
    fn capacity_eviction_replaces_weakest_entry() {
        let mut table = LinkQualityTable::<u8>::new();
        // Fill the table with distinct neighbors, all with high quality
        // except one weak entry.
        for n in 0..(LINK_QUALITY_CAPACITY as u16) {
            let q = if n == 7 { 10 } else { 200 };
            table.update(n as u8, 0, Some(q));
        }
        assert_eq!(table.entries.len(), LINK_QUALITY_CAPACITY);

        // Inserting one more entry should evict the weak (neighbor 7) row.
        table.update(200, 0, Some(180));
        assert_eq!(
            table.best_interface_for(7),
            None,
            "weakest entry should have been evicted"
        );
        assert_eq!(table.best_interface_for(200), Some(0));
        assert_eq!(table.entries.len(), LINK_QUALITY_CAPACITY);
        table.assert_invariants();
    }

    // ── normalize_quality curve ───────────────────────────────────────────

    #[test]
    fn normalize_uses_explicit_quality_when_set() {
        let metrics = LinkMetrics {
            rssi_dbm: Some(-30),
            snr_db: Some(20),
            quality: Some(42),
        };
        assert_eq!(normalize_quality(&metrics), Some(42));
    }

    #[test]
    fn normalize_floors_at_zero_for_very_weak_signal() {
        let metrics = LinkMetrics {
            rssi_dbm: Some(-130),
            snr_db: Some(-20),
            quality: None,
        };
        // A measured-but-terrible link is a real 0 — distinct from `None`.
        assert_eq!(normalize_quality(&metrics), Some(0));
    }

    #[test]
    fn normalize_saturates_at_255_for_very_strong_signal() {
        let metrics = LinkMetrics {
            rssi_dbm: Some(-30),
            snr_db: Some(20),
            quality: None,
        };
        assert_eq!(normalize_quality(&metrics), Some(255));
    }

    #[test]
    fn normalize_scores_a_partial_measurement() {
        // Only SNR available: still a measurement, so the curve applies with
        // RSSI at its worst-credible default rather than reporting "no data".
        let metrics = LinkMetrics {
            rssi_dbm: None,
            snr_db: Some(10),
            quality: None,
        };
        assert_eq!(normalize_quality(&metrics), Some(30));
    }

    #[test]
    fn normalize_orders_typical_lora_strong_above_weak() {
        let weak = LinkMetrics {
            rssi_dbm: Some(-115),
            snr_db: Some(-5),
            quality: None,
        };
        let strong = LinkMetrics {
            rssi_dbm: Some(-60),
            snr_db: Some(10),
            quality: None,
        };
        assert!(
            normalize_quality(&strong) > normalize_quality(&weak),
            "strong link should score higher than weak"
        );
    }

    #[test]
    fn normalize_reports_no_measurement_when_every_field_is_absent() {
        // No metrics at all → `None`, not a fabricated 0.  This is what a
        // metric-less transport (raw L2, UDP, Unix) reports on every frame;
        // scoring it 0 would both misreport the link as dead-quality and
        // wrongly clamp the OGM TQ through it.
        let blank = LinkMetrics::default();
        assert_eq!(normalize_quality(&blank), None);
    }
}
