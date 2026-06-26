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
use interfaces::{frame::MeshIdentifier, link::LinkMetrics};

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
    /// EWMA-smoothed quality on the 0..=255 scale.
    pub ewma_quality: u8,
    /// Number of samples folded into the EWMA.  Saturates at `u32::MAX`.
    pub sample_count: u32,
}

/// Fixed-capacity table of per-(neighbor, interface) link-quality estimates.
pub struct LinkQualityTable<Ident: MeshIdentifier> {
    entries: HVec<LinkQualityRecord<Ident>, LINK_QUALITY_CAPACITY>,
}

impl<Ident: MeshIdentifier> Default for LinkQualityTable<Ident> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Ident: MeshIdentifier> LinkQualityTable<Ident> {
    /// Create an empty table.
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

    /// Fold a new normalized quality sample for `(neighbor, iface_idx)` into
    /// the table.  Creates a fresh entry if the pair has not been seen
    /// before, evicting the weakest existing entry when the table is at
    /// capacity.
    pub fn update(&mut self, neighbor: Ident, iface_idx: usize, sample: u8) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.neighbor == neighbor && e.iface_idx == iface_idx)
        {
            // EWMA: new = (sample + (2^k - 1) * prev) / 2^k, with k = EWMA_SHIFT.
            let prev = e.ewma_quality as u16;
            let alpha_denom: u16 = 1 << EWMA_SHIFT;
            e.ewma_quality = ((sample as u16 + (alpha_denom - 1) * prev) / alpha_denom) as u8;
            e.sample_count = e.sample_count.saturating_add(1);
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
    /// iface_idx)`, or `None` if the pair has not been observed.  Used to clamp
    /// an OGM's advertised TQ by the link we actually measure to the relaying
    /// neighbor (the `local_quality` argument to `BatmanEngine::handle_rx`).
    pub fn quality_for(&self, neighbor: Ident, iface_idx: usize) -> Option<u8> {
        self.entries
            .iter()
            .find(|e| e.neighbor == neighbor && e.iface_idx == iface_idx)
            .map(|e| e.ewma_quality)
    }

    /// Borrow the table as a contiguous slice of records.  Used by
    /// inspection APIs (e.g. the management RPC) that need to expose the
    /// full link-quality snapshot to external callers.
    pub fn records(&self) -> &[LinkQualityRecord<Ident>] {
        &self.entries
    }
}

/// Map raw [`LinkMetrics`] to a 0..=255 normalized quality score.
///
/// When `metrics.quality` is `Some`, it is returned verbatim — the driver
/// has already done the mapping.  Otherwise the function applies a default
/// curve tuned for LoRa-like radios:
///
/// * RSSI is mapped linearly across `-120..=-50 dBm` into `0..=255`.
/// * SNR adds a small bias (≈3 quality units per dB, clamped to ±60).
/// * Missing fields default to the worst credible value (`-120 dBm` / `0
///   dB`), so a frame with no metrics scores 0 rather than a misleading
///   non-zero value.
pub fn normalize_quality(metrics: &LinkMetrics) -> u8 {
    if let Some(q) = metrics.quality {
        return q;
    }

    let rssi = metrics.rssi_dbm.unwrap_or(-120);
    let snr = metrics.snr_db.unwrap_or(0);

    let rssi_offset = (rssi as i32 + 120).clamp(0, 70);
    let rssi_score = (rssi_offset * 255 / 70) as i16;

    let snr_bias = ((snr as i16) * 3).clamp(-60, 60);

    (rssi_score + snr_bias).clamp(0, 255) as u8
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

        fn ewma_for(&self, neighbor: Ident, iface_idx: usize) -> Option<u8> {
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
        table.update(2, 0, 200);
        assert_eq!(table.best_interface_for(2), Some(0));
        assert_eq!(table.ewma_for(2, 0), Some(200));
        assert_eq!(table.sample_count_for(2, 0), Some(1));
        table.assert_invariants();
    }

    #[test]
    fn best_interface_picks_highest_quality_for_neighbor() {
        let mut table = LinkQualityTable::<u8>::new();
        // Three interfaces all carrying neighbor 5, varying qualities.
        table.update(5, 0, 100);
        table.update(5, 1, 250);
        table.update(5, 2, 50);
        assert_eq!(table.best_interface_for(5), Some(1));
        table.assert_invariants();
    }

    #[test]
    fn ewma_smooths_repeated_samples() {
        let mut table = LinkQualityTable::<u8>::new();
        // First sample inserts verbatim.
        table.update(2, 0, 0);
        assert_eq!(table.ewma_for(2, 0), Some(0));

        // Subsequent identical-value samples don't move the average.
        for _ in 0..10 {
            table.update(2, 0, 0);
        }
        assert_eq!(table.ewma_for(2, 0), Some(0));

        // A sudden high sample only moves the EWMA by a fraction of the
        // delta — alpha = 1/4, so 0 + (200 - 0)/4 = 50.
        table.update(2, 0, 200);
        assert_eq!(table.ewma_for(2, 0), Some(50));

        // Several more high samples should converge toward the new level.
        for _ in 0..20 {
            table.update(2, 0, 200);
        }
        let q = table.ewma_for(2, 0).unwrap();
        assert!(
            q > 195,
            "EWMA should converge toward 200 after sustained high samples, got {q}"
        );
        table.assert_invariants();
    }

    #[test]
    fn sample_count_increments_on_each_update() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(7, 1, 128);
        table.update(7, 1, 128);
        table.update(7, 1, 128);
        assert_eq!(table.sample_count_for(7, 1), Some(3));
    }

    #[test]
    fn different_neighbors_do_not_interfere() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, 200);
        table.update(3, 0, 50);
        // Neighbor 2 on iface 0 stays strong; neighbor 3 on iface 0 stays weak.
        assert_eq!(table.ewma_for(2, 0), Some(200));
        assert_eq!(table.ewma_for(3, 0), Some(50));
        assert_eq!(table.best_interface_for(2), Some(0));
        assert_eq!(table.best_interface_for(3), Some(0));
        table.assert_invariants();
    }

    #[test]
    fn lookup_for_unknown_neighbor_returns_none() {
        let mut table = LinkQualityTable::<u8>::new();
        table.update(2, 0, 200);
        assert_eq!(table.best_interface_for(99), None);
    }

    #[test]
    fn capacity_eviction_replaces_weakest_entry() {
        let mut table = LinkQualityTable::<u8>::new();
        // Fill the table with distinct neighbors, all with high quality
        // except one weak entry.
        for n in 0..(LINK_QUALITY_CAPACITY as u16) {
            let q = if n == 7 { 10 } else { 200 };
            table.update(n as u8, 0, q);
        }
        assert_eq!(table.entries.len(), LINK_QUALITY_CAPACITY);

        // Inserting one more entry should evict the weak (neighbor 7) row.
        table.update(200, 0, 180);
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
        assert_eq!(normalize_quality(&metrics), 42);
    }

    #[test]
    fn normalize_floors_at_zero_for_very_weak_signal() {
        let metrics = LinkMetrics {
            rssi_dbm: Some(-130),
            snr_db: Some(-20),
            quality: None,
        };
        assert_eq!(normalize_quality(&metrics), 0);
    }

    #[test]
    fn normalize_saturates_at_255_for_very_strong_signal() {
        let metrics = LinkMetrics {
            rssi_dbm: Some(-30),
            snr_db: Some(20),
            quality: None,
        };
        assert_eq!(normalize_quality(&metrics), 255);
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
    fn normalize_treats_missing_fields_as_worst_credible() {
        // No metrics at all → 0.  A driver that can't measure must not
        // accidentally win the egress decision over one that can.
        let blank = LinkMetrics::default();
        assert_eq!(normalize_quality(&blank), 0);
    }
}
