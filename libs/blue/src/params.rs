//! Deployment parameters for the host-side BLE link.
//!
//! Split out from `std_link.rs` — which speaks BlueZ over D-Bus and so
//! only exists on Linux — because this is plain configuration with no
//! platform dependency. Keeping it portable lets a host node's config parsing
//! and CLI plumbing compile on any OS, with only the link construction itself
//! failing on a platform that has no BlueZ.

use core::time::Duration;

/// Deployment parameters for a `StdBleLink`.
///
/// Not intra-doc-linked to that type on purpose: it only exists on Linux, so
/// the link would dangle on every other host.
pub struct BleLinkParams {
    /// BlueZ adapter to use (e.g. `hci0`). `None` selects the system's
    /// default adapter, which is the right choice on a host with one
    /// controller.
    pub adapter: Option<String>,
    /// How long each fragment's advertisement stays registered with BlueZ.
    ///
    /// The airtime knob, and the one value here worth tuning per deployment.
    /// It must outlast the on-air repeat interval this crate explicitly
    /// requests (`ADVERTISING_INTERVAL` in `std_link.rs`,
    /// `min_interval`/`max_interval` on the `Advertisement`) by enough to
    /// cover several repeats, not just one — a single on-air transmission is
    /// one coin flip against a scanner that isn't listening at that exact
    /// moment. Raising it costs latency directly: a frame takes
    /// `dwell × fragment_count`, up to 14 fragments.
    pub advertise_dwell: Duration,
}

impl BleLinkParams {
    /// Default per-fragment dwell: 150 ms, giving several repeats at the
    /// 20 ms advertising interval before the advertising set is torn down.
    /// Confirmed via `btmon` against a real controller — see
    /// `libs/blue/CLAUDE.md`.
    pub const DEFAULT_ADVERTISE_DWELL: Duration = Duration::from_millis(150);
}

impl Default for BleLinkParams {
    fn default() -> Self {
        Self {
            adapter: None,
            advertise_dwell: Self::DEFAULT_ADVERTISE_DWELL,
        }
    }
}
