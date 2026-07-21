//! Per-link participation features ([`LinkFeatures`]).
//!
//! This lives in the `no_std`, allocation-free core (unlike [`config`], which
//! needs `alloc` for its `String`/`Vec` fields) because [`CentralRouter`] stores
//! a `LinkFeatures` per interface and gates traffic on it on every embedded
//! deployment, where `alloc` may be absent.  The serde derives — used only to
//! parse the `features:` config block on the host — are gated behind the
//! `alloc` feature, so the plain flag struct is available everywhere while the
//! (de)serialization machinery is compiled only where the config layer is.
//!
//! [`config`]: crate::config
//! [`CentralRouter`]: crate::CentralRouter

/// One link's keep-alive heartbeat cadence.  Carried on
/// [`LinkFeatures::tx_keepalive`] rather than as a separate `Driver`
/// constructor parameter, so it rides along on the per-link config/features
/// plumbing that already exists instead of adding a parallel one.
// `deny_unknown_fields` turns a misspelled key (e.g. `intervall_ms`) into a
// hard parse error rather than a silent fall-back to the default cadence —
// the same reasoning `LinkFeatures` documents for its own use of this
// attribute.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "alloc", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "alloc", serde(default, deny_unknown_fields))]
pub struct KeepAliveConfig {
    /// The heartbeat period, in milliseconds.
    pub interval_ms: u64,
}

impl KeepAliveConfig {
    /// Default keep-alive cadence (5 s) used when a `tx_keepalive: {}` block
    /// omits `interval_ms`.
    pub const fn default_interval_ms() -> u64 {
        5_000
    }

    /// This cadence as a [`core::time::Duration`].
    pub fn interval(&self) -> core::time::Duration {
        core::time::Duration::from_millis(self.interval_ms)
    }
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            interval_ms: Self::default_interval_ms(),
        }
    }
}

/// Per-link participation capabilities: one **send** gate and one **receive**
/// gate for each of the two planes — the OGM control plane (topology) and the
/// data plane (unicast, multicast, and broadcast lumped together) — plus the
/// keep-alive heartbeat's transmit schedule.  Each flag is an independent
/// switch on how *this node* takes part in the mesh over *this one link*; the
/// two ends of a link may be configured asymmetrically (a LoRa edge node may
/// [`tx_ogm`](Self::tx_ogm) while a ground station fronting that same mesh
/// does not).
///
/// Every **bool** flag defaults to `true` — a link with no `features:` block,
/// or one that names only the flags it flips, is a fully participating link
/// (the historical behavior). [`tx_keepalive`](Self::tx_keepalive) is the one
/// exception: it defaults to `None` (off), since keep-alives are a new,
/// opt-in traffic class rather than part of the historical baseline. A link
/// that turns some off participates partially. Some illustrative shapes:
///
/// - **ground station fronting a LoRa mesh (reachable)**: only `tx_ogm: false` —
///   hears the edge nodes' OGMs (so they stay visible *and reachable*, since
///   `tx_data` is still on) and bridges data, but stays OGM-silent on the slow
///   link, so it spends no airtime announcing there.
/// - **read-only front / tap**: `tx_ogm: false`, `tx_data: false` — learns the
///   nodes behind the link for local visibility (surfaced via the management
///   API) but advertises them to no one and transmits nothing; a pure observer
///   that never black-holes traffic (see [`tx_data`](Self::tx_data)).
/// - **broadcast-only "terminal" node**: `tx_ogm: false`, `rx_ogm: false` — data
///   flows both ways but no topology is announced or learned; the link is never
///   a transit path.
// `serde(default)` fills every omitted field from the `Default` impl below
// (the single source of the all-true default), so a partial `features:` block
// flips only the flags it names.  `deny_unknown_fields` turns a misspelled gate
// key into a hard parse error rather than a silent no-op — important because
// every flag defaults to *participate*, so a typo would otherwise fail open
// (e.g. `tx_ogmm: false` would leave the node flooding OGMs onto the very link
// it was meant to silence).  `LinkConfig` can't do the same (its `#[serde(
// flatten)]` transport is incompatible with `deny_unknown_fields`), but this
// leaf struct can.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "alloc", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "alloc", serde(default, deny_unknown_fields))]
pub struct LinkFeatures {
    /// Send OGMs on this link: emit this node's own Trickle-paced OGMs *and*
    /// re-flood others' OGMs out this link, announcing topology on it.  `false`
    /// keeps the node OGM-silent here (no own emission, no re-floods) — the
    /// dominant airtime saving on a slow link a ground station only fronts.
    pub tx_ogm: bool,
    /// Receive OGMs on this link: accept inbound OGMs *and learn routes from
    /// them*, so the link may become a next hop.  `false` drops an OGM heard
    /// here before the engine sees it — nothing behind this link is ever
    /// learned, so the node cannot be routed *through* it.
    pub rx_ogm: bool,
    /// Send data-plane traffic (unicast, multicast, *and* broadcast) onto this
    /// link.  `false` transmits no data at all — a listen-only link.  Because
    /// `tx_data` *is* this node's ability to deliver to whatever is behind the
    /// link, it also governs **route re-advertisement**: an originator learned
    /// on a `tx_data`-off link (via [`rx_ogm`](Self::rx_ogm)) is kept in the
    /// local table for visibility but its OGM is *not* re-flooded, so this node
    /// never advertises a route it cannot honor.  That is what makes a
    /// `tx_data`-off, `rx_ogm`-on "read-only front" observe the nodes behind the
    /// link (surfaced via the management API) without black-holing peers that
    /// would otherwise route to them through it.
    pub tx_data: bool,
    /// Receive data-plane traffic (unicast, multicast, *and* broadcast) on this
    /// link: accept it to deliver locally, forward onward, or bridge onto other
    /// links.  `false` drops inbound data before the engine sees it.
    pub rx_data: bool,
    /// Send keep-alive heartbeats on this link at the given cadence. `None`
    /// (the default) disables keep-alive transmission entirely — the
    /// graceful-degradation default, since a neighbor never heard sending one
    /// is never penalized for its silence (see
    /// `BatmanEngine::keepalive_missed`). Reception of keep-alives is always
    /// accepted regardless of this setting — it costs nothing to observe one
    /// opportunistically, so there is no matching `rx_keepalive` gate.
    pub tx_keepalive: Option<KeepAliveConfig>,
}

impl Default for LinkFeatures {
    fn default() -> Self {
        Self {
            tx_ogm: true,
            rx_ogm: true,
            tx_data: true,
            rx_data: true,
            tx_keepalive: None,
        }
    }
}
