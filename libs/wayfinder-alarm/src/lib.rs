//! The node's alarm board: the bounded set of conditions this node currently
//! believes are wrong.
//!
//! A node is already *observable* — `GetMetrics` for here-and-now gauges,
//! `GetLogs` for the record ring — but until now it could not **flag**
//! anything. When something anomalous happens (a flood of frames from an
//! unauthorized source, a run of failed management-API authentications, an OGM
//! replay), the evidence exists only as `trace!` lines in a ring that rolls over
//! in seconds under exactly the load that matters. Reading it requires already
//! watching, already at the right verbosity, and already knowing what to grep
//! for.
//!
//! An alarm survives that burst. It is a latched `(kind, subject)` condition
//! with a first/last timestamp and a coalesced count, held in a fixed-capacity
//! table, readable long after the traffic that caused it stopped.
//!
//! # Two layers
//!
//! [`AlarmBoard`] is plain owned state: no globals, no locks, and an explicit
//! `now_ms` on every method, exactly as `RateEstimator` in the routing core
//! takes its `now`. All of the coalescing, eviction and staleness logic lives
//! there, so it is deterministic and tests on a virtual clock.
//!
//! [`SharedBoard`] wraps one in the cross-target lock, stamps it from the
//! uptime clock, and mirrors new alarms into the log. A process-global instance
//! plus a scoped override ([`with_board`]) is what lets a raise site deep in the
//! routing core reach a board without carrying a handle — the same arrangement
//! `tracing` uses for its `Dispatch`, and for the same reason.
//!
//! ```
//! use wayfinder_alarm::AlarmKind;
//! use wayfinder_alarm::NodeId;
//! use wayfinder_alarm::Severity;
//! use wayfinder_alarm::Subject;
//! use wayfinder_alarm::alarm;
//!
//! let peer = Subject::Node(NodeId::new(&[0x02, 0, 0, 0, 0, 0x07]));
//! alarm!(
//!     Severity::Warning,
//!     AlarmKind::TrafficFlood,
//!     peer,
//!     "fps={}",
//!     4200
//! );
//! ```
//!
//! # Why the scope exists
//!
//! On a real node — a board, or a host running one `wayfinder-tap` — there is
//! one node per process, so the process-global board *is* the node's board and
//! nothing ever sets a scope. The simulator is the exception: it runs many nodes
//! in one process, each a `PyDriver`, and a single merged board would lose
//! precisely the per-node attribution its adversarial scenarios exist to show.
//! Wrapping a node's tick in [`with_board`] restores it.
//!
//! # Storm safety
//!
//! An alarm system that floods under attack is worse than none, so every part of
//! this is bounded by construction: raising an already-present condition
//! coalesces into its row rather than adding one, the table is fixed-capacity
//! with severity-aware eviction, and only a *new* or *escalated* alarm mirrors
//! into the log. Ten thousand frames of a flood produce one row and one log
//! line.
//!
//! # What lives elsewhere
//!
//! Nothing here decides *when* a condition holds. [`AlarmKind`] names the
//! conditions and this crate raises them; the detectors that call it are the
//! callers' business, and belong next to the state they watch.

#![cfg_attr(target_os = "none", no_std)]
// `unwrap`/`expect` are denied workspace-wide in production code; tests opt back
// out, matching every other crate here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

mod board;
mod global;
mod macros;

pub use board::ALARM_CAPACITY;
pub use board::Alarm;
pub use board::AlarmBoard;
pub use board::AlarmSnapshot;
pub use board::DETAIL_CAP;
pub use global::SharedBoard;
pub use global::clear;
pub use global::process_board;
pub use global::raise;
pub use global::raise_at;
pub use global::snapshot;
#[cfg(not(target_os = "none"))]
pub use global::with_board;

/// How bad a condition is, and — through [`hold_ms`](Severity::hold_ms) — how
/// long the node keeps asserting it before deciding it has stopped.
///
/// Ordered worst-last so `>` means "worse", which is what the severity ratchet
/// on a coalescing raise and the eviction policy on a full board both compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth recording, not worth waking anyone: a condition that is unusual
    /// but has a benign explanation more often than not.
    Info,
    /// Something is wrong and an operator should look: the mesh is still
    /// carrying traffic, but not the way it was configured to.
    Warning,
    /// Something is wrong *now* and is degrading or attacking the mesh.
    Critical,
}

impl Severity {
    /// How long after its last raise this severity is still reported as
    /// [`active`](Alarm::is_active).
    ///
    /// A de-assert delay, not a guess at duration: the node keeps claiming a
    /// condition until it has been quiet for this long. Worse conditions are
    /// held longer, so a client polling on a slow cadence cannot miss the
    /// serious ones between polls — the cost of being wrong in the "still
    /// firing" direction is far lower here than in the other.
    #[must_use]
    pub const fn hold_ms(self) -> u64 {
        match self {
            Self::Info => 60_000,
            Self::Warning => 300_000,
            Self::Critical => 900_000,
        }
    }

    /// A stable lowercase name, for the log line and for an operator-facing
    /// projection.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// What kind of condition an alarm reports.
///
/// A closed enum rather than a free-form string: the set of things a node can
/// flag is a design decision, not caller data, and a fixed set is what lets a
/// client render, group and threshold alarms it has never seen. Each variant
/// carries a stable [`code`](AlarmKind::code) so a future management-API
/// projection can add variants without renumbering.
///
/// Nothing in this crate decides *when* one of these holds — see the crate
/// docs. The variants name the conditions the mesh's own threat model already
/// identifies, so a detector has somewhere to report to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmKind {
    /// Frames are arriving from a source that fails authentication, in volume.
    /// One malformed frame is a `trace!`; a sustained stream of them is this.
    UnauthenticatedTraffic,
    /// A source or interface is offering frames far faster than this mesh's
    /// configured cadence explains.
    TrafficFlood,
    /// Repeated management-API authentication failures — the mesh's
    /// administrative front door being tried.
    ManagementAuthFailures,
    /// An OGM was accepted or seen whose sequence number this node has already
    /// processed: the signature of a replay rather than a fresh advertisement.
    OgmReplay,
    /// Traffic from a peer holding a certificate this node knows to be revoked.
    RevokedPeer,
    /// A link is failing I/O persistently rather than transiently — the radio
    /// or its transport is not merely busy.
    LinkErrors,
    /// A bounded table is at capacity and evicting, so the node is now
    /// forgetting state it would otherwise have kept.
    TableSaturation,
    /// The host's system clock is not disciplined, so this node refuses every
    /// credential decision that depends on knowing the time.
    ///
    /// Latched rather than momentary: it stays wrong until someone fixes NTP,
    /// and an operator who sees only the downstream refusals — a certificate
    /// that will not issue, a login that will not complete — debugs the wrong
    /// thing. The node keeps routing, which is exactly why this needs saying
    /// out loud: it looks healthy.
    ClockUnsynchronized,
    /// This node's own mesh membership has been revoked: it holds a
    /// root-signed record naming itself, has dropped its certificate and trust
    /// anchor, and is inert until an authority re-admits it.
    ///
    /// Distinct from [`RevokedPeer`](Self::RevokedPeer), which is about
    /// somebody else. This one is the node reporting its own removal, and it
    /// is the only record of *why* the node went silent — so it is the alarm
    /// that has to survive the burst of frames that carried it.
    SelfRevoked,
    /// Two distinct identity keys are claiming one mesh address: a second
    /// CA-signed certificate arrived for a MAC whose held certificate is still
    /// live, under a different `ed_pubkey`, and was refused.
    ///
    /// Refused rather than honoured, so nothing is broken by the time this is
    /// raised — which is exactly why it has to be said out loud. A node that
    /// silently dropped the loser would present the same way as one with an
    /// intermittent radio, and the actual explanation (an authority that
    /// issued twice for one address, or an anchor no longer under the
    /// operator's sole control) is not something route flapping ever suggests.
    ///
    /// Addresses derived from an identity key carry 46 bits, so an accidental
    /// collision is negligible and a deliberate one is days of GPU time; this
    /// is a credential-issuance condition far more often than an address-space
    /// one.
    IdentityConflict,
    /// This node's own membership certificate is inside the last quarter of its
    /// validity window and has not been renewed yet.
    ///
    /// A *warning* condition, not a critical one: the node is fully working and
    /// routing normally while this is raised. That is precisely why it needs
    /// saying out loud — the failure it precedes is silent and total. When
    /// `not_after` passes, peers stop accepting this node's OGMs and the
    /// authority stops recognising it as a renewing holder, so recovery is no
    /// longer something the node can do alone: it re-enters the enrollment queue
    /// and waits for an operator.
    ///
    /// Distinct from [`SelfRevoked`](Self::SelfRevoked), which is the same
    /// outcome arrived at deliberately and already complete. This one is a
    /// deadline with time still on it, and it is latched so that a node nobody
    /// watched for a week still says why it is about to go quiet.
    CertExpiring,
}

impl AlarmKind {
    /// A stable numeric code, so a wire projection is not tied to declaration
    /// order and a variant can be added without renumbering the rest.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::UnauthenticatedTraffic => 1,
            Self::TrafficFlood => 2,
            Self::ManagementAuthFailures => 3,
            Self::OgmReplay => 4,
            Self::RevokedPeer => 5,
            Self::LinkErrors => 6,
            Self::TableSaturation => 7,
            Self::ClockUnsynchronized => 8,
            Self::SelfRevoked => 9,
            Self::IdentityConflict => 10,
            Self::CertExpiring => 11,
        }
    }

    /// A stable snake-case name, for the log line and for an operator-facing
    /// projection.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnauthenticatedTraffic => "unauthenticated_traffic",
            Self::TrafficFlood => "traffic_flood",
            Self::ManagementAuthFailures => "management_auth_failures",
            Self::OgmReplay => "ogm_replay",
            Self::RevokedPeer => "revoked_peer",
            Self::LinkErrors => "link_errors",
            Self::TableSaturation => "table_saturation",
            Self::ClockUnsynchronized => "clock_unsynchronized",
            Self::SelfRevoked => "self_revoked",
            Self::IdentityConflict => "identity_conflict",
            Self::CertExpiring => "cert_expiring",
        }
    }
}

/// Raw identifier bytes naming who an alarm is about.
///
/// Deliberately address-family agnostic and deliberately *not* a
/// `wayfinder-auth` or `interfaces` type: it holds a 6-byte `Mac`, a 1-byte
/// short address, or the leading bytes of a key fingerprint equally well, and a
/// dependency on either of those crates would be a cycle the moment one of them
/// wants to raise an alarm. The management API already takes the same line with
/// its `bytes node_id` fields.
///
/// [`MAX_LEN`](NodeId::MAX_LEN) bytes is enough to identify a mesh node exactly
/// and enough of a fingerprint to identify a key in practice; a longer
/// identifier is truncated to its leading bytes rather than rejected, because a
/// slightly less precise subject beats no alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId {
    /// The identifier, left-aligned; bytes at and beyond `len` are zero.
    bytes: [u8; Self::MAX_LEN],
    /// How many of `bytes` are significant.
    len: u8,
}

impl NodeId {
    /// Longest identifier retained, in bytes.
    pub const MAX_LEN: usize = 8;

    /// Take up to [`MAX_LEN`](Self::MAX_LEN) leading bytes of `id`.
    #[must_use]
    pub fn new(id: &[u8]) -> Self {
        let len = id.len().min(Self::MAX_LEN);
        let mut bytes = [0u8; Self::MAX_LEN];
        bytes[..len].copy_from_slice(&id[..len]);
        Self {
            bytes,
            // `len` is bounded by `MAX_LEN`, which is far below `u8::MAX`.
            len: len as u8,
        }
    }

    /// The significant bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl core::fmt::Display for NodeId {
    /// Colon-delimited hex, the form every other node identifier in this
    /// project is displayed in.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, byte) in self.as_bytes().iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Who or what an alarm is about — the other half of its identity, alongside
/// its [`AlarmKind`].
///
/// Two alarms of one kind about different subjects are separate conditions, so
/// one misbehaving peer can never mask another by coalescing into its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// A peer, by mesh identifier or key fingerprint.
    Node(NodeId),
    /// One of this node's links, by interface index.
    Interface(u8),
    /// Nothing more specific than "this node" — a property of the node itself,
    /// such as a saturated table.
    None,
}

impl core::fmt::Display for Subject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Node(id) => write!(f, "{id}"),
            Self::Interface(idx) => write!(f, "iface{idx}"),
            Self::None => write!(f, "-"),
        }
    }
}

/// What a [`raise`] did.
///
/// Returned so a caller can gate a side effect on the outcome — which is how
/// the log mirroring stays storm-safe — and so a test can assert on the
/// board's decision rather than inferring it from the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Raised {
    /// The condition was not on the board and now is.
    New,
    /// The condition was already on the board; its count and recency advanced.
    Coalesced,
    /// As [`Coalesced`](Self::Coalesced), and the row's severity rose to meet
    /// this raise.
    Escalated,
    /// The board was full of conditions at least this severe, so this one was
    /// counted (see [`AlarmBoard::dropped`]) but not recorded.
    Dropped,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind this build knows about.  Spelled out rather than derived so
    /// that adding a variant is a deliberate edit here too — which is what makes
    /// the uniqueness check below a real guard rather than a tautology.
    const ALL: &[AlarmKind] = &[
        AlarmKind::UnauthenticatedTraffic,
        AlarmKind::TrafficFlood,
        AlarmKind::ManagementAuthFailures,
        AlarmKind::OgmReplay,
        AlarmKind::RevokedPeer,
        AlarmKind::LinkErrors,
        AlarmKind::TableSaturation,
        AlarmKind::ClockUnsynchronized,
        AlarmKind::SelfRevoked,
        AlarmKind::IdentityConflict,
        AlarmKind::CertExpiring,
    ];

    /// Codes and names are a wire contract: a client renders a row by them, so
    /// two kinds sharing either would make one condition indistinguishable from
    /// another on every dashboard at once.
    #[test]
    fn every_kind_has_a_unique_code_and_name() {
        for (i, a) in ALL.iter().enumerate() {
            for b in &ALL[i + 1..] {
                assert_ne!(a.code(), b.code(), "{a:?} and {b:?} share a code");
                assert_ne!(a.as_str(), b.as_str(), "{a:?} and {b:?} share a name");
            }
            assert_ne!(a.code(), 0, "0 is reserved for the unspecified wire value");
        }
    }

    /// The condition this node reports about its *own* certificate, distinct
    /// from [`AlarmKind::SelfRevoked`]: an expiring cert is still working and
    /// still renewable, where a revoked one has already gone inert.  Pinned
    /// because the remedies differ — wait for (or trigger) a renewal, versus
    /// re-enroll from scratch.
    #[test]
    fn cert_expiring_is_its_own_condition() {
        assert_eq!(AlarmKind::CertExpiring.code(), 11);
        assert_eq!(AlarmKind::CertExpiring.as_str(), "cert_expiring");
        assert_ne!(AlarmKind::CertExpiring, AlarmKind::SelfRevoked);
    }
}
