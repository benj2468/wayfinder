//! The two on-air advertising formats this crate speaks, and the per-node
//! policy choosing which of them to transmit.
//!
//! Legacy (non-extended) advertising caps total advertising data at 31 bytes;
//! Bluetooth 5's extended advertising raises that by roughly an order of
//! magnitude. Both are live simultaneously rather than one replacing the
//! other — see `docs/design/implemented/07-ble-extended-advertising.md` for
//! why, and
//! `libs/blue/CLAUDE.md` for the operational consequences.
//!
//! Not feature-gated: [`BleSendMode`] is plain configuration both backends
//! read, and [`BleAdvFormat`] appears in [`crate::BleAdvertiser`]'s signature,
//! so gating either would leave them unnameable on one target or the other.

/// Which on-air advertising format one fragment was cut and framed for.
///
/// This is a **wire value**, not an implementation detail: it is carried as
/// the leading byte of every fragment's manufacturer data (see
/// `crate::frame`), so a receiver can pick the matching reassembler without
/// having to already know what a sender chose. Two backends and two firmware
/// generations have to agree on [`tag`](Self::tag)'s numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleAdvFormat {
    /// Legacy (non-extended) advertising: 31 bytes of advertising data
    /// total, repeated on all three primary channels each advertising event.
    /// Understood by every BLE controller, including pre-Bluetooth-5 ones.
    Legacy,
    /// Extended advertising: a small pointer on the primary channels and the
    /// payload carried once on a secondary channel, for a far larger budget
    /// (`crate::ad::MAX_EXTENDED_ADV_DATA_LEN`). Requires a Bluetooth
    /// 5-capable controller on **both** ends — a peer whose radio cannot
    /// receive extended PDUs never hears a node transmitting only this.
    Extended,
}

impl BleAdvFormat {
    /// This format's wire tag — the first byte of every fragment's
    /// manufacturer data.
    ///
    /// Written as explicit literals rather than an `as u8` cast of the
    /// discriminant: reordering the variants must not silently renumber a
    /// deployed wire format.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Legacy => 0,
            Self::Extended => 1,
        }
    }

    /// The format a wire tag names, or `None` for a tag this build does not
    /// know — a future third format, or garbage off the air. The caller drops
    /// the fragment either way, which is the same fail-closed posture
    /// `wayfinder_link_utils::parse_fragment` takes for a malformed header.
    pub(crate) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Legacy),
            1 => Some(Self::Extended),
            _ => None,
        }
    }

    /// Frame-content bytes one fragment of this format carries, once the AD
    /// structure's framing, the mode tag, the fragment header and the
    /// embedded origin are all subtracted.
    ///
    /// This is a **compile-time property of the format, never carried on the
    /// wire** — `wayfinder_link_utils::Reassembler` places a fragment's bytes
    /// at `index * FRAG_PAYLOAD` with `FRAG_PAYLOAD` a const generic, so a
    /// receiver must already know which budget a sender cut at. That is
    /// exactly what the mode tag exists to tell it.
    pub(crate) const fn frag_payload(self) -> usize {
        match self {
            Self::Legacy => crate::frame::FRAG_PAYLOAD_LEGACY,
            Self::Extended => crate::frame::FRAG_PAYLOAD_EXTENDED,
        }
    }

    /// Total advertising-data budget for one advertisement of this format.
    pub(crate) const fn max_adv_data_len(self) -> usize {
        match self {
            Self::Legacy => crate::ad::MAX_LEGACY_ADV_DATA_LEN,
            Self::Extended => crate::ad::MAX_EXTENDED_ADV_DATA_LEN,
        }
    }
}

/// Which format(s) a node transmits. A **local deployment-time policy**, not
/// a negotiation: nothing asks a peer what it can receive, because this is a
/// connectionless, fire-and-forget medium with no round trip to ask over.
///
/// Receiving is unconditional and unaffected by this setting — a node always
/// demuxes and reassembles both formats, subject only to whether its own
/// controller surfaces extended PDUs at all. So the only thing this chooses
/// is what a node *costs* the air and who can hear it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BleSendMode {
    /// Transmit legacy-format advertisements only. Every peer hears this
    /// node, upgraded or not, at legacy's fragment count. The default,
    /// because it is the only setting with no dependency on any peer's
    /// hardware.
    #[default]
    Legacy,
    /// Transmit extended-format only: the smallest fragment count and the
    /// least airtime, but a peer whose controller cannot receive extended
    /// PDUs never hears this node at all. Choose it only once every peer in
    /// radio range is confirmed extended-capable.
    Extended,
    /// Transmit both, each independently fragmented at its own budget.
    /// Roughly the sum of the two formats' airtime, paid deliberately during
    /// a rollout so every peer keeps working regardless of which formats it
    /// can receive.
    Both,
}

impl BleSendMode {
    /// The formats a `send` transmits under this policy, in transmission
    /// order — legacy first under [`Both`](Self::Both), so the format every
    /// peer can receive goes out before the airtime spent on the other.
    ///
    /// Returned as a slice rather than an iterator so a caller can cheaply
    /// ask how many passes a frame costs.
    pub const fn formats(self) -> &'static [BleAdvFormat] {
        match self {
            Self::Legacy => &[BleAdvFormat::Legacy],
            Self::Extended => &[BleAdvFormat::Extended],
            Self::Both => &[BleAdvFormat::Legacy, BleAdvFormat::Extended],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_send_mode_transmits_the_formats_it_names() {
        assert_eq!(BleSendMode::Legacy.formats(), &[BleAdvFormat::Legacy]);
        assert_eq!(BleSendMode::Extended.formats(), &[BleAdvFormat::Extended]);
        assert_eq!(
            BleSendMode::Both.formats(),
            &[BleAdvFormat::Legacy, BleAdvFormat::Extended]
        );
    }

    /// Under `Both`, the format every peer can receive must go out first: a
    /// `send` occupies the driver's event loop for its whole duration, so a
    /// peer that can only hear legacy should not wait behind an extended
    /// pass it will discard.
    #[test]
    fn both_transmits_legacy_before_extended() {
        assert_eq!(BleSendMode::Both.formats()[0], BleAdvFormat::Legacy);
    }

    /// A freshly-updated node must not change what it puts on the air until
    /// an operator opts it in — design 07 §9.6.
    #[test]
    fn default_send_mode_is_legacy_only() {
        assert_eq!(BleSendMode::default(), BleSendMode::Legacy);
    }

    #[test]
    fn unknown_wire_tags_have_no_format() {
        assert_eq!(BleAdvFormat::from_tag(2), None);
        assert_eq!(BleAdvFormat::from_tag(0xff), None);
    }

    #[test]
    fn extended_carries_more_per_fragment_and_per_advertisement() {
        assert!(BleAdvFormat::Extended.frag_payload() > BleAdvFormat::Legacy.frag_payload());
        assert!(
            BleAdvFormat::Extended.max_adv_data_len() > BleAdvFormat::Legacy.max_adv_data_len()
        );
    }
}
