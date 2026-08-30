//! IGMP snooping: learn which IPv4 multicast groups the local host listens to
//! by observing the IGMP membership reports/leaves it emits on the host link, so
//! the router can announce those groups to the mesh (and receive only the
//! multicast traffic the host actually wants).
//!
//! Scope: IPv4 IGMP only (v1/v2/v3); IPv6 MLD is not yet snooped.  Ethernet and
//! IPv4 headers are parsed with `etherparse`; the IGMP message body is parsed
//! by hand (etherparse does not decode IGMP).

use std::collections::HashSet;
use std::net::Ipv4Addr;

use etherparse::NetSlice;
use etherparse::SlicedPacket;
use wayfinder::interfaces::frame::Mac;

/// IP protocol number for IGMP.
const IP_PROTO_IGMP: u8 = 2;

/// Tracks the IPv4 multicast groups the local host has joined, learned by
/// snooping the IGMP membership messages it emits on the host link.
#[derive(Default)]
pub struct McastSnooper {
    groups: HashSet<Mac>,
}

impl McastSnooper {
    /// A snooper that has observed nothing yet (no joined groups).
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one host Ethernet frame.  If it carries an IGMP membership
    /// report or leave, update the joined-group set accordingly and return
    /// `true` when the set actually changed; otherwise return `false`.
    pub fn observe(&mut self, eth: &[u8]) -> bool {
        match igmp_payload(eth) {
            Some(igmp) => self.apply_igmp(igmp),
            None => false,
        }
    }

    /// The multicast group MACs the host currently listens to, in a stable
    /// (ascending) order.
    ///
    /// Sorted rather than handed back in `HashSet` order, because two callers
    /// downstream treat this as a *sequence* and both break on an unstable
    /// one:
    ///
    /// * `BatmanEngine::set_local_mcast_groups` compares the new list against
    ///   the current one to decide whether this node's advertised state
    ///   changed. `heapless::Vec` equality is element-wise, so an unordered
    ///   source makes an unchanged set compare as changed and reset the
    ///   Trickle backoff — pinning the node near `i_min`, the exact thing that
    ///   comparison exists to prevent.
    /// * That same setter truncates at `MAX_LOCAL_MCAST`. With more groups
    ///   joined than fit, an unordered source means *which* groups get
    ///   advertised is arbitrary and reshuffles on any unrelated join or
    ///   leave, so a group the host still wants silently drops out of the OGM
    ///   and back in again. Sorted, the surviving prefix is at least stable.
    pub fn groups(&self) -> Vec<Mac> {
        let mut groups: Vec<Mac> = self.groups.iter().copied().collect();
        groups.sort_unstable_by_key(|m| m.0);
        groups
    }

    /// Apply one parsed IGMP message body to the group set.
    fn apply_igmp(&mut self, igmp: &[u8]) -> bool {
        match igmp.first().copied() {
            // IGMPv1 / IGMPv2 membership report: a join for the named group.
            Some(0x12) | Some(0x16) => group_at(igmp, 4).map(|g| self.join(g)).unwrap_or(false),
            // IGMPv2 leave group.
            Some(0x17) => group_at(igmp, 4).map(|g| self.leave(g)).unwrap_or(false),
            // IGMPv3 membership report: a list of per-group records.
            Some(0x22) => self.apply_igmp_v3(igmp),
            _ => false,
        }
    }

    /// Apply an IGMPv3 membership report's group records.  Tracking is at
    /// group granularity (sources are ignored), so a record means "join"
    /// unless it is an INCLUDE-mode record with no sources, which means the
    /// host no longer wants the group.
    fn apply_igmp_v3(&mut self, igmp: &[u8]) -> bool {
        // Header: [type][reserved][checksum:2][reserved:2][num_records:2].
        if igmp.len() < 8 {
            return false;
        }
        let num_records = u16::from_be_bytes([igmp[6], igmp[7]]) as usize;

        let mut off = 8;
        let mut changed = false;
        for _ in 0..num_records {
            // Record: [rec_type][aux_len][num_sources:2][group:4][sources..][aux..].
            if off + 8 > igmp.len() {
                break;
            }
            let rec_type = igmp[off];
            let aux_words = igmp[off + 1] as usize;
            let num_sources = u16::from_be_bytes([igmp[off + 2], igmp[off + 3]]) as usize;
            let Some(group) = group_at(igmp, off + 4) else {
                break;
            };

            // MODE_IS_INCLUDE (1) / CHANGE_TO_INCLUDE_MODE (3) with no sources
            // is a leave; every other record expresses interest in the group.
            let is_leave = matches!(rec_type, 1 | 3) && num_sources == 0;
            changed |= if is_leave {
                self.leave(group)
            } else {
                self.join(group)
            };

            // Advance past this record's sources (4 bytes each) and aux data
            // (counted in 32-bit words).
            off += 8 + num_sources * 4 + aux_words * 4;
        }
        changed
    }

    fn join(&mut self, group: Mac) -> bool {
        self.groups.insert(group)
    }

    fn leave(&mut self, group: Mac) -> bool {
        self.groups.remove(&group)
    }
}

/// Read the IPv4 group address at byte offset `off` of an IGMP message and map
/// it to its multicast MAC.
fn group_at(igmp: &[u8], off: usize) -> Option<Mac> {
    let b = igmp.get(off..off + 4)?;
    Some(Mac::from_ipv4_multicast(Ipv4Addr::new(
        b[0], b[1], b[2], b[3],
    )))
}

/// If `eth` is an IPv4 frame carrying IGMP, return the IGMP message bytes.
fn igmp_payload(eth: &[u8]) -> Option<&[u8]> {
    let sliced = SlicedPacket::from_ethernet(eth).ok()?;
    match sliced.net? {
        NetSlice::Ipv4(ip) => {
            let payload = ip.payload();
            (payload.ip_number.0 == IP_PROTO_IGMP).then_some(payload.payload)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder::interfaces::frame::Mac;

    // ── frame builders ──────────────────────────────────────────────────────

    /// Wrap an IGMP message in IPv4 + Ethernet so the snooper can parse it.
    fn igmp_eth(igmp: &[u8]) -> Vec<u8> {
        let total_len = (20 + igmp.len()) as u16;
        let mut v = Vec::new();
        // Ethernet: dst (arbitrary mcast), src host, IPv4 ethertype.
        v.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x16]);
        v.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x09]);
        v.extend_from_slice(&[0x08, 0x00]);
        // IPv4 header (20 bytes, no options).
        v.push(0x45); // version 4, IHL 5
        v.push(0x00);
        v.extend_from_slice(&total_len.to_be_bytes());
        v.extend_from_slice(&[0, 0]); // id
        v.extend_from_slice(&[0, 0]); // flags/frag
        v.push(1); // ttl
        v.push(2); // protocol = IGMP
        v.extend_from_slice(&[0, 0]); // checksum (unverified)
        v.extend_from_slice(&[10, 0, 0, 9]); // src
        v.extend_from_slice(&[224, 0, 0, 22]); // dst
        v.extend_from_slice(igmp);
        v
    }

    /// IGMPv2 message: `[type][max_resp][checksum:2][group:4]`.
    fn igmp_v2(msg_type: u8, group: [u8; 4]) -> Vec<u8> {
        let mut v = vec![msg_type, 0, 0, 0];
        v.extend_from_slice(&group);
        v
    }

    /// IGMPv3 membership report carrying a single group record.
    fn igmp_v3_report(record_type: u8, num_sources: u16, group: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0x22, 0]; // type, reserved
        v.extend_from_slice(&[0, 0]); // checksum
        v.extend_from_slice(&[0, 0]); // reserved
        v.extend_from_slice(&1u16.to_be_bytes()); // number of group records
        // One group record.
        v.push(record_type);
        v.push(0); // aux data len
        v.extend_from_slice(&num_sources.to_be_bytes());
        v.extend_from_slice(&group);
        for _ in 0..num_sources {
            v.extend_from_slice(&[0, 0, 0, 0]); // dummy source
        }
        v
    }

    const G1: [u8; 4] = [239, 1, 1, 1];
    fn g1_mac() -> Mac {
        Mac([0x01, 0x00, 0x5e, 0x01, 0x01, 0x01])
    }

    // ── IGMPv2 ────────────────────────────────────────────────────────────────

    #[test]
    fn igmpv2_report_joins_group() {
        let mut s = McastSnooper::new();
        let changed = s.observe(&igmp_eth(&igmp_v2(0x16, G1)));
        assert!(changed);
        assert!(s.groups().contains(&g1_mac()));
    }

    #[test]
    fn igmpv2_leave_removes_group() {
        let mut s = McastSnooper::new();
        s.observe(&igmp_eth(&igmp_v2(0x16, G1)));
        let changed = s.observe(&igmp_eth(&igmp_v2(0x17, G1)));
        assert!(changed);
        assert!(!s.groups().contains(&g1_mac()));
    }

    #[test]
    fn duplicate_report_does_not_signal_change() {
        let mut s = McastSnooper::new();
        assert!(s.observe(&igmp_eth(&igmp_v2(0x16, G1))));
        assert!(!s.observe(&igmp_eth(&igmp_v2(0x16, G1))));
    }

    // ── IGMPv3 ────────────────────────────────────────────────────────────────

    /// CHANGE_TO_EXCLUDE_MODE (4) with no sources is an any-source join.
    #[test]
    fn igmpv3_exclude_record_joins_group() {
        let mut s = McastSnooper::new();
        let changed = s.observe(&igmp_eth(&igmp_v3_report(4, 0, G1)));
        assert!(changed);
        assert!(s.groups().contains(&g1_mac()));
    }

    /// CHANGE_TO_INCLUDE_MODE (3) with no sources is a leave.
    #[test]
    fn igmpv3_include_with_no_sources_leaves_group() {
        let mut s = McastSnooper::new();
        s.observe(&igmp_eth(&igmp_v3_report(4, 0, G1)));
        let changed = s.observe(&igmp_eth(&igmp_v3_report(3, 0, G1)));
        assert!(changed);
        assert!(!s.groups().contains(&g1_mac()));
    }

    // ── non-IGMP traffic ────────────────────────────────────────────────────

    #[test]
    fn non_igmp_frame_is_ignored() {
        let mut s = McastSnooper::new();
        // An ARP frame (ethertype 0x0806) carries no IGMP.
        let mut arp = Vec::new();
        arp.extend_from_slice(&[0xff; 6]);
        arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 9]);
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0u8; 28]);
        assert!(!s.observe(&arp));
        assert!(s.groups().is_empty());
    }
}

#[cfg(test)]
mod order_tests {
    use super::*;

    /// `groups()` is a stable sequence, not a `HashSet` iteration order.
    ///
    /// The consumers treat it as one — see the method's doc comment for the
    /// two things that break otherwise. Asserted by building the same set by
    /// two different join orders and requiring identical output; a `HashSet`
    /// of `Mac` does not guarantee that on its own.
    #[test]
    fn groups_are_returned_in_a_stable_order() {
        let a = Mac([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        let b = Mac([0x01, 0x00, 0x5e, 0x00, 0x00, 0x02]);
        let c = Mac([0x01, 0x00, 0x5e, 0x01, 0x02, 0x03]);

        let mut forward = McastSnooper::new();
        for g in [a, b, c] {
            forward.groups.insert(g);
        }
        let mut backward = McastSnooper::new();
        for g in [c, b, a] {
            backward.groups.insert(g);
        }

        assert_eq!(forward.groups(), backward.groups());
        assert_eq!(forward.groups(), vec![a, b, c], "ascending by MAC bytes");
    }
}
