use interfaces::frame::Mac;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// EtherType identifying BATMAN frames on the wire (batman-adv's `ETH_P_BATMAN`).
pub const ETH_P_BATMAN: u16 = 0x4305;

// Core BATMAN packet identifiers
/// `packet_type` for an originator message (OGM), the topology-discovery
/// broadcast — batman-adv's `BATADV_IV_OGM`.
pub const BATADV_IV_OGM: u8 = 0x01;

/// Originator Message header.  A variable-length TVLV region of `tvlv_len`
/// bytes (a sequence of [`BatmanTvlvHdr`]-prefixed records) follows this fixed
/// header on the wire; it carries piggybacked announcements such as
/// multicast group memberships.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanOgmPacket {
    /// Always [`BATADV_IV_OGM`] for this packet type.
    pub packet_type: u8,
    /// Protocol version (typically 5).
    pub version: u8,
    /// Time-to-live, decremented at each hop to bound flood radius.
    pub ttl: u8,
    /// Reserved flag bits (batman-adv `BATADV_*_FLAG`); unused here, sent as 0.
    pub flags: u8,
    /// Sequence number (network byte order / big endian).
    pub seqno: u32,
    /// The node that originally generated this message.
    pub orig: Mac,
    /// Reserved padding byte; sent as 0.
    pub reserved: u8,
    /// Transmission Quality metric of the path (0..=255).
    pub tq: u8,
    /// Length in bytes of the TVLV region that follows this header
    /// (network byte order / big endian).  Zero when no TVLV is attached.
    pub tvlv_len: u16,
}

/// Header prefixing one record in an OGM's TVLV (Type-Version-Length-Value)
/// region, matching batman-adv's `batadv_tvlv_hdr`.  The `len` bytes of value
/// follow immediately; records are packed back-to-back to fill `tvlv_len`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanTvlvHdr {
    /// What the value encodes — a [`TvlvType`] byte for the records this
    /// implementation produces, though the field is a raw `u8` because the wire
    /// may carry record types this node does not recognise.
    pub tvlv_type: u8,
    /// Version of this TVLV type's value format.
    pub version: u8,
    /// Length of the value following this header, in bytes (big endian).
    pub len: u16,
}

/// The TVLV record types this implementation produces and matches, each a
/// distinct on-the-wire type byte.  Modelled as a `#[repr(u8)]` enum — rather
/// than a set of free `const`s — so the compiler *guarantees* the type bytes
/// are unique (a duplicated discriminant is a compile error) and keeps every
/// assignment in one place.  The raw byte is [`TvlvType::as_u8`]; the
/// [`BatmanTvlvHdr::tvlv_type`] wire field stays a `u8` because a tail can also
/// carry types not listed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TvlvType {
    /// Multicast-membership announcement, matching batman-adv's
    /// `BATADV_TVLV_MCAST`.  Its value is the list of multicast group MAC
    /// addresses the originating node currently listens for.
    Mcast = 0x06,
    /// The originator's Wayfinder membership certificate
    /// (`wayfinder_auth::MembershipCert` bytes).  Wayfinder-specific extension —
    /// present only when mesh authentication is enabled — so a receiver can
    /// verify the OGM's signature against the mesh trust anchor and learn the
    /// originator's keys.  Carried periodically (amortized) rather than on every
    /// OGM.
    Cert = 0x80,
    /// The originator's Ed25519 signature (64 bytes) over the OGM's immutable
    /// identity fields.  Wayfinder-specific; present only when mesh
    /// authentication is enabled.  This is what lets every member reject spurious
    /// or forged OGMs — a pairwise hop tag cannot, since an OGM is flooded
    /// one-to-many.
    OgmSig = 0x81,
    /// A signed revocation record (`wayfinder_auth::RevocationRecord` bytes).
    /// Wayfinder-specific; present only when a node is actively re-flooding an
    /// emergency purge.  A node attaches known revocations to its OGMs so they
    /// propagate with normal control-plane traffic; each record is independently
    /// signed by the mesh root, so its authenticity does not depend on the
    /// carrying OGM's signature.  An OGM may carry several of these back-to-back.
    Revoke = 0x82,
    /// An 8-byte `MembershipCert::fingerprint()`, replacing [`TvlvType::Cert`]
    /// on a mesh with lazy cert distribution enabled. A receiver that already
    /// holds a cert with a matching fingerprint verifies the OGM signature
    /// against its cached copy with zero cert bytes on the wire; a mismatch
    /// (unknown originator, or a changed fingerprint = rotation) triggers an
    /// on-demand `CertReq`/`CertReply` fetch rather than re-verifying inline.
    CertFp = 0x83,
}

impl TvlvType {
    /// The on-the-wire type byte for this record type — the enum's discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Scan a TVLV region (`tail`, the bytes following an OGM's fixed header) for
/// the first record of type `tvlv_type` and return its value bytes, or `None`
/// if absent or malformed.  Records are `[`[`BatmanTvlvHdr`]`][value]` packed
/// back-to-back; a record whose advertised length runs past the end of `tail`
/// terminates the scan.
pub fn find_tvlv(tail: &[u8], tvlv_type: TvlvType) -> Option<&[u8]> {
    let hdr_size = core::mem::size_of::<BatmanTvlvHdr>();
    let mut off = 0;
    while off + hdr_size <= tail.len() {
        let (hdr, _) = BatmanTvlvHdr::ref_from_prefix(&tail[off..]).ok()?;
        let len = u16::from_be(hdr.len) as usize;
        let value_start = off + hdr_size;
        let value_end = value_start.checked_add(len)?;
        if value_end > tail.len() {
            return None; // record claims more bytes than the tail holds
        }
        if hdr.tvlv_type == tvlv_type.as_u8() {
            return tail.get(value_start..value_end);
        }
        off = value_end;
    }
    None
}

/// Iterate the value bytes of *every* record of type `tvlv_type` in a TVLV
/// region (`tail`, the bytes following an OGM's fixed header), in wire order.
/// Unlike [`find_tvlv`] (which stops at the first match) this yields each
/// matching record, so a tail carrying several records of one type — e.g.
/// multiple [`TvlvType::Revoke`] records — can be processed in full.  A record
/// whose advertised length runs past the end of `tail` terminates the scan.
pub fn iter_tvlv(tail: &[u8], tvlv_type: TvlvType) -> TvlvValues<'_> {
    TvlvValues {
        tail,
        off: 0,
        tvlv_type: tvlv_type.as_u8(),
    }
}

/// Iterator returned by [`iter_tvlv`] yielding each matching record's value
/// bytes.  See [`iter_tvlv`] for the scanning rules.
pub struct TvlvValues<'a> {
    /// The TVLV region being scanned.
    tail: &'a [u8],
    /// Offset of the next record header to inspect.
    off: usize,
    /// The on-the-wire byte of the record type to yield.
    tvlv_type: u8,
}

impl<'a> Iterator for TvlvValues<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let hdr_size = core::mem::size_of::<BatmanTvlvHdr>();
        while self.off + hdr_size <= self.tail.len() {
            let (hdr, _) = BatmanTvlvHdr::ref_from_prefix(&self.tail[self.off..]).ok()?;
            let len = u16::from_be(hdr.len) as usize;
            let value_start = self.off + hdr_size;
            let value_end = value_start.checked_add(len)?;
            if value_end > self.tail.len() {
                return None; // record claims more bytes than the tail holds
            }
            let matched = hdr.tvlv_type == self.tvlv_type;
            self.off = value_end;
            if matched {
                return self.tail.get(value_start..value_end);
            }
        }
        None
    }
}

/// Packet sub-type for a flooded broadcast frame.  Matches batman-adv's
/// `BATADV_BCAST`.  Used to carry broadcast/multicast link-layer frames
/// (e.g. ARP) across the mesh, deduplicated and TTL-limited so they reach
/// every node exactly once without looping.
pub const BATADV_BCAST: u8 = 0x02;

/// Header for a broadcast frame flooded across the mesh.
///
/// The encapsulated link-layer frame (the thing actually being broadcast,
/// e.g. an ARP request) immediately follows this header on the wire.  A node
/// floods a broadcast by re-transmitting it with `ttl` decremented, dropping
/// it once `ttl` reaches 1 or once it has already seen this `(orig, seqno)`
/// pair — see the broadcast handling in the engine.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanBroadcastPacket {
    /// Always [`BATADV_BCAST`] for this packet type.
    pub packet_type: u8,
    /// Protocol version (typically 5), matching the OGM/unicast convention.
    pub version: u8,
    /// Time-to-live, decremented at each hop to bound the flood radius and
    /// prevent broadcast storms on cyclic topologies.
    pub ttl: u8,
    /// Per-originator sequence number in network byte order (big endian).
    /// Combined with `orig` it uniquely identifies a broadcast so that
    /// duplicate copies arriving via different paths are dropped.
    pub seqno: u32,
    /// The node that originally generated this broadcast.  Preserved
    /// unchanged as the frame is re-flooded so every node deduplicates
    /// against the true source rather than the immediate relay.
    pub orig: Mac,
}

/// `packet_type` for a unicast data packet routed hop-by-hop toward a single
/// destination node — batman-adv's `BATADV_UNICAST`.
pub const BATADV_UNICAST: u8 = 0x03;

/// Packet sub-type for a selectively-forwarded multicast frame, mirroring
/// batman-adv's `batadv_mcast_packet`.  A multicast frame with a bounded set
/// of interested listeners is delivered as one [`BatmanMcastPacket`] per
/// listener, each addressed to that listener's node and routed toward it like
/// a unicast.  Kept distinct from [`BATADV_UNICAST`] so multicast traffic
/// stays identifiable on the wire.
pub const BATADV_MCAST: u8 = 0x04;

/// Header for a [`BATADV_MCAST`] packet.  Structurally a unicast header: the
/// encapsulated multicast frame follows it, and the packet is routed hop by
/// hop toward `dest` (the listener node this copy targets), TTL-limited to
/// prevent loops, and delivered to the local host on arrival at `dest`.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanMcastPacket {
    /// Always [`BATADV_MCAST`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to bound routing loops.
    pub ttl: u8,
    /// The listener node this copy is addressed to (final destination).
    pub dest: Mac,
}

/// Header for a [`BATADV_UNICAST`] data packet.  The encapsulated payload
/// follows it and the packet is routed hop by hop toward `dest`, TTL-limited to
/// prevent loops, and delivered to the local host on arrival at `dest`.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanUnicastPacket {
    /// Always [`BATADV_UNICAST`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to prevent routing loops for data.
    pub ttl: u8,
    /// The final destination node address in the mesh.
    pub dest: Mac,
}

/// `packet_type` for a lazy-cert-distribution fetch request, routed hop-by-hop
/// toward the originator whose cert is needed — Wayfinder-specific, no
/// batman-adv counterpart. Kept as its own packet type (not a
/// [`BATADV_UNICAST`] payload) for the same reason as [`BATADV_MCAST`]: so
/// cert-control traffic stays identifiable on the wire, separate from data.
pub const BATADV_CERT_REQ: u8 = 0x05;

/// `packet_type` for the reply to a [`BATADV_CERT_REQ`], routed hop-by-hop back
/// toward the requester. Wayfinder-specific, no batman-adv counterpart.
pub const BATADV_CERT_REPLY: u8 = 0x06;

/// Header for a [`BATADV_CERT_REQ`] packet. Structurally a unicast header: the
/// requester's `MembershipCert` + signature (see the router's cert-request
/// logic) follows it, and the packet is routed hop by hop toward `dest` — the
/// originator whose cert is being requested — TTL-limited, delivered to the
/// local auth state on arrival at `dest` (or at any intermediate holder that
/// answers early).
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanCertReqPacket {
    /// Always [`BATADV_CERT_REQ`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to prevent routing loops.
    pub ttl: u8,
    /// The originator node whose certificate is being requested.
    pub dest: Mac,
}

/// Header for a [`BATADV_CERT_REPLY`] packet. Structurally a unicast header:
/// the requested `MembershipCert` follows it, and the packet is routed hop by
/// hop back toward `dest` — the original requester — TTL-limited, delivered to
/// the local auth state on arrival at `dest`.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanCertReplyPacket {
    /// Always [`BATADV_CERT_REPLY`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to prevent routing loops.
    pub ttl: u8,
    /// The requester node this reply is addressed back to.
    pub dest: Mac,
}

/// `packet_type` for a link-local keep-alive heartbeat. Single-hop only —
/// never forwarded/relayed, carries no destination or TTL (the link-layer
/// `frame.src` already identifies the sender). Detects a gone-quiet immediate
/// neighbor far faster than OGM-interval-based staleness, without affecting
/// OGM-driven topology discovery at all. Wayfinder-specific, no batman-adv
/// counterpart.
pub const BATADV_KEEPALIVE: u8 = 0x07;

/// Header for a [`BATADV_KEEPALIVE`] heartbeat. Deliberately minimal (no
/// seqno, no origin, no TVLV tail) — it exists purely to prove a link is
/// still alive between OGMs, so it carries nothing beyond the packet-type
/// tag and protocol version.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanKeepAlivePacket {
    /// Always [`BATADV_KEEPALIVE`].
    pub packet_type: u8,
    /// Protocol version (typically 5), matching every other BATMAN packet.
    pub version: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TVLV region from `(type, value)` records packed back-to-back.
    fn tvlv_region(records: &[(TvlvType, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (ty, value) in records {
            let hdr = BatmanTvlvHdr {
                tvlv_type: ty.as_u8(),
                version: 1,
                len: (value.len() as u16).to_be(),
            };
            out.extend_from_slice(hdr.as_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    /// `iter_tvlv` yields *every* record of the requested type in wire order,
    /// skipping interleaved records of other types — the property `find_tvlv`
    /// (first match only) cannot provide for multi-revocation OGM tails.
    #[test]
    fn iter_tvlv_yields_every_matching_record() {
        let region = tvlv_region(&[
            (TvlvType::Revoke, &[1, 1]),
            (TvlvType::Mcast, &[9, 9, 9]),
            (TvlvType::Revoke, &[2, 2]),
            (TvlvType::Revoke, &[3, 3]),
        ]);
        let got: Vec<&[u8]> = iter_tvlv(&region, TvlvType::Revoke).collect();
        assert_eq!(got, vec![&[1, 1][..], &[2, 2][..], &[3, 3][..]]);
        // The first-match helper still agrees on the first one.
        assert_eq!(find_tvlv(&region, TvlvType::Revoke), Some(&[1, 1][..]));
    }

    /// A record whose advertised length overruns the tail terminates the scan
    /// rather than reading out of bounds.
    #[test]
    fn iter_tvlv_stops_on_overrun() {
        let mut region = tvlv_region(&[(TvlvType::Revoke, &[1, 1])]);
        // Corrupt the length field to claim more bytes than remain.
        region[2..4].copy_from_slice(&255u16.to_be_bytes());
        assert_eq!(iter_tvlv(&region, TvlvType::Revoke).count(), 0);
    }

    /// An empty tail yields nothing.
    #[test]
    fn iter_tvlv_empty_tail() {
        assert_eq!(iter_tvlv(&[], TvlvType::Revoke).count(), 0);
    }

    /// The enum's discriminants are the documented on-the-wire bytes.
    #[test]
    fn tvlv_type_bytes_are_stable() {
        assert_eq!(TvlvType::Mcast.as_u8(), 0x06);
        assert_eq!(TvlvType::Cert.as_u8(), 0x80);
        assert_eq!(TvlvType::OgmSig.as_u8(), 0x81);
        assert_eq!(TvlvType::Revoke.as_u8(), 0x82);
        assert_eq!(TvlvType::CertFp.as_u8(), 0x83);
    }

    /// A `CertFp` record round-trips through the TVLV encoding like any other
    /// record type.
    #[test]
    fn certfp_tvlv_roundtrips() {
        let fp = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let region = tvlv_region(&[(TvlvType::CertFp, &fp)]);
        assert_eq!(find_tvlv(&region, TvlvType::CertFp), Some(&fp[..]));
    }

    /// The cert-request/reply packet-type bytes are the documented values and
    /// distinct from every other packet type on the wire.
    #[test]
    fn cert_packet_types_are_stable_and_distinct() {
        assert_eq!(BATADV_CERT_REQ, 0x05);
        assert_eq!(BATADV_CERT_REPLY, 0x06);
        assert_eq!(BATADV_KEEPALIVE, 0x07);
        let all = [
            BATADV_IV_OGM,
            BATADV_BCAST,
            BATADV_UNICAST,
            BATADV_MCAST,
            BATADV_CERT_REQ,
            BATADV_CERT_REPLY,
            BATADV_KEEPALIVE,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "packet types must be distinct");
            }
        }
    }

    /// `BatmanKeepAlivePacket` round-trips through `zerocopy` parsing like
    /// every other minimal control packet.
    #[test]
    fn keepalive_packet_roundtrips() {
        let pkt = BatmanKeepAlivePacket {
            packet_type: BATADV_KEEPALIVE,
            version: 5,
        };
        let (parsed, _) = BatmanKeepAlivePacket::ref_from_prefix(pkt.as_bytes()).unwrap();
        assert_eq!(parsed.packet_type, BATADV_KEEPALIVE);
        assert_eq!(parsed.version, 5);
        assert_eq!(core::mem::size_of::<BatmanKeepAlivePacket>(), 2);
    }

    /// `BatmanCertReqPacket`/`BatmanCertReplyPacket` are structurally identical
    /// to `BatmanUnicastPacket` (same 4-field, same-size header), the shape the
    /// engine's forwarding logic mirrors.
    #[test]
    fn cert_packets_mirror_unicast_layout() {
        assert_eq!(
            core::mem::size_of::<BatmanCertReqPacket>(),
            core::mem::size_of::<BatmanUnicastPacket>()
        );
        assert_eq!(
            core::mem::size_of::<BatmanCertReplyPacket>(),
            core::mem::size_of::<BatmanUnicastPacket>()
        );

        let req = BatmanCertReqPacket {
            packet_type: BATADV_CERT_REQ,
            version: 5,
            ttl: 10,
            dest: Mac([0, 0, 0, 0, 0, 9]),
        };
        let (parsed, _) = BatmanCertReqPacket::ref_from_prefix(req.as_bytes()).unwrap();
        assert_eq!(parsed.packet_type, BATADV_CERT_REQ);
        assert_eq!(parsed.dest, Mac([0, 0, 0, 0, 0, 9]));
    }
}
