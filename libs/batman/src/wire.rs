use interfaces::frame::Mac;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// EtherType identifying BATMAN frames on the wire (batman-adv's `ETH_P_BATMAN`).
pub const ETH_P_BATMAN: u16 = 0x4305;

/// The BATMAN protocol version this build speaks, carried at byte 1 of every
/// packet header and **checked on ingress** by
/// [`handle_rx`](interfaces::engine::MeshRoutingEngine::handle_rx).
///
/// It is a hard equality test, not a floor: a node that does not speak exactly
/// this version has a different idea of what the bytes after the header mean,
/// and guessing is worse than dropping. Every emitter writes it from here, so
/// changing a wire layout is one edit rather than a hunt for literals.
pub const BATMAN_VERSION: u8 = 6;

/// The BATMAN packet types this implementation produces and routes, each a
/// distinct on-the-wire `packet_type` byte (the first byte of a BATMAN frame's
/// payload).  Modelled as a `#[repr(u8)]` enum — rather than a set of free
/// `const`s — so the compiler *guarantees* the type bytes are unique (a
/// duplicated discriminant is a compile error) and keeps every assignment in
/// one place, exactly as [`TvlvType`] does for TVLV records.  The raw byte is
/// [`BatmanPacketType::as_u8`]; [`BatmanPacketType::from_u8`] recovers the
/// variant from a received byte, returning `None` for a type this node does not
/// recognise.  The `packet_type` field of each header struct stays a `u8`
/// because the wire may carry those unrecognised types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BatmanPacketType {
    /// An originator message (OGM), the topology-discovery broadcast —
    /// batman-adv's `BATADV_IV_OGM`.  Header: [`BatmanOgmPacket`].
    Ogm = 0x01,
    /// A flooded broadcast frame.  Matches batman-adv's `BATADV_BCAST`.  Used
    /// to carry broadcast/multicast link-layer frames (e.g. ARP) across the
    /// mesh, deduplicated and TTL-limited so they reach every node exactly once
    /// without looping.  Header: [`BatmanBroadcastPacket`].
    Bcast = 0x02,
    /// A unicast data packet routed hop-by-hop toward a single destination node
    /// — batman-adv's `BATADV_UNICAST`.  Header: [`BatmanUnicastPacket`].
    Unicast = 0x03,
    /// A selectively-forwarded multicast frame, mirroring batman-adv's
    /// `batadv_mcast_packet`.  A multicast frame with a bounded set of
    /// interested listeners is delivered as one [`BatmanMcastPacket`] per
    /// listener, each addressed to that listener's node and routed toward it
    /// like a unicast.  Kept distinct from [`BatmanPacketType::Unicast`] so
    /// multicast traffic stays identifiable on the wire.
    Mcast = 0x04,
    /// A lazy-cert-distribution fetch request, routed hop-by-hop toward the
    /// originator whose cert is needed — Wayfinder-specific, no batman-adv
    /// counterpart. Kept as its own packet type (not a
    /// [`BatmanPacketType::Unicast`] payload) for the same reason as
    /// [`BatmanPacketType::Mcast`]: so cert-control traffic stays identifiable
    /// on the wire, separate from data.  Header: [`BatmanCertReqPacket`].
    CertReq = 0x05,
    /// The reply to a [`BatmanPacketType::CertReq`], routed hop-by-hop back
    /// toward the requester. Wayfinder-specific, no batman-adv counterpart.
    /// Header: [`BatmanCertReplyPacket`].
    CertReply = 0x06,
    /// A link-local keep-alive heartbeat. Single-hop only — never
    /// forwarded/relayed, carries no destination or TTL (the link-layer
    /// `frame.src` already identifies the sender). Detects a gone-quiet
    /// immediate neighbor far faster than OGM-interval-based staleness, without
    /// affecting OGM-driven topology discovery at all. Wayfinder-specific, no
    /// batman-adv counterpart.  Header: [`BatmanKeepAlivePacket`].
    Keepalive = 0x07,
    /// A next-hop proof challenge: a nonce a node sends to a candidate next hop,
    /// which only the holder of that neighbor's pairwise key can answer.
    ///
    /// Link-local and single-hop, for the same reason as
    /// [`BatmanPacketType::Keepalive`] and then some: a proof that carried a
    /// `dest` would be relayable by the mesh's own forwarding, which is exactly
    /// what it exists to rule out. Wayfinder-specific, no batman-adv
    /// counterpart.  Header: [`BatmanNextHopChallengePacket`], nonce as body.
    NextHopChallenge = 0x08,
    /// The answer to a [`BatmanPacketType::NextHopChallenge`]: a pairwise tag
    /// over the challenger's nonce. Link-local and single-hop like the
    /// challenge. Wayfinder-specific, no batman-adv counterpart.  Header:
    /// [`BatmanNextHopResponsePacket`], tag as body.
    NextHopResponse = 0x09,
    /// A reachability probe addressed to one node — the mesh's answer to
    /// `ping`, at the layer this stack actually operates at (there are no IP
    /// addresses here, so ICMP is not available). Routed hop-by-hop toward
    /// `dest` exactly like a unicast, and answered by the destination with a
    /// [`BatmanPacketType::EchoReply`]. Wayfinder-specific, no batman-adv
    /// counterpart.  Header: [`BatmanEchoPacket`], pad bytes as body.
    EchoRequest = 0x0a,
    /// The answer to a [`BatmanPacketType::EchoRequest`], routed hop-by-hop
    /// back toward the node that sent it. Wayfinder-specific, no batman-adv
    /// counterpart.  Header: [`BatmanEchoPacket`], the request's pad bytes
    /// echoed verbatim as body.
    EchoReply = 0x0b,
}

impl BatmanPacketType {
    /// The on-the-wire `packet_type` byte for this packet type — the enum's
    /// discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The packet type a received `packet_type` byte denotes, or `None` when
    /// `byte` is a type this node does not recognise (a newer peer's extension,
    /// or garbage).  Callers treat `None` as "not a BATMAN packet type we route
    /// by sub-type" rather than as a parse error.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Ogm),
            0x02 => Some(Self::Bcast),
            0x03 => Some(Self::Unicast),
            0x04 => Some(Self::Mcast),
            0x05 => Some(Self::CertReq),
            0x06 => Some(Self::CertReply),
            0x07 => Some(Self::Keepalive),
            0x08 => Some(Self::NextHopChallenge),
            0x09 => Some(Self::NextHopResponse),
            0x0a => Some(Self::EchoRequest),
            0x0b => Some(Self::EchoReply),
            _ => None,
        }
    }
}

/// Originator Message header.  A variable-length TVLV region of `tvlv_len`
/// bytes (a sequence of [`BatmanTvlvHdr`]-prefixed records) follows this fixed
/// header on the wire; it carries piggybacked announcements such as
/// multicast group memberships.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanOgmPacket {
    /// Always [`BatmanPacketType::Ogm`] for this packet type.
    pub packet_type: u8,
    /// Protocol version; see [`BATMAN_VERSION`].
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
    /// The neighbour a *forwarder* heard this OGM from — six `Mac` bytes.
    /// Wayfinder-specific, and the one TVLV a relay writes about itself rather
    /// than carrying on the originator's behalf.
    ///
    /// Present only on **forwarded** OGMs. A node's own emission has no
    /// previous sender, so an originated OGM carries no such record and costs
    /// nothing — which matters on the small-MTU radios, where every byte is
    /// fragments.
    ///
    /// # What it is for
    ///
    /// Floods go out every interface including the one they arrived on
    /// (`driver_core::Egress::Auto`, deliberately — per-interface exclusion
    /// black-holes real topologies), so a neighbour re-floods our own forward
    /// straight back at us. Path learning is *also* deliberately not gated on
    /// the sequence number advancing (design 09 §8.11), so without this record
    /// that echo is learned as a path to the originator — a path that does not
    /// exist, and whose selection is a routing loop.
    ///
    /// Naming who the forwarder heard it from is exactly enough to tell the
    /// two apart, and nothing else on the wire can: `orig` names the
    /// originator and the link header names the immediate sender, both of
    /// which look identical in the genuine and the laundered case.
    ///
    /// # Semantics, which are easy to get backwards
    ///
    /// A forwarder stamps **the address it received the OGM from**, not its
    /// own. A receiver drops an OGM whose record names *itself*: the sender
    /// heard this copy from us, so it is repeating our own re-flood.
    ///
    /// It does not prove the sender's *route* to the originator runs back
    /// through us. A node re-floods only the first copy of each seqno it sees,
    /// so a neighbour with a genuine independent path that happened to hear
    /// our copy first stamps us too, and is dropped alongside the phantoms.
    /// That is the accepted cost: it forgoes at most one seqno's worth of path
    /// evidence from that neighbour, and the next seqno re-tests it.
    ///
    /// Stamping one's own address instead would never match anything — B would
    /// write `B`, and A would compare it against `A` — and the guard would
    /// silently do nothing.
    ///
    /// # What it does not catch
    ///
    /// Only the two-hop bounce (`A → B → A`). A longer cycle
    /// (`A → B → C → A`) reaches A naming `B`, which A cannot recognise; a
    /// full path vector would be needed, at a cost this medium cannot pay.
    /// The two-hop case is the one a stub neighbour manufactures continuously,
    /// which is what makes it worth the ten bytes a record costs
    /// ([`PREV_SENDER_RECORD_LEN`] — a four-byte TVLV header around the six
    /// address bytes).
    ///
    /// # Not signed, and it must stay that way
    ///
    /// [`TvlvType::OgmSig`] spans the originator's immutable identity (`orig`,
    /// `seqno`) and its certificate — and no TVLV bytes on the wire at all, so
    /// this record is not an exception to a rule; it is like every other
    /// record in that respect. What *is* specific to this one is that it is
    /// rewritten at every hop like `ttl` and `tq`, so bringing it under the
    /// signature would make every forwarded OGM fail verification.
    ///
    /// The consequence to keep in view: this is a **cooperative correctness
    /// mechanism, not a security control**. It has no integrity protection,
    /// the link-layer source it is compared against is unauthenticated, and a
    /// hostile relay declines the guard for free by simply not stamping —
    /// exactly as an un-upgraded peer does. It buys correct path selection
    /// among cooperating nodes; it buys nothing against an adversary.
    PrevSender = 0x84,
}

/// Length of a TVLV record header on the wire.
const TVLV_HDR_LEN: usize = core::mem::size_of::<BatmanTvlvHdr>();

/// Value length of a [`TvlvType::PrevSender`] record: one `Mac`.
///
/// Derived from `Mac` rather than written as `6`, so the record and the type
/// it carries cannot drift apart.
const PREV_SENDER_LEN: usize = core::mem::size_of::<Mac>();

/// Total wire cost of a [`TvlvType::PrevSender`] record, header included —
/// what forwarding an OGM adds to it.
pub const PREV_SENDER_RECORD_LEN: usize = TVLV_HDR_LEN + PREV_SENDER_LEN;

/// The exact number of bytes [`stamp_prev_sender`] would write for `tail`, or
/// `None` if `tail` is malformed.
///
/// Exists so a caller can tell the two ways a rewrite fails apart *before*
/// attempting it. `stamp_prev_sender` returns `None` both for a malformed tail
/// and for an output buffer too small to hold the result, but those are
/// opposite diagnoses: a small buffer is this node's own scratchpad being
/// wrong for the link it is relaying onto, while a malformed tail is a peer
/// emitting frames no buffer size will make forwardable. Reporting one as the
/// other sends an operator to resize an MTU that was never the problem.
///
/// The count is exact rather than an upper bound, which matters because it is
/// the number an operator sizes a link by: a tail that already carries a
/// previous hop's stamp does not grow, since [`stamp_prev_sender`] replaces
/// that record rather than appending to it.
pub fn stamped_len(tail: &[u8]) -> Option<usize> {
    let mut read = 0usize;
    let mut kept = 0usize;

    while read + TVLV_HDR_LEN <= tail.len() {
        let (hdr, _) = BatmanTvlvHdr::ref_from_prefix(&tail[read..]).ok()?;
        let value_end = (read + TVLV_HDR_LEN).checked_add(u16::from_be(hdr.len) as usize)?;
        if value_end > tail.len() {
            return None;
        }
        if hdr.tvlv_type != TvlvType::PrevSender.as_u8() {
            kept = kept.checked_add(value_end - read)?;
        }
        read = value_end;
    }

    kept.checked_add(PREV_SENDER_RECORD_LEN)
}

/// Copy the TVLV region `tail` into `out`, dropping any
/// [`TvlvType::PrevSender`] record already there and appending one naming
/// `prev`.  Returns the number of bytes written, or `None` if `out` cannot
/// hold the result, or a record in `tail` claims more bytes than `tail` holds.
/// A trailing fragment shorter than a TVLV header is dropped rather than
/// refused.
///
/// Callers needing to tell those two failures apart — they are opposite
/// diagnoses — should ask [`stamped_len`] first.
///
/// **Replace rather than append**, which is the whole reason this is a
/// function and not two calls: every hop stamps this record, so a tail
/// carrying the previous hop's copy must lose it here. Appending instead
/// would grow an OGM by [`PREV_SENDER_RECORD_LEN`] at every hop, so the cost
/// would scale with path length rather than staying flat.
///
/// Every other record is copied through byte-for-byte and in order, since a
/// relay is not entitled to alter what the originator said — the certificate,
/// the signature over it, multicast memberships and revocations all propagate
/// unchanged.
pub fn stamp_prev_sender(tail: &[u8], out: &mut [u8], prev: Mac) -> Option<usize> {
    let mut read = 0usize;
    let mut written = 0usize;

    while read + TVLV_HDR_LEN <= tail.len() {
        let (hdr, _) = BatmanTvlvHdr::ref_from_prefix(&tail[read..]).ok()?;
        let value_end = (read + TVLV_HDR_LEN).checked_add(u16::from_be(hdr.len) as usize)?;
        // A record claiming more bytes than the tail holds makes the rest of
        // the region unparseable; refuse rather than forward a truncated tail.
        if value_end > tail.len() {
            return None;
        }
        if hdr.tvlv_type != TvlvType::PrevSender.as_u8() {
            let record = tail.get(read..value_end)?;
            out.get_mut(written..written.checked_add(record.len())?)?
                .copy_from_slice(record);
            written += record.len();
        }
        read = value_end;
    }

    let hdr = BatmanTvlvHdr {
        tvlv_type: TvlvType::PrevSender.as_u8(),
        version: 1,
        len: (PREV_SENDER_LEN as u16).to_be(),
    };
    out.get_mut(written..written.checked_add(TVLV_HDR_LEN)?)?
        .copy_from_slice(hdr.as_bytes());
    written += TVLV_HDR_LEN;
    out.get_mut(written..written.checked_add(PREV_SENDER_LEN)?)?
        .copy_from_slice(prev.as_bytes());
    written += PREV_SENDER_LEN;

    Some(written)
}

/// The neighbour the forwarder of this OGM heard it from, if it said — the
/// value of the **first** [`TvlvType::PrevSender`] record in `tail`.
///
/// First rather than only: [`stamp_prev_sender`] emits exactly one, but a
/// hand-crafted OGM can carry several and nothing on receipt rejects that.
/// Reading the first is safe because the guard is cooperative either way (see
/// [`TvlvType::PrevSender`]) — a sender wanting to evade it omits the record
/// rather than duplicating it.
///
/// `None` for an originated OGM (which has no previous sender), for a peer
/// too old to stamp one, and for a malformed record. All three mean "cannot
/// tell", which leaves the pre-existing behaviour in place rather than
/// dropping traffic on a guess.
pub fn prev_sender(tail: &[u8]) -> Option<Mac> {
    Mac::try_from(find_tvlv(tail, TvlvType::PrevSender)?).ok()
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
    /// Always [`BatmanPacketType::Bcast`] for this packet type.
    pub packet_type: u8,
    /// Protocol version; see [`BATMAN_VERSION`].
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

/// Which proof a [`BatmanPacketType::Mcast`] frame's auth trailer carries.
///
/// **No value of this field means "unauthenticated"** — it selects *which*
/// check a frame must pass, never *whether* it is checked. That distinction is
/// the whole of design 17 §4.4: the field is attacker-chosen like every other
/// header byte, and the earlier bug it is written against (`8ab9285`) was not
/// that an attacker picked the branch, but that one branch was no check at all.
/// Both branches here are proofs, so flipping the byte only chooses the check
/// the forger fails — and since each proof covers the header, flipping it also
/// invalidates the proof that was there.
///
/// An unrecognised value is a **drop**, never a fallback to trying the other
/// verifier: with the payload running to the end of the frame there is no way
/// to tell where a 24- or 72-byte trailer begins without being told, so trying
/// both would be an oracle rather than a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum McastAuthForm {
    /// One next hop: the ordinary pairwise tag every directed frame carries,
    /// verified by the neighbour it was addressed to.
    Tag = 1,
    /// Several next hops reached by one transmission on a shared medium: the
    /// forwarding node's own signature, which every receiver verifies against
    /// the cert it already holds for that hop. A single transmission cannot
    /// carry one pairwise tag per recipient, each derived from a different key.
    Signature = 2,
}

impl McastAuthForm {
    /// The on-wire byte for this form.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse an on-wire form byte, returning `None` for a value this build
    /// cannot demand a proof for (which the caller must treat as a drop).
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Tag),
            2 => Some(Self::Signature),
            _ => None,
        }
    }
}

/// Zero is reserved: an all-zero header must fail closed, so no form may claim
/// it. Enforced here rather than left to convention — adding a `= 0` variant
/// would silently make every zeroed header parse.
const _: () = assert!(McastAuthForm::from_u8(0).is_none());

/// Fixed prefix of a [`BatmanPacketType::Mcast`] packet, followed on the wire
/// by `n_dests` destination addresses and then the encapsulated frame.
///
/// Multicast is delivered as routed unicast to an **explicit destination
/// list**, batched so destinations sharing a next hop travel in one frame. Each
/// hop delivers to itself if named, removes itself, splits the rest by next
/// hop, and emits one frame per group — so the list strictly shrinks along any
/// path and a destination traverses exactly one route.
///
/// The single-destination case is not special: it is `n_dests = 1`, an 11-byte
/// header against the 9 of the single-`dest` shape this replaces. There is no
/// fallback path and no second handler.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanMcastPacket {
    /// Always [`BatmanPacketType::Mcast`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop.
    ///
    /// A **loop backstop, not a routing input** — the same 50 a unicast
    /// carries, for the same reason. Routing follows next hops, so a loop needs
    /// a transient inconsistency during reconvergence and the TTL bounds it.
    /// Nothing sizes it to the topology.
    pub ttl: u8,
    /// How many destination addresses follow this header. MUST be >= 1: a
    /// frame naming nobody has nothing to be delivered to or routed toward.
    pub n_dests: u8,
    /// Which proof the auth trailer carries — see [`McastAuthForm`].
    pub form: u8,
}

/// Length of the fixed [`BatmanMcastPacket`] prefix, before the destination
/// list.
pub const MCAST_HEADER_LEN: usize = core::mem::size_of::<BatmanMcastPacket>();

/// A parsed multi-destination multicast packet: its header, the destination
/// list, and the encapsulated frame behind it.
///
/// Produced by [`parse`](Self::parse), so holding one is evidence that
/// `n_dests` is non-zero, that the destination list **fits the frame**, and
/// that `form` names a proof this build can demand.
///
/// Note what it does *not* prove: the list may still be longer than
/// [`MAX_MCAST_DESTS`](crate::MAX_MCAST_DESTS) — a 255-destination frame parses
/// fine — because that bound is a routing-capacity decision, not a wire one.
/// The engine applies it separately, and must.
#[derive(Debug)]
pub struct McastPacketView<'a> {
    /// The fixed header, copied out (the wire struct is packed).
    pub header: BatmanMcastPacket,
    /// Which proof the trailer carries. Already validated: parsing rejects a
    /// form byte this build does not recognise.
    pub form: McastAuthForm,
    /// The destinations this frame is still on the path to.
    pub dests: &'a [Mac],
    /// The encapsulated multicast frame.
    pub inner: &'a [u8],
}

impl<'a> McastPacketView<'a> {
    /// Parse a multicast packet from a BATMAN payload whose auth trailer has
    /// already been stripped.
    ///
    /// Returns `None` — a drop, never a partial parse — for a frame shorter
    /// than the header, a zero `n_dests`, a list that overruns the frame, or a
    /// `form` byte naming no proof.
    pub fn parse(payload: &'a [u8]) -> Option<Self> {
        let (header, rest) = BatmanMcastPacket::read_from_prefix(payload).ok()?;
        let form = McastAuthForm::from_u8(header.form)?;
        let n = header.n_dests as usize;
        if n == 0 {
            return None;
        }
        let list_len = core::mem::size_of::<Mac>().checked_mul(n)?;
        let (list, inner) = rest.split_at_checked(list_len)?;
        let dests = <[Mac]>::ref_from_bytes(list).ok()?;
        Some(Self {
            header,
            form,
            dests,
            inner,
        })
    }
}

/// Write a multicast packet into `out`, returning its total length.
///
/// Returns `None` rather than truncating: an empty `dests` (which would name
/// nobody), a list longer than `u8::MAX`, or a buffer too small for the whole
/// frame. Truncating a destination list would silently drop the listeners past
/// the cut, which is exactly the failure this design exists to remove.
pub fn write_mcast(
    ttl: u8,
    form: McastAuthForm,
    dests: &[Mac],
    inner: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if dests.is_empty() || dests.len() > u8::MAX as usize {
        return None;
    }
    let list_len = core::mem::size_of_val(dests);
    let total = MCAST_HEADER_LEN + list_len + inner.len();
    if total > out.len() {
        return None;
    }

    let header = BatmanMcastPacket {
        packet_type: BatmanPacketType::Mcast.as_u8(),
        version: BATMAN_VERSION,
        ttl,
        n_dests: dests.len() as u8,
        form: form.as_u8(),
    };
    out[..MCAST_HEADER_LEN].copy_from_slice(header.as_bytes());
    out[MCAST_HEADER_LEN..MCAST_HEADER_LEN + list_len].copy_from_slice(dests.as_bytes());
    out[MCAST_HEADER_LEN + list_len..total].copy_from_slice(inner);
    Some(total)
}

/// Header for a [`BatmanPacketType::Unicast`] data packet.  The encapsulated
/// payload follows it and the packet is routed hop by hop toward `dest`,
/// TTL-limited to prevent loops, and delivered to the local host on arrival at `dest`.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanUnicastPacket {
    /// Always [`BatmanPacketType::Unicast`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to prevent routing loops for data.
    pub ttl: u8,
    /// The final destination node address in the mesh.
    pub dest: Mac,
}

/// Header for a [`BatmanPacketType::CertReq`] packet. Structurally a unicast
/// header: the requester's `MembershipCert` + signature (see the router's cert-request
/// logic) follows it, and the packet is routed hop by hop toward `dest` — the
/// originator whose cert is being requested — TTL-limited, delivered to the
/// local auth state on arrival at `dest` (or at any intermediate holder that
/// answers early).
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanCertReqPacket {
    /// Always [`BatmanPacketType::CertReq`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to prevent routing loops.
    pub ttl: u8,
    /// The originator node whose certificate is being requested.
    pub dest: Mac,
}

/// Header for a [`BatmanPacketType::CertReply`] packet. Structurally a unicast header:
/// the requested `MembershipCert` follows it, and the packet is routed hop by
/// hop back toward `dest` — the original requester — TTL-limited, delivered to
/// the local auth state on arrival at `dest`.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanCertReplyPacket {
    /// Always [`BatmanPacketType::CertReply`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to prevent routing loops.
    pub ttl: u8,
    /// The requester node this reply is addressed back to.
    pub dest: Mac,
}

/// Header for both halves of the reachability-probe pair
/// ([`BatmanPacketType::EchoRequest`] and [`BatmanPacketType::EchoReply`]) —
/// one struct, because a reply is the request with the addresses swapped and
/// the hop counters carried forward. Pad bytes follow it on the wire and are
/// echoed back verbatim, so a probe can be sized to exercise a link's MTU.
///
/// Structurally a unicast header plus what a round trip needs to be *measured*:
/// the packet is routed hop by hop toward `dest`, TTL-limited, and delivered
/// locally on arrival.
///
/// Carries **no transmit timestamp**, deliberately. The node that originates a
/// probe owns the ping session that produced it, so it already knows when it
/// sent sequence *n*; reading the round trip from local state rather than from
/// bytes a peer handed back is both smaller on the wire and not something a
/// peer can skew.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanEchoPacket {
    /// [`BatmanPacketType::EchoRequest`] or [`BatmanPacketType::EchoReply`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to prevent routing loops.
    pub ttl: u8,
    /// The node this packet is routed toward: the probe's target in a request,
    /// the node that sent the probe in a reply.
    pub dest: Mac,
    /// The node that sent *this* packet: the pinger in a request, the
    /// responder in a reply.  Together with `seqno` it is what lets a pinger
    /// match a reply to the probe it issued.
    pub orig: Mac,
    /// The probe's sequence number within its ping session, in network byte
    /// order (big endian).  Echoed unchanged in the reply.
    pub seqno: u16,
    /// How many relays the *request* traversed.  Zero in a request that has not
    /// been relayed yet, incremented at each hop, then frozen by the responder
    /// into the reply — so a pinger learns the forward path length even when
    /// the return path differs, which on an asymmetric mesh it often does.
    pub req_hops: u8,
    /// How many relays *this* packet has traversed so far, incremented at each
    /// hop.  In a reply this counts the return path only; `req_hops` holds the
    /// forward one.
    pub hops: u8,
}

/// Header for a [`BatmanPacketType::NextHopChallenge`]. Minimal by the same
/// reasoning as [`BatmanKeepAlivePacket`]: the challenger's nonce follows as the
/// body, and its length is the router's concern — `batman` carries no crypto
/// dependency, so no key or tag size appears here.
///
/// Carries no `dest` and no `ttl`: a proof is only meaningful between immediate
/// neighbors, and the link-layer `frame.src` already names the challenger.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanNextHopChallengePacket {
    /// Always [`BatmanPacketType::NextHopChallenge`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
}

/// Header for a [`BatmanPacketType::NextHopResponse`]. The pairwise tag over
/// the challenger's nonce follows as the body; see
/// [`BatmanNextHopChallengePacket`] for why the header carries nothing else.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanNextHopResponsePacket {
    /// Always [`BatmanPacketType::NextHopResponse`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
}

/// Header for a [`BatmanPacketType::Keepalive`] heartbeat. Deliberately minimal
/// (no seqno, no origin, no TVLV tail) — it exists purely to prove a link is
/// still alive between OGMs, so it carries nothing beyond the packet-type
/// tag and protocol version.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanKeepAlivePacket {
    /// Always [`BatmanPacketType::Keepalive`].
    pub packet_type: u8,
    /// Protocol version; see [`BATMAN_VERSION`].
    pub version: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// The shape design 17 exists for: one frame naming several listeners.
    #[test]
    fn mcast_round_trips_a_multi_destination_list() {
        let dests = [mac(4), mac(5), mac(6)];
        let mut buf = [0u8; 128];
        let n = write_mcast(50, McastAuthForm::Signature, &dests, b"PAYLOAD", &mut buf)
            .expect("three destinations fit");

        let view = McastPacketView::parse(&buf[..n]).expect("round trips");
        assert_eq!(view.header.packet_type, BatmanPacketType::Mcast.as_u8());
        assert_eq!(view.header.version, BATMAN_VERSION);
        assert_eq!(view.header.ttl, 50);
        assert_eq!(view.form, McastAuthForm::Signature);
        assert_eq!(view.dests, &dests);
        assert_eq!(view.inner, b"PAYLOAD");
    }

    /// The single-destination case is `n_dests = 1`, not a fallback — one code
    /// path, so this parses through exactly the same route.
    #[test]
    fn mcast_round_trips_a_single_destination() {
        let mut buf = [0u8; 64];
        let n = write_mcast(50, McastAuthForm::Tag, &[mac(7)], b"X", &mut buf).unwrap();

        let view = McastPacketView::parse(&buf[..n]).unwrap();
        assert_eq!(view.dests, &[mac(7)]);
        assert_eq!(view.form, McastAuthForm::Tag);
        assert_eq!(view.inner, b"X");
        assert_eq!(
            n,
            MCAST_HEADER_LEN + 6 + 1,
            "an 11-byte header against the old 9"
        );
    }

    /// `n_dests` MUST be >= 1 (§4.1). A zero-destination frame is malformed:
    /// it names nobody, so there is nothing it could be delivered to or routed
    /// toward.
    #[test]
    fn mcast_rejects_zero_destinations() {
        let mut buf = [0u8; 64];
        let n = write_mcast(50, McastAuthForm::Tag, &[mac(7)], b"X", &mut buf).unwrap();
        buf[3] = 0;
        assert!(McastPacketView::parse(&buf[..n]).is_none());

        // And the writer refuses to build one in the first place.
        assert!(write_mcast(50, McastAuthForm::Tag, &[], b"X", &mut buf).is_none());
    }

    /// A destination count larger than the bytes behind it. This is the bounds
    /// check that stops a remote frame reading a list out of a payload that
    /// has none.
    #[test]
    fn mcast_rejects_a_list_that_overruns_the_frame() {
        let mut buf = [0u8; 64];
        let n = write_mcast(50, McastAuthForm::Tag, &[mac(7)], b"", &mut buf).unwrap();
        for claimed in [2u8, 3, 255] {
            buf[3] = claimed;
            assert!(
                McastPacketView::parse(&buf[..n]).is_none(),
                "a claimed count of {claimed} must not read past the frame"
            );
        }
    }

    /// **No value of `form` means "unauthenticated"** (§4.4). An unrecognised
    /// one is a drop, never a fallback to trying the other verifier.
    #[test]
    fn mcast_rejects_an_unrecognised_auth_form() {
        let mut buf = [0u8; 64];
        let n = write_mcast(50, McastAuthForm::Tag, &[mac(7)], b"X", &mut buf).unwrap();
        for form in [0u8, 3, 4, 255] {
            buf[4] = form;
            let view = McastPacketView::parse(&buf[..n]);
            assert!(
                view.is_none(),
                "form {form} is not a proof this build can demand"
            );
        }
    }

    /// A truncated frame — shorter than the fixed header — is not a panic.
    #[test]
    fn mcast_rejects_a_frame_too_short_for_its_header() {
        for len in 0..MCAST_HEADER_LEN {
            assert!(McastPacketView::parse(&[0u8; MCAST_HEADER_LEN][..len]).is_none());
        }
    }

    /// The writer reports the space it needs rather than truncating a list.
    #[test]
    fn mcast_refuses_a_buffer_it_does_not_fit() {
        let dests = [mac(4), mac(5), mac(6)];
        let mut tiny = [0u8; MCAST_HEADER_LEN + 6];
        assert!(write_mcast(50, McastAuthForm::Tag, &dests, b"", &mut tiny).is_none());
    }

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

    /// Every packet type's discriminant is the documented on-the-wire byte.
    /// The enum makes collisions a compile error, so this only has to pin the
    /// *values* — the wire contract other implementations (and the Wireshark
    /// dissector) are written against.
    #[test]
    fn packet_type_bytes_are_stable() {
        assert_eq!(BatmanPacketType::Ogm.as_u8(), 0x01);
        assert_eq!(BatmanPacketType::Bcast.as_u8(), 0x02);
        assert_eq!(BatmanPacketType::Unicast.as_u8(), 0x03);
        assert_eq!(BatmanPacketType::Mcast.as_u8(), 0x04);
        assert_eq!(BatmanPacketType::CertReq.as_u8(), 0x05);
        assert_eq!(BatmanPacketType::CertReply.as_u8(), 0x06);
        assert_eq!(BatmanPacketType::Keepalive.as_u8(), 0x07);
        assert_eq!(BatmanPacketType::NextHopChallenge.as_u8(), 0x08);
        assert_eq!(BatmanPacketType::NextHopResponse.as_u8(), 0x09);
        assert_eq!(BatmanPacketType::EchoRequest.as_u8(), 0x0a);
        assert_eq!(BatmanPacketType::EchoReply.as_u8(), 0x0b);
    }

    /// `from_u8` is the exact inverse of `as_u8` over the known types, and
    /// rejects a byte outside them rather than inventing a variant — the
    /// engine's dispatch relies on `None` meaning "route by destination".
    #[test]
    fn packet_type_roundtrips_and_rejects_unknown() {
        let all = [
            BatmanPacketType::Ogm,
            BatmanPacketType::Bcast,
            BatmanPacketType::Unicast,
            BatmanPacketType::Mcast,
            BatmanPacketType::CertReq,
            BatmanPacketType::CertReply,
            BatmanPacketType::Keepalive,
            BatmanPacketType::NextHopChallenge,
            BatmanPacketType::NextHopResponse,
            BatmanPacketType::EchoRequest,
            BatmanPacketType::EchoReply,
        ];
        for ty in all {
            assert_eq!(BatmanPacketType::from_u8(ty.as_u8()), Some(ty));
        }
        assert_eq!(BatmanPacketType::from_u8(0x00), None);
        assert_eq!(BatmanPacketType::from_u8(0x0c), None);
        assert_eq!(BatmanPacketType::from_u8(0xff), None);
    }

    /// `BatmanKeepAlivePacket` round-trips through `zerocopy` parsing like
    /// every other minimal control packet.
    #[test]
    fn keepalive_packet_roundtrips() {
        let pkt = BatmanKeepAlivePacket {
            packet_type: BatmanPacketType::Keepalive.as_u8(),
            version: BATMAN_VERSION,
        };
        let (parsed, _) = BatmanKeepAlivePacket::ref_from_prefix(pkt.as_bytes()).unwrap();
        assert_eq!(parsed.packet_type, BatmanPacketType::Keepalive.as_u8());
        assert_eq!(parsed.version, BATMAN_VERSION);
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
            packet_type: BatmanPacketType::CertReq.as_u8(),
            version: BATMAN_VERSION,
            ttl: 10,
            dest: Mac([0, 0, 0, 0, 0, 9]),
        };
        let (parsed, _) = BatmanCertReqPacket::ref_from_prefix(req.as_bytes()).unwrap();
        assert_eq!(parsed.packet_type, BatmanPacketType::CertReq.as_u8());
        assert_eq!(parsed.dest, Mac([0, 0, 0, 0, 0, 9]));
    }

    /// `BatmanEchoPacket` round-trips through `zerocopy` parsing, and its
    /// multi-byte field is big-endian on the wire like every other one here.
    /// The size is pinned because it is a wire contract: the dissector and any
    /// other implementation are written against these 19 bytes.
    #[test]
    fn echo_packet_roundtrips() {
        let pkt = BatmanEchoPacket {
            packet_type: BatmanPacketType::EchoRequest.as_u8(),
            version: BATMAN_VERSION,
            ttl: 50,
            dest: Mac([0, 0, 0, 0, 0, 9]),
            orig: Mac([0, 0, 0, 0, 0, 1]),
            seqno: 0x1234u16.to_be(),
            req_hops: 0,
            hops: 0,
        };
        let (parsed, rest) = BatmanEchoPacket::ref_from_prefix(pkt.as_bytes()).unwrap();
        assert_eq!(parsed.packet_type, BatmanPacketType::EchoRequest.as_u8());
        assert_eq!(parsed.dest, Mac([0, 0, 0, 0, 0, 9]));
        assert_eq!(parsed.orig, Mac([0, 0, 0, 0, 0, 1]));
        assert_eq!(u16::from_be(parsed.seqno), 0x1234);
        assert!(rest.is_empty());
        assert_eq!(core::mem::size_of::<BatmanEchoPacket>(), 19);
    }

    /// The next-hop proof pair carries its payload — a nonce out, a tag back —
    /// as the body after a minimal header, exactly as `BatmanKeepAlivePacket`
    /// carries its auth trailer. The crypto lengths live in the router, not
    /// here: `batman` stays free of any crypto dependency.
    #[test]
    fn next_hop_proof_packets_are_minimal_headers() {
        let challenge = BatmanNextHopChallengePacket {
            packet_type: BatmanPacketType::NextHopChallenge.as_u8(),
            version: BATMAN_VERSION,
        };
        let (parsed, rest) =
            BatmanNextHopChallengePacket::ref_from_prefix(challenge.as_bytes()).unwrap();
        assert_eq!(
            parsed.packet_type,
            BatmanPacketType::NextHopChallenge.as_u8()
        );
        assert_eq!(parsed.version, BATMAN_VERSION);
        assert!(rest.is_empty(), "the nonce is the body, not a header field");

        let response = BatmanNextHopResponsePacket {
            packet_type: BatmanPacketType::NextHopResponse.as_u8(),
            version: BATMAN_VERSION,
        };
        let (parsed, _) =
            BatmanNextHopResponsePacket::ref_from_prefix(response.as_bytes()).unwrap();
        assert_eq!(
            parsed.packet_type,
            BatmanPacketType::NextHopResponse.as_u8()
        );

        assert_eq!(
            core::mem::size_of::<BatmanNextHopChallengePacket>(),
            core::mem::size_of::<BatmanKeepAlivePacket>()
        );
        assert_eq!(
            core::mem::size_of::<BatmanNextHopResponsePacket>(),
            core::mem::size_of::<BatmanKeepAlivePacket>()
        );
    }

    /// Neither carries a `dest` or a `ttl`, and that is load-bearing rather
    /// than an omission: a proof is link-local, so the mesh's own forwarding
    /// can never relay one. An attacker wanting to wormhole a challenge to the
    /// node it is impersonating has to carry the bytes itself.
    #[test]
    fn next_hop_proof_packets_are_not_routable() {
        assert!(
            core::mem::size_of::<BatmanNextHopChallengePacket>()
                < core::mem::size_of::<BatmanUnicastPacket>(),
            "a routable header would need at least a dest"
        );
        assert!(
            core::mem::size_of::<BatmanNextHopResponsePacket>()
                < core::mem::size_of::<BatmanUnicastPacket>()
        );
    }

    /// A header truncated below its two bytes is refused rather than read as a
    /// valid packet, matching every sibling handler's malformed-input rule.
    #[test]
    fn a_truncated_next_hop_proof_header_does_not_parse() {
        let one_byte = [BatmanPacketType::NextHopChallenge.as_u8()];
        assert!(BatmanNextHopChallengePacket::ref_from_prefix(&one_byte).is_err());
        assert!(BatmanNextHopResponsePacket::ref_from_prefix(&one_byte).is_err());
    }
}
