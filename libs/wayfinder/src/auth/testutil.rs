//! Fixtures shared by this module's test submodules.
//!
//! Here rather than in any one of them because every topic needs a mesh:
//! an authority, a member holding a certificate it signed, and a pair of
//! nodes that have admitted each other. Duplicating that per file is how
//! two files end up disagreeing about what a valid member looks like.

use super::*;
use batman::wire::BATMAN_VERSION;
use batman::wire::BatmanKeepAlivePacket;
use batman::wire::BatmanOgmPacket;
use batman::wire::BatmanPacketType;
use wayfinder_auth::Authority;

/// The address the identity seeded with `n` derives.
///
/// Not the compact `00:00:00:00:00:n` this used to be: since the key↔address
/// binding landed (design 09 §5) a certificate's subject *is* the address
/// its key derives, so a fixture that numbered addresses independently of
/// the keys it mints could not produce a certificate that verifies. The
/// module's `member`/`verified_cert` helpers already paired seed `n` with
/// `mac(n)` almost everywhere, so pairing them here fixes the whole module
/// at once — and makes the mismatch impossible to write by accident.
pub(in crate::auth) fn mac(n: u8) -> Mac {
    Keypair::from_seed(&[n; 32]).derived_mac()
}

/// Build a bare OGM (header only, no TVLV) for `orig` into a fresh buffer,
/// returning `(buf, len)` with generous trailing capacity for augmentation.
pub(in crate::auth) fn bare_ogm(orig: Mac, seqno: u32) -> ([u8; 512], usize) {
    let ogm = BatmanOgmPacket {
        packet_type: BatmanPacketType::Ogm.as_u8(),
        version: BATMAN_VERSION,
        ttl: 50,
        flags: 0,
        seqno: seqno.to_be(),
        orig,
        reserved: 0,
        tq: 255,
        tvlv_len: 0,
    };
    let mut buf = [0u8; 512];
    buf[..OGM_HDR].copy_from_slice(ogm.as_bytes());
    (buf, OGM_HDR)
}

/// Build a bare keep-alive body (header only, no auth trailer) into a fresh
/// buffer, returning `(buf, len)` with generous trailing capacity for
/// augmentation.
pub(in crate::auth) fn bare_keepalive() -> ([u8; 128], usize) {
    let pkt = BatmanKeepAlivePacket {
        packet_type: BatmanPacketType::Keepalive.as_u8(),
        version: BATMAN_VERSION,
    };
    let mut buf = [0u8; 128];
    let len = core::mem::size_of::<BatmanKeepAlivePacket>();
    buf[..len].copy_from_slice(pkt.as_bytes());
    (buf, len)
}

/// An authority and a member node's auth state, sharing the same anchor.
pub(in crate::auth) fn member(authority: &Authority, seed: u8, m: Mac, valid_to: u64) -> OgmAuth {
    let kp = Keypair::from_seed(&[seed; 32]);
    let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), 0, valid_to);
    let mut auth = OgmAuth::new(kp, cert, authority.trust_anchor());
    auth.set_time(Duration::from_secs(100), Clocked::At(100));
    auth
}

/// A neighbour entry for the identity seeded `seed`, but *addressed* at
/// `at` — the `derive_mac` collision the §8.9 identity lock now exists for.
///
/// Since the key↔address binding landed (design 09 §5) a certificate cannot
/// name an address its key does not derive, so a second *certified* key for
/// one address is refused by `verify_cert` before `cache_neighbor` ever sees
/// it. The lock survives as defense in depth over exactly one residual: two
/// distinct identity keys hashing to one 46-bit address. That cannot be
/// minted (it would need a preimage), so it is built here by hand — a
/// genuine verified certificate with its subject rewritten, which is the
/// same state a real collision would produce.
pub(in crate::auth) fn colliding_neighbor(
    authority: &Authority,
    seed: u8,
    at: Mac,
    valid_to: u64,
    holder: &OgmAuth,
) -> NeighborKeys {
    let kp = Keypair::from_seed(&[seed; 32]);
    let raw = authority.issue_cert(kp.derived_mac(), kp.ed_pubkey(), kp.x_pubkey(), 0, valid_to);
    let mut cert = authority
        .trust_anchor()
        .verify_cert(&raw, Clocked::At(100))
        .expect("the colliding key's own certificate is perfectly valid");
    // The collision itself: the same key, reached at another address.
    cert.mac = at;
    NeighborKeys {
        pairwise_key: holder.keypair.pairwise_key(&cert.x_pubkey),
        cert,
        raw_cert: raw,
        last_ogm: None,
    }
}

/// A [`VerifiedCert`] for `m` issued at `issued_at`, for the tests that
/// exercise [`OgmAuth::is_revoked`] directly rather than driving it
/// through [`OgmAuth::verify_ogm`].
pub(in crate::auth) fn verified_cert(
    authority: &Authority,
    seed: u8,
    m: Mac,
    issued_at: u64,
) -> VerifiedCert {
    let kp = Keypair::from_seed(&[seed; 32]);
    let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), issued_at, 1_000_000);
    authority
        .trust_anchor()
        .verify_cert(&cert, Clocked::At(issued_at))
        .expect("a freshly issued cert verifies at its own issuance instant")
}

/// [`member`] with an explicit issuance instant and clock, for the
/// revocation-by-invalidity-date tests: which side of a revocation's
/// instant a certificate was issued on is the whole question there, and
/// [`member`]'s hardcoded `not_before` of 0 cannot express it.
pub(in crate::auth) fn member_issued_at(
    authority: &Authority,
    seed: u8,
    m: Mac,
    issued_at: u64,
    valid_to: u64,
    wall: Clocked,
) -> OgmAuth {
    let kp = Keypair::from_seed(&[seed; 32]);
    let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), issued_at, valid_to);
    let mut auth = OgmAuth::new(kp, cert, authority.trust_anchor());
    auth.set_time(Duration::from_secs(wall.unix_or_zero()), wall);
    auth
}

/// Exchange one signed OGM each way, so both nodes hold the other's
/// verified certificate and the pairwise key derived from it — the
/// precondition for any pairwise operation between them.
pub(in crate::auth) fn admit_each_other(x: &mut OgmAuth, x_mac: Mac, y: &mut OgmAuth, y_mac: Mac) {
    let (mut buf, len) = bare_ogm(x_mac, 7);
    let len = x.augment_ogm(&mut buf, len).expect("augment");
    assert_eq!(y.verify_ogm(&buf[..len]), OgmVerdict::Verified);

    let (mut buf, len) = bare_ogm(y_mac, 7);
    let len = y.augment_ogm(&mut buf, len).expect("augment");
    assert_eq!(x.verify_ogm(&buf[..len]), OgmVerdict::Verified);
}

/// The `default` profile's capacities, spelled out positionally.
pub(in crate::auth) type DefaultAuth =
    OgmAuth<MAX_NEIGHBOR_KEYS, MAX_REVOKED, MAX_IN_FLIGHT_CERT_REQUESTS, MAX_PENDING_REPLIES>;

/// Exchange OGMs both ways so `a` and `b` each cache the other's verified
/// pairwise key (a precondition for tagging/verifying directed frames).
pub(in crate::auth) fn mutual_verify(a: &mut OgmAuth, a_mac: Mac, b: &mut OgmAuth, b_mac: Mac) {
    let (mut buf, len) = bare_ogm(a_mac, 1);
    let len = a.augment_ogm(&mut buf, len).unwrap();
    assert_eq!(b.verify_ogm(&buf[..len]), OgmVerdict::Verified);
    let (mut buf, len) = bare_ogm(b_mac, 1);
    let len = b.augment_ogm(&mut buf, len).unwrap();
    assert_eq!(a.verify_ogm(&buf[..len]), OgmVerdict::Verified);
}
