"""End-to-end tests for the BATMAN OGM dissection in wayfinder.lua.

A crafted Ethernet frame (EtherType 0x4305) carrying a BATMAN OGM with known
field values is fed through tshark with the dissector loaded; each decoded
field is asserted against its expected value. Mirrors the Rust wire layout in
libs/batman/src/wire.rs.
"""

import struct

import pytest

# EtherType the dissector hooks (ETH_P_BATMAN); see libs/batman/src/wire.rs.
ETH_P_BATMAN = 0x4305
# packet_type for an Originator Message (BATADV_IV_OGM).
BATADV_IV_OGM = 0x01

BROADCAST = b"\xff" * 6
NODE1 = b"\x02\x00\x00\x00\x00\x01"
NODE2 = b"\x02\x00\x00\x00\x00\x02"


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    """Build an Ethernet frame: ``[dst][src][ethertype BE][payload]``."""
    return dst + src + struct.pack(">H", ethertype) + payload


def batman_ogm(
    *,
    version: int = 15,
    ttl: int = 50,
    flags: int = 0,
    seqno: int = 1234,
    orig: bytes = NODE1,
    reserved: int = 0,
    tq: int = 255,
    tvlv: bytes = b"",
) -> bytes:
    """Serialize a ``BatmanOgmPacket`` (fixed header + TVLV tail) to wire bytes."""
    return (
        struct.pack(">BBBB", BATADV_IV_OGM, version, ttl, flags)
        + struct.pack(">I", seqno)  # seqno is big-endian on the wire
        + orig
        + struct.pack(">BB", reserved, tq)
        + struct.pack(">H", len(tvlv))  # tvlv_len, big-endian
        + tvlv
    )


def ogm_frame(**ogm_kwargs) -> bytes:
    """A complete OGM-carrying Ethernet frame for the dissector to chew on."""
    return ethernet(BROADCAST, NODE1, ETH_P_BATMAN, batman_ogm(**ogm_kwargs))


# TVLV record type bytes (libs/batman/src/wire.rs).
WF_TVLV_CERT = 0x80
WF_TVLV_OGM_SIG = 0x81
WF_TVLV_REVOKE = 0x82
WF_TVLV_CERTFP = 0x83


def tvlv(tvlv_type: int, value: bytes, version: int = 1) -> bytes:
    """Serialize one TVLV record: ``[type][version][len BE][value]``."""
    return struct.pack(">BBH", tvlv_type, version, len(value)) + value


def revocation_record(
    *,
    mesh_id: int = 0xABCD,
    node_mac: bytes = NODE2,
    not_before: int = 500,
    not_after: int = 1000,
    signature: bytes = b"\x33" * 64,
) -> bytes:
    """A synthetic 92-byte ``RevocationRecord`` (layout only; not a real signature)."""
    return (
        struct.pack(">BB", 1, 0)  # version, flags
        + struct.pack(">I", mesh_id)
        + node_mac
        + struct.pack(">Q", not_before)
        + struct.pack(">Q", not_after)
        + signature
    )


def membership_cert(
    *,
    mesh_id: int = 0xABCD,
    node_mac: bytes = NODE1,
    ed_pubkey: bytes = bytes(range(32)),
    x_pubkey: bytes = bytes(range(32, 64)),
    not_before: int = 100,
    not_after: int = 200,
    signature: bytes = b"\x11" * 64,
) -> bytes:
    """A synthetic 156-byte ``MembershipCert`` (layout only; not a real signature)."""
    return (
        struct.pack(">BB", 1, 0)  # version, flags
        + struct.pack(">I", mesh_id)
        + node_mac
        + ed_pubkey
        + x_pubkey
        + struct.pack(">Q", not_before)
        + struct.pack(">Q", not_after)
        + signature
    )


# field name -> expected decoded value for the default OGM above (with a
# 4-byte 0xdeadbeef TVLV tail).
EXPECTED_FIELDS = {
    "wayfinder.batman.ttl": "50",
    "wayfinder.batman.ogm.seqno": "1234",
    "wayfinder.batman.ogm.orig": "02:00:00:00:00:01",
    "wayfinder.batman.ogm.tq": "255",
    "wayfinder.batman.ogm.tvlv_len": "4",
    "wayfinder.batman.ogm.tvlv": "deadbeef",
}


@pytest.mark.parametrize("field,expected", list(EXPECTED_FIELDS.items()))
def test_ogm_field_decodes(dissect, field, expected):
    """Each fixed-header / TVLV field decodes to its known value."""
    result = dissect(ogm_frame(tvlv=bytes.fromhex("deadbeef")), [field])
    assert result[field] == expected


def test_protocol_column_is_claimed(dissect):
    """The dissector claims the protocol column for the frame."""
    result = dissect(ogm_frame(), ["_ws.col.protocol"])
    assert result["_ws.col.protocol"] == "Wayfinder"


def test_ogm_without_tvlv_has_zero_len(dissect):
    """An OGM with no TVLV tail reports tvlv_len 0 and decodes its header."""
    result = dissect(
        ogm_frame(seqno=7, tvlv=b""),
        ["wayfinder.batman.ogm.tvlv_len", "wayfinder.batman.ogm.seqno"],
    )
    assert result["wayfinder.batman.ogm.tvlv_len"] == "0"
    assert result["wayfinder.batman.ogm.seqno"] == "7"


# Expected decoded cert fields for the synthetic membership_cert() above.
EXPECTED_CERT_FIELDS = {
    "wayfinder.batman.tvlv.type": "0x80",
    "wayfinder.batman.tvlv.cert.version": "1",
    "wayfinder.batman.tvlv.cert.mesh_id": "0x0000abcd",
    "wayfinder.batman.tvlv.cert.node_mac": "02:00:00:00:00:01",
    "wayfinder.batman.tvlv.cert.not_before": "100",
    "wayfinder.batman.tvlv.cert.not_after": "200",
}


@pytest.mark.parametrize("field,expected", list(EXPECTED_CERT_FIELDS.items()))
def test_cert_tvlv_decodes(dissect, field, expected):
    """A WF_TVLV_CERT record decodes into its membership-certificate fields."""
    frame = ogm_frame(tvlv=tvlv(WF_TVLV_CERT, membership_cert()))
    result = dissect(frame, [field])
    assert result[field] == expected


def test_ogm_signature_tvlv_decodes(dissect):
    """A WF_TVLV_OGM_SIG record surfaces the 64-byte signature."""
    sig = bytes(range(64))
    frame = ogm_frame(tvlv=tvlv(WF_TVLV_OGM_SIG, sig))
    result = dissect(frame, ["wayfinder.batman.tvlv.ogm_sig"])
    assert result["wayfinder.batman.tvlv.ogm_sig"] == sig.hex()


def test_walk_handles_cert_then_signature(dissect):
    """Cert and signature records in one tail are both decoded (record walk)."""
    tail = tvlv(WF_TVLV_CERT, membership_cert(mesh_id=0x1234)) + tvlv(
        WF_TVLV_OGM_SIG, b"\x22" * 64
    )
    frame = ogm_frame(tvlv=tail)
    result = dissect(
        frame,
        ["wayfinder.batman.tvlv.cert.mesh_id", "wayfinder.batman.tvlv.ogm_sig"],
    )
    assert result["wayfinder.batman.tvlv.cert.mesh_id"] == "0x00001234"
    assert result["wayfinder.batman.tvlv.ogm_sig"] == ("22" * 64)


# Expected decoded revocation fields for the synthetic revocation_record() above.
EXPECTED_REVOKE_FIELDS = {
    "wayfinder.batman.tvlv.type": "0x82",
    "wayfinder.batman.tvlv.revoke.version": "1",
    "wayfinder.batman.tvlv.revoke.mesh_id": "0x0000abcd",
    "wayfinder.batman.tvlv.revoke.node_mac": "02:00:00:00:00:02",
    "wayfinder.batman.tvlv.revoke.not_before": "500",
    "wayfinder.batman.tvlv.revoke.not_after": "1000",
}


@pytest.mark.parametrize("field,expected", list(EXPECTED_REVOKE_FIELDS.items()))
def test_revoke_tvlv_decodes(dissect, field, expected):
    """A WF_TVLV_REVOKE record decodes into its revocation-record fields."""
    frame = ogm_frame(tvlv=tvlv(WF_TVLV_REVOKE, revocation_record()))
    result = dissect(frame, [field])
    assert result[field] == expected


def test_revoke_signature_decodes(dissect):
    """The revocation's 64-byte root signature surfaces verbatim."""
    sig = bytes(range(64, 128))
    frame = ogm_frame(tvlv=tvlv(WF_TVLV_REVOKE, revocation_record(signature=sig)))
    result = dissect(frame, ["wayfinder.batman.tvlv.revoke.signature"])
    assert result["wayfinder.batman.tvlv.revoke.signature"] == sig.hex()


def test_certfp_tvlv_decodes(dissect):
    """A WF_TVLV_CERTFP record (lazy cert distribution) surfaces the 8-byte
    fingerprint, labelled and typed distinctly from the full WF_TVLV_CERT."""
    fp = bytes(range(8))
    frame = ogm_frame(tvlv=tvlv(WF_TVLV_CERTFP, fp))
    result = dissect(
        frame,
        ["wayfinder.batman.tvlv.type", "wayfinder.batman.tvlv.cert_fp"],
    )
    assert result["wayfinder.batman.tvlv.type"] == "0x83"
    assert result["wayfinder.batman.tvlv.cert_fp"] == fp.hex()


def test_walk_handles_cert_sig_then_revoke(dissect):
    """A full auth tail — cert, OGM signature, and two revocations — all decode."""
    tail = (
        tvlv(WF_TVLV_CERT, membership_cert(mesh_id=0x1234))
        + tvlv(WF_TVLV_OGM_SIG, b"\x22" * 64)
        + tvlv(WF_TVLV_REVOKE, revocation_record(node_mac=NODE1))
        + tvlv(WF_TVLV_REVOKE, revocation_record(node_mac=NODE2))
    )
    frame = ogm_frame(tvlv=tail)
    # Both revocations decode: tshark joins a field occurring on several records
    # with a comma, so seeing both MACs proves the walk advanced past each
    # record rather than stalling on the first.
    result = dissect(
        frame,
        ["wayfinder.batman.tvlv.cert.mesh_id", "wayfinder.batman.tvlv.revoke.node_mac"],
    )
    assert result["wayfinder.batman.tvlv.cert.mesh_id"] == "0x00001234"
    assert (
        result["wayfinder.batman.tvlv.revoke.node_mac"]
        == "02:00:00:00:00:01,02:00:00:00:00:02"
    )
