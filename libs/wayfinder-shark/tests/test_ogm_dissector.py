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
    prev_sender: bytes = NODE2,
    reserved: int = 0,
    tq: int = 255,
    tvlv: bytes = b"",
) -> bytes:
    """Serialize a ``BatmanOgmPacket`` (fixed header + TVLV tail) to wire bytes."""
    return (
        struct.pack(">BBBB", BATADV_IV_OGM, version, ttl, flags)
        + struct.pack(">I", seqno)  # seqno is big-endian on the wire
        + orig
        + prev_sender
        + struct.pack(">BB", reserved, tq)
        + struct.pack(">H", len(tvlv))  # tvlv_len, big-endian
        + tvlv
    )


def ogm_frame(**ogm_kwargs) -> bytes:
    """A complete OGM-carrying Ethernet frame for the dissector to chew on."""
    return ethernet(BROADCAST, NODE1, ETH_P_BATMAN, batman_ogm(**ogm_kwargs))


# field name -> expected decoded value for the default OGM above (with a
# 4-byte 0xdeadbeef TVLV tail).
EXPECTED_FIELDS = {
    "wayfinder.batman.ttl": "50",
    "wayfinder.batman.ogm.seqno": "1234",
    "wayfinder.batman.ogm.orig": "02:00:00:00:00:01",
    "wayfinder.batman.ogm.prev_sender": "02:00:00:00:00:02",
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
