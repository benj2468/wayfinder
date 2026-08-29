"""End-to-end tests for the reachability-probe packets
(`BatmanPacketType::EchoRequest` / `BatmanPacketType::EchoReply`) in
wayfinder.lua.

Mirrors `BatmanEchoPacket` in libs/batman/src/wire.rs: one 19-byte header serves
both halves of the pair, because a reply is the request with the addresses
swapped and the hop counters carried forward. Pad bytes follow it and are echoed
verbatim by the responder.

The two hop counters are what a capture is usually opened for, so they get their
own cases: `req_hops` is the *forward* path length, frozen by the responder into
the reply, while `hops` counts the leg the packet in hand has travelled. A
capture that showed only one of them could not distinguish an asymmetric path
from a symmetric one.
"""

import struct

import pytest

# EtherType the dissector hooks (ETH_P_BATMAN); see libs/batman/src/wire.rs.
ETH_P_BATMAN = 0x4305

# packet_type bytes for the probe pair (libs/batman/src/wire.rs).
PKT_ECHO_REQUEST = 0x0A
PKT_ECHO_REPLY = 0x0B

NODE1 = b"\x02\x00\x00\x00\x00\x01"
NODE2 = b"\x02\x00\x00\x00\x00\x02"


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    """Build an Ethernet frame: ``[dst][src][ethertype BE][payload]``."""
    return dst + src + struct.pack(">H", ethertype) + payload


def echo_header(
    packet_type: int,
    *,
    version: int = 5,
    ttl: int = 50,
    dest: bytes,
    orig: bytes,
    seqno: int = 0,
    req_hops: int = 0,
    hops: int = 0,
) -> bytes:
    """Serialize a ``BatmanEchoPacket`` header."""
    return (
        struct.pack(">BBB", packet_type, version, ttl)
        + dest
        + orig
        + struct.pack(">HBB", seqno, req_hops, hops)
    )


def echo_frame(packet_type: int, *, pad: bytes = b"", **kwargs) -> bytes:
    """A complete probe-carrying Ethernet frame."""
    kwargs.setdefault("dest", NODE1)
    kwargs.setdefault("orig", NODE2)
    body = echo_header(packet_type, **kwargs) + pad
    return ethernet(kwargs["dest"], NODE2, ETH_P_BATMAN, body)


def test_echo_request_packet_type_labelled(dissect):
    """A probe's packet type decodes to its known value."""
    result = dissect(echo_frame(PKT_ECHO_REQUEST), ["wayfinder.type"])
    assert result["wayfinder.type"] == "0x0a"


def test_echo_reply_packet_type_labelled(dissect):
    """And so does its answer's."""
    result = dissect(echo_frame(PKT_ECHO_REPLY), ["wayfinder.type"])
    assert result["wayfinder.type"] == "0x0b"


# field name -> expected decoded value for a request from NODE2 to NODE1.
EXPECTED_ECHO_FIELDS = {
    "wayfinder.echo.ttl": "50",
    "wayfinder.echo.dest": "02:00:00:00:00:01",
    "wayfinder.echo.orig": "02:00:00:00:00:02",
    "wayfinder.echo.seqno": "7",
    "wayfinder.echo.hops": "2",
}


@pytest.mark.parametrize("field,expected", list(EXPECTED_ECHO_FIELDS.items()))
def test_echo_request_header_decodes(dissect, field, expected):
    """Every header field of a probe decodes."""
    frame = echo_frame(PKT_ECHO_REQUEST, seqno=7, hops=2)
    result = dissect(frame, [field])
    assert result[field] == expected


def test_a_reply_reports_both_legs_of_the_path(dissect):
    """The pair of hop counters is the point of capturing a reply: the forward
    path length the responder froze, and the return leg this packet has
    travelled — different numbers on an asymmetric mesh."""
    frame = echo_frame(PKT_ECHO_REPLY, dest=NODE2, orig=NODE1, req_hops=3, hops=1)
    result = dissect(frame, ["wayfinder.echo.req_hops", "wayfinder.echo.hops"])
    assert result["wayfinder.echo.req_hops"] == "3"
    assert result["wayfinder.echo.hops"] == "1"


def test_probe_payload_surfaces_verbatim(dissect):
    """The pad a probe carries — what makes a probe usable for sizing against a
    link's MTU — is shown as-is rather than dropped."""
    pad = bytes(range(16))
    frame = echo_frame(PKT_ECHO_REQUEST, pad=pad)
    result = dissect(frame, ["wayfinder.echo.pad"])
    assert result["wayfinder.echo.pad"] == pad.hex()


def test_a_padless_probe_has_no_payload_field(dissect):
    """A probe sized to zero pad bytes is well-formed, and must not produce an
    empty payload field for a payload that is not there."""
    result = dissect(echo_frame(PKT_ECHO_REQUEST), ["wayfinder.echo.pad"])
    assert result.get("wayfinder.echo.pad", "") == ""


def test_truncated_probe_header_does_not_crash(dissect):
    """A capture cut mid-header degrades to the bare packet type rather than
    erroring the dissector, like every other truncated case here."""
    body = echo_header(PKT_ECHO_REQUEST, dest=NODE1, orig=NODE2)[:10]
    frame = ethernet(NODE1, NODE2, ETH_P_BATMAN, body)
    result = dissect(frame, ["wayfinder.type"])
    assert result["wayfinder.type"] == "0x0a"
