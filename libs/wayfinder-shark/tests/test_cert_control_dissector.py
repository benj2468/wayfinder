"""End-to-end tests for the lazy-cert-distribution control packets
(`BatmanPacketType::CertReq` / `BatmanPacketType::CertReply`) in wayfinder.lua.

Mirrors libs/batman/src/wire.rs's `BatmanCertReqPacket`/`BatmanCertReplyPacket`:
a unicast-shaped header (`packet_type`, `version`, `ttl`, `dest`) followed by a
body — the requester's own cert + a 64-byte self-authenticating signature for
a request, or the requested originator's raw cert for a reply.
"""

import struct

import pytest

# EtherType the dissector hooks (ETH_P_BATMAN); see libs/batman/src/wire.rs.
ETH_P_BATMAN = 0x4305

# packet_type bytes for the cert-control packets (libs/batman/src/wire.rs).
PKT_CERT_REQ = 0x05
PKT_CERT_REPLY = 0x06

NODE1 = b"\x02\x00\x00\x00\x00\x01"
NODE2 = b"\x02\x00\x00\x00\x00\x02"


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    """Build an Ethernet frame: ``[dst][src][ethertype BE][payload]``."""
    return dst + src + struct.pack(">H", ethertype) + payload


def cert_ctrl_header(
    packet_type: int, *, version: int = 5, ttl: int = 50, dest: bytes
) -> bytes:
    """Serialize the shared cert-control header: type/version/ttl/dest."""
    return struct.pack(">BBB", packet_type, version, ttl) + dest


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


def cert_req_frame(
    *,
    dest: bytes = NODE1,
    requester_cert: bytes | None = None,
    signature: bytes = b"\x44" * 64,
) -> bytes:
    """A complete ``BatmanPacketType::CertReq``-carrying Ethernet frame."""
    if requester_cert is None:
        requester_cert = membership_cert(node_mac=NODE2)
    body = cert_ctrl_header(PKT_CERT_REQ, dest=dest) + requester_cert + signature
    return ethernet(dest, NODE2, ETH_P_BATMAN, body)


def cert_reply_frame(*, dest: bytes = NODE2, cert: bytes | None = None) -> bytes:
    """A complete ``BatmanPacketType::CertReply``-carrying Ethernet frame."""
    if cert is None:
        cert = membership_cert(node_mac=dest)
    body = cert_ctrl_header(PKT_CERT_REPLY, dest=dest) + cert
    return ethernet(dest, NODE1, ETH_P_BATMAN, body)


def test_cert_req_packet_type_labelled(dissect):
    """A CertReq's packet type decodes to its known value."""
    result = dissect(cert_req_frame(), ["wayfinder.batman.type"])
    assert result["wayfinder.batman.type"] == "0x05"


def test_cert_reply_packet_type_labelled(dissect):
    """A CertReply's packet type decodes to its known value."""
    result = dissect(cert_reply_frame(), ["wayfinder.batman.type"])
    assert result["wayfinder.batman.type"] == "0x06"


# field name -> expected decoded value for a CertReq addressed to NODE1,
# carrying a requester cert for NODE2.
EXPECTED_CERT_REQ_FIELDS = {
    "wayfinder.batman.cert_ctrl.ttl": "50",
    "wayfinder.batman.cert_ctrl.dest": "02:00:00:00:00:01",
    "wayfinder.batman.tvlv.cert.node_mac": "02:00:00:00:00:02",
    "wayfinder.batman.tvlv.cert.mesh_id": "0x0000abcd",
}


@pytest.mark.parametrize("field,expected", list(EXPECTED_CERT_REQ_FIELDS.items()))
def test_cert_req_header_and_cert_decode(dissect, field, expected):
    """A CertReq's header and embedded requester cert both decode."""
    result = dissect(cert_req_frame(dest=NODE1), [field])
    assert result[field] == expected


def test_cert_req_signature_decodes(dissect):
    """The self-authenticating 64-byte signature following the requester's
    cert surfaces verbatim."""
    sig = bytes(range(64))
    frame = cert_req_frame(signature=sig)
    result = dissect(frame, ["wayfinder.batman.cert_req.signature"])
    assert result["wayfinder.batman.cert_req.signature"] == sig.hex()


# field name -> expected decoded value for a CertReply addressed to NODE2,
# carrying NODE2's own cert.
EXPECTED_CERT_REPLY_FIELDS = {
    "wayfinder.batman.cert_ctrl.ttl": "50",
    "wayfinder.batman.cert_ctrl.dest": "02:00:00:00:00:02",
    "wayfinder.batman.tvlv.cert.node_mac": "02:00:00:00:00:02",
    "wayfinder.batman.tvlv.cert.mesh_id": "0x0000abcd",
}


@pytest.mark.parametrize("field,expected", list(EXPECTED_CERT_REPLY_FIELDS.items()))
def test_cert_reply_header_and_cert_decode(dissect, field, expected):
    """A CertReply's header and embedded cert both decode."""
    result = dissect(cert_reply_frame(dest=NODE2), [field])
    assert result[field] == expected


def test_cert_req_truncated_body_does_not_crash(dissect):
    """A CertReq whose body is too short for a full cert + signature must not
    error the dissector — it degrades to the bare header, like a truncated
    capture elsewhere in this dissector."""
    dest = NODE1
    body = cert_ctrl_header(PKT_CERT_REQ, dest=dest) + b"\x00" * 10
    frame = ethernet(dest, NODE2, ETH_P_BATMAN, body)
    result = dissect(frame, ["wayfinder.batman.cert_ctrl.dest"])
    assert result["wayfinder.batman.cert_ctrl.dest"] == "02:00:00:00:00:01"
