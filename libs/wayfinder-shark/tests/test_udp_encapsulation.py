"""Tests for decoding a Wayfinder frame carried inside a UDP datagram.

The `Udp` and `UdpMulti` link transports (libs/wayfinder-driver/src/net.rs) put
a whole `LinkFrame` — `[dst][src][protocol][payload]`, the same
Ethernet-shaped 14-byte header `frame_into_buf` writes for every other carrier
— in the *payload* of a UDP datagram. So a capture of a UDP-carried mesh has an
extra Ethernet/IP/UDP wrapper in front of the bytes the ethertype-registered
dissector already understands, and nothing in the ethertype table can reach it.

There is no canonical mesh UDP port (this repo alone uses 6000 in
nix/machines/wayfinder-ca and 9191/9192 in var/conf/peer.yml), so the claim is
made by a *heuristic* on the datagram's own shape rather than by port: a
14-byte header whose protocol field is the mesh protocol, followed by a known
packet type. These tests pin both halves of that — that a real frame is
claimed, and that a datagram which merely happens to be UDP is not.
"""

import struct

# The mesh protocol a UDP carrier writes into the encapsulated LinkFrame. A UDP
# port is already the demux, so there is no wire-vs-mesh split here and no
# carrier EtherType to configure (contrast test_carrier_ethertype.py).
ETH_P_BATMAN = 0x4305
ETH_P_IPV4 = 0x0800

PKT_OGM = 0x01

BROADCAST = b"\xff" * 6
NODE1 = b"\x02\x00\x00\x00\x00\x01"
NODE2 = b"\x02\x00\x00\x00\x00\x02"

# Arbitrary; the point of the heuristic is that neither port matters.
SPORT, DPORT = 6000, 6000


def ogm(seqno: int = 4242) -> bytes:
    """A minimal TVLV-less Originator packet body."""
    return (
        struct.pack(">BBBB", PKT_OGM, 15, 50, 0)
        + struct.pack(">I", seqno)
        + NODE1  # orig
        + struct.pack(">BB", 0, 255)  # reserved, tq
        + struct.pack(">H", 0)  # tvlv_len
    )


def link_frame(
    body: bytes, dst: bytes = BROADCAST, protocol: int = ETH_P_BATMAN
) -> bytes:
    """The `LinkFrame` a UDP link puts in its datagram payload."""
    return dst + NODE1 + struct.pack(">H", protocol) + body


def _checksum(data: bytes) -> int:
    """The standard 16-bit one's-complement Internet checksum over `data`."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp_frame(payload: bytes, sport: int = SPORT, dport: int = DPORT) -> bytes:
    """An Ethernet + IPv4 + UDP frame carrying `payload` as the datagram body.

    Enough of a real stack for tshark to reach the UDP payload: the IPv4 header
    checksum is computed (an obviously wrong one would be flagged), the UDP
    checksum is left zero — which IPv4 explicitly permits and tshark accepts.
    """
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip_no_csum = (
        struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0)
        + bytes((10, 0, 0, 1))
        + bytes((10, 0, 0, 2))
    )
    ip = ip_no_csum[:10] + struct.pack(">H", _checksum(ip_no_csum)) + ip_no_csum[12:]
    return NODE2 + NODE1 + struct.pack(">H", ETH_P_IPV4) + ip + udp


def test_udp_encapsulated_originator_is_dissected(dissect):
    """A UDP-carried OGM decodes down to its body fields, on no configuration."""
    result = dissect(
        udp_frame(link_frame(ogm())),
        ["_ws.col.protocol", "wayfinder.originator.seqno"],
    )
    assert result["_ws.col.protocol"] == "Wayfinder"
    assert result["wayfinder.originator.seqno"] == "4242"


def test_encapsulated_link_header_is_decoded(dissect):
    """The 14-byte LinkFrame header is spelled out, not skipped over.

    Under an ethertype registration Wireshark's own `eth` dissector shows these
    three fields; over UDP nothing else will, and they are the only place a
    capture records which mesh node sent the datagram — the IP columns show the
    transport endpoints instead.
    """
    result = dissect(
        udp_frame(link_frame(ogm(), dst=NODE2)),
        ["wayfinder.link.dst", "wayfinder.link.src", "wayfinder.link.protocol"],
    )
    assert result["wayfinder.link.dst"] == "02:00:00:00:00:02"
    assert result["wayfinder.link.src"] == "02:00:00:00:00:01"
    assert result["wayfinder.link.protocol"] == "0x4305"


def test_udp_info_column_names_the_mesh_endpoints(dissect):
    """The Info column carries the mesh addresses the IP columns displace."""
    result = dissect(
        udp_frame(link_frame(ogm(), dst=NODE2)),
        ["_ws.col.info"],
    )
    assert "Originator" in result["_ws.col.info"]
    assert "02:00:00:00:00:01" in result["_ws.col.info"]
    assert "02:00:00:00:00:02" in result["_ws.col.info"]


def test_udp_payload_with_a_foreign_protocol_is_not_claimed(dissect):
    """A datagram whose encapsulated protocol isn't the mesh one is left alone.

    The heuristic runs against *every* UDP datagram in a capture, so the check
    that matters most is the one that declines.
    """
    result = dissect(
        udp_frame(link_frame(ogm(), protocol=0x0800)),
        ["_ws.col.protocol"],
    )
    assert result["_ws.col.protocol"] != "Wayfinder"


def test_udp_payload_with_an_unknown_packet_type_is_not_claimed(dissect):
    """0x4305 at offset 12 alone isn't enough; the body must look like one too."""
    body = b"\xee" + ogm()[1:]
    result = dissect(
        udp_frame(link_frame(body)),
        ["_ws.col.protocol"],
    )
    assert result["_ws.col.protocol"] != "Wayfinder"


def test_short_udp_payload_is_not_claimed(dissect):
    """A datagram too short to hold a header plus a packet type is declined."""
    result = dissect(
        udp_frame(BROADCAST + NODE1 + struct.pack(">H", ETH_P_BATMAN)),
        ["_ws.col.protocol"],
    )
    assert result["_ws.col.protocol"] != "Wayfinder"


def test_udp_encapsulated_echo_reaches_the_body_dissector(dissect):
    """Encapsulation is a wrapper, not a second decoder: every type still works.

    An Echo Reply rather than an Originator, so the test would fail if the UDP
    path had grown its own partial copy of the body decode.
    """
    echo = (
        struct.pack(">BBB", 0x0B, 15, 50)
        + NODE1  # dest
        + NODE2  # orig
        + struct.pack(">HBB", 7, 3, 2)  # seqno, req_hops, hops
    )
    result = dissect(
        udp_frame(link_frame(echo, dst=NODE1)),
        ["_ws.col.protocol", "wayfinder.echo.seqno", "wayfinder.echo.hops"],
    )
    assert result["_ws.col.protocol"] == "Wayfinder"
    assert result["wayfinder.echo.seqno"] == "7"
    assert result["wayfinder.echo.hops"] == "2"
