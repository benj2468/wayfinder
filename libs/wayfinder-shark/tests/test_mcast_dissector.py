"""End-to-end tests for the multi-destination multicast packet
(`BatmanPacketType::Mcast`) in wayfinder.lua.

Mirrors `BatmanMcastPacket` in libs/batman/src/wire.rs. Multicast is delivered
as routed unicast to an **explicit destination list** (design 17), so the header
is a fixed 5-byte prefix — type, version, ttl, `n_dests`, `form` — followed by
that many addresses and then the encapsulated frame. It is not a unicast header
with one `dest`, which is the shape this replaced.

The destination list is the reason to open a multicast capture at all, so it is
spelled out per address rather than summarised. A frame's list *shrinks* at
every hop (each hop removes itself and splits the rest by next hop), so the same
multicast legitimately names different sets at two points in one capture, and a
dissector that showed only a count could not show that.
"""

import struct

# EtherType the dissector hooks (ETH_P_BATMAN); see libs/batman/src/wire.rs.
ETH_P_BATMAN = 0x4305

# packet_type byte for a multicast frame (libs/batman/src/wire.rs).
PKT_MCAST = 0x04

# The protocol version this layout ships with — bumped for the flag day that
# changed `Mcast`'s shape, so a node meeting the other layout rejects it on the
# version rather than misparsing.
BATMAN_VERSION = 6

# `McastAuthForm`. Both are proofs; the field selects which check a frame must
# pass, never whether it is checked.
FORM_TAG = 1
FORM_SIGNATURE = 2

SENDER = b"\x02\x00\x00\x00\x00\x09"
NODE1 = b"\x02\x00\x00\x00\x00\x01"
NODE2 = b"\x02\x00\x00\x00\x00\x02"
NODE3 = b"\x02\x00\x00\x00\x00\x03"


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    """Build an Ethernet frame: ``[dst][src][ethertype BE][payload]``."""
    return dst + src + struct.pack(">H", ethertype) + payload


def mcast_body(
    dests: list[bytes],
    *,
    version: int = BATMAN_VERSION,
    ttl: int = 50,
    form: int = FORM_TAG,
    payload: bytes = b"",
    n_dests: int | None = None,
) -> bytes:
    """Serialize a ``BatmanMcastPacket`` plus its destination list and body.

    ``n_dests`` overrides the declared count independently of ``dests`` so a
    test can build the malformed frame a remote peer could send.
    """
    count = len(dests) if n_dests is None else n_dests
    return (
        struct.pack(">BBBBB", PKT_MCAST, version, ttl, count, form)
        + b"".join(dests)
        + payload
    )


def mcast_frame(dests: list[bytes], **kwargs) -> bytes:
    """A complete multicast-carrying Ethernet frame."""
    return ethernet(NODE1, SENDER, ETH_P_BATMAN, mcast_body(dests, **kwargs))


def test_mcast_packet_type_labelled(dissect):
    """A multicast frame's packet type decodes to its known value."""
    result = dissect(mcast_frame([NODE1]), ["wayfinder.type"])
    assert result["wayfinder.type"] == "0x04"


def test_single_destination_header_fields(dissect):
    """The ordinary one-listener case is `n_dests = 1`, not a special shape."""
    result = dissect(
        mcast_frame([NODE1], ttl=42),
        [
            "wayfinder.mcast.version",
            "wayfinder.mcast.ttl",
            "wayfinder.mcast.n_dests",
            "wayfinder.mcast.form",
            "wayfinder.mcast.dest",
        ],
    )
    assert result["wayfinder.mcast.version"] == str(BATMAN_VERSION)
    assert result["wayfinder.mcast.ttl"] == "42"
    assert result["wayfinder.mcast.n_dests"] == "1"
    assert result["wayfinder.mcast.form"] == str(FORM_TAG)
    assert result["wayfinder.mcast.dest"] == "02:00:00:00:00:01"


def test_every_destination_in_the_list_is_decoded(dissect):
    """**The point of the packet.** Three listeners behind one next hop travel
    in one frame naming all three, and the capture must show all three."""
    result = dissect(
        mcast_frame([NODE1, NODE2, NODE3]),
        ["wayfinder.mcast.n_dests", "wayfinder.mcast.dest"],
    )
    assert result["wayfinder.mcast.n_dests"] == "3"
    assert result["wayfinder.mcast.dest"] == (
        "02:00:00:00:00:01,02:00:00:00:00:02,02:00:00:00:00:03"
    )


def test_both_auth_forms_are_named(dissect):
    """`form` selects which proof the trailer carries. A capture that showed
    the raw byte would leave the reader to remember which is which."""
    for form in (FORM_TAG, FORM_SIGNATURE):
        result = dissect(mcast_frame([NODE1], form=form), ["wayfinder.mcast.form"])
        assert result["wayfinder.mcast.form"] == str(form)


def test_encapsulated_frame_follows_the_list(dissect):
    """The payload starts after the list, not at a fixed offset — so a
    two-destination frame's body sits six bytes further along than a one's."""
    result = dissect(
        mcast_frame([NODE1, NODE2], payload=b"\xde\xad\xbe\xef"),
        ["wayfinder.mcast.payload"],
    )
    assert result["wayfinder.mcast.payload"].replace(":", "") == "deadbeef"


def test_a_list_overrunning_the_frame_is_not_decoded(dissect):
    """`n_dests` is remote input. A count larger than the bytes behind it must
    not read off the end of the capture — the dissector believes the field only
    as far as the frame actually goes."""
    frame = mcast_frame([NODE1], n_dests=8)
    result = dissect(frame, ["wayfinder.mcast.n_dests", "wayfinder.mcast.dest"])
    assert result["wayfinder.mcast.n_dests"] == "8"
    assert not result.get("wayfinder.mcast.dest")


def test_zero_destinations_is_malformed(dissect):
    """`n_dests` MUST be >= 1: a frame naming nobody has nothing to be
    delivered to or routed toward."""
    result = dissect(mcast_frame([], n_dests=0), ["wayfinder.mcast.dest"])
    assert not result.get("wayfinder.mcast.dest")


def test_a_truncated_header_does_not_decode(dissect):
    """Shorter than the fixed prefix: labelled, but nothing is read from it."""
    body = struct.pack(">BBB", PKT_MCAST, BATMAN_VERSION, 50)
    frame = ethernet(NODE1, SENDER, ETH_P_BATMAN, body)
    result = dissect(frame, ["wayfinder.type", "wayfinder.mcast.n_dests"])
    assert result["wayfinder.type"] == "0x04"
    assert not result.get("wayfinder.mcast.n_dests")
