"""Tests for which EtherTypes the dissector claims.

A Wayfinder frame reaches a capture under one of two EtherTypes, because a
`RawL2Link` separates the *transport label* it stamps on the wire from the
*mesh protocol* the router demuxes on (see libs/wayfinder-driver/src/raw.rs):

* **0x4305** (ETH_P_BATMAN) — the mesh protocol, what a `LinkFrame.protocol`
  holds and what a carrier with no wire/mesh split (TAP, UDP) puts on the wire.
* **the carrier EtherType** — what a raw-L2 packet socket or the nRF's CDC-NCM
  USB link actually stamps, so co-located meshes can be kept apart. 0xfafa is
  this repo's default (`MESH_ETHERTYPE`, containers/node.yml), but a deployment
  may configure any value — hence the `wayfinder.carrier_ethertype` preference.

Both must dissect out of the box, and the preference must move the second one.
"""

import struct

import pytest

# The mesh protocol, always claimed (libs/batman/src/wire.rs).
ETH_P_BATMAN = 0x4305
# The default raw-L2 carrier label (libs/wayfinder-nrf/src/usb_link.rs).
DEFAULT_CARRIER = 0xFAFA

PKT_OGM = 0x01
BROADCAST = b"\xff" * 6
NODE1 = b"\x02\x00\x00\x00\x00\x01"


def frame_with_ethertype(ethertype: int) -> bytes:
    """A minimal OGM-carrying Ethernet frame stamped with `ethertype`.

    Only the seqno is asserted on, so the OGM header is inlined here rather
    than shared with test_ogm_dissector — what's under test is the EtherType
    the frame arrives under, not the body.
    """
    ogm = (
        struct.pack(">BBBB", PKT_OGM, 15, 50, 0)
        + struct.pack(">I", 4242)  # seqno
        + NODE1  # orig
        + struct.pack(">BB", 0, 255)  # reserved, tq
        + struct.pack(">H", 0)  # tvlv_len
    )
    return BROADCAST + NODE1 + struct.pack(">H", ethertype) + ogm


@pytest.mark.parametrize("ethertype", [ETH_P_BATMAN, DEFAULT_CARRIER])
def test_default_ethertypes_are_claimed(dissect, ethertype):
    """Both the mesh protocol and the default carrier dissect with no config."""
    result = dissect(
        frame_with_ethertype(ethertype),
        ["_ws.col.protocol", "wayfinder.originator.seqno"],
    )
    assert result["_ws.col.protocol"] == "Wayfinder"
    assert result["wayfinder.originator.seqno"] == "4242"


def test_carrier_ethertype_preference_moves_the_claim(dissect):
    """Setting the preference claims that EtherType instead of the default."""
    result = dissect(
        frame_with_ethertype(0x1234),
        ["_ws.col.protocol", "wayfinder.originator.seqno"],
        ["-o", "wayfinder.carrier_ethertype:0x1234"],
    )
    assert result["_ws.col.protocol"] == "Wayfinder"
    assert result["wayfinder.originator.seqno"] == "4242"


def test_carrier_preference_releases_the_previous_ethertype(dissect):
    """Re-pointing the preference stops claiming the default carrier.

    The registration is a mutation of a global table, so a changed preference
    has to *remove* the old entry — not just add the new one — or a capture
    keeps decoding an EtherType the operator has configured away.
    """
    result = dissect(
        frame_with_ethertype(DEFAULT_CARRIER),
        ["_ws.col.protocol"],
        ["-o", "wayfinder.carrier_ethertype:0x1234"],
    )
    assert result["_ws.col.protocol"] != "Wayfinder"


def test_mesh_protocol_is_claimed_regardless_of_preference(dissect):
    """0x4305 is the protocol itself, so no preference can unclaim it."""
    result = dissect(
        frame_with_ethertype(ETH_P_BATMAN),
        ["_ws.col.protocol"],
        ["-o", "wayfinder.carrier_ethertype:0x1234"],
    )
    assert result["_ws.col.protocol"] == "Wayfinder"


def test_carrier_preference_can_be_disabled(dissect):
    """An empty preference claims only the mesh protocol."""
    result = dissect(
        frame_with_ethertype(DEFAULT_CARRIER),
        ["_ws.col.protocol"],
        ["-o", "wayfinder.carrier_ethertype:"],
    )
    assert result["_ws.col.protocol"] != "Wayfinder"


def test_carrier_preference_cannot_collide_with_mesh_protocol(dissect):
    """Pointing the preference at 0x4305 does not double-register it.

    A second `DissectorTable:add` for an EtherType already claimed by this
    dissector errors at load time ("there cannot be two protocols with the
    same description" — see the module header), which would break dissection
    outright rather than fail a clean assertion. The `apply_carrier_pref`
    guard against `wanted == ETH_P_BATMAN` exists specifically to prevent
    this.
    """
    result = dissect(
        frame_with_ethertype(ETH_P_BATMAN),
        ["_ws.col.protocol", "wayfinder.originator.seqno"],
        ["-o", "wayfinder.carrier_ethertype:0x4305"],
    )
    assert result["_ws.col.protocol"] == "Wayfinder"
    assert result["wayfinder.originator.seqno"] == "4242"


def test_carrier_ethertype_preference_accepts_decimal(dissect):
    """The preference's help text promises decimal or 0x-hex; decimal works too."""
    result = dissect(
        frame_with_ethertype(0x1234),
        ["_ws.col.protocol"],
        ["-o", "wayfinder.carrier_ethertype:4660"],  # 0x1234 in decimal
    )
    assert result["_ws.col.protocol"] == "Wayfinder"
