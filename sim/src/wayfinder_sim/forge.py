"""Hand-built mesh frames, for a scenario acting as an attacker.

Everything here writes raw wire bytes with no router involved and no
guardrails applied — which is the point. A real attacker does not call
`PyDriver.queue_local_send`; it reimplements the wire format from what it
observed on the air and emits whatever it likes. These helpers are that
reimplementation, kept deliberately small and separate from the bindings so
nothing in a scenario can accidentally reach for the blessed encoder and
prove less than it thinks.

The layouts mirror `interfaces::frame::LinkFrame` and
`batman::wire::BatmanOgmPacket`; `test_adversary.py` pins them against a
router that must accept (open mesh) or reject (authenticated mesh) the
result, so drift shows up as a failing test rather than a silent no-op.
"""

from __future__ import annotations

import random

import wayfinder_py as wf

BATMAN_ETHERTYPE = 0x4305
"""`wayfinder::DEFAULT_BATMAN_ETHER_TYPE` — the protocol field carrying mesh
frames."""

PACKET_OGM = 0x01
PACKET_BCAST = 0x02
PACKET_UNICAST = 0x03
PACKET_KEEPALIVE = 0x07
PACKET_NEXT_HOP_CHALLENGE = 0x08
PACKET_NEXT_HOP_RESPONSE = 0x09
"""`batman::wire::BatmanPacketType` discriminants, as the first payload
byte."""

OGM_VERSION = 5
"""The BATMAN protocol version wayfinder emits; an OGM claiming another is
dropped as unparseable rather than routed."""

LINK_HEADER_LEN = 14
"""`[dst:6][src:6][protocol:2]` — the fixed link header every mesh frame
carries."""


def link_frame(
    dst: wf.PyMac,
    src: wf.PyMac,
    payload: bytes,
    *,
    protocol: int = BATMAN_ETHERTYPE,
) -> bytes:
    """A raw link frame: `[dst][src][protocol big-endian][payload]`.

    `src` is whatever the attacker cares to claim — a link layer stamps it,
    and nothing about the frame proves it.
    """
    return b"".join(
        (
            bytes(dst.bytes),
            bytes(src.bytes),
            protocol.to_bytes(2, "big"),
            payload,
        )
    )


def ogm(
    orig: wf.PyMac,
    seqno: int = 1,
    *,
    ttl: int = 50,
    tq: int = 255,
    flags: int = 0,
    tvlv: bytes = b"",
) -> bytes:
    """An originator message claiming to come from `orig`, with no signature.

    `tq` is the advertised path quality. A forged OGM with `tq=255` and a
    high `ttl` is the classic route-hijack shape: it claims to be the best
    path to `orig` from everywhere at once, so an open mesh converges its
    traffic onto the attacker.
    """
    return b"".join(
        (
            bytes(
                (
                    PACKET_OGM,
                    OGM_VERSION,
                    ttl & 0xFF,
                    flags & 0xFF,
                )
            ),
            (seqno & 0xFFFF_FFFF).to_bytes(4, "big"),
            bytes(orig.bytes),
            bytes((0, tq & 0xFF)),  # reserved padding, then TQ
            len(tvlv).to_bytes(2, "big"),
            tvlv,
        )
    )


def keepalive(seqno: int = 1) -> bytes:
    """A link-local keep-alive heartbeat, single-hop and unrouted. Cheap to
    forge and cheap to send, which is what makes it interesting as a flood."""
    return bytes((PACKET_KEEPALIVE, OGM_VERSION)) + (seqno & 0xFFFF).to_bytes(2, "big")


def next_hop_challenge(nonce: bytes) -> bytes:
    """A next-hop proof challenge: `[type][version][nonce]`, link-local and
    single-hop like `keepalive`. A real challenger derives `nonce` from a PRF
    keyed on its own secret, unpredictable to anyone else; nothing about the
    wire format stops an attacker sending whatever bytes it likes here."""
    return bytes((PACKET_NEXT_HOP_CHALLENGE, OGM_VERSION)) + nonce


def next_hop_response(tag: bytes) -> bytes:
    """The answer to a next-hop proof challenge: `[type][version][tag]`. A
    real responder computes `tag` as a pairwise-keyed MAC over the
    challenger's nonce — proof of holding a key this forges nothing about;
    this just writes whatever bytes the caller gives it."""
    return bytes((PACKET_NEXT_HOP_RESPONSE, OGM_VERSION)) + tag


def tvlv(record_type: int, value: bytes, *, version: int = 1) -> bytes:
    """One TVLV record — `[type][version][len big-endian][value]` — for
    stuffing into `ogm(tvlv=...)`. `batman::wire::TvlvType` names the types
    wayfinder produces (`0x80` cert, `0x81` OGM signature, `0x82`
    revocation)."""
    return (
        bytes((record_type & 0xFF, version & 0xFF))
        + len(value).to_bytes(2, "big")
        + value
    )


def garbage(rng: random.Random, *, min_len: int = 14, max_len: int = 512) -> bytes:
    """Random bytes of a plausible frame length.

    Long enough to clear the link header — a frame shorter than that is
    rejected as malformed at the point of the call, which proves nothing
    about the parser behind it. This is the input that has to be *survived*,
    not understood.
    """
    return bytes(
        rng.getrandbits(8) for _ in range(rng.randint(max(min_len, 1), max_len))
    )


def corrupt(frame: bytes, rng: random.Random, *, bits: int = 1) -> bytes:
    """`frame` with `bits` random bits flipped — a captured frame replayed
    with damage, for probing whether a mangled-but-plausible frame is
    rejected as cleanly as obvious garbage."""
    out = bytearray(frame)
    if not out:
        return bytes(out)
    for _ in range(bits):
        index = rng.randrange(len(out))
        out[index] ^= 1 << rng.randrange(8)
    return bytes(out)
