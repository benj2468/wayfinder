"""Passive observation of a link — the listening half of a red-team scenario.

`Simulation.wiretap` attaches a `Wiretap` to a link and every frame that
crosses it is recorded, exactly as it appeared on the medium. There is no
node behind it and nothing for a router to reject: a radio link is a shared
medium, and anyone in range hears it.

That is worth stating plainly, because a successful wiretap is not a
finding. Wayfinder authenticates and segregates; it never encrypts. A
listener reading application payloads off an authenticated mesh has
confirmed the design, not broken it — and a scenario that records the fact
is documenting the boundary rather than discovering a hole. What *would* be
a finding is a forged frame the mesh accepts, which is `forge` plus
`Simulation.inject`, not this.
"""

from __future__ import annotations

import dataclasses

import wayfinder_py as wf

from .forge import BATMAN_ETHERTYPE, LINK_HEADER_LEN


@dataclasses.dataclass(frozen=True)
class CapturedFrame:
    """One frame seen crossing a tapped link, with its link header already
    split out — the view an attacker with a packet capture has."""

    t_s: float
    """Simulation time the frame was transmitted."""

    link: str
    """Name of the link it crossed."""

    src: wf.PyMac
    """The source MAC as stamped on the wire. Claimed, not proven: on an
    unauthenticated mesh anything may appear here."""

    dst: wf.PyMac
    """The destination MAC, or `PyMac.BROADCAST` for a flood."""

    protocol: int
    """The EtherType-style protocol field — `0x4305` for mesh traffic."""

    payload: bytes
    """Everything after the 14-byte link header. For mesh traffic its first
    byte is the BATMAN packet type (`forge.PACKET_*`)."""

    raw: bytes
    """The complete frame, header included."""

    @property
    def packet_type(self) -> int | None:
        """The BATMAN sub-type byte, or `None` for a non-mesh frame."""
        if self.protocol != BATMAN_ETHERTYPE or not self.payload:
            return None
        return self.payload[0]

    @property
    def delivered(self) -> bool:
        """Whether the channel actually delivered this frame to anyone.

        A tap sees what was *transmitted*; on a lossy radio that is not the
        same as what arrived. Kept as a property so the distinction stays
        visible in a scenario rather than being quietly assumed away.
        """
        return self._delivered

    _delivered: bool = True


@dataclasses.dataclass
class Wiretap:
    """Everything heard on one link.

    Attached by `Simulation.wiretap`; frames accumulate for the whole run, so
    a long flood scenario will fill it. Read it after `run`, or clear it
    between phases with `reset`.
    """

    link: str
    frames: list[CapturedFrame] = dataclasses.field(default_factory=list)

    def reset(self) -> None:
        """Drop everything captured so far — for measuring one phase of a
        scenario without the previous phase's traffic in the total."""
        self.frames.clear()

    def by_source(self, src: wf.PyMac) -> list[CapturedFrame]:
        """Only the frames claiming to come from `src`."""
        return [frame for frame in self.frames if frame.src == src]

    def of_type(self, packet_type: int) -> list[CapturedFrame]:
        """Only the mesh frames with the given BATMAN sub-type
        (`forge.PACKET_OGM` and friends)."""
        return [frame for frame in self.frames if frame.packet_type == packet_type]

    def containing(self, needle: bytes) -> list[CapturedFrame]:
        """Frames whose bytes contain `needle` — how a scenario asks whether
        a payload it sent was readable off the wire."""
        return [frame for frame in self.frames if needle in frame.raw]

    def capture(self, t_s: float, raw: bytes, delivered: bool = True) -> None:
        """Record one frame. Called by `Simulation`; a scenario reads, it
        does not write."""
        if len(raw) < LINK_HEADER_LEN:
            return
        self.frames.append(
            CapturedFrame(
                t_s=t_s,
                link=self.link,
                src=wf.PyMac(raw[6:12]),
                dst=wf.PyMac(raw[0:6]),
                protocol=int.from_bytes(raw[12:14], "big"),
                payload=raw[LINK_HEADER_LEN:],
                raw=raw,
                _delivered=delivered,
            )
        )

    def __len__(self) -> int:
        return len(self.frames)
