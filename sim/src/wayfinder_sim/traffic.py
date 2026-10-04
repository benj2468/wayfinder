"""Application traffic: numbered packets sent at a steady rate, and the record
of which arrived when.

Routing state answers "does a path exist"; a `Flow` answers the question a
user of the mesh actually has — "did my packets get through, and for how long
did they not". Every failover number a resilience study reports (time to
recover, packets lost in the gap) is read off one of these, rather than
inferred from when a route table changed: a route can resolve to a next hop
that is already dead, and only traffic notices.

`Simulation.stream` creates and drives a `Flow`; the class itself is plain
bookkeeping with no SimPy in it, so its arithmetic is testable on its own.
"""

from __future__ import annotations

import dataclasses
import struct

__all__ = ["Flow", "Outage", "Recovery", "decode_payload", "encode_payload"]

_MAGIC = b"wfFLOW"
_HEADER = struct.Struct(">6sHI")


def encode_payload(flow_id: int, seq: int) -> bytes:
    """The bytes a stream sends for packet `seq` of flow `flow_id`."""
    return _HEADER.pack(_MAGIC, flow_id, seq)


def decode_payload(payload: bytes) -> tuple[int, int] | None:
    """`(flow_id, seq)` if `payload` is a stream packet, else `None` — so an
    ordinary `Simulation.send` payload passes through to `poll_local`."""
    if len(payload) != _HEADER.size or not payload.startswith(_MAGIC):
        return None
    _, flow_id, seq = _HEADER.unpack(payload)
    return flow_id, seq


@dataclasses.dataclass(frozen=True)
class Outage:
    """A run of consecutive lost packets: `start_s` and `end_s` are the send
    times of the first and last of them."""

    start_s: float
    end_s: float
    lost: int


@dataclasses.dataclass(frozen=True)
class Recovery:
    """What a flow went through after an event at `event_s`.

    `recovered_s` is the time from the event to the send time of the first
    packet sent at or after it that arrived — the "time to reroute" a user
    experiences — or `None` if nothing sent after the event ever arrived.
    `lost` counts the packets sent from the event up to that one (or to the
    end of the flow, when it never recovered).
    """

    event_s: float
    recovered_s: float | None
    lost: int


@dataclasses.dataclass
class Flow:
    """One stream from `src` to `dest`. `sent` is `(seq, send_time_s)` in
    send order; `received` maps `seq` to its first arrival time."""

    src: str
    dest: str
    flow_id: int
    sent: list[tuple[int, float]] = dataclasses.field(default_factory=list)
    received: dict[int, float] = dataclasses.field(default_factory=dict)

    def record_sent(self, seq: int, t_s: float) -> None:
        """Note that packet `seq` left `src` at `t_s`."""
        self.sent.append((seq, t_s))

    def record_received(self, seq: int, t_s: float) -> None:
        """Note that packet `seq` reached `dest` at `t_s`. A duplicate keeps
        the first arrival."""
        self.received.setdefault(seq, t_s)

    def _window(
        self, start_s: float | None, end_s: float | None
    ) -> list[tuple[int, float]]:
        return [
            (seq, t)
            for seq, t in self.sent
            if (start_s is None or t >= start_s) and (end_s is None or t <= end_s)
        ]

    def delivery_ratio(
        self, start_s: float | None = None, end_s: float | None = None
    ) -> float | None:
        """Share of packets sent in `[start_s, end_s]` that arrived, or `None`
        when none were sent there — "no data", not zero delivery."""
        window = self._window(start_s, end_s)
        if not window:
            return None
        return sum(1 for seq, _ in window if seq in self.received) / len(window)

    def outages(self, min_lost: int = 1) -> list[Outage]:
        """Every run of at least `min_lost` consecutive lost packets, in
        order. A run still open when the flow ends is reported too."""
        out: list[Outage] = []
        run: list[float] = []
        for seq, t in self.sent:
            if seq in self.received:
                if len(run) >= min_lost:
                    out.append(Outage(run[0], run[-1], len(run)))
                run = []
            else:
                run.append(t)
        if len(run) >= min_lost:
            out.append(Outage(run[0], run[-1], len(run)))
        return out

    def recovery_after(self, event_s: float) -> Recovery:
        """How the flow fared after an event (a failure) at `event_s`."""
        lost = 0
        for seq, t in self.sent:
            if t < event_s:
                continue
            if seq in self.received:
                return Recovery(event_s, t - event_s, lost)
            lost += 1
        return Recovery(event_s, None, lost)

    def latencies_s(self) -> list[float]:
        """One-way latency of every delivered packet, in send order."""
        return [self.received[seq] - t for seq, t in self.sent if seq in self.received]
