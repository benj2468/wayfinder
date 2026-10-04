"""A shared radio medium: the cost of being on the air.

A `Channel` answers "if this frame is sent, does it arrive, and how well?"
for one transmitter and one receiver, as though nobody else existed. That is
the right model for a link with capacity to spare and the wrong one for a
crowded LoRa channel, where the binding constraints are all *between*
transmissions: a frame occupies the air for a measurable time, two frames
overlapping at a receiver destroy each other, a radio cannot hear while it
transmits, and a regulator caps how much of each hour it may transmit at all.

A `Medium`, attached to a `Link`, adds exactly those:

- **Airtime.** Every frame takes `phy.airtime_s(len)` to send — LoRa's
  time-on-air formula (`LoRaPhy`) or a plain bit rate (`FixedRate`) — and
  arrives when it has finished, not instantly.
- **One frame at a time.** Each node's radio on the link sends its queue
  back to back; frames wait their turn, and a queue past `queue_limit` drops
  rather than grows.
- **Collisions, with capture.** A reception survives only if its signal
  beats the summed power of everything else overlapping it at that receiver
  by `capture_db`. Two equal frames kill each other; a much stronger one
  survives a weak one, as real FSK and LoRa receivers do. This is pure ALOHA:
  nobody listens before talking, which is what LoRa mesh radios typically do.
- **Half-duplex.** A radio transmitting during any part of a reception
  misses it.
- **Duty cycle.** After a transmission of `T`, the radio stays silent for
  `T * (1/duty_cycle - 1)` — the per-transmission off-time form of the ETSI
  EN 300 220 limit (1% in most of the EU 868 MHz band).

None of it changes the channel model: the channel still decides how likely a
lone frame is to survive the noise, and the medium decides whether it was
alone. A channel that reports no RSSI (`PerfectWire`) is treated as every
frame arriving at equal strength, so any overlap is fatal.

`RadioStats` counts what each radio did, and `EnergyModel` turns its
transmit, receive and idle time into energy — the input to a battery-life
estimate.
"""

from __future__ import annotations

import dataclasses
import math
from typing import Protocol, runtime_checkable

__all__ = [
    "EnergyModel",
    "FixedRate",
    "LoRaPhy",
    "Medium",
    "Phy",
    "RadioStats",
]


@runtime_checkable
class Phy(Protocol):
    """How long a frame of a given size occupies the air."""

    def airtime_s(self, frame_len: int) -> float:
        """Seconds on the air for `frame_len` bytes of link frame."""
        ...


@dataclasses.dataclass(frozen=True)
class LoRaPhy:
    """LoRa time-on-air (Semtech AN1200.13).

    `sf` 7..12, `bw_hz` (125/250/500 kHz), `cr` 1..4 meaning 4/5..4/8,
    `preamble` symbols. Low-data-rate optimisation switches on automatically
    when a symbol exceeds 16 ms (SF11/12 at 125 kHz), as the radios require.

    `max_payload` is the most one LoRa packet carries; a longer link frame is
    split into that many packets and pays each one's preamble and header —
    what `libs/lora-link`'s fragmentation does on the real radio.
    """

    sf: int = 7
    bw_hz: float = 125e3
    cr: int = 1
    preamble: int = 8
    explicit_header: bool = True
    crc: bool = True
    max_payload: int = 255

    def __post_init__(self) -> None:
        if not 6 <= self.sf <= 12:
            raise ValueError(f"spreading factor {self.sf} outside 6..12")
        if not 1 <= self.cr <= 4:
            raise ValueError(f"coding rate {self.cr} outside 1..4 (4/5..4/8)")
        if self.max_payload <= 0:
            raise ValueError("max_payload must be positive")

    @property
    def symbol_s(self) -> float:
        """One symbol's duration."""
        return (2**self.sf) / self.bw_hz

    def _packet_s(self, payload: int) -> float:
        ts = self.symbol_s
        de = 1 if ts > 0.016 else 0
        ih = 0 if self.explicit_header else 1
        numerator = 8 * payload - 4 * self.sf + 28 + 16 * int(self.crc) - 20 * ih
        symbols = 8 + max(math.ceil(numerator / (4 * (self.sf - 2 * de))) * (self.cr + 4), 0)
        return (self.preamble + 4.25) * ts + symbols * ts

    def airtime_s(self, frame_len: int) -> float:
        full, rest = divmod(frame_len, self.max_payload)
        total = full * self._packet_s(self.max_payload)
        if rest or not full:
            total += self._packet_s(rest)
        return total


@dataclasses.dataclass(frozen=True)
class FixedRate:
    """A plain bit-rate PHY: `(frame_len + overhead_bytes) * 8 / bitrate_bps`.
    `overhead_bytes` is the preamble, sync word and PHY header — 6 for an
    802.15.4 frame, for instance."""

    bitrate_bps: float
    overhead_bytes: int = 0

    def airtime_s(self, frame_len: int) -> float:
        return (frame_len + self.overhead_bytes) * 8 / self.bitrate_bps


@dataclasses.dataclass(frozen=True)
class Medium:
    """The contention rules of one shared segment (see the module docs)."""

    phy: Phy
    capture_db: float = 6.0
    """How far a frame must out-power the sum of its overlapping interferers
    to survive. ~6 dB is the usual figure for LoRa at the same spreading
    factor and for narrowband FSK."""
    duty_cycle: float = 1.0
    """Share of time a radio may transmit, enforced as per-transmission
    off-time. `1.0` means unregulated."""
    queue_limit: int = 32
    """Frames a radio holds waiting for the air before it starts dropping."""

    def __post_init__(self) -> None:
        if not 0.0 < self.duty_cycle <= 1.0:
            raise ValueError(f"duty_cycle {self.duty_cycle} outside (0, 1]")
        if self.queue_limit < 1:
            raise ValueError("queue_limit must be at least 1")

    def off_time_s(self, airtime_s: float) -> float:
        """Silence owed after a transmission of `airtime_s`."""
        return airtime_s * (1.0 / self.duty_cycle - 1.0)


@dataclasses.dataclass
class RadioStats:
    """What one node's radios did on media-carrying links, summed over them.

    `rx_airtime_s` is time spent receiving anything — frames for others and
    frames that collided included, since the radio burns receive power on all
    of them — counted once where receptions overlap.
    """

    tx_frames: int = 0
    tx_airtime_s: float = 0.0
    rx_frames: int = 0
    """Frames received intact and handed to the router."""
    rx_airtime_s: float = 0.0
    collisions: int = 0
    """Receptions lost to overlap with other transmissions or interference."""
    jammed: int = 0
    """Receptions lost to a `Jammer`'s interference (counted here on any
    link, contended or not)."""
    half_duplex_losses: int = 0
    """Receptions lost because this radio was transmitting at the time."""
    noise_losses: int = 0
    """Receptions that were alone on the air and lost to the channel anyway."""
    queue_drops: int = 0
    """Frames discarded because the transmit queue was full."""
    duty_wait_s: float = 0.0
    """Total time frames spent waiting out duty-cycle off-time."""


@dataclasses.dataclass(frozen=True)
class EnergyModel:
    """Radio power draw by state, in milliwatts.

    Defaults are an SX1262-class LoRa radio at 3.3 V: ~14 dBm transmit
    (~45 mA), receive (~5 mA), and a duty-cycled listen (~0.6 mA) standing in
    for idle — the radio alone, not the MCU or sensors.
    """

    tx_mw: float = 150.0
    rx_mw: float = 17.0
    idle_mw: float = 2.0

    def energy_mj(self, elapsed_s: float, stats: RadioStats) -> float:
        """Energy over `elapsed_s` given what the radio did, in millijoules."""
        idle_s = max(0.0, elapsed_s - stats.tx_airtime_s - stats.rx_airtime_s)
        return (
            stats.tx_airtime_s * self.tx_mw
            + stats.rx_airtime_s * self.rx_mw
            + idle_s * self.idle_mw
        )

    @staticmethod
    def battery_life_h(capacity_mwh: float, average_power_mw: float) -> float:
        """Hours a battery of `capacity_mwh` lasts at `average_power_mw`."""
        if average_power_mw <= 0:
            return math.inf
        return capacity_mwh / average_power_mw
