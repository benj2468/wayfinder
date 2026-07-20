"""RF/wired channel models: geometry + time -> a delivered frame's metrics.

A `Channel` is the thing a `Link` (see `link.py`) carries — the engine calls
`evaluate()` once per (transmitter, receiver) pair on every frame a node
egresses, using positions it already resolved from each end's `Mobility`.
"""

from __future__ import annotations

import dataclasses
import math
from random import Random
from typing import Protocol, runtime_checkable

import wayfinder_py as wf

from .mobility import Vec3

SPEED_OF_LIGHT_M_S = 299_792_458.0


@dataclasses.dataclass(frozen=True)
class ChannelSample:
    """The outcome of evaluating a channel for one (tx, rx) pair at an instant."""

    metrics: wf.PyLinkMetrics
    """What `PyDriver.push_rx` should stamp on the frame, if it's delivered."""

    delivery_probability: float
    """P(this specific frame arrives), in `[0, 1]`."""

    latency_ms: float = 0.0
    """Propagation + airtime delay before `push_rx` is called, if delivered."""


@runtime_checkable
class Channel(Protocol):
    """A model mapping a transmitter/receiver pair's geometry and the current
    simulation time to a `ChannelSample`."""

    def evaluate(self, tx: Vec3, rx: Vec3, t_s: float, rng: Random) -> ChannelSample:
        """`rng` is this evaluation's dedicated random stream (e.g. for
        fading/noise) — implementations must not mutate anything outside
        `rng` and their own (frozen) parameters, since the engine also calls
        this off a separate probe RNG for charting without affecting the
        simulated delivery outcome."""
        ...


@dataclasses.dataclass(frozen=True)
class PerfectWire:
    """A lossless wired link (fiber, Ethernet): fixed quality, always
    delivered, geometry ignored."""

    quality: int = 255
    latency_ms: float = 0.0

    def evaluate(self, tx: Vec3, rx: Vec3, t_s: float, rng: Random) -> ChannelSample:
        return ChannelSample(
            metrics=wf.PyLinkMetrics(quality=self.quality),
            delivery_probability=1.0,
            latency_ms=self.latency_ms,
        )


@dataclasses.dataclass(frozen=True)
class FreeSpacePathLoss:
    """A free-space-path-loss radio model mapping distance to RSSI, then RSSI
    to the 0-255 `quality` figure wayfinder's `LinkMetrics` carries.

    Default parameters are tuned (not just realistic-sounding) so a ~1 km
    separation puts the delivery-probability crossover in the middle of the
    usable RSSI range, rather than pinned at floor or ceiling: a 14 dBm link
    on 2.4 GHz sits at exactly the RSSI midpoint at 500 m.
    """

    freq_hz: float = 2.4e9  # 2.4 GHz ISM band
    tx_power_dbm: float = 14.0  # ~25 mW — a small telemetry radio
    rssi_floor_dbm: float = -100.0  # at/below this, quality is 0 (unusable)
    rssi_ceiling_dbm: float = -60.0  # at/above this, quality is 255 (excellent)
    noise_sigma_db: float = 1.5  # per-sample RSSI jitter, for realism
    delivery_steepness: float = 0.3  # logistic "waterfall" width, in 1/dB
    latency_ms: float = 0.0
    max_range_m: float | None = None
    """A hard link-budget cutoff, distinct from the gradual RSSI waterfall:
    beyond this distance there's no signal to speak of (`delivery_probability
    = 0`, `quality = 0`), rather than just a weak one — e.g. a small
    telemetry radio's fixed maximum range. `None` (default) means the
    waterfall alone governs delivery, unbounded."""

    def path_loss_db(self, distance_m: float) -> float:
        d = max(distance_m, 1.0)  # avoid log(0) at zero range
        return (
            20 * math.log10(d)
            + 20 * math.log10(self.freq_hz)
            + 20 * math.log10(4 * math.pi / SPEED_OF_LIGHT_M_S)
        )

    def rssi_dbm(self, distance_m: float, rng: Random) -> float:
        ideal = self.tx_power_dbm - self.path_loss_db(distance_m)
        return ideal + rng.gauss(0.0, self.noise_sigma_db)

    def quality(self, rssi_dbm: float) -> int:
        span = self.rssi_ceiling_dbm - self.rssi_floor_dbm
        frac = (rssi_dbm - self.rssi_floor_dbm) / span
        return round(max(0.0, min(1.0, frac)) * 255)

    def delivery_probability(self, rssi_dbm: float) -> float:
        """A logistic "waterfall" curve centered at the midpoint of the
        usable RSSI range: near-certain delivery well above it, near-zero
        well below — a digital radio's sharp fall from "fine" to "unusable"
        near its noise floor, rather than a hard range cutoff."""
        midpoint = (self.rssi_floor_dbm + self.rssi_ceiling_dbm) / 2
        return 1.0 / (1.0 + math.exp(-self.delivery_steepness * (rssi_dbm - midpoint)))

    def evaluate(self, tx: Vec3, rx: Vec3, t_s: float, rng: Random) -> ChannelSample:
        distance_m = tx.distance_to(rx)
        if self.max_range_m is not None and distance_m > self.max_range_m:
            return ChannelSample(
                metrics=wf.PyLinkMetrics(quality=0),
                delivery_probability=0.0,
                latency_ms=self.latency_ms,
            )
        rssi = self.rssi_dbm(distance_m, rng)
        return ChannelSample(
            metrics=wf.PyLinkMetrics(rssi_dbm=round(rssi), quality=self.quality(rssi)),
            delivery_probability=self.delivery_probability(rssi),
            latency_ms=self.latency_ms,
        )
