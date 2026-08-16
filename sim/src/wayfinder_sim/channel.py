"""RF/wired channel models: geometry + time -> a delivered frame's metrics.

A `Channel` is the thing a `Link` (see `link.py`) carries — the engine calls
`evaluate()` once per (transmitter, receiver) pair on every frame a node
egresses, using positions it already resolved from each end's `Mobility`.

Models compose: `TerrainMasked` wraps a plain radio model and subtracts the
diffraction loss the ground between the two nodes imposes, so "what does this
radio do over distance" and "what does the mountain in between do to it" stay
separately testable.
"""

from __future__ import annotations

import dataclasses
import math
from random import Random
from typing import Protocol, runtime_checkable

import wayfinder_py as wf

from .mobility import EARTH_RADIUS_M, Vec3
from .terrain import (
    DEFAULT_PROFILE_SAMPLES,
    SPEED_OF_LIGHT_M_S,
    Terrain,
    max_fresnel_parameter,
)

__all__ = [
    "SPEED_OF_LIGHT_M_S",
    "Channel",
    "ChannelSample",
    "EarthOccluded",
    "FreeSpacePathLoss",
    "PerfectWire",
    "RadioModel",
    "TerrainMasked",
    "knife_edge_loss_db",
]


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


@runtime_checkable
class RadioModel(Protocol):
    """A `Channel` that also exposes its RSSI-domain internals.

    A plain `Channel` only reports a finished `ChannelSample`, which is not
    enough to compose models: a wrapper that wants to add a path-loss term
    has to re-derive quality and delivery probability *after* subtracting it,
    using the same curves the base model would have used. Exposing the two
    scalar mappings is what makes that possible without the wrapper
    reimplementing (and drifting from) the base radio's tuning.

    `FreeSpacePathLoss` satisfies this as written; `PerfectWire` does not,
    and cannot be wrapped by `TerrainMasked` — a lossless wire has no RSSI to
    attenuate.
    """

    def evaluate(
        self, tx: Vec3, rx: Vec3, t_s: float, rng: Random
    ) -> ChannelSample: ...

    def quality(self, rssi_dbm: float) -> int:
        """This radio's 0-255 `LinkMetrics` quality figure for an RSSI."""
        ...

    def delivery_probability(self, rssi_dbm: float) -> float:
        """P(a frame at this RSSI arrives), in `[0, 1]`."""
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
    rx_gain_dbi: float = 0.0
    """Receive antenna gain, added straight to the received power.

    Zero — an isotropic antenna — is right for the small omnidirectional
    radios these scenarios started with, and keeps their tuning untouched. It
    is not right for anything pointing a dish: a satellite link closes on
    gain far more than on transmit power, and a Starlink terminal's phased
    array is worth ~35 dB, more than the whole span of a power sweep. Without
    it, `tx_power_dbm` has to absorb the antennas at both ends and stops
    meaning transmit power at all."""
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
        ideal = self.tx_power_dbm + self.rx_gain_dbi - self.path_loss_db(distance_m)
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


def knife_edge_loss_db(v: float) -> float:
    """Excess path loss from a single knife-edge obstruction with Fresnel
    parameter `v` (ITU-R P.526's closed-form approximation, valid for
    `v > -0.78`).

    Below `v = -0.78` — a path clearing the obstacle by more than ~55% of the
    first Fresnel zone — the loss is taken as zero, which is where the
    engineering rule of thumb that 60% clearance behaves as free space comes
    from. At `v = 0` (the line of sight exactly grazing the obstacle) the
    loss is already ~6 dB, and it grows roughly as `20*log10(v)` beyond that.
    """
    if v <= -0.78:
        return 0.0
    return 6.9 + 20 * math.log10(math.sqrt((v - 0.1) ** 2 + 1) + v - 0.1)


_FRESNEL_CACHE_ENTRIES = 4096
"""How many (tx, rx) geometries `TerrainMasked` memoizes before dropping the
lot. Sized so a scenario's fixed infrastructure — whose pairwise geometry
never changes, and which is most of the link count in a relay mesh — stays
resident, while a moving node's ever-changing positions can't grow it without
bound."""


@dataclasses.dataclass(frozen=True)
class TerrainMasked:
    """A radio model with the ground in the way: `base`, minus the
    diffraction loss the terrain between the two endpoints imposes.

    The terrain profile under the path is reduced to its single worst
    obstruction (`terrain.max_fresnel_parameter`) and run through
    `knife_edge_loss_db`. That is deliberately the simple model — a real
    multi-obstacle path wants Deygout or Epstein-Peterson — but it captures
    the effect these scenarios exist to study: a node in a valley cannot hear
    a node in the next valley over no matter how strong its radio, while the
    same node at altitude, or a relay on the ridge between them, can hear
    both.

    Only the *radio* is attenuated, not the geometry: `base` still sees the
    true distance, so its own range cutoff and RSSI-vs-distance curve apply
    first and terrain loss comes off the top of the result.
    """

    base: RadioModel
    terrain: Terrain
    freq_hz: float | None = None
    """Frequency the Fresnel geometry is evaluated at. `None` (the default)
    takes it from `base.freq_hz`, so the diffraction model and the path-loss
    model cannot silently disagree about the band; set it only to model them
    deliberately differently."""

    profile_samples: int = DEFAULT_PROFILE_SAMPLES
    """Ground samples taken along each path — the resolution at which a ridge
    can be detected, traded against per-frame evaluation cost."""

    max_loss_db: float = 90.0
    """Ceiling on the excess loss. Diffraction loss grows without bound as an
    obstacle rises, and past ~60 dB the link is dead by any measure; the cap
    keeps a deeply shadowed link's reported RSSI a plausible number rather
    than an arbitrarily large negative one."""

    _fresnel_cache: dict[tuple[tuple[float, float, float], ...], float] = (
        dataclasses.field(default_factory=dict, init=False, compare=False, repr=False)
    )
    """Pure memo of `max_fresnel_parameter` per endpoint pair — geometry
    only, never anything drawn from `rng`, so it cannot perturb a simulated
    delivery outcome (see `Channel.evaluate`'s contract)."""

    def effective_freq_hz(self) -> float:
        """The frequency the Fresnel geometry is evaluated at — `freq_hz` if
        set, otherwise the base radio's own."""
        if self.freq_hz is not None:
            return self.freq_hz
        inherited = getattr(self.base, "freq_hz", None)
        if inherited is None:
            raise ValueError(
                f"TerrainMasked cannot infer a frequency from "
                f"{type(self.base).__name__}; pass freq_hz= explicitly"
            )
        return float(inherited)

    def excess_loss_db(self, tx: Vec3, rx: Vec3) -> float:
        """Extra path loss, in dB, the terrain imposes between these two
        points — `0.0` for a path that clears the ground comfortably.

        Exposed (rather than kept inside `evaluate`) because it's the natural
        thing for a scenario to chart or assert on: it's the pure geometric
        penalty, with no RNG and no radio tuning mixed in.
        """
        a, b = (tx.x, tx.y, tx.z), (rx.x, rx.y, rx.z)
        # Diffraction is reciprocal, so normalise the pair's order and let
        # both directions of a link share one entry.
        key = (a, b) if a <= b else (b, a)
        v = self._fresnel_cache.get(key)
        if v is None:
            if len(self._fresnel_cache) >= _FRESNEL_CACHE_ENTRIES:
                self._fresnel_cache.clear()
            v = max_fresnel_parameter(
                self.terrain,
                tx,
                rx,
                self.effective_freq_hz(),
                samples=self.profile_samples,
            )
            self._fresnel_cache[key] = v
        return min(knife_edge_loss_db(v), self.max_loss_db)

    def evaluate(self, tx: Vec3, rx: Vec3, t_s: float, rng: Random) -> ChannelSample:
        sample = self.base.evaluate(tx, rx, t_s, rng)
        if sample.delivery_probability == 0.0:
            # The base radio already ruled the path out (e.g. its own hard
            # range cutoff); terrain can only make that more true.
            return sample

        rssi_dbm = sample.metrics.rssi_dbm
        if rssi_dbm is None:
            raise ValueError(
                f"TerrainMasked needs a base channel that reports rssi_dbm, "
                f"since terrain loss is applied in the RSSI domain; "
                f"{type(self.base).__name__} reported none"
            )

        loss_db = self.excess_loss_db(tx, rx)
        if loss_db == 0.0:
            return sample

        # `rssi_dbm` has already been rounded to a whole dB by the base
        # model, so this drops sub-dB precision — immaterial next to the
        # tens of dB a real obstruction costs.
        masked_dbm = rssi_dbm - loss_db
        snr_db = sample.metrics.snr_db
        return ChannelSample(
            metrics=wf.PyLinkMetrics(
                rssi_dbm=round(masked_dbm),
                # Noise is unchanged, so SNR falls by the same amount signal does.
                snr_db=None if snr_db is None else round(snr_db - loss_db),
                quality=self.base.quality(masked_dbm),
            ),
            delivery_probability=self.base.delivery_probability(masked_dbm),
            latency_ms=sample.latency_ms,
        )


@dataclasses.dataclass(frozen=True)
class EarthOccluded:
    """A radio model with the planet in the way: `base`, but with no signal
    at all once the other end drops below the local horizon.

    `TerrainMasked` is the same idea at the scale of a ridge; this is the one
    that matters in orbit. The scene frame is ENU with its origin on the
    surface, so the Earth's centre sits at `Vec3(0, 0, -EARTH_RADIUS_M)` and
    the test below is exact for a spherical Earth rather than an
    approximation — no projection, no flat-plane fudge.

    `min_elevation_deg` raises that horizon to where a real terminal gives
    up. Starlink's user terminals mask at around 25 degrees: below it the
    slant range through the atmosphere is long, the dish is at the edge of
    its scan, and neighbouring satellites interfere. Left as `None` — no mask
    — the only question asked is whether the planet blocks the path, which is
    the right question between two satellites.

    Two separate tests, because they are two separate questions and only one
    of them is about the planet:

    - Occlusion always applies: does the straight path dip below the surface?
    - The elevation mask, when set, applies at the *lower* end of the link.

    Conflating them gets cross-links wrong. Two satellites at the same
    altitude see each other at a *negative* elevation — the chord between
    them runs below both local horizons — while still clearing the planet by
    hundreds of kilometres. That is a perfectly good inter-satellite link,
    and an elevation test alone would refuse it.
    """

    base: RadioModel
    min_elevation_deg: float | None = None

    def _elevation_deg(self, low: Vec3, high: Vec3) -> float:
        """Elevation of `high` above the local horizontal at `low`."""
        # Local vertical at `low`: straight out from the planet's centre.
        up = (low.x, low.y, low.z + EARTH_RADIUS_M)
        up_len = math.sqrt(sum(c * c for c in up))
        los = (high.x - low.x, high.y - low.y, high.z - low.z)
        los_len = math.sqrt(sum(c * c for c in los))
        if up_len == 0.0 or los_len == 0.0:
            return 90.0
        sin_elevation = sum(u * l for u, l in zip(up, los)) / (up_len * los_len)
        return math.degrees(math.asin(max(-1.0, min(1.0, sin_elevation))))

    def _passes_through_the_earth(self, tx: Vec3, rx: Vec3) -> bool:
        """Whether the segment's closest approach to the planet's centre
        falls inside the surface.

        Distance-to-centre along a straight line is a convex quadratic, so
        its minimum over the segment is at a single interior point or at an
        endpoint — which is the whole test, in closed form.
        """
        a = (tx.x, tx.y, tx.z + EARTH_RADIUS_M)
        d = (rx.x - tx.x, rx.y - tx.y, rx.z - tx.z)
        len_sq = sum(c * c for c in d)
        if len_sq == 0.0:
            return False
        s = max(0.0, min(1.0, -sum(ac * dc for ac, dc in zip(a, d)) / len_sq))
        closest = math.sqrt(sum((ac + s * dc) ** 2 for ac, dc in zip(a, d)))
        return closest < EARTH_RADIUS_M

    def evaluate(self, tx: Vec3, rx: Vec3, t_s: float, rng: Random) -> ChannelSample:
        # The mask is judged from whichever end is nearer the planet: that is
        # the terminal doing the looking up.
        low, high = sorted(
            (tx, rx),
            key=lambda p: math.dist((p.x, p.y, p.z + EARTH_RADIUS_M), (0.0, 0.0, 0.0)),
        )
        masked = (
            self.min_elevation_deg is not None
            and self._elevation_deg(low, high) < self.min_elevation_deg
        )
        if masked or self._passes_through_the_earth(tx, rx):
            return ChannelSample(
                metrics=wf.PyLinkMetrics(quality=0),
                delivery_probability=0.0,
                latency_ms=0.0,
            )
        return self.base.evaluate(tx, rx, t_s, rng)
