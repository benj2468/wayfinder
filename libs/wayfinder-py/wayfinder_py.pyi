"""PyO3 bindings over wayfinder's tick-based mesh routing driver.

See `wayfinder_tick_driver::Driver` (Rust) for the full behavioral contract;
this module is a thin, one-to-one binding over it.
"""

from __future__ import annotations

MAX_INTERFACES: int
MAX_LINK_FRAME_LEN: int

def init_tracing(filter: str | None = None) -> None:
    """Install a `tracing_subscriber::fmt` subscriber (writing to stdout) so
    the mesh stack's trace/debug/info/warn/error records become visible.

    `filter` is an `EnvFilter` directive string (e.g.
    "wayfinder=debug,wayfinder_tick_driver=trace"); when `None`, falls back to
    the `RUST_LOG` environment variable. Safe to call more than once — a
    global subscriber can only be installed once per process, so a repeat
    call is silently ignored rather than raising.
    """

class WayfinderError(Exception):
    """Base exception for all wayfinder_py errors."""

class MalformedFrameError(WayfinderError):
    """Bytes passed to `PyDriver.push_rx` do not parse as a well-formed
    on-wire link frame."""

class PyMac:
    """A 6-byte mesh MAC address."""

    BROADCAST: PyMac

    def __init__(self, addr: bytes) -> None: ...
    @property
    def raw_bytes(self) -> bytes: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class PyLinkFeatures:
    """Per-link participation gates; every flag defaults to full
    participation."""

    tx_ogm: bool
    rx_ogm: bool
    tx_data: bool
    rx_data: bool

    def __init__(
        self,
        tx_ogm: bool = True,
        rx_ogm: bool = True,
        tx_data: bool = True,
        rx_data: bool = True,
    ) -> None: ...

class PyLinkMetrics:
    """A received frame's physical-layer quality; every field defaults to
    `None` (no signal information available)."""

    rssi_dbm: int | None
    snr_db: int | None
    quality: int | None

    def __init__(
        self,
        rssi_dbm: int | None = None,
        snr_db: int | None = None,
        quality: int | None = None,
    ) -> None: ...

class PyEgressInterface:
    """Which interface(s) a planned frame should egress on, as resolved by
    `PyDriver.get_egress_interface`. Read-only introspection — the send path
    itself never needs this to be resolved by the caller."""

    all: bool
    interface: int | None

class PyDriver:
    """A tick-based, queue-backed wayfinder router."""

    def __init__(
        self,
        mac: PyMac,
        trickle: list[tuple[int, int]],
        features: list[PyLinkFeatures] | None = None,
    ) -> None: ...
    def num_interfaces(self) -> int: ...
    def push_rx(
        self,
        idx: int,
        frame: bytes,
        metrics: PyLinkMetrics | None = None,
    ) -> None: ...
    def queue_local_send(self, dest: PyMac, payload: bytes) -> None: ...
    def tick(self, now_ms: int) -> None: ...
    def poll_egress(self, idx: int) -> bytes | None: ...
    def poll_local(self) -> bytes | None: ...
    def get_egress_interface(self, dest: PyMac) -> PyEgressInterface | None: ...
