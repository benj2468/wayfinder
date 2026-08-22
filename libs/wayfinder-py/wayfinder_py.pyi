"""PyO3 bindings over wayfinder's tick-based mesh routing driver.

See `wayfinder_tick_driver::Driver` (Rust) for the full behavioral contract;
this module is a thin, one-to-one binding over it.
"""

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
    def bytes(self) -> bytes:
        """The 6 address bytes."""

    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class PyLinkFeatures:
    """Per-link participation gates; every bool flag defaults to full
    participation. `tx_keepalive_interval_ms` defaults to `None` (keep-alive
    transmission off — opt-in, since it's a new traffic class rather than
    part of the historical baseline). Reception of keep-alives is always
    accepted regardless of this setting."""

    tx_ogm: bool
    rx_ogm: bool
    tx_data: bool
    rx_data: bool
    tx_keepalive_interval_ms: int | None

    def __init__(
        self,
        tx_ogm: bool = True,
        rx_ogm: bool = True,
        tx_data: bool = True,
        rx_data: bool = True,
        tx_keepalive_interval_ms: int | None = None,
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

class PyNeighborStats:
    """One candidate path to an originator: the immediate neighbor relaying
    its OGMs, and how that path is currently performing."""

    neighbor: PyMac
    last_tq: int
    last_seqno: int
    last_heard_ms: int
    interval_estimate_ms: int

class PyOriginatorRecord:
    """One known destination and every candidate path to it. Written only by
    an OGM that passed verification, which is what makes it — rather than
    `get_egress_interface` — the right thing to ask about reachability on an
    authenticated mesh."""

    originator: PyMac
    best_next_hop: PyMac
    max_tq: int
    last_seqno: int
    last_heard_ms: int
    paths: list[PyNeighborStats]

class PyLinkQualityRecord:
    """A per-`(neighbor, interface)` local link-quality estimate.

    Populated when a frame is *received*, before any authentication verdict —
    so a row exists for a peer whose every OGM was rejected. `ewma_quality`
    of `None` means never measurable, which is not the same as zero."""

    neighbor: PyMac
    iface_idx: int
    ewma_quality: int | None
    sample_count: int

class PyKeypair:
    """A node's cryptographic identity: one 32-byte seed, from which the
    Ed25519 signing key, the X25519 agreement key, and the node's mesh MAC
    are all derived. The MAC being derived from the key is what stops a node
    claiming an address it holds no key for."""

    @staticmethod
    def from_seed(seed: bytes) -> PyKeypair:
        """Derive an identity deterministically from exactly 32 seed bytes."""

    @staticmethod
    def generate() -> PyKeypair:
        """Draw a fresh identity from the OS RNG."""

    @property
    def seed(self) -> bytes: ...
    @property
    def ed_pubkey(self) -> bytes: ...
    @property
    def x_pubkey(self) -> bytes: ...
    @property
    def derived_mac(self) -> PyMac: ...
    def sign(self, msg: bytes) -> bytes: ...

class PyTrustAnchor:
    """The public half of a mesh's root of trust — the mesh id plus the root
    Ed25519 public key certificates are verified against. This is the whole
    of what segregates one mesh from another."""

    def __init__(self, raw: bytes) -> None: ...
    @property
    def mesh_id(self) -> int: ...
    @property
    def root_pubkey(self) -> bytes: ...
    def __bytes__(self) -> bytes: ...

class PyMembershipCert:
    """A root-signed attestation that one Ed25519 key owns one MAC in one
    mesh, over a validity window. Note that verification checks the root's
    signature, *not* that `node_mac` is derived from `ed_pubkey` — issuance
    policy is what stops a certificate naming an address its holder cannot
    prove it owns."""

    def __init__(self, raw: bytes) -> None: ...
    @property
    def node_mac(self) -> PyMac: ...
    @property
    def mesh_id(self) -> int: ...
    @property
    def ed_pubkey(self) -> bytes: ...
    @property
    def x_pubkey(self) -> bytes: ...
    @property
    def not_before(self) -> int: ...
    @property
    def not_after(self) -> int: ...
    @property
    def admin(self) -> bool: ...
    @property
    def fingerprint(self) -> bytes: ...
    def __bytes__(self) -> bytes: ...

class PyRevocationRecord:
    """A root-signed order to purge one MAC, flooded on OGMs — the active
    revocation mechanism, complementing certificate expiry."""

    def __init__(self, raw: bytes) -> None: ...
    @property
    def node_mac(self) -> PyMac: ...
    @property
    def mesh_id(self) -> int: ...
    @property
    def not_before(self) -> int: ...
    @property
    def not_after(self) -> int: ...
    def __bytes__(self) -> bytes: ...

class PyAuthority:
    """A mesh's certificate authority — custody of the root key. One
    `PyAuthority` is one mesh; a second one is a foreign mesh whose
    certificates the first will never accept."""

    @staticmethod
    def from_seed(seed: bytes, mesh_id: int) -> PyAuthority: ...
    @staticmethod
    def generate(mesh_id: int) -> PyAuthority: ...
    @property
    def mesh_id(self) -> int: ...
    def trust_anchor(self) -> PyTrustAnchor: ...
    def issue_cert(
        self,
        mac: PyMac,
        ed_pubkey: bytes,
        x_pubkey: bytes,
        not_before: int,
        not_after: int,
    ) -> PyMembershipCert:
        """Bind `mac` to raw public keys. Takes the keys separately rather
        than a `PyKeypair` so a caller can deliberately mint a mismatched
        credential; use `enroll` for the ordinary case."""

    def enroll(
        self, keypair: PyKeypair, not_before: int, not_after: int
    ) -> PyMembershipCert:
        """Certify `keypair` for the MAC its own key derives."""

    def issue_user_cert(
        self,
        keypair: PyKeypair,
        not_before: int,
        not_after: int,
        admin: bool = False,
    ) -> PyMembershipCert: ...
    def revoke(
        self, mac: PyMac, not_before: int, not_after: int
    ) -> PyRevocationRecord: ...

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
    def originator_table(self) -> list[PyOriginatorRecord]:
        """Every known destination and its candidate paths, in no particular
        order. Read-only: building a snapshot never perturbs the run."""

    def link_quality_records(self) -> list[PyLinkQualityRecord]:
        """Per-`(neighbor, interface)` local link-quality estimates."""

    def neighbor_count(self) -> int: ...
    def originator_occupancy(self) -> tuple[int, int]: ...
    def get_egress_interface(self, dest: PyMac) -> PyEgressInterface | None:
        """Resolve the current egress interface(s) toward `dest`.

        Note this falls back to the link-quality table, which is populated
        when a frame is *received* — before its signature is judged. On an
        authenticated mesh it therefore resolves an interface for a peer whose
        every OGM was rejected. Ask `originator_table` (routes) or
        `neighbor_macs` (verified members) about membership.
        """

    # --- mesh authentication --------------------------------------------

    def set_auth(
        self, keypair: PyKeypair, cert: PyMembershipCert, anchor: PyTrustAnchor
    ) -> None:
        """Enable mesh authentication: sign emitted OGMs, and reject incoming
        ones that do not verify against `anchor`. Pair with `set_epoch_unix`,
        or certificate validity is judged against a clock that never left
        zero. Resets learned routing state, which was learned under a
        different trust regime."""

    def set_epoch_unix(self, epoch_unix: int) -> None:
        """Pin the wall-clock unix second that `tick(0)` corresponds to."""

    def set_require_auth(self, require: bool) -> None:
        """Fail closed: with no certificate installed, be inert on the mesh
        rather than falling back to open operation."""

    @property
    def auth_enabled(self) -> bool: ...
    @property
    def auth_locked(self) -> bool: ...
    def own_cert(self) -> PyMembershipCert | None: ...
    def ingest_revocation(self, record: PyRevocationRecord) -> bool:
        """Record a root-signed purge, returning whether it was new."""

    def revoked_macs(self) -> list[PyMac]: ...
    def neighbor_macs(self) -> list[PyMac]:
        """Peers whose certificate this node has verified — the ones actually
        admitted to the mesh, as distinct from the ones it has a route to.

        Note the cache is not pruned when a certificate expires, so an entry
        can outlive the credential that created it."""

    def neighbor_cert(self, mac: PyMac) -> PyMembershipCert | None: ...
