"""`Simulation` — the engine that builds one real `wf.PyDriver` per `Node`,
wires a SimPy environment around them, and drives per-node ticking and
per-frame delivery so a scenario only has to describe topology, channels,
and what to record.

SimPy scheduling scheme (see the design writeup for the full rationale):
each node ticks on its own cadence (derived from its fastest Trickle
interval, not a shared global step), and every egressed frame is evaluated
against its link's channel and — if delivered — scheduled as its own
event after the channel's latency. There is no global tick grid: mobility
is a pure function of time, so positions are resolved lazily at whatever
instant an event actually needs them.
"""

from __future__ import annotations

import dataclasses
import itertools
import math
from collections import deque
from collections.abc import Callable, Sequence
from random import Random
from typing import Any

import simpy
import wayfinder_py as wf

from . import NoLinkError
from .adversary import Wiretap
from .link import Link
from .interference import DEFAULT_CAPTURE_DB, Jammer, sum_dbm
from .medium import EnergyModel, RadioStats
from .mobility import Static, Vec3
from .node import Node
from .recorder import Recorder
from .security import Mesh
from .traffic import Flow, decode_payload, encode_payload

Probe = Callable[["Simulation"], Any]
"""A function of the running `Simulation`, sampled once per recorder tick —
typically a closure over `Simulation.distance`/`route_via`/`sample_channel`."""

# Locally-administered OUI (the U/L bit set, per IEEE 802) used for
# auto-derived MACs, so they can never collide with a real vendor OUI.
_AUTO_MAC_OUI = (0x02, 0x00, 0x00, 0x00, 0x00)

# Floor and divisor for deriving a node's tick cadence from its fastest
# Trickle i_min when `Node.tick_interval_ms` isn't set explicitly: fine
# enough to resolve that node's own timer, no finer.
_MIN_TICK_INTERVAL_MS = 10
_TICK_INTERVAL_DIVISOR = 4


@dataclasses.dataclass
class _Reception:
    """One frame arriving at one receiver's radio over a contended medium."""

    src: str
    start_ms: float
    end_ms: float
    rssi_dbm: float
    frame: bytes
    metrics: wf.PyLinkMetrics
    delivery_probability: float
    iface: int
    boot: int
    latency_ms: float


@dataclasses.dataclass
class _Radio:
    """One node's radio on one contended link."""

    queue: deque[tuple[int, bytes]] = dataclasses.field(default_factory=deque)
    sending: bool = False
    off_until_ms: float = 0.0
    tx_intervals: list[tuple[float, float]] = dataclasses.field(default_factory=list)
    receptions: list[_Reception] = dataclasses.field(default_factory=list)
    rx_busy_until_ms: float = 0.0


_HISTORY_MS = 60_000.0
"""How long a radio remembers past transmissions and receptions, for judging
overlap with ones still in progress. Far longer than any single airtime."""


@dataclasses.dataclass
class _NodeState:
    node: Node
    mac: wf.PyMac
    driver: wf.PyDriver
    interfaces: dict[int, Link]  # this node's interface index -> the Link on it
    tick_interval_ms: int
    trickle: list[tuple[int, int]]
    keepalive: list[int | None]
    keypair: wf.PyKeypair | None = None
    up: bool = True
    # Bumped on every reboot, so a frame already in flight to the old router
    # is not delivered into the new one's queue as if it had just arrived.
    boot: int = 0
    # Payloads the router delivered locally that are not stream packets,
    # waiting for `Simulation.poll_local`.
    inbox: deque[bytes] = dataclasses.field(default_factory=deque)
    tx_frames: int = 0
    tx_bytes: int = 0
    """This node's mesh identity, when it has one. Retained so a scenario can
    sign or re-enroll on its behalf mid-run."""


class Simulation:
    """A running mesh simulation over `nodes` wired by `links`."""

    def __init__(
        self,
        nodes: Sequence[Node],
        links: Sequence[Link],
        *,
        seed: int = 0,
        mesh: Mesh | None = None,
    ) -> None:
        """`mesh`, when given, makes this an *authenticated* mesh: every node
        carrying a `Credential` is enrolled against that root before the run
        starts, its routers sign the OGMs they emit, and unverifiable ones are
        rejected. Left `None` every node is open and unauthenticated, which is
        what a scenario studying routing rather than trust wants."""
        node_list = list(nodes)
        names = [n.name for n in node_list]
        if len(set(names)) != len(names):
            raise ValueError(f"duplicate node names: {names!r}")
        name_set = set(names)
        for link in links:
            for endpoint in link.endpoints:
                if endpoint not in name_set:
                    raise ValueError(
                        f"link {link.name!r} references unknown node {endpoint!r}"
                    )

        self.env = simpy.Environment()
        # Two independent RNG streams: `_delivery_rng` drives the actual
        # simulated drops (deterministic given `seed`), `_probe_rng` backs
        # `sample_channel` so charting/inspecting a channel never perturbs
        # the delivery outcome by consuming from the same stream.
        self._delivery_rng = Random(seed)
        self._probe_rng = Random(seed)

        self._links = list(links)
        self._mesh = mesh
        self._taps: dict[str, list[Wiretap]] = {}
        node_by_name = {n.name: n for n in node_list}

        # Assign each node's interface indices and per-interface trickle
        # config in link-declaration order, and remember, for each link,
        # which interface index it landed on for each of its endpoints (so
        # delivery can look up the receiving side's interface).
        self._link_iface: dict[int, dict[str, int]] = {}
        node_interfaces: dict[str, dict[int, Link]] = {name: {} for name in names}
        node_trickle: dict[str, list[tuple[int, int]]] = {name: [] for name in names}
        node_keepalive: dict[str, list[int | None]] = {name: [] for name in names}
        for link in self._links:
            for endpoint in link.endpoints:
                iface = len(node_trickle[endpoint])
                node_interfaces[endpoint][iface] = link
                self._link_iface.setdefault(id(link), {})[endpoint] = iface
                trickle = (
                    link.trickle
                    if link.trickle is not None
                    else node_by_name[endpoint].trickle
                )
                node_trickle[endpoint].append(trickle)
                keepalive = (
                    link.tx_keepalive_interval_ms
                    if link.tx_keepalive_interval_ms is not None
                    else node_by_name[endpoint].tx_keepalive_interval_ms
                )
                node_keepalive[endpoint].append(keepalive)

        # A node's links are its router interfaces, and the router holds a
        # fixed `wf.MAX_INTERFACES` of them. The driver drops the surplus (with
        # a warning nobody reads in a sweep), so a node past the cap goes mute
        # on links this topology says are up — and the only symptom is a route
        # that never converges, which reads as a routing or trust result rather
        # than a wiring mistake. Refuse the topology instead of measuring it.
        overloaded = {
            name: len(ifaces)
            for name, ifaces in node_interfaces.items()
            if len(ifaces) > wf.MAX_INTERFACES
        }
        if overloaded:
            detail = ", ".join(
                f"{name!r} has {count}" for name, count in sorted(overloaded.items())
            )
            raise ValueError(
                f"a node may have at most wf.MAX_INTERFACES={wf.MAX_INTERFACES} "
                f"links, one per router interface: {detail}"
            )

        # A pair of node names -> the (possibly shared-LAN) Link joining
        # them, for `sample_channel`'s probing.
        self._link_for_pair: dict[frozenset[str], Link] = {}
        for link in self._links:
            for a, b in itertools.combinations(link.endpoints, 2):
                self._link_for_pair[frozenset((a, b))] = link

        self._states: dict[str, _NodeState] = {}
        for idx, node in enumerate(node_list, start=1):
            keypair = self._identity_for(node)
            if keypair is not None:
                # A certificate binds key to MAC, so an authenticated node's
                # address is not a free choice: it is whatever its key
                # derives. Silently overriding an explicitly requested MAC
                # would hide that, so refuse instead.
                if node.mac is not None:
                    raise ValueError(
                        f"node {node.name!r} has a credential, so its MAC is "
                        f"derived from its key — remove the explicit mac="
                    )
                mac = keypair.derived_mac
            elif node.mac is not None:
                mac = node.mac
            else:
                mac = wf.PyMac(bytes((*_AUTO_MAC_OUI, idx)))
            driver = self._build_driver(
                node, mac, node_trickle[node.name], node_keepalive[node.name], keypair
            )
            tick_interval_ms = node.tick_interval_ms
            if tick_interval_ms is None:
                i_mins = [t[0] for t in node_trickle[node.name]] or [node.trickle[0]]
                tick_interval_ms = max(
                    _MIN_TICK_INTERVAL_MS, min(i_mins) // _TICK_INTERVAL_DIVISOR
                )
            self._states[node.name] = _NodeState(
                node=node,
                mac=mac,
                driver=driver,
                interfaces=node_interfaces[node.name],
                tick_interval_ms=tick_interval_ms,
                trickle=node_trickle[node.name],
                keepalive=node_keepalive[node.name],
                keypair=keypair,
            )

        self._probes: dict[str, Probe] = {}
        self._recorder: Recorder | None = None
        self._down_links: set[str] = set()
        self._radios: dict[tuple[str, str], _Radio] = {}
        self._jammers: list[Jammer] = []
        self._receivers: dict[tuple[int, str], tuple[str, ...]] = {}
        self._radio_stats: dict[str, RadioStats] = {name: RadioStats() for name in names}
        self._compromised: set[str] = set()
        # Wire bytes of every revocation issued, keyed by the revoked node's
        # name — what a compromised node's firmware watches for and discards.
        self._revocation_bytes: dict[str, list[bytes]] = {}
        self._flows: list[Flow] = []

        for name in self._states:
            self.env.process(self._tick_proc(name))

    def _build_driver(
        self,
        node: Node,
        mac: wf.PyMac,
        trickle: list[tuple[int, int]],
        keepalive: list[int | None],
        keypair: wf.PyKeypair | None,
    ) -> wf.PyDriver:
        """A fresh router for `node` — at construction, and again on every
        reboot, which is what makes a reboot lose everything the old one
        learned."""
        features = [wf.PyLinkFeatures(tx_keepalive_interval_ms=ka) for ka in keepalive]
        driver = wf.PyDriver(mac, trickle, features)
        self._install_credential(node, driver, keypair)
        return driver

    # --- identity ---------------------------------------------------------

    def _identity_for(self, node: Node) -> wf.PyKeypair | None:
        """The keypair `node` runs under, or `None` if it has no mesh identity
        at all (no credential declared, or no mesh to declare it against).

        Derived from the *issuing* mesh, so a foreign-mesh intruder gets an
        identity from its own root rather than ours.
        """
        credential = node.credential
        if credential is None or self._mesh is None:
            return None
        issuer = credential.mesh or self._mesh
        return issuer.keypair(node.name, credential.seed)

    def _install_credential(
        self, node: Node, driver: wf.PyDriver, keypair: wf.PyKeypair | None
    ) -> None:
        """Put `node`'s credential into its router before the run starts.

        The order matters: the epoch has to be pinned before any certificate
        is installed, because validity is judged in unix seconds while the
        driver counts monotonic milliseconds from zero. Skipping it leaves the
        auth clock at zero, which reads as "never set" and judges every
        window against the wrong time.
        """
        credential = node.credential
        if credential is None or self._mesh is None:
            return
        issuer = credential.mesh or self._mesh
        driver.set_epoch_unix(issuer.epoch_unix)
        driver.set_require_auth(credential.require_auth)
        if not credential.enrolled or keypair is None:
            return  # fail-closed: required to authenticate, holding nothing
        cert = issuer.enroll(
            keypair,
            valid_from_s=credential.valid_from_s,
            valid_until_s=credential.valid_until_s,
            claim_mac=credential.claim_mac,
        )
        driver.set_auth(keypair, cert, issuer.trust_anchor)

    @property
    def mesh(self) -> Mesh | None:
        """The root of trust this simulation's members are enrolled against,
        or `None` for an open, unauthenticated mesh."""
        return self._mesh

    def keypair(self, node: str) -> wf.PyKeypair | None:
        """`node`'s mesh identity, or `None` if it has none."""
        return self._states[node].keypair

    def revoke(
        self,
        node: str,
        *,
        effective_s: float = 0.0,
        notify: Sequence[str] | None = None,
    ) -> None:
        """Have the mesh root purge `node`, and hand the signed record to
        every other member — or, with `notify`, only to those members.

        Delivering it to each member directly models an operator pushing the
        revocation over the management API — which is what a real deployment
        does, because a node that has just been revoked is precisely the one
        you cannot rely on to flood the order that revokes it. Members
        re-flood it on their own OGMs from there, so `notify=["gateway"]`
        models the common case of an operator who can reach one node and
        leaves the mesh to carry the order to the rest; `knows_revoked` then
        says how far it has got.
        """
        if self._mesh is None:
            raise ValueError("no mesh: nothing to revoke against")
        targets = [name for name in self._states if name != node]
        if notify is not None:
            for name in notify:
                if name not in self._states:
                    raise KeyError(name)
                if name == node:
                    raise ValueError(f"cannot notify {node!r} of its own revocation")
            targets = list(notify)
        record = self._mesh.revoke(self.mac(node), effective_s=effective_s)
        self._revocation_bytes.setdefault(node, []).append(bytes(record))
        for name in targets:
            self._states[name].driver.ingest_revocation(record)

    def compromise(self, node: str) -> None:
        """Hand `node` to an attacker: from now on it runs firmware that
        discards any frame carrying a revocation of itself, so it never goes
        inert and keeps relaying and sending under its still-valid key.

        This is the captured-radio threat. An honest node that hears its own
        revocation stops (`auth_locked`); a stolen one has no reason to, and a
        scenario that let it would credit the mesh for an exclusion the
        attacker performed on themselves. Exclusion then has to come from the
        members alone, which is the claim worth measuring.

        The filter matches the record's exact wire bytes, which every frame
        re-flooding that record carries verbatim — so it needs no knowledge of
        the TVLV layout, and drops the whole frame the way firmware that
        refused to parse it would.
        """
        if node not in self._states:
            raise KeyError(node)
        self._compromised.add(node)

    def knows_revoked(self, node: str, target: str) -> bool:
        """Whether `node` holds a revocation naming `target` right now."""
        return self._states[target].mac in self._states[node].driver.revoked_macs()

    def admitted(
        self, node: str, targets: Sequence[str] | None = None
    ) -> tuple[str, ...]:
        """Which of `targets` `node` has actually verified as mesh members —
        peers whose certificate it holds and checked against the trust anchor.

        This, not `route_via` or `reachable`, is the membership question.
        Route resolution falls back to the link-quality table, which is
        populated when a frame is *received*, before its signature is judged —
        so a node whose every OGM was rejected still resolves an egress
        interface. Nothing can be sent to it (the data plane has no pairwise
        key for an unverified peer, so the frame is dropped rather than sent
        in the clear), but the resolution is there, and reading it as
        membership would report an intruder as admitted.

        Empty for an unauthenticated node: with no mesh there is nothing to
        verify and no such thing as membership.
        """
        if targets is None:
            targets = [name for name in self._states if name != node]
        admitted = self._states[node].driver.neighbor_macs()
        return tuple(
            name
            for name in targets
            if name != node and self._states[name].mac in admitted
        )

    def has_route(self, src: str, dest: str | wf.PyMac) -> bool:
        """Whether `src` has actually *learned* a route to `dest` (a node name,
        or a raw `PyMac` for a destination that is not a node in this
        simulation — an address an attacker invented, say).

        Asks the originator table, which only a frame that passed
        verification writes to — unlike `route_via`, which resolves through
        link quality and so answers for rejected senders too.

        A *usable* route, not merely a discovered originator: on an
        authenticated mesh a path is recorded before its next hop has proven
        itself, and cannot carry traffic until it has. Asking only whether the
        record exists would call an attacker's re-flood a route, since
        discovery is exactly the part an outsider can still drive.
        """
        mac = dest if isinstance(dest, wf.PyMac) else self._states[dest].mac
        return any(
            record.originator == mac and record.best_next_hop is not None
            for record in self._states[src].driver.originator_table()
        )

    def tq_to(self, src: str, dest: str) -> int | None:
        """`src`'s end-to-end transmission quality (0..=255) toward `dest` —
        the metric its route was selected by — or `None` when it has no
        usable path.

        The multi-hop counterpart to `link_quality`, which measures one
        physical hop. BATMAN charges every hop `saturating_sub(10)` and then
        clamps the result by the receiving node's own measurement of the link
        it arrived over (`batman::engine`), so this falls with both distance
        in hops and the worst link along the way — and a chain deeper than
        ~25 perfect hops reads 0 however good every link in it is.

        `None` and `0` are different answers, and a depth study needs both
        kept apart: `None` is "no route", while `0` is a route whose metric
        has bottomed out. A saturated path still forwards traffic; what it
        has lost is the ability to be compared against another one, since
        every path past the floor reads the same.
        """
        mac = self._states[dest].mac
        for record in self._states[src].driver.originator_table():
            if record.originator == mac and record.best_next_hop is not None:
                return record.max_tq
        return None

    # --- red team ---------------------------------------------------------

    def wiretap(self, link: str) -> Wiretap:
        """Attach a passive listener to `link` and return it. Every frame
        transmitted on that link from now on is recorded verbatim.

        There is no node behind this and nothing for a router to reject: a
        shared medium is audible to anyone in range. A wiretap that reads
        application payloads has therefore *confirmed* wayfinder's threat
        model rather than broken it — authenticity and segregation are what
        the mesh provides, and confidentiality is left to the layer above.
        """
        if not any(existing.name == link for existing in self._links):
            raise KeyError(f"no link named {link!r}")
        tap = Wiretap(link=link)
        self._taps.setdefault(link, []).append(tap)
        return tap

    def inject(
        self,
        src: str,
        frame: bytes,
        *,
        at_s: float = 0.0,
        link: str | None = None,
    ) -> None:
        """Put raw `frame` bytes on the medium from `src` at `at_s`, bypassing
        `src`'s own router entirely.

        This is the attacker primitive. `Simulation.send` asks a node's
        routing stack to deliver a payload; `inject` asks nothing of anyone —
        the bytes go through the same channel model (loss, latency, signal
        metrics) a legitimate frame crosses and land in the receiver's `push_rx`
        exactly as if a radio had produced them. Whatever `src` MAC the frame
        claims is what receivers see; nothing checks it against `src`.

        `link` names which of `src`'s links to transmit on, defaulting to all
        of them — a node with several radios shouting on every one.
        """
        if src not in self._states:
            raise KeyError(src)
        if link is not None and not any(
            existing.name == link for existing in self._states[src].interfaces.values()
        ):
            raise KeyError(f"node {src!r} has no link named {link!r}")
        self.env.process(self._inject_proc(src, frame, at_s, link))

    def flood(
        self,
        src: str,
        frame: Callable[[], bytes],
        *,
        rate_hz: float,
        start_s: float,
        duration_s: float,
        link: str | None = None,
    ) -> None:
        """Blast `frame()` from `src` at `rate_hz` for `duration_s`, starting
        at `start_s` — a sustained storm rather than a single injected frame.

        `frame` is called per transmission rather than taken as fixed bytes,
        so a flood can vary its sequence numbers (or its claimed identity) the
        way a real one would, instead of emitting one frame the mesh's
        deduplication would collapse into nothing.

        What this measures is not whether the frames are accepted — a forged
        frame is rejected whether it arrives once or ten thousand times — but
        what the *cost of rejecting them* does to a mesh that must keep
        routing while it happens.
        """
        if rate_hz <= 0:
            raise ValueError("rate_hz must be positive")
        self.env.process(
            self._flood_proc(src, frame, rate_hz, start_s, duration_s, link)
        )

    # --- failures ---------------------------------------------------------

    def fail_node(
        self, node: str, *, at_s: float, recover_s: float | None = None
    ) -> None:
        """Power `node` off at `at_s` and, if `recover_s` is given, back on
        then.

        Off means off: it neither ticks nor transmits, and a frame addressed
        to it is lost on the air. Coming back is a *reboot* rather than a
        resume — the node gets a fresh router (same address, same credential)
        that has to relearn the mesh from nothing, which is what a power-cycled
        board does and what makes recovery time worth measuring at all.
        """
        if node not in self._states:
            raise KeyError(node)
        if recover_s is not None and recover_s <= at_s:
            raise ValueError(f"recover_s={recover_s} must be after at_s={at_s}")
        self.env.process(self._fail_node_proc(node, at_s, recover_s))

    def fail_link(
        self, link: str, *, at_s: float, recover_s: float | None = None
    ) -> None:
        """Cut `link` at `at_s` (every frame on it is lost) and, if
        `recover_s` is given, restore it then. A cable pulled or a radio
        blocked, with both ends still running."""
        if not any(existing.name == link for existing in self._links):
            raise KeyError(f"no link named {link!r}")
        if recover_s is not None and recover_s <= at_s:
            raise ValueError(f"recover_s={recover_s} must be after at_s={at_s}")
        self.env.process(self._fail_link_proc(link, at_s, recover_s))

    def is_up(self, node: str) -> bool:
        """Whether `node` is powered on right now."""
        return self._states[node].up

    def tx_frames(self, node: str) -> int:
        """Frames `node`'s router has put on the air so far, across every
        interface — control and data alike. Survives a reboot (it counts the
        node's radio, not one router's lifetime); injected frames are not
        counted, since no router sent them."""
        return self._states[node].tx_frames

    def tx_bytes(self, node: str) -> int:
        """Total size of the frames counted by `tx_frames`."""
        return self._states[node].tx_bytes

    def add_jammer(self, jammer: Jammer) -> None:
        """Switch on `jammer` (see `interference.py`): from now on every
        reception on the links it reaches must beat its power by the capture
        margin."""
        if jammer.links is not None:
            known = {link.name for link in self._links}
            for name in jammer.links:
                if name not in known:
                    raise KeyError(f"no link named {name!r}")
        self._jammers.append(jammer)

    def interference_dbm(self, node: str) -> float | None:
        """Total power of the jammers active right now at `node`'s position,
        on any of its links, or `None` when none is."""
        t_s = self.env.now / 1000.0
        pos = self.position(node)
        names = {link.name for link in self._states[node].interfaces.values()}
        return sum_dbm(
            j.received_dbm(pos, t_s)
            for j in self._jammers
            if j.is_active(t_s) and any(j.reaches(n or "") for n in names)
        )

    def _jamming_mw(self, link: Link, rx: Vec3, start_s: float, end_s: float) -> float:
        """Summed power, in mW, of jammers reaching `link` and transmitting
        at some point in `[start_s, end_s]`, arriving at `rx`."""
        return sum(
            10.0 ** (j.received_dbm(rx, start_s) / 10.0)
            for j in self._jammers
            if j.reaches(link.name or "") and j.overlaps(start_s, end_s)
        )

    def radio_stats(self, node: str) -> RadioStats:
        """What `node`'s radios have done on contended (`Link.medium`) links:
        airtime, frames, and every way a reception was lost. All zero for a
        node with no such link."""
        return self._radio_stats[node]

    def energy_mj(self, node: str, model: EnergyModel) -> float:
        """Energy `node`'s radios have used so far under `model`, from its
        transmit, receive and idle time on contended links."""
        return model.energy_mj(self.env.now / 1000.0, self._radio_stats[node])

    def average_power_mw(self, node: str, model: EnergyModel) -> float:
        """`energy_mj` averaged over the time simulated so far."""
        elapsed_s = self.env.now / 1000.0
        return self.energy_mj(node, model) / elapsed_s if elapsed_s > 0 else 0.0

    def is_link_up(self, link: str) -> bool:
        """Whether `link` is carrying frames right now."""
        return link not in self._down_links

    # --- traffic -----------------------------------------------------------

    def stream(
        self,
        src: str,
        dest: str,
        *,
        rate_hz: float,
        start_s: float,
        duration_s: float,
    ) -> Flow:
        """Send numbered packets from `src` to `dest` at `rate_hz` for
        `duration_s` from `start_s`, and return the `Flow` recording what
        arrived. Stream packets are consumed by their flow and never surface
        through `poll_local`."""
        for name in (src, dest):
            if name not in self._states:
                raise KeyError(name)
        if rate_hz <= 0:
            raise ValueError("rate_hz must be positive")
        flow = Flow(src=src, dest=dest, flow_id=len(self._flows))
        self._flows.append(flow)
        self.env.process(self._stream_proc(flow, rate_hz, start_s, duration_s))
        return flow

    # --- probe-facing introspection -----------------------------------

    @property
    def node_names(self) -> tuple[str, ...]:
        """Every node's name, in the order they were declared."""
        return tuple(self._states)

    def driver(self, node: str) -> wf.PyDriver:
        """`node`'s underlying router.

        Exposed for callers that read routing state directly rather than
        through `route_via` — feature extraction for the learned-routing
        pipeline needs the originator and link-quality tables, not just the
        resolved egress. Read-only in practice: mutating the returned driver
        would desynchronise it from the SimPy schedule driving it.
        """
        return self._states[node].driver

    def mac(self, node: str) -> wf.PyMac:
        """`node`'s mesh identifier, whether explicit or auto-derived."""
        return self._states[node].mac

    def node_for_mac(self, mac: wf.PyMac) -> str | None:
        """The node owning `mac`, or `None` if no node in this simulation
        does — the inverse of `mac`, since router state is keyed by identifier
        while scenarios and topology are written in names."""
        for name, state in self._states.items():
            if state.mac == mac:
                return name
        return None

    def position(self, node: str) -> Vec3:
        """`node`'s world position at the current simulation time."""
        state = self._states[node]
        return state.node.mobility.position(self.env.now / 1000.0)

    def distance(self, a: str, b: str) -> float:
        """Straight-line distance between `a` and `b` right now."""
        return self.position(a).distance_to(self.position(b))

    def egress_interface(self, src: str, dest: str) -> wf.PyEgressInterface | None:
        """`src`'s currently resolved egress interface(s) toward `dest`, or
        `None` if unroutable — see `wf.PyDriver.get_egress_interface`."""
        return self._states[src].driver.get_egress_interface(self._states[dest].mac)

    def route_via(self, src: str, dest: str) -> str | None:
        """Name of the `Link` `src` currently forwards toward `dest` on, or
        `None` if unroutable. `"*"` in the (rare, for a specific unicast
        dest) case a route resolves to every interface at once."""
        egress = self.egress_interface(src, dest)
        if egress is None:
            return None
        if egress.all or egress.interface is None:
            return "*"
        return self._states[src].interfaces[egress.interface].name

    def next_hop(self, src: str, dest: str) -> str | None:
        """The neighbour `src` forwards toward `dest` through, by name, or
        `None` with no usable route. On a shared segment every route leaves
        by the same link, so this — not `route_via` — is what says which
        relay is carrying the traffic."""
        mac = self._states[dest].mac
        for record in self._states[src].driver.originator_table():
            if record.originator == mac and record.best_next_hop is not None:
                return self.node_for_mac(record.best_next_hop)
        return None

    def route_path(self, src: str, dest: str) -> tuple[str, ...] | None:
        """The whole path `src`'s traffic to `dest` takes right now, hop by
        hop through each relay's *own* next-hop choice, or `None` if it breaks
        anywhere (a hop with no route, or a forwarding loop).

        Each hop's choice is that node's, not `src`'s: BATMAN routes hop by
        hop, so this is the path a packet would actually walk."""
        path = [src]
        while path[-1] != dest:
            hop = self.next_hop(path[-1], dest)
            if hop is None or hop in path:
                return None
            path.append(hop)
        return tuple(path)

    def link_quality(self, src: str, neighbor: str) -> float | None:
        """`src`'s own estimate of the link it hears `neighbor` on — the EWMA
        over frames received directly from it — or `None` if `src` has no
        live record for it at all.

        The neighbour-table question, as distinct from `route_via`'s
        forwarding one. A link can be perfectly alive while the route ignores
        it (a better path exists, or the end-to-end quality through it is too
        weak to be chosen), and a study that can only ask where traffic goes
        reads every such link as absent. `None` is the real "not in contact"
        answer: the record is dropped once `src` stops hearing `neighbor`.

        Where the two are joined by more than one link, this is the best of
        them — the one the router would use.
        """
        mac = self._states[neighbor].mac
        # Unmeasurable rows (`ewma_quality is None`) are dropped rather than
        # compared: `None` means the link never carried a physical-layer
        # measurement, which is missing data, not a quality of zero. Keeping
        # them would also make `max` raise on a pair joined by two such links.
        qualities = [
            record.ewma_quality
            for record in self._states[src].driver.link_quality_records()
            if record.neighbor == mac and record.ewma_quality is not None
        ]
        return max(qualities) if qualities else None

    def link_age_ms(self, src: str, neighbor: str) -> float | None:
        """How long since `src` last heard `neighbor` directly, in
        milliseconds, or `None` if it has no direct-path record for it at all.

        The companion to `link_quality`, and the one that can say a link has
        *stopped*. Quality is an EWMA over frames that arrived, so it holds
        its last value indefinitely once they stop arriving — a hop nothing
        has crossed for half a minute still reports the quality it had when
        it was working. Only the timestamp moves.

        Direct-path only: a destination reached through someone else has no
        link age here, however fresh the route to it is.
        """
        mac = self._states[neighbor].mac
        for record in self._states[src].driver.originator_table():
            if record.originator != mac:
                continue
            # The path whose next hop *is* the destination: the frames `src`
            # received from `neighbor` itself, not ones it relayed.
            heard = [p.last_heard_ms for p in record.paths if p.neighbor == mac]
            if heard:
                return self.env.now - max(heard)
        return None

    def reachable(
        self, src: str, targets: Sequence[str] | None = None
    ) -> tuple[str, ...]:
        """Which of `targets` `src` currently has *any* route to, in the order
        given (default: every other node, in declaration order).

        The set form of `route_via`, for the coverage question a mobility
        study actually asks: not "which link does this node forward on" but
        "is it in touch with anything at all". Pass `targets` to narrow that
        to the nodes that count — typically the ground relays with backhaul,
        since being routable only via another airborne node is not the same
        as being connected.

        Truthiness is the connectivity signal: an empty tuple means
        unreachable, which is what `connectivity.connectivity_stats` reads by
        default.
        """
        if src not in self._states:
            raise KeyError(src)
        if targets is None:
            targets = [name for name in self._states if name != src]
        return tuple(
            name
            for name in targets
            if name != src and self.egress_interface(src, name) is not None
        )

    def sample_channel(self, a: str, b: str):
        """Evaluate the link joining `a` and `b` right now, on a dedicated
        probe RNG stream so recording it never perturbs simulated delivery."""
        link = self._link_for_pair.get(frozenset((a, b)))
        if link is None:
            raise NoLinkError(f"no link between {a!r} and {b!r}")
        t_s = self.env.now / 1000.0
        return link.channel.evaluate(
            self.position(a), self.position(b), t_s, self._probe_rng
        )

    def poll_local(self, node: str) -> bytes | None:
        """Pop the next payload delivered to `node`'s local host, if any —
        see `wf.PyDriver.poll_local`. Packets belonging to a `stream` are
        never returned here; their `Flow` consumed them."""
        state = self._states[node]
        self._drain_local(state, node)
        return state.inbox.popleft() if state.inbox else None

    # --- setup -----------------------------------------------------------

    def record(self, name: str, probe: Probe) -> None:
        """Register `probe` to be sampled once per recorder tick under
        column `name`."""
        self._probes[name] = probe

    def send(self, src: str, dest: str, payload: bytes, at_s: float) -> None:
        """Schedule `payload` for `queue_local_send` from `src` toward
        `dest` (a node name, or `"*"` to flood) at simulation time `at_s`."""
        self.env.process(self._send_proc(src, dest, payload, at_s))

    # --- drive -------------------------------------------------------------

    def run(self, until_s: float, *, sample_interval_ms: int = 50) -> Recorder:
        """Run the simulation from wherever it currently is up to `until_s`,
        sampling every registered probe every `sample_interval_ms`."""
        recorder = Recorder(interval_ms=sample_interval_ms)
        self._recorder = recorder
        self.env.process(self._sample_proc(sample_interval_ms, recorder))
        self.env.run(until=until_s * 1000)
        return recorder

    # --- internal SimPy processes ------------------------------------------

    def _tick_node(self, name: str) -> None:
        state = self._states[name]
        if not state.up:
            return
        state.driver.tick(int(self.env.now))
        for iface, link in state.interfaces.items():
            frame = state.driver.poll_egress(iface)
            while frame is not None:
                state.tx_frames += 1
                state.tx_bytes += len(frame)
                self._schedule_delivery(link, name, iface, frame)
                frame = state.driver.poll_egress(iface)
        self._drain_local(state, name)

    def _drain_local(self, state: _NodeState, name: str) -> None:
        """Move what the router delivered locally into `state.inbox`,
        handing stream packets to their flow on the way."""
        t_s = self.env.now / 1000.0
        payload = state.driver.poll_local()
        while payload is not None:
            decoded = decode_payload(payload)
            if (
                decoded is not None
                and decoded[0] < len(self._flows)
                and self._flows[decoded[0]].dest == name
            ):
                self._flows[decoded[0]].record_received(decoded[1], t_s)
            else:
                state.inbox.append(payload)
            payload = state.driver.poll_local()

    def _tick_proc(self, name: str):
        self._tick_node(name)
        state = self._states[name]
        while True:
            yield self.env.timeout(state.tick_interval_ms)
            self._tick_node(name)

    def _schedule_delivery(
        self, link: Link, src_name: str, src_iface: int, frame: bytes
    ) -> None:
        if link.name in self._down_links or not self._states[src_name].up:
            return
        if link.medium is not None:
            self._enqueue(link, src_name, src_iface, frame)
            return
        t_s = self.env.now / 1000.0
        # Tap on transmit, not on delivery: a listener hears what went out
        # over the medium, including the frames a lossy channel then drops
        # before they reach their intended receiver.
        # `Link.__post_init__` always fills `name`; the `or ""` is only to
        # keep the key a `str` for the type checker.
        for tap in self._taps.get(link.name or "", ()):
            tap.capture(t_s, frame)
        tx_pos = self._states[src_name].node.mobility.position(t_s)
        for dst_name in self._receivers_for(link, src_name):
            dst_state = self._states[dst_name]
            if not dst_state.up:
                continue
            rx_pos = dst_state.node.mobility.position(t_s)
            sample = link.channel.evaluate(tx_pos, rx_pos, t_s, self._delivery_rng)
            rssi = sample.metrics.rssi_dbm
            if self._jammers and rssi is not None:
                jam_mw = self._jamming_mw(link, rx_pos, t_s, t_s)
                if jam_mw > 0.0 and rssi - 10.0 * math.log10(jam_mw) < DEFAULT_CAPTURE_DB:
                    self._radio_stats[dst_name].jammed += 1
                    continue
            if self._delivery_rng.random() < sample.delivery_probability:
                dst_iface = self._link_iface[id(link)][dst_name]
                self.env.process(
                    self._deliver(
                        sample.latency_ms,
                        dst_state,
                        dst_state.boot,
                        dst_iface,
                        frame,
                        sample.metrics,
                    )
                )

    def _deliver(
        self,
        latency_ms: float,
        dst_state: _NodeState,
        boot: int,
        dst_iface: int,
        frame: bytes,
        metrics: wf.PyLinkMetrics,
    ):
        if latency_ms > 0:
            yield self.env.timeout(latency_ms)
        # Lost if the receiver went down (or down and back up) mid-flight.
        if not dst_state.up or dst_state.boot != boot:
            return
        self._push_rx(dst_state, dst_iface, frame, metrics)

    def _push_rx(
        self,
        dst_state: _NodeState,
        dst_iface: int,
        frame: bytes,
        metrics: wf.PyLinkMetrics,
    ) -> None:
        """Hand a frame that survived the air to `dst_state`'s router —
        unless that node is compromised and the frame carries its own
        revocation, which its firmware discards."""
        name = dst_state.node.name
        if name in self._compromised and any(
            record in frame for record in self._revocation_bytes.get(name, ())
        ):
            return
        dst_state.driver.push_rx(dst_iface, frame, metrics)

    # --- contended medium ---------------------------------------------------

    def _receivers_for(self, link: Link, src: str) -> tuple[str, ...]:
        """The members of `link` worth evaluating a frame from `src` at.

        Everyone but `src`, except that where `src` and a receiver are both
        `Static` and the channel has a hard range cutoff (`max_range_m`, on it
        or on the model it wraps), a receiver beyond that range is dropped once
        and for all. On a large segment that is most of it, and asking the
        channel per frame for an answer fixed at construction is the dominant
        cost of a big simulation.
        """
        key = (id(link), src)
        cached = self._receivers.get(key)
        if cached is not None:
            return cached
        others = [n for n in link.endpoints if n != src]
        max_range = getattr(link.channel, "max_range_m", None)
        if max_range is None:
            max_range = getattr(getattr(link.channel, "base", None), "max_range_m", None)
        src_mob = self._states[src].node.mobility
        if max_range is not None and isinstance(src_mob, Static):
            src_pos = src_mob.position(0.0)
            others = [
                n
                for n in others
                if not isinstance(self._states[n].node.mobility, Static)
                or src_pos.distance_to(self._states[n].node.mobility.position(0.0)) <= max_range
            ]
        result = tuple(others)
        self._receivers[key] = result
        return result

    def _radio(self, node: str, link: Link) -> _Radio:
        key = (node, link.name or "")
        radio = self._radios.get(key)
        if radio is None:
            radio = self._radios[key] = _Radio()
        return radio

    def _enqueue(self, link: Link, src: str, iface: int, frame: bytes) -> None:
        """Put `frame` on `src`'s radio for `link`: straight onto the air if
        the radio is idle and owes no off-time, into its queue otherwise."""
        assert link.medium is not None
        radio = self._radio(src, link)
        if not radio.sending:
            radio.sending = True
            first = None
            if radio.off_until_ms <= self.env.now:
                first = (iface, frame)
            else:
                radio.queue.append((iface, frame))
            self.env.process(self._radio_proc(link, src, radio, first))
            return
        if len(radio.queue) >= link.medium.queue_limit:
            self._radio_stats[src].queue_drops += 1
            return
        radio.queue.append((iface, frame))

    def _radio_proc(
        self, link: Link, src: str, radio: _Radio, first: tuple[int, bytes] | None
    ):
        assert link.medium is not None
        medium = link.medium
        stats = self._radio_stats[src]
        state = self._states[src]
        pending = first
        while True:
            if pending is None:
                if not radio.queue:
                    break
                wait_ms = radio.off_until_ms - self.env.now
                if wait_ms > 0:
                    stats.duty_wait_s += wait_ms / 1000.0
                    yield self.env.timeout(wait_ms)
                if not radio.queue:
                    break
                pending = radio.queue.popleft()
            iface, frame = pending
            pending = None
            if not state.up or link.name in self._down_links:
                # Powered off or cut with frames still queued: they die with it.
                radio.queue.clear()
                break
            airtime_ms = medium.phy.airtime_s(len(frame)) * 1000.0
            self._transmit(link, src, frame, airtime_ms)
            stats.tx_frames += 1
            stats.tx_airtime_s += airtime_ms / 1000.0
            yield self.env.timeout(airtime_ms)
            radio.off_until_ms = self.env.now + medium.off_time_s(airtime_ms / 1000.0) * 1000.0
        radio.sending = False

    def _transmit(self, link: Link, src: str, frame: bytes, airtime_ms: float) -> None:
        """Start `frame` on the air from `src`: record the transmission (for
        half-duplex), let wiretaps hear it, and open a reception at every
        receiver the signal reaches."""
        now = self.env.now
        end = now + airtime_ms
        tx_radio = self._radio(src, link)
        _prune(tx_radio, now)
        tx_radio.tx_intervals.append((now, end))
        t_s = now / 1000.0
        for tap in self._taps.get(link.name or "", ()):
            tap.capture(t_s, frame)
        tx_pos = self._states[src].node.mobility.position(t_s)
        for dst in self._receivers_for(link, src):
            dst_state = self._states[dst]
            if not dst_state.up:
                continue
            sample = link.channel.evaluate(
                tx_pos, dst_state.node.mobility.position(t_s), t_s, self._delivery_rng
            )
            rssi = sample.metrics.rssi_dbm
            if sample.delivery_probability == 0.0 and rssi is None:
                continue  # beyond any reach: no signal, no interference
            rx_radio = self._radio(dst, link)
            _prune(rx_radio, now)
            reception = _Reception(
                src=src,
                start_ms=now,
                end_ms=end,
                rssi_dbm=0.0 if rssi is None else float(rssi),
                frame=frame,
                metrics=sample.metrics,
                delivery_probability=sample.delivery_probability,
                iface=self._link_iface[id(link)][dst],
                boot=dst_state.boot,
                latency_ms=sample.latency_ms,
            )
            rx_radio.receptions.append(reception)
            busy_from = max(now, rx_radio.rx_busy_until_ms)
            if end > busy_from:
                self._radio_stats[dst].rx_airtime_s += (end - busy_from) / 1000.0
                rx_radio.rx_busy_until_ms = end
            self.env.process(self._reception_proc(link, dst, rx_radio, reception))

    def _reception_proc(self, link: Link, dst: str, radio: _Radio, rec: _Reception):
        assert link.medium is not None
        yield self.env.timeout(rec.end_ms - self.env.now)
        dst_state = self._states[dst]
        if not dst_state.up or dst_state.boot != rec.boot:
            return
        stats = self._radio_stats[dst]
        if any(s < rec.end_ms and e > rec.start_ms for s, e in radio.tx_intervals):
            stats.half_duplex_losses += 1
            return
        overlap_mw = sum(
            10.0 ** (other.rssi_dbm / 10.0)
            for other in radio.receptions
            if other is not rec and other.start_ms < rec.end_ms and other.end_ms > rec.start_ms
        )
        jam_mw = 0.0
        if self._jammers:
            jam_mw = self._jamming_mw(
                link,
                dst_state.node.mobility.position(rec.start_ms / 1000.0),
                rec.start_ms / 1000.0,
                rec.end_ms / 1000.0,
            )
        interference_mw = overlap_mw + jam_mw
        if interference_mw > 0.0:
            sir_db = rec.rssi_dbm - 10.0 * math.log10(interference_mw)
            if sir_db < link.medium.capture_db:
                # Blame whichever contributed more of the interference.
                if jam_mw >= overlap_mw:
                    stats.jammed += 1
                else:
                    stats.collisions += 1
                return
        if self._delivery_rng.random() >= rec.delivery_probability:
            stats.noise_losses += 1
            return
        stats.rx_frames += 1
        if rec.latency_ms > 0:
            yield self.env.timeout(rec.latency_ms)
            if not dst_state.up or dst_state.boot != rec.boot:
                return
        self._push_rx(dst_state, rec.iface, rec.frame, rec.metrics)

    def _inject_proc(self, src: str, frame: bytes, at_s: float, link: str | None):
        target_ms = at_s * 1000
        if target_ms > self.env.now:
            yield self.env.timeout(target_ms - self.env.now)
        self._inject_now(src, frame, link)

    def _inject_now(self, src: str, frame: bytes, link: str | None) -> None:
        """Transmit `frame` on each of `src`'s links (or just `link`) right
        now, through the ordinary delivery path — so injected traffic is
        subject to the same channel model, and visible to the same wiretaps,
        as anything a router emitted."""
        for iface, candidate in self._states[src].interfaces.items():
            if link is None or candidate.name == link:
                self._schedule_delivery(candidate, src, iface, frame)

    def _flood_proc(
        self,
        src: str,
        frame: Callable[[], bytes],
        rate_hz: float,
        start_s: float,
        duration_s: float,
        link: str | None,
    ):
        start_ms = start_s * 1000
        if start_ms > self.env.now:
            yield self.env.timeout(start_ms - self.env.now)
        interval_ms = 1000.0 / rate_hz
        end_ms = start_ms + duration_s * 1000
        while self.env.now < end_ms:
            self._inject_now(src, frame(), link)
            yield self.env.timeout(interval_ms)

    def _send_proc(self, src: str, dest: str, payload: bytes, at_s: float):
        target_ms = at_s * 1000
        if target_ms > self.env.now:
            yield self.env.timeout(target_ms - self.env.now)
        mac = wf.PyMac.BROADCAST if dest == "*" else self._states[dest].mac
        if self._states[src].up:
            self._states[src].driver.queue_local_send(mac, payload)

    def _wait_until(self, t_s: float):
        target_ms = t_s * 1000
        if target_ms > self.env.now:
            yield self.env.timeout(target_ms - self.env.now)

    def _fail_node_proc(self, node: str, at_s: float, recover_s: float | None):
        yield from self._wait_until(at_s)
        state = self._states[node]
        state.up = False
        state.inbox.clear()
        if recover_s is None:
            return
        yield from self._wait_until(recover_s)
        state.boot += 1
        state.driver = self._build_driver(
            state.node, state.mac, state.trickle, state.keepalive, state.keypair
        )
        state.up = True
        self._tick_node(node)

    def _fail_link_proc(self, link: str, at_s: float, recover_s: float | None):
        yield from self._wait_until(at_s)
        self._down_links.add(link)
        if recover_s is None:
            return
        yield from self._wait_until(recover_s)
        self._down_links.discard(link)

    def _stream_proc(
        self, flow: Flow, rate_hz: float, start_s: float, duration_s: float
    ):
        yield from self._wait_until(start_s)
        interval_ms = 1000.0 / rate_hz
        count = round(duration_s * rate_hz)
        dest_mac = self._states[flow.dest].mac
        for seq in range(count):
            # Recorded even when the source is down: the application tried,
            # and a packet that never left is as lost as one dropped en route.
            flow.record_sent(seq, self.env.now / 1000.0)
            src = self._states[flow.src]
            if src.up:
                src.driver.queue_local_send(
                    dest_mac, encode_payload(flow.flow_id, seq)
                )
            yield self.env.timeout(interval_ms)

    def _sample_proc(self, interval_ms: int, recorder: Recorder):
        # Each `run` starts its own sampler for its own recorder; one left over
        # from an earlier `run` stops the moment a newer one takes over, or a
        # scenario run in segments would sample every instant once per segment.
        while self._recorder is recorder:
            t_s = self.env.now / 1000.0
            values = {name: probe(self) for name, probe in self._probes.items()}
            recorder.append(t_s, values)
            yield self.env.timeout(interval_ms)


def _prune(radio: _Radio, now_ms: float) -> None:
    """Forget transmissions and receptions too old to overlap anything still
    on the air."""
    horizon = now_ms - _HISTORY_MS
    if radio.tx_intervals and radio.tx_intervals[0][1] < horizon:
        radio.tx_intervals = [iv for iv in radio.tx_intervals if iv[1] >= horizon]
    if radio.receptions and radio.receptions[0].end_ms < horizon:
        radio.receptions = [r for r in radio.receptions if r.end_ms >= horizon]
