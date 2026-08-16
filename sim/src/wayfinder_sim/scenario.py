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
from collections.abc import Callable, Sequence
from random import Random
from typing import Any

import simpy
import wayfinder_py as wf

from . import NoLinkError
from .link import Link
from .mobility import Vec3
from .node import Node
from .recorder import Recorder

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
class _NodeState:
    node: Node
    mac: wf.PyMac
    driver: wf.PyDriver
    interfaces: dict[int, Link]  # this node's interface index -> the Link on it
    tick_interval_ms: int


class Simulation:
    """A running mesh simulation over `nodes` wired by `links`."""

    def __init__(
        self, nodes: Sequence[Node], links: Sequence[Link], *, seed: int = 0
    ) -> None:
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

        # A pair of node names -> the (possibly shared-LAN) Link joining
        # them, for `sample_channel`'s probing.
        self._link_for_pair: dict[frozenset[str], Link] = {}
        for link in self._links:
            for a, b in itertools.combinations(link.endpoints, 2):
                self._link_for_pair[frozenset((a, b))] = link

        self._states: dict[str, _NodeState] = {}
        for idx, node in enumerate(node_list, start=1):
            mac = (
                node.mac
                if node.mac is not None
                else wf.PyMac(bytes((*_AUTO_MAC_OUI, idx)))
            )
            features = [
                wf.PyLinkFeatures(tx_keepalive_interval_ms=ka)
                for ka in node_keepalive[node.name]
            ]
            driver = wf.PyDriver(mac, node_trickle[node.name], features)
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
            )

        self._probes: dict[str, Probe] = {}
        self._recorder: Recorder | None = None

        for name in self._states:
            self.env.process(self._tick_proc(name))

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
        qualities = [
            record.ewma_quality
            for record in self._states[src].driver.link_quality_records()
            if record.neighbor == mac
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
        see `wf.PyDriver.poll_local`."""
        return self._states[node].driver.poll_local()

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
        self._recorder = Recorder(interval_ms=sample_interval_ms)
        self.env.process(self._sample_proc(sample_interval_ms))
        self.env.run(until=until_s * 1000)
        return self._recorder

    # --- internal SimPy processes ------------------------------------------

    def _tick_node(self, name: str) -> None:
        state = self._states[name]
        state.driver.tick(int(self.env.now))
        for iface, link in state.interfaces.items():
            frame = state.driver.poll_egress(iface)
            while frame is not None:
                self._schedule_delivery(link, name, iface, frame)
                frame = state.driver.poll_egress(iface)

    def _tick_proc(self, name: str):
        self._tick_node(name)
        state = self._states[name]
        while True:
            yield self.env.timeout(state.tick_interval_ms)
            self._tick_node(name)

    def _schedule_delivery(
        self, link: Link, src_name: str, src_iface: int, frame: bytes
    ) -> None:
        t_s = self.env.now / 1000.0
        tx_pos = self._states[src_name].node.mobility.position(t_s)
        for dst_name in link.endpoints:
            if dst_name == src_name:
                continue
            dst_state = self._states[dst_name]
            rx_pos = dst_state.node.mobility.position(t_s)
            sample = link.channel.evaluate(tx_pos, rx_pos, t_s, self._delivery_rng)
            if self._delivery_rng.random() < sample.delivery_probability:
                dst_iface = self._link_iface[id(link)][dst_name]
                self.env.process(
                    self._deliver(
                        sample.latency_ms, dst_state, dst_iface, frame, sample.metrics
                    )
                )

    def _deliver(
        self,
        latency_ms: float,
        dst_state: _NodeState,
        dst_iface: int,
        frame: bytes,
        metrics: wf.PyLinkMetrics,
    ):
        if latency_ms > 0:
            yield self.env.timeout(latency_ms)
        dst_state.driver.push_rx(dst_iface, frame, metrics)

    def _send_proc(self, src: str, dest: str, payload: bytes, at_s: float):
        target_ms = at_s * 1000
        if target_ms > self.env.now:
            yield self.env.timeout(target_ms - self.env.now)
        mac = wf.PyMac.BROADCAST if dest == "*" else self._states[dest].mac
        self._states[src].driver.queue_local_send(mac, payload)

    def _sample_proc(self, interval_ms: int):
        assert self._recorder is not None
        while True:
            t_s = self.env.now / 1000.0
            values = {name: probe(self) for name, probe in self._probes.items()}
            self._recorder.append(t_s, values)
            yield self.env.timeout(interval_ms)
