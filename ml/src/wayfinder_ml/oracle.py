"""The privileged labeler.

The simulator knows things no router can: every node's true position and, from
the channel model, the true instantaneous delivery probability of every pair.
This module turns that into the answer key — the next hop a perfectly-informed
router would choose — which supervises a model that only ever sees the
router's own noisy, delayed view.

Cost is **expected transmission count** (ETX): the expected number of frames
that must be sent for one to arrive. It composes additively along a path,
which is what makes "best route" a shortest-path problem, and it captures the
case that motivates the whole project — that one reliable extra hop beats a
marginal direct link, a trade a hop-count-flavoured metric gets wrong.

Nothing here imports the simulator: the input is a plain edge -> probability
mapping, so the oracle is testable on hand-written graphs and reusable for any
future scenario source.
"""

from __future__ import annotations

import heapq
import math
from collections.abc import Mapping

Edge = tuple[str, str]
"""A directed `(from, to)` pair. Channels may be asymmetric, so direction is
significant even when the simulator's model happens to be symmetric."""


def etx(delivery_probability: float) -> float:
    """Expected transmissions for one success over a link that delivers
    `delivery_probability` of its frames.

    A dead link (`0.0`) costs `inf` rather than a large finite number, so it is
    excluded from paths outright instead of being chosen when every
    alternative is merely bad.
    """
    if delivery_probability <= 0.0:
        return math.inf
    return 1.0 / delivery_probability


def costs_to(graph: Mapping[Edge, float], dest: str) -> dict[str, float]:
    """Minimum total ETX from every node to `dest`.

    Dijkstra over the graph with edges reversed — one pass yields every
    node's cost-to-destination, rather than a separate search per source.
    Unreachable nodes are absent from the result.
    """
    incoming: dict[str, list[tuple[str, float]]] = {}
    for (src, dst), probability in graph.items():
        cost = etx(probability)
        if math.isinf(cost):
            continue
        # Walking edges backwards from `dest`: to relax "who can reach `dst`",
        # we need the predecessors of `dst` and the forward cost they pay.
        incoming.setdefault(dst, []).append((src, cost))

    best: dict[str, float] = {dest: 0.0}
    queue: list[tuple[float, str]] = [(0.0, dest)]
    while queue:
        cost_here, node = heapq.heappop(queue)
        if cost_here > best.get(node, math.inf):
            continue  # a shorter route to `node` was already finalized
        for predecessor, edge_cost in incoming.get(node, ()):
            candidate = cost_here + edge_cost
            if candidate < best.get(predecessor, math.inf):
                best[predecessor] = candidate
                heapq.heappush(queue, (candidate, predecessor))
    return best


def best_next_hops(graph: Mapping[Edge, float], dest: str) -> dict[str, str | None]:
    """The optimal next hop toward `dest` for every node in `graph`.

    `None` where no route exists — and for `dest` itself, which has no next
    hop. Every node mentioned by any edge appears in the result, so a caller
    can tell "unreachable" apart from "not in the topology".
    """
    costs = costs_to(graph, dest)

    nodes = {dest}
    outgoing: dict[str, list[tuple[str, float]]] = {}
    for (src, dst), probability in graph.items():
        nodes.update((src, dst))
        cost = etx(probability)
        if not math.isinf(cost):
            outgoing.setdefault(src, []).append((dst, cost))

    hops: dict[str, str | None] = {}
    for node in nodes:
        if node == dest:
            hops[node] = None
            continue
        best_hop: str | None = None
        best_cost = math.inf
        # Ties resolve to the lexicographically smaller neighbor so a label is
        # a deterministic function of the graph — otherwise dict iteration
        # order would make a dataset unreproducible across runs.
        for neighbor, edge_cost in sorted(outgoing.get(node, ())):
            total = edge_cost + costs.get(neighbor, math.inf)
            if total < best_cost:
                best_cost, best_hop = total, neighbor
        hops[node] = best_hop
    return hops
