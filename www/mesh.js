/*
 * The hero diagram: a small mesh that loses links and re-routes around them.
 *
 * This is the one place on the page where the product is *shown* rather than
 * described, so it runs a real (tiny) shortest-path search over a real link
 * graph rather than replaying a scripted animation. When a link goes down the
 * route that appears is genuinely the next-best path through the remaining
 * edges — which is also why a scripted version would have been more code, not
 * less: the failure sequence would have to be authored per edge.
 *
 * Deliberately dependency-free and ~200 lines: the page ships no framework and
 * no build step, and this is the only script on it.
 */

(() => {
  "use strict";

  const svg = document.getElementById("mesh");
  const statusEl = document.getElementById("mesh-status");
  if (!svg) return;

  const NS = "http://www.w3.org/2000/svg";
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------- topology */

  /* Hand-placed rather than force-laid-out: the composition has to read at a
   * glance in a fixed 520x400 box, and a layout run would put nodes wherever
   * it liked each load. Positions are viewBox units. */
  const nodes = [
    { x: 58, y: 208, label: "drone" }, // 0 — source
    { x: 146, y: 92 },
    { x: 152, y: 218 },
    { x: 138, y: 330 },
    { x: 250, y: 146 },
    { x: 256, y: 268 },
    { x: 352, y: 82 },
    { x: 358, y: 210 },
    { x: 344, y: 326 },
    { x: 462, y: 196, label: "operator" }, // 9 — destination
  ];

  /* Every edge is bidirectional. The set is chosen so that removing any single
   * edge still leaves at least two distinct routes from 0 to 9 — otherwise the
   * animation would have to show a partition, which is a different story than
   * the one this diagram is telling. */
  // Grouped by source node so the graph is readable as a topology rather than a
  // list of pairs; prettier would otherwise put each pair on its own line.
  // prettier-ignore
  const edges = [
    [0, 1], [0, 2], [0, 3],
    [1, 2], [1, 4],
    [2, 4], [2, 5],
    [3, 5], [3, 8],
    [4, 5], [4, 6], [4, 7],
    [5, 7], [5, 8],
    [6, 7], [6, 9],
    [7, 8], [7, 9],
    [8, 9],
  ];

  const SRC = 0;
  const DST = 9;

  const dist = (a, b) =>
    Math.hypot(nodes[a].x - nodes[b].x, nodes[a].y - nodes[b].y);

  /* Edge indices currently considered down, oldest first. */
  const down = [];
  const isDown = (i) => down.includes(i);

  /* Dijkstra over the up edges. Nine nodes — an adjacency scan per step is
   * cheaper than any structure that would make it asymptotically better. */
  function route(exclude = -1, from = SRC) {
    const n = nodes.length;
    const best = new Array(n).fill(Infinity);
    const prev = new Array(n).fill(-1);
    const seen = new Array(n).fill(false);
    best[from] = 0;

    for (;;) {
      let u = -1;
      for (let i = 0; i < n; i++) {
        if (!seen[i] && best[i] < (u === -1 ? Infinity : best[u])) u = i;
      }
      if (u === -1) break;
      seen[u] = true;

      edges.forEach(([a, b], i) => {
        if (i === exclude || isDown(i)) return;
        const v = a === u ? b : b === u ? a : -1;
        if (v === -1) return;
        const alt = best[u] + dist(a, b);
        if (alt < best[v]) {
          best[v] = alt;
          prev[v] = u;
        }
      });
    }

    if (best[DST] === Infinity) return null;
    const path = [];
    for (let at = DST; at !== -1; at = prev[at]) path.unshift(at);
    return path;
  }

  /* --------------------------------------------------------------- render */

  const el = (name, attrs) => {
    const e = document.createElementNS(NS, name);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  };

  const gLinks = el("g", {});
  const gRoute = el("g", {});
  const gNodes = el("g", {});
  const gText = el("g", {});
  svg.append(gLinks, gRoute, gNodes, gText);

  const linkEls = edges.map(([a, b]) => {
    const line = el("line", {
      class: "mesh-link",
      x1: nodes[a].x,
      y1: nodes[a].y,
      x2: nodes[b].x,
      y2: nodes[b].y,
    });
    gLinks.append(line);
    return line;
  });

  const routeEl = el("polyline", { class: "mesh-route", points: "" });
  gRoute.append(routeEl);

  nodes.forEach((nd, i) => {
    const endpoint = i === SRC || i === DST;
    gNodes.append(
      el("circle", {
        class: "mesh-node" + (endpoint ? " is-endpoint" : ""),
        cx: nd.x,
        cy: nd.y,
        r: endpoint ? 9 : 6.5,
      }),
    );
    if (nd.label) {
      const t = el("text", {
        class: "mesh-label",
        x: nd.x,
        y: nd.y + (i === SRC ? 26 : 26),
        "text-anchor": "middle",
      });
      t.textContent = nd.label;
      gText.append(t);
    }
  });

  const halo = el("circle", {
    class: "mesh-halo",
    cx: nodes[SRC].x,
    cy: nodes[SRC].y,
    r: 9,
    opacity: 0,
  });
  const packet = el("circle", {
    class: "mesh-packet",
    cx: nodes[SRC].x,
    cy: nodes[SRC].y,
    r: 4.5,
    opacity: 0,
  });
  gNodes.append(halo, packet);

  /* The frame's decision state. `at` is the node holding it, `to` the single
   * next hop that node has chosen, and `trail` the hops already taken.
   *
   * There is deliberately no variable holding the whole path. That is the
   * claim the section makes — no node holds a map of the network, each one
   * only knows the next hop toward a destination — and a diagram that drew the
   * finished route before the frame set off would be illustrating link-state
   * routing, which is the other thing. */
  let trail = [SRC];
  let at = SRC;
  let to = null;
  let legProgress = 0;

  /* What `at` would do with a frame for DST: run the search from itself and
   * take the first step. Nine nodes makes this cheap enough to redo at every
   * hop, which is also the honest thing to do — the answer can change between
   * one hop and the next. */
  function nextHop(from) {
    const p = route(-1, from);
    return p && p.length > 1 ? p[1] : null;
  }

  function drawLinks() {
    linkEls.forEach((l, i) => l.classList.toggle("is-down", isDown(i)));
  }

  /* The route line is drawn *by* the frame rather than ahead of it: the trail
   * so far, plus however far along the current leg it has travelled. */
  function drawTrail() {
    const pts = trail.map((i) => `${nodes[i].x},${nodes[i].y}`);
    if (to !== null && legProgress > 0) {
      const a = nodes[at];
      const b = nodes[to];
      pts.push(
        `${a.x + (b.x - a.x) * legProgress},${a.y + (b.y - a.y) * legProgress}`,
      );
    }
    routeEl.setAttribute("points", pts.join(" "));
  }

  drawLinks();

  function setStatus(text, alarm) {
    if (!statusEl) return;
    statusEl.textContent = text;
    statusEl.classList.toggle("is-alarm", !!alarm);
  }

  if (reduced) {
    /* No motion to carry the hop-by-hop story, so show the converged result
     * instead: the whole route, drawn at rest. */
    const p = route();
    if (p) {
      routeEl.setAttribute(
        "points",
        p.map((i) => `${nodes[i].x},${nodes[i].y}`).join(" "),
      );
    }
    setStatus("converged", false);
    return;
  }

  /* ------------------------------------------------------------ animation */

  const SPEED = 108; // viewBox units per second
  const DWELL = 170; // ms a node holds the frame while it picks its next hop

  let dwellUntil = 0;
  let last = 0;

  /* A ring at whichever node is currently deciding. */
  function pulse(i) {
    halo.setAttribute("cx", nodes[i].x);
    halo.setAttribute("cy", nodes[i].y);
    halo.setAttribute("opacity", 0.9);
    halo.setAttribute("r", 9);
    const t0 = performance.now();
    const ring = (now) => {
      const p = (now - t0) / 620;
      if (p >= 1) {
        halo.setAttribute("opacity", 0);
        return;
      }
      halo.setAttribute("r", 9 + p * 20);
      halo.setAttribute("opacity", 0.9 * (1 - p));
      requestAnimationFrame(ring);
    };
    requestAnimationFrame(ring);
  }

  function placePacket(x, y) {
    packet.setAttribute("cx", x);
    packet.setAttribute("cy", y);
    packet.setAttribute("opacity", 1);
  }

  function step(now) {
    if (!last) last = now;
    const dt = Math.min((now - last) / 1000, 0.05); // clamp after a tab switch
    last = now;

    if (to === null || now < dwellUntil) {
      drawTrail();
      requestAnimationFrame(step);
      return;
    }

    const a = nodes[at];
    const b = nodes[to];
    const len = Math.hypot(b.x - a.x, b.y - a.y);
    legProgress += (SPEED * dt) / len;

    if (legProgress >= 1) {
      /* Delivered to the next hop. That node now decides for itself, knowing
       * nothing about where the frame has been. */
      at = to;
      legProgress = 0;
      trail.push(at);
      placePacket(nodes[at].x, nodes[at].y);

      if (at === DST) {
        to = null;
        drawTrail();
        packet.setAttribute("opacity", 0);
        setStatus("delivered", false);
        setTimeout(emit, 900);
        requestAnimationFrame(step);
        return;
      }

      to = nextHop(at);
      if (to === null) {
        /* The guards in dropLink should make this unreachable; do not leave the
         * frame parked forever if they ever stop holding. */
        packet.setAttribute("opacity", 0);
        setTimeout(emit, 900);
        requestAnimationFrame(step);
        return;
      }
      dwellUntil = now + DWELL;
      pulse(at);
    } else {
      placePacket(
        a.x + (b.x - a.x) * legProgress,
        a.y + (b.y - a.y) * legProgress,
      );
    }

    drawTrail();
    requestAnimationFrame(step);
  }

  function emit() {
    trail = [SRC];
    at = SRC;
    legProgress = 0;
    to = nextHop(SRC);
    dwellUntil = performance.now() + DWELL;
    placePacket(nodes[SRC].x, nodes[SRC].y);
    setStatus("forwarding", false);
    pulse(SRC);
  }

  /* --------------------------------------------------------- link failure */

  /* Take down an edge the frame is about to need — a failure on a link nothing
   * was going to use demonstrates nothing. Never take one whose loss would
   * strand either endpoint, since a partition is a different story than the
   * one this diagram tells. */
  function dropLink() {
    const ahead = route(-1, at);
    if (!ahead) return;

    const candidates = [];
    for (let i = 0; i < ahead.length - 1; i++) {
      const [u, v] = [ahead[i], ahead[i + 1]];
      const idx = edges.findIndex(
        ([a, b]) => (a === u && b === v) || (a === v && b === u),
      );
      if (idx === -1 || isDown(idx)) continue;
      if (route(idx, SRC) && route(idx, at)) candidates.push(idx);
    }
    if (!candidates.length) return;

    const idx = candidates[Math.floor(Math.random() * candidates.length)];
    down.push(idx);
    if (down.length > 2) down.shift(); // heal the oldest failure
    drawLinks();

    /* If that was the leg in flight, the frame never arrived: it falls back to
     * the node that sent it, which picks again. Otherwise the break is still
     * ahead, and the node holding it next will simply choose differently. */
    const inFlight =
      to !== null &&
      ((edges[idx][0] === at && edges[idx][1] === to) ||
        (edges[idx][0] === to && edges[idx][1] === at));

    if (inFlight) {
      legProgress = 0;
      placePacket(nodes[at].x, nodes[at].y);
      pulse(at);
      dwellUntil = performance.now() + DWELL;
    }

    to = nextHop(at);
    if (to === null && at !== DST) setTimeout(emit, 900);
    drawTrail();

    setStatus("link lost", true);
    setTimeout(() => setStatus("re-routing", true), 700);
    setTimeout(() => setStatus("forwarding", false), 1900);
  }

  emit();
  requestAnimationFrame(step);

  /* The failure is the whole point of the diagram, so land the first one while
   * the visitor is still watching rather than a full interval in. */
  setTimeout(() => {
    dropLink();
    setInterval(dropLink, 6200);
  }, 2500);

  /* ------------------------------------------------------------ page bits */

  const nav = document.getElementById("nav");
  if (nav) {
    const onScroll = () => nav.classList.toggle("is-stuck", window.scrollY > 8);
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }
})();
