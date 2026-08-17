#!/usr/bin/env python3
"""Generate (and optionally run) an ephemeral docker-compose file for a
Wayfinder mesh simulation of an arbitrary topology.

The simulation image (``containers/sim.Dockerfile``) derives each node's config
purely from the docker networks attached to it: its entrypoint discovers every
``eth*`` NIC and emits one ``RawL2`` mesh link per NIC.  So the *topology is the
wiring* — which is exactly what this script controls.  Edit ``build_links()``
below (or the helpers it calls) and re-run; nothing else needs to change.

A "link" here is one isolated L2 bridge network shared by its member nodes:

* **2 members**  → a point-to-point link (the common case).
* **N members**  → a shared LAN where every member hears every other directly
  (a complete graph on those nodes over a single segment).

Usage
-----
    python scripts/topology.py print              # print the generated compose YAML
    python scripts/topology.py write [PATH]       # write it (default: docker-compose-sim.yml)
    python scripts/topology.py up [-- ARGS...]    # generate ephemeral file + compose up --build -d
        (add --require-approval so the provider parks hand-submitted CSRs for
        operator approval instead of auto-signing; also accepted by
        `print`/`write`)
    python scripts/topology.py restart [NODE...]  # re-run the entrypoint (pick up a host rebuild)
    python scripts/topology.py down               # tear the ephemeral stack down
    python scripts/topology.py logs [NODE...]     # follow logs
    python scripts/topology.py graph              # print an ASCII adjacency summary
    python scripts/topology.py blast [NODE]       # flood broadcast traffic from a node (stress test)

The ``up``/``restart``/``down``/``logs`` subcommands shell out to ``docker
compose`` against an ephemeral file written to the repo root
(``.sim-compose.gen.yml``, gitignored) under the fixed project name
``wayfinder-sim``.

Fast dev loop: the repo is mounted into each node at ``/workspace`` and the
host-built binaries under ``./target`` are on the container's ``PATH`` (the
image bakes in none), so ``wayfinder-tap``/``wayfinder-ctl``/``wayfinder-tui``
run by bare name — in the entrypoint and via ``docker exec``::

    cargo build -p wayfinder-tap -p wayfinder-ctl   # on the host
    python scripts/topology.py restart                  # re-exec the new binaries

rebuilds without ``docker compose build``. (On a Nix host ``/nix/store`` is
mounted read-only so the host binary's interpreter resolves.)

Dashboards
----------
Every node gets its own ``wayfinder-web`` container beside it, published on
loopback at ``8080`` for the first node, ``8081`` for the second, and so on in
the order nodes appear in the topology.  ``up`` prints the table; ``graph``
repeats it per node.  They run the host-built ``wayfinder-web`` from
``./target`` like everything else here, but that binary is the one thing a
plain ``cargo build`` does *not* produce usably — build it with::

    cargo leptos build      # the ssr binary AND the wasm bundle it serves

A dashboard authenticates with a shared *operator* identity minted alongside
the node certificates: an enrolled node refuses any management connection that
cannot present a certificate carrying the admin capability.

Identity
--------
``make_identities`` mints the mesh root, one plain *member* certificate per
node, and one *admin* operator certificate, all on the host before the stack
starts.  Each node mounts only its own at ``/secrets`` and is a mesh member from
its first instant, which also makes its MAC (derived from that seed)
reproducible across runs.

Nothing enrols at runtime.  An earlier version had each node generate a key and
enrol against the provider over the management API; once that API required an
authenticated TLS handshake, a node with no certificate could no longer open the
connection it would have used to ask for one.  So online enrollment — and the
CSR-approval flow — is *not* exercised by this sim, even though the provider
still serves those RPCs for a CSR submitted by hand.
"""

from __future__ import annotations

import argparse
import itertools
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# Ephemeral, gitignored compose file the `up`/`down` subcommands operate on.
# Kept at the repo root so `build.context: .` resolves like the committed one.
EPHEMERAL = REPO_ROOT / ".sim-compose.gen.yml"
PROJECT = "wayfinder-sim"

# Default verbosity for every node's RUST_LOG. "trace" is very chatty across a
# 9-node mesh; "info" is a sane default — bump a specific node in build_nodes().
DEFAULT_RUST_LOG = "info"

# The mesh every node in this sim belongs to. One value, used both when minting
# certificates on the host and in the provider node's config — they must agree
# or nothing verifies.
MESH_ID = 1

# Expiry for every certificate minted here. Far enough out that a sim left
# running never expires out from under itself; a real deployment keeps this
# short, since passive expiry is the primary revocation mechanism.
CERT_NOT_AFTER = 100_000_000_000

# Host port for the first node's dashboard; each subsequent node takes the next
# port up, in the same order `node_order` assigns node IPs. Published on
# loopback only — the dashboard has no login of its own.
WEB_PORT_BASE = 8090


# ── topology helpers ──────────────────────────────────────────────────────────
#
# Each returns a list of links, where a link is a list of member node names.


def complete_graph(prefix: str, n: int) -> list[list[str]]:
    """Every pair of ``{prefix}1..{prefix}n`` joined by its own point-to-point
    link — the K_n mesh as ``n*(n-1)/2`` distinct segments, so each edge is a
    separate interface that BATMAN paces independently.

    For a lighter "all hear all on one wire" variant, use ``shared_lan`` instead:
    ``shared_lan([f"{prefix}{i}" for i in range(1, n + 1)])``.
    """
    nodes = [f"{prefix}{i}" for i in range(1, n + 1)]
    return [[a, b] for i, a in enumerate(nodes) for b in nodes[i + 1 :]]


def diamond(prefix: str) -> list[list[str]]:
    """A 4-node diamond: ``{p}1`` fans out to ``{p}2`` and ``{p}3``, which both
    rejoin at ``{p}4`` — two disjoint 2-hop paths between ``{p}1`` and ``{p}4``."""
    a, b, c, d = (f"{prefix}{i}" for i in range(1, 5))
    return [[a, b], [a, c], [b, d], [c, d]]


def path(prefix: str, n: int) -> list[list[str]]:
    """A line of ``n`` nodes: ``{p}1 — {p}2 — … — {p}n``."""
    nodes = [f"{prefix}{i}" for i in range(1, n + 1)]
    return [[a, b] for a, b in itertools.pairwise(nodes)]


def shared_lan(nodes: list[str]) -> list[list[str]]:
    """One segment shared by all ``nodes`` (a single multi-access bridge)."""
    return [list(nodes)]


# ── Certificate helpers ───────────────────────────────────────────────────────
#
# Mint the whole mesh's identity on the host before bringing the compose project
# up: the root key (mounted into the *provider* node only), one member cert per
# node, and one admin cert for the dashboards. See `make_identities`.


def _ctl(*args: str) -> str:
    """Run `wayfinderctl` from the workspace, returning its stdout.

    Via ``cargo run`` rather than a path into ``target/``, so the caller never
    has to have built it first — the same reason ``make_identities`` can be the
    first thing ``up`` does.
    """
    result = subprocess.run(
        ["cargo", "run", "--quiet", "-p", "wayfinder-ctl", "--", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _ed_pubkey(ctl_output: str) -> str:
    """Pull the ed25519 public key out of `cert keygen`/`cert show` output.

    The dashboards need it to *pin* the node they connect to, and it is
    otherwise only recoverable by re-deriving it from the secret seed.
    """
    for line in ctl_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("ed25519:"):
            return stripped.split(":", 1)[1].strip()
    raise RuntimeError(f"no ed25519 key in wayfinderctl output:\n{ctl_output}")


def make_identities(node_names: list[str]) -> tuple[Path, dict[str, str]]:
    """Mint the whole mesh's cryptographic identity on the host, up front.

    Returns the directory holding it and a map of node name → ed25519 public
    key (hex), which the dashboards use to pin the node they connect to.

    Layout, all under one temp dir:

    * ``seed`` / ``root``     — the mesh root seed and its public trust anchor.
      Only the provider node mounts these.
    * ``nodes/<name>/``       — one node's ``seed``/``cert``/``anchor``. A plain
      *member* certificate: enough to route, deliberately not enough to
      administer, so the sim reflects the real split.
    * ``operator/``           — a single *admin* identity, not tied to any radio.
      This is what the dashboards authenticate with; an enrolled node refuses a
      management connection that cannot present one.

    Pre-issuing rather than enrolling at runtime is what makes each node's MAC
    reproducible: the node derives its MAC from this seed, and ``cert issue``
    defaults to that same derivation, so a certificate minted before the
    container exists still binds the MAC the node comes up with.

    The directory is intentionally *not* auto-deleted: it is mounted into the
    sim containers for the lifetime of the compose project.
    """
    ca_dir = Path(tempfile.mkdtemp(prefix="wayfinder-ca-"))
    root_seed = ca_dir / "seed"
    anchor = ca_dir / "root"

    _ctl(
        "cert", "init-ca",
        "--mesh-id", str(MESH_ID),
        "--generate",
        "--out-seed", str(root_seed),
        "--out-anchor", str(anchor),
    )  # fmt: skip

    def issue_into(dest: Path, admin: bool) -> str:
        """Mint one identity into `dest`, returning its ed25519 public key."""
        dest.mkdir(parents=True, exist_ok=True)
        pubkey = _ed_pubkey(_ctl("cert", "keygen", "--out-seed", str(dest / "seed")))
        _ctl(
            "cert", "issue",
            "--ca-seed", str(root_seed),
            "--mesh-id", str(MESH_ID),
            "--node-seed", str(dest / "seed"),
            # A window wide enough that a long-running sim never expires out
            # from under itself; a real deployment keeps this short, because
            # expiry is the primary revocation mechanism.
            "--not-before", "0",
            "--not-after", str(CERT_NOT_AFTER),
            "--out-cert", str(dest / "cert"),
            *(["--admin"] if admin else []),
        )  # fmt: skip
        # Every identity verifies against the same anchor, so each directory is
        # self-contained and can be mounted alone.
        (dest / "anchor").write_bytes(anchor.read_bytes())
        return pubkey

    node_keys = {
        name: issue_into(ca_dir / "nodes" / name, admin=False) for name in node_names
    }
    # One admin identity shared by every dashboard. Separate from the node certs
    # on purpose: making each node its own administrator would hand the admin
    # capability to every router in the mesh, which is exactly what the signed
    # admin bit exists to prevent.
    issue_into(ca_dir / "operator", admin=True)

    print(f"minted mesh identities in {ca_dir}", file=sys.stderr)
    return ca_dir, node_keys


# ── the topology (edit me) ────────────────────────────────────────────────────


def build_links() -> list[list[str]]:
    """The mesh wiring.  Returns a flat list of links (each a list of members).

    Default: a 4-node **diamond** (``d1..d4``) bolted onto a 5-node **complete
    graph** mesh (``m1..m5``, K5), joined by a single link between the diamond's
    far vertex ``d4`` and the mesh node ``m1``.  End-to-end traffic from the
    diamond to the deep mesh (e.g. ``d1 → m5``) must cross the diamond, hop the
    bridge, then route through the dense mesh — a good stress test for OGM
    convergence and multi-path forwarding.
    """
    return [
        # *diamond("d"),  # d1..d4: two 2-hop paths d1⇒d4
        # *complete_graph("m", 5),  # m1..m5: fully meshed (10 links)
        ["d4", "m1"],  # the bridge joining the diamond to the mesh
    ]


# ── compose generation ────────────────────────────────────────────────────────


def node_order(links: list[list[str]]) -> list[str]:
    """Unique node names in first-appearance order (drives stable IP assignment)."""
    seen: dict[str, None] = {}
    for link in links:
        for node in link:
            seen.setdefault(node, None)
    return list(seen)


def link_name(members: list[str]) -> str:
    """A deterministic docker-network name for a link from its members."""
    return "link_" + "_".join(sorted(members))


def dedup_links(links: list[list[str]]) -> list[list[str]]:
    """Drop duplicate links (same member set), preserving first-seen order."""
    out: list[list[str]] = []
    seen: set[frozenset[str]] = set()
    for link in links:
        key = frozenset(link)
        if len(key) < 2:
            raise ValueError(f"link {link!r} must connect at least two distinct nodes")
        if key not in seen:
            seen.add(key)
            out.append(link)
    return out


def build_nodes(links: list[list[str]]) -> dict[str, dict]:
    """Per-node settings: IP, log level, and any per-node environment.

    Edit here to give a node a different RUST_LOG, or to set the per-link OGM
    backoff bounds the sim image honours: ``OGM_I_MIN_MS`` / ``OGM_I_MAX_MS``
    (added to every RawL2 link's ``ogm:`` block by the entrypoint).  For example
    a slow-radio node could carry ``{"OGM_I_MIN_MS": "2000", "OGM_I_MAX_MS": "120000"}``.
    """
    nodes: dict[str, dict] = {}
    for idx, name in enumerate(node_order(links), start=1):
        nodes[name] = {
            "ip": f"10.0.0.{idx}",
            "rust_log": DEFAULT_RUST_LOG,
            "env": {},  # extra env vars, e.g. OGM_I_MIN_MS / OGM_I_MAX_MS
        }
    return nodes


def render_compose(require_approval: bool = False) -> str:
    """Render the full docker-compose YAML for the current topology.

    When ``require_approval`` is set, the provider parks incoming CSRs as
    pending until an operator approves them (``wayfinderctl csr approve`` / the
    Security tab) instead of auto-signing on submission. Nothing in this sim
    enrols at runtime — every node is minted a certificate up front — so this
    only affects a CSR you submit yourself, by hand.
    """
    links = dedup_links(build_links())
    nodes = build_nodes(links)
    ca_dir, node_keys = make_identities(list(nodes))
    # node -> the networks it is attached to, in deterministic order.
    attached: dict[str, list[str]] = {name: [] for name in nodes}
    for members in links:
        net = link_name(members)
        for member in members:
            attached[member].append(net)

    lines: list[str] = []
    e = lines.append

    e("# GENERATED by scripts/topology.py — do not edit by hand; edit the script.")
    e("#")
    e(f"# {len(nodes)} nodes, {len(links)} L2 segments.")
    e("#")
    e("# Each docker network is an isolated L2 bridge segment carrying RawL2 mesh")
    e("# frames; the sim image emits one mesh link per attached NIC, so this wiring")
    e("# *is* the topology.  Bring it up with:  python scripts/topology.py up")
    e("")
    # The first node is the certificate-authority *provider*: it alone mounts
    # the mesh root seed, so the root key lives on exactly one node. Every other
    # node is a plain member holding a certificate this CA already signed.
    node_names = list(nodes.keys())
    provider_name = node_names[0]

    e("# Shared service definition, merged into each node via a YAML anchor.")
    e("x-node: &node")
    e("  build:")
    e("    context: .")
    e("    dockerfile: containers/sim.Dockerfile")
    e("  image: wayfinder-sim:latest")
    e("  volumes:")
    # Mount the repo so the container can run *host-built* binaries from
    # ./target instead of the ones baked into the image: rebuild on the host
    # (`cargo build`) then `./scripts/topology.py restart` — no image rebuild. The
    # entrypoint prefers these and falls back to the baked-in binaries.
    e(f"    - {REPO_ROOT!s}:/workspace:ro")
    # On a Nix host the host-built binary's ELF interpreter (and glibc) live in
    # /nix/store; mount it read-only so a plain `cargo build` artifact is
    # runnable in the Debian-based container without a musl/static rebuild.
    if Path("/nix/store").is_dir():
        e("    - /nix/store:/nix/store:ro")
    e("  cap_add:")
    e("    - NET_ADMIN # create the kernel TAP device")
    e("    - NET_RAW # AF_PACKET raw L2 sockets")
    e("  devices:")
    e("    - /dev/net/tun")
    e("  tty: true")
    e("  stdin_open: true")
    e("  restart: unless-stopped")
    e("")
    e("services:")
    for idx, (name, cfg) in enumerate(nodes.items()):
        mgmt_ip = f"10.99.0.{idx + 2}"
        is_provider = name == provider_name
        e(f"  {name}:")
        e("    !!merge <<: *node")
        e(f"    container_name: wf-{name}")
        e(f"    hostname: {name}")
        # Every node mounts its own pre-issued identity; only the provider also
        # mounts the mesh root seed, so the key that can mint certificates lives
        # on exactly one node.
        e("    volumes:")
        e(f"      - {ca_dir / 'nodes' / name!s}:/secrets:ro")
        e(f"      - {REPO_ROOT!s}:/workspace:ro")
        # On a Nix host the host-built binary's ELF interpreter (and glibc) live in
        # /nix/store; mount it read-only so a plain `cargo build` artifact is
        # runnable in the Debian-based container without a musl/static rebuild.
        if Path("/nix/store").is_dir():
            e("      - /nix/store:/nix/store:ro")
        if is_provider:
            e(f"      - {ca_dir!s}:/ca:ro")
        e("    environment:")
        e(f"      NODE_IP: {cfg['ip']}")
        e(f"      RUST_LOG: {cfg['rust_log']}")
        e(f"      MESH_ID: {MESH_ID}")
        if is_provider:
            e('      PROVIDER: "1"')
            # Gate hand-submitted CSRs on operator approval instead of
            # auto-signing. Nothing enrols on its own here — every node is
            # already certified — so this only affects a CSR you submit
            # yourself.
            e(f'      REQUIRE_APPROVAL: "{str(require_approval).lower()}"')
        for key, value in cfg["env"].items():
            e(f"      {key}: {value}")
        # Mesh links (map form so we can pin a static IP on the mgmt net), plus
        # the out-of-band management network with a deterministic address.
        e("    networks:")
        for net in attached[name]:
            e(f"      {net}: {{}}")
        e("      wf_mgmt:")
        e(f"        ipv4_address: {mgmt_ip}")

        # One dashboard per node, on the management network only — it is a
        # management client, not a mesh participant, so it gets no mesh segment
        # and no TAP.
        #
        # It authenticates with the shared *operator* identity: an enrolled node
        # refuses any management connection that cannot present an admin
        # certificate, and these nodes are enrolled from their first instant.
        # `--node-key` pins the node being connected to, which is that node's
        # own ed25519 key — it cannot be defaulted here the way it can when a
        # client bootstraps with a node's own seed.
        e(f"  {name}-web:")
        e("    image: wayfinder-sim:latest")
        # Same image as the nodes purely to avoid a second build; its entrypoint
        # is the node's, so it is replaced wholesale here.
        e('    entrypoint: ["/bin/sh", "-c"]')
        e("    command:")
        e("      - |")
        e("        test -s /workspace/target/site/pkg/wayfinder-web.wasm || {")
        e(
            "          echo \"dashboard assets missing: run 'cargo leptos build' on the host\" >&2"
        )
        e(
            "          echo \"(a plain 'cargo build' makes a stub binary and no wasm).\" >&2"
        )
        e("          exit 1")
        e("        }")
        e("        exec wayfinder-web \\")
        e("          --listen 0.0.0.0:8080 \\")
        e(f"          --addr {mgmt_ip}:7700 \\")
        e("          --identity /operator/seed \\")
        e("          --cert /operator/cert \\")
        e(f"          --node-key {node_keys[name]}")
        e("    volumes:")
        e(f"      - {ca_dir / 'operator'!s}:/operator:ro")
        e(f"      - {REPO_ROOT!s}:/workspace:ro")
        if Path("/nix/store").is_dir():
            e("      - /nix/store:/nix/store:ro")
        e("    environment:")
        e("      RUST_LOG: info")
        # Outside `cargo leptos`, the binary finds its assets only through
        # these three (see bins/wayfinder-web/CLAUDE.md). Get one wrong and the
        # dashboard serves correct markup that never becomes interactive.
        e('      LEPTOS_OUTPUT_NAME: "wayfinder-web"')
        e('      LEPTOS_SITE_ROOT: "/workspace/target/site"')
        e('      LEPTOS_SITE_PKG_DIR: "pkg"')
        e("    ports:")
        # Loopback only: the dashboard has no authentication of its own, and it
        # can now edit the mesh's security settings.
        e(f'      - "127.0.0.1:{WEB_PORT_BASE + idx}:8080"')
        e("    networks:")
        e("      wf_mgmt: {}")
        e("    depends_on:")
        e(f"      - {name}")
        e("    restart: unless-stopped")
    e("")
    e("networks:")
    for members in links:
        e(f"  {link_name(members)}:")
        e("    driver: bridge")
    # Out-of-band management/enrolment network. A distinct subnet (10.99.0.0/24)
    # the entrypoint uses to tell this NIC apart from the mesh links (which it
    # must *not* turn into a RawL2 mesh segment).
    e("  wf_mgmt:")
    e("    driver: bridge")
    e("    ipam:")
    e("      config:")
    e("        - subnet: 10.99.0.0/24")
    e("")
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────


def compose(*args: str) -> int:
    """Run ``docker compose`` against the ephemeral file + fixed project name."""
    cmd = ["docker", "compose", "--verbose", "-p", PROJECT, "-f", str(EPHEMERAL), *args]
    print("+ " + " ".join(cmd), file=sys.stderr)
    return subprocess.call(cmd)


def nix_fmt(path: Path) -> None:
    """Format the generated file with the repo's `nix fmt` (treefmt → yamlfmt),
    so every generated compose is byte-identical to a hand-formatted one and
    re-running `write` never churns the committed file.  Best-effort: a warning,
    not a failure, when `nix` isn't on PATH (e.g. outside the dev shell)."""
    try:
        subprocess.run(
            ["nix", "fmt", str(path)],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"warning: `nix fmt {path.name}` skipped ({exc})", file=sys.stderr)


def write_compose(path: Path, require_approval: bool = False) -> None:
    path.write_text(render_compose(require_approval))
    nix_fmt(path)
    print(f"wrote {path}", file=sys.stderr)


# Bytes consumed by the IPv4 (20) + ICMP (8) headers in front of the ping
# payload; `ping -s` sizes only the payload, so we subtract these to let the user
# think in whole IP-packet sizes.
IP_ICMP_OVERHEAD = 28


def cmd_blast(
    node: str | None,
    rate: float,
    size: int,
    duration: float,
    iface: str,
    broadcast: str,
) -> int:
    """Flood broadcast frames from one node into the mesh to stress the flood path.

    Runs ``ping`` inside the chosen node's container, aimed at the subnet
    broadcast address (default ``10.0.0.255``). Every echo request goes to the
    all-ones MAC, so the router floods it out *every* mesh interface exactly like
    a host's ARP/DHCP would — only as fast and as large as asked. ``-I <iface>``
    pins egress to the host TAP (``wayfinder0``), so the traffic never leaks onto
    the ``eth*`` mesh-segment NICs directly.

    ``rate`` is frames/second (``0`` floods as fast as the kernel allows, via
    ``ping -f``); ``size`` is the total IP packet size in bytes; ``duration`` is
    how long to run (``0`` runs until interrupted with Ctrl-C).
    """
    if not EPHEMERAL.exists():
        print(
            "warning: no ephemeral compose file — is the stack up? "
            "run `python scripts/topology.py up` first",
            file=sys.stderr,
        )

    nodes = node_order(dedup_links(build_links()))
    if node is None:
        node = nodes[0]
    elif node not in nodes:
        print(
            f"error: {node!r} is not a node in the topology ({', '.join(nodes)})",
            file=sys.stderr,
        )
        return 1

    # `ping -s` sizes the payload only; let the user pass a whole-IP-packet size.
    payload = max(size - IP_ICMP_OVERHEAD, 0)
    cmd = ["exec", node, "ping", "-b", "-I", iface]
    if rate > 0:
        # Sub-second intervals require root; the sim containers run as root.
        cmd += ["-i", f"{1.0 / rate:.6f}"]
    else:
        cmd += ["-f"]  # flood: send as fast as the kernel will accept
    if duration > 0:
        cmd += ["-w", str(max(1, round(duration)))]
    cmd += ["-s", str(payload), broadcast]
    return compose(*cmd)


def web_urls() -> list[tuple[str, str]]:
    """Each node paired with the URL its dashboard is published on.

    Derived from the same ordering that assigns node IPs and host ports, so it
    is a description of the generated compose rather than a second source of
    truth that could drift from it.
    """
    nodes = node_order(dedup_links(build_links()))
    return [
        (name, f"http://127.0.0.1:{WEB_PORT_BASE + idx}")
        for idx, name in enumerate(nodes)
    ]


def print_web_urls() -> None:
    """Print the node → dashboard URL table.

    Printed after `up` because the alternative is counting ports by hand off
    the compose file, which is exactly the sort of thing that makes people stop
    using the dashboards.
    """
    print("\ndashboards:", file=sys.stderr)
    for name, url in web_urls():
        print(f"  {name:<6} {url}", file=sys.stderr)


def cmd_graph() -> None:
    links = dedup_links(build_links())
    adj: dict[str, set[str]] = {n: set() for n in node_order(links)}
    for members in links:
        for a in members:
            for b in members:
                if a != b:
                    adj[a].add(b)
    print(f"{len(adj)} nodes, {len(links)} segments")
    urls = dict(web_urls())
    for node, neighbors in adj.items():
        print(f"  {node}: {', '.join(sorted(neighbors))}")
        print(f"    dashboard: {urls[node]}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Shared flag: gate enrolment on operator approval rather than auto-signing.
    def add_require_approval(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--require-approval",
            action="store_true",
            help="provider parks CSRs as pending until an operator approves them "
            "(`wayfinderctl csr approve` / TUI Security tab) instead of auto-signing",
        )

    p = sub.add_parser("print", help="print the generated compose YAML to stdout")
    add_require_approval(p)
    sub.add_parser("graph", help="print an ASCII adjacency summary of the topology")
    w = sub.add_parser("write", help="write the compose YAML to a path")
    w.add_argument("path", nargs="?", default=str(REPO_ROOT / "docker-compose-sim.yml"))
    add_require_approval(w)
    up = sub.add_parser(
        "up", help="generate the ephemeral file and `docker compose up --build -d`"
    )
    up.add_argument("extra", nargs="*", help="extra args passed to `docker compose up`")
    add_require_approval(up)
    sub.add_parser(
        "down", help="`docker compose down` the ephemeral stack (removes networks)"
    )
    rs = sub.add_parser(
        "restart",
        help="re-run the entrypoint on the running nodes (`docker compose restart`) "
        "— picks up a host rebuild of the mounted binaries without rebuilding the image",
    )
    rs.add_argument("nodes", nargs="*", help="nodes to restart (default: all)")
    lg = sub.add_parser(
        "logs", help="follow `docker compose logs -f` (optionally for given nodes)"
    )
    lg.add_argument("nodes", nargs="*")
    bl = sub.add_parser(
        "blast",
        help="flood broadcast traffic from a node into the mesh (stress the flood path)",
    )
    bl.add_argument(
        "node",
        nargs="?",
        help="origin node (default: the first node in the topology)",
    )
    bl.add_argument(
        "--rate",
        type=float,
        default=100.0,
        help="frames per second; 0 floods as fast as possible (default: 100)",
    )
    bl.add_argument(
        "--size",
        type=int,
        default=1000,
        help="total IP packet size in bytes (default: 1000)",
    )
    bl.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="seconds to blast; 0 runs until interrupted (default: 10)",
    )
    bl.add_argument(
        "--iface",
        default="wayfinder0",
        help="host interface to send from — egress is pinned here (default: wayfinder0)",
    )
    bl.add_argument(
        "--broadcast",
        default="10.0.0.255",
        help="broadcast destination IP (default: 10.0.0.255)",
    )

    args = parser.parse_args(argv)

    if args.cmd == "print":
        print(render_compose(args.require_approval), end="")
        return 0
    if args.cmd == "graph":
        cmd_graph()
        return 0
    if args.cmd == "write":
        write_compose(Path(args.path), args.require_approval)
        return 0
    if args.cmd == "up":
        write_compose(EPHEMERAL, args.require_approval)
        rc = compose("up", "--build", "-d", *args.extra)
        if rc == 0:
            print_web_urls()
        return rc
    if args.cmd == "down":
        if not EPHEMERAL.exists():
            write_compose(EPHEMERAL)
        return compose("down")
    if args.cmd == "restart":
        if not EPHEMERAL.exists():
            write_compose(EPHEMERAL)
        return compose("restart", *args.nodes)
    if args.cmd == "logs":
        return compose("logs", "-f", *args.nodes)
    if args.cmd == "blast":
        return cmd_blast(
            args.node,
            args.rate,
            args.size,
            args.duration,
            args.iface,
            args.broadcast,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
