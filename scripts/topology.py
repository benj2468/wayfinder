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
        (add --open N for N nodes with mesh authentication switched off; see
        "Open nodes" below.  Accepted by every subcommand, since they all
        re-derive the topology)
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

A secured node's dashboard has **no credential of its own**: it is started in
login mode (``--provider``), and whoever opens it signs in with one of the two
accounts this script mints into the provider before the stack comes up —
``admin`` (full management) and ``viewer`` (read-only).  Both use the password
``SIM_PASSWORD`` below and have no second factor, since a simulation has nowhere
to enrol an authenticator.  Signing in obtains a short-lived certificate from
the provider; the dashboard holds it for that browser session and nobody else.

The ``viewer`` account is the only way to see the read-only management tier end
to end — no node in this sim would otherwise hold a viewer certificate.

An *open* node's dashboard is the exception, and is the reason static
credentials still exist at all (§8.3 of
``docs/design/06-management-api-authentication.md``): an un-enrolled node has no
user store, so there is nobody to sign in to, and proving the node's own key is
the only credential there is.

Identity
--------
``make_identities`` mints the mesh root, one plain *member* certificate per
node, and one *admin* operator certificate, all on the host before the stack
starts.  Each node mounts only its own at ``/secrets`` and is a mesh member from
its first instant, which also makes its MAC (derived from that seed)
reproducible across runs.

Nothing enrols at runtime.  An earlier version had each node generate a key and
enroll against the provider over the management API; once that API required an
authenticated TLS handshake, a node with no certificate could no longer open the
connection it would have used to ask for one.  So online enrollment — and the
CSR-approval flow — is *not* exercised by this sim, even though the provider
still serves those RPCs for a CSR submitted by hand.

Open nodes
----------
``--open N`` (or the ``OPEN_NODE_COUNT`` constant) adds ``N`` nodes that run
with mesh authentication switched off entirely — no ``auth:`` block, no
certificate, ``require_auth: false`` — named ``o1..oN`` and each hung off the
first node by its own link.

They are here because "no authentication" is a *state* every security surface
has to render, not merely a gap in the data: an unauthenticated node reports an
empty identity, no per-node rows, and no enrollment policy, and both the
dashboard and the TUI have to make that as legible as a full mesh.  The routing
behaviour is worth watching too — the secured nodes are ``require_auth: true``,
so an open node is heard and dropped rather than routed to.

An open node's dashboard authenticates the *opposite* way to a secured one: the
node is un-enrolled, so it admits only a client proving the node's own key, and
its dashboard is given that seed as a static credential rather than a sign-in.
Its MAC is the one thing that is not reproducible across ``up``, since it has no
identity seed to derive one from — the node generates and persists a MAC on
first boot instead.
"""

from __future__ import annotations

import argparse
import itertools
import subprocess
import sys
import tempfile
from dataclasses import dataclass
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

# The two accounts minted into the provider's user store before the stack comes
# up, so a dashboard has somebody to sign in as. `admin` can drive every control;
# `viewer` can read and change nothing, which is the only way to exercise the
# read-only management tier at all — no node in this sim holds a viewer
# certificate otherwise.
#
# One password for both, printed by `up`: this is a simulation on a private
# docker network, and a credential nobody can find is a credential nobody uses.
# Neither account has a second factor (`--no-totp`), because there is nowhere
# here to enrol an authenticator.
SIM_ADMIN_USER = "admin"
SIM_VIEWER_USER = "viewer"
SIM_PASSWORD = "wayfinder"

# How long a session certificate the sim's accounts obtain stays valid. A week:
# long enough that a sim left running over a weekend does not sign everyone out,
# short enough to stay under the provider's own 90-day cap rather than relying
# on the `allow_unbounded_cert_ttl` escape the node config sets for device
# certificates.
SIM_SESSION_TTL_SECS = 7 * 24 * 60 * 60

# Host port for the first node's dashboard; each subsequent node takes the next
# port up, in the same order `node_order` assigns node IPs. Published on
# loopback only — the dashboard has no login of its own.
WEB_PORT_BASE = 8090

# Host port for the first node's own management API; each subsequent node
# takes the next port up, same ordering as WEB_PORT_BASE. Published on
# loopback so a *host-run* dashboard — `cargo leptos watch`, developing
# wayfinder-web itself rather than just viewing it — can reach a node
# directly, without an image rebuild or restarting the node underneath.
# `up` prints the exact command per node; see `print_dev_watch_commands`.
# Distinct range from the primary docker-compose.yml's bare 7700 (host
# networking there, so it would otherwise collide) and from WEB_PORT_BASE.
MGMT_PORT_BASE = 17700

# How many *open* nodes to add: nodes that run with mesh authentication switched
# off entirely (no `auth:` block, `require_auth: false`), named ``o1``, ``o2``, …
# and hung off the secured topology by `open_nodes` below. Override per run with
# `--open N`.
#
# They exist because "no authentication" is a distinct state of every security
# surface, not merely a missing one: an unauthenticated node reports an empty
# identity, no per-node rows and no enrollment policy, and both the dashboard
# and the TUI have to render *that* as intelligibly as they render a full mesh.
# The mesh behaviour is worth watching too — the secured nodes here are
# `require_auth: true`, so an open node is heard and dropped rather than routed
# to, which is what segregation is supposed to look like from the outside.
OPEN_NODE_COUNT = 0

# Name prefix for the open nodes, kept distinct from any secured prefix so
# `graph`/`logs`/`blast` name them unambiguously.
OPEN_NODE_PREFIX = "o"


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


def open_node_names(count: int = -1) -> list[str]:
    """The names of the open (unauthenticated) nodes, ``o1..oN``.

    Derived from the count rather than from the generated links, so it answers
    "is this node open?" the same way whether or not the node was wired in.
    """
    if count < 0:
        count = OPEN_NODE_COUNT
    return [f"{OPEN_NODE_PREFIX}{i}" for i in range(1, count + 1)]


def open_nodes(attach_to: str, count: int = -1) -> list[list[str]]:
    """Each open node on its own point-to-point link to ``attach_to``.

    A star rather than a chain: every open node is then one hop from the secured
    mesh and independent of the others, so what one of them can and cannot reach
    is a statement about authentication alone and not about a neighbour of its
    own that might also be open.
    """
    return [[attach_to, name] for name in open_node_names(count)]


# ── Certificate helpers ───────────────────────────────────────────────────────
#
# Mint the whole mesh's identity on the host before bringing the compose project
# up: the root key (mounted into the *provider* node only), one member cert per
# node, and one admin cert for the dashboards. See `make_identities`.


def _ctl(*args: str, stdin: str | None = None) -> str:
    """Run `wayfinderctl` from the workspace, returning its stdout.

    Via ``cargo run`` rather than a path into ``target/``, so the caller never
    has to have built it first — the same reason ``make_identities`` can be the
    first thing ``up`` does.

    ``stdin`` feeds a password to ``user add --password-stdin``.  It has to be
    stdin and cannot be an argument: argv is readable by every process on the
    host, and the prompt the command otherwise uses reads ``/dev/tty``, which
    would block here on whatever terminal this script inherited.
    """
    result = subprocess.run(
        ["cargo", "run", "--quiet", "-p", "wayfinder-ctl", "--", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        input=stdin,
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


def make_identities(
    node_names: list[str], open_names: list[str] | None = None
) -> tuple[Path, dict[str, str]]:
    """Mint the whole mesh's cryptographic identity on the host, up front.

    Returns the directory holding it and a map of node name → ed25519 public
    key (hex), which the dashboards use to pin the node they connect to. Both
    kinds of node appear in that map: pinning is about *which* node you reached,
    which an open node has to answer too.

    Layout, all under one temp dir:

    * ``seed`` / ``root``     — the mesh root seed and its public trust anchor.
      Only the provider node mounts these.
    * ``nodes/<name>/``       — one node's ``seed``/``cert``/``anchor``. A plain
      *member* certificate: enough to route, deliberately not enough to
      administer, so the sim reflects the real split.
    * ``open/<name>/``        — an open node's ``seed`` and nothing else. It has
      no mesh identity to certify; the seed exists only so its *management-TLS*
      server has a stable key (see below).
    * ``operator/``           — a single *admin* identity, not tied to any radio.
      Not used by the dashboards any more (they sign in instead), but it is what
      a ``wayfinderctl`` run from the host presents when it drives a node
      directly, and an enrolled node refuses a management connection that cannot
      present one.
    * ``provider-state/``     — the provider's durable CA state, pre-seeded with
      the two user accounts a dashboard signs in as, and mounted *writable* into
      the provider (everything else here is read-only).  It has to be seeded
      before the stack comes up: the provider holds this state in memory and
      rewrites the whole snapshot, so an account added to a running provider's
      file is overwritten by the next thing it persists.

    Pre-issuing rather than enrolling at runtime is what makes each node's MAC
    reproducible: the node derives its MAC from this seed, and ``cert issue``
    defaults to that same derivation, so a certificate minted before the
    container exists still binds the MAC the node comes up with.

    An open node's seed is minted here for a different reason. With no ``auth:``
    block the node has no membership seed for its TLS server to reuse, so it
    would generate one on first boot — and nothing on the host could know the
    key to pin, nor the key its dashboard has to *prove* (an un-enrolled node
    admits exactly one client: one holding the node's own key). Minting it here
    and mounting it as ``identity_seed_path`` closes that circle.

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

    def keygen_into(dest: Path) -> str:
        """Mint a bare keypair into `dest`, with no certificate at all."""
        dest.mkdir(parents=True, exist_ok=True)
        return _ed_pubkey(_ctl("cert", "keygen", "--out-seed", str(dest / "seed")))

    node_keys = {
        name: issue_into(ca_dir / "nodes" / name, admin=False) for name in node_names
    }
    for name in open_names or []:
        node_keys[name] = keygen_into(ca_dir / "open" / name)
    # One admin identity for a host-side `wayfinderctl`. Separate from the node
    # certs on purpose: making each node its own administrator would hand the
    # admin capability to every router in the mesh, which is exactly what the
    # signed admin bit exists to prevent.
    issue_into(ca_dir / "operator", admin=True)

    make_accounts(ca_dir)

    print(f"minted mesh identities in {ca_dir}", file=sys.stderr)
    return ca_dir, node_keys


def provider_state_dir(ca_dir: Path) -> Path:
    """Where the provider's durable CA state lives on the host.

    A *directory*, mounted whole, rather than the state file alone: the durable
    store replaces a snapshot by writing a temporary file beside it and renaming
    over the top, which is what makes a torn read impossible — and a bind mount
    of a single file has no "beside it" to write into.
    """
    return ca_dir / "provider-state"


def provider_state_path(ca_dir: Path) -> Path:
    """The provider's CA state file on the host."""
    return provider_state_dir(ca_dir) / "ca-state.json"


def make_accounts(ca_dir: Path) -> None:
    """Seed the provider's user store with the accounts a dashboard signs in as.

    Offline, on the host, before anything starts — the same reason
    ``wayfinderctl user`` is an offline tool at all: the first account cannot be
    created over the management API, because creating it needs the credential it
    creates.  Here there is a second reason on top, which is that the provider
    holds this state in memory and rewrites the whole snapshot, so an edit made
    while it runs does not survive its next write.
    """
    state = provider_state_path(ca_dir)
    state.parent.mkdir(parents=True, exist_ok=True)
    for username, extra in ((SIM_ADMIN_USER, ["--admin"]), (SIM_VIEWER_USER, [])):
        _ctl(
            "user", "add",
            "--state", str(state),
            "--username", username,
            "--session-ttl", str(SIM_SESSION_TTL_SECS),
            # A simulation has nowhere to enrol an authenticator app, which is
            # the case this flag exists for.
            "--no-totp",
            "--password-stdin",
            *extra,
            stdin=f"{SIM_PASSWORD}\n",
        )  # fmt: skip
    print(
        f"minted sim accounts {SIM_ADMIN_USER!r} (admin) and {SIM_VIEWER_USER!r} "
        f"(read-only), password {SIM_PASSWORD!r}",
        file=sys.stderr,
    )


# ── the topology (edit me) ────────────────────────────────────────────────────


def build_links() -> list[list[str]]:
    """The mesh wiring.  Returns a flat list of links (each a list of members).

    Default: a 4-node **diamond** (``d1..d4``) bolted onto a 5-node **complete
    graph** mesh (``m1..m5``, K5), joined by a single link between the diamond's
    far vertex ``d4`` and the mesh node ``m1``.  End-to-end traffic from the
    diamond to the deep mesh (e.g. ``d1 → m5``) must cross the diamond, hop the
    bridge, then route through the dense mesh — a good stress test for OGM
    convergence and multi-path forwarding.

    Any `OPEN_NODE_COUNT` unauthenticated nodes are appended last, so the
    secured topology below stays the thing you edit and the first node — the
    certificate authority — is always a secured one.
    """
    secured = [
        # *diamond("d"),  # d1..d4: two 2-hop paths d1⇒d4
        # *complete_graph("m", 5),  # m1..m5: fully meshed (10 links)
        ["d4", "m1"],  # the bridge joining the diamond to the mesh
    ]
    return secured + open_nodes(node_order(secured)[0])


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


@dataclass
class DevInfo:
    """What one `render_compose` call minted, kept around so `up` can print
    host dev-watch commands afterward without re-minting.

    `ca_dir`/`node_keys` are randomly generated each call (`make_identities`),
    so recomputing them from the topology alone — the way `web_urls` and
    `mgmt_ports` do — would hand back a *different* identity than the one the
    stack actually started with. This is the other half: the part of
    `render_compose`'s output that has to be threaded through instead of
    re-derived.
    """

    ca_dir: Path
    provider_name: str
    node_keys: dict[str, str]
    open_names: list[str]


def render_compose(require_approval: bool = False) -> tuple[str, DevInfo]:
    """Render the full docker-compose YAML for the current topology.

    When ``require_approval`` is set, the provider parks incoming CSRs as
    pending until an operator approves them (``wayfinderctl csr approve`` / the
    Security tab) instead of auto-signing on submission. Nothing in this sim
    enrols at runtime — every node is minted a certificate up front — so this
    only affects a CSR you submit yourself, by hand.

    The flag keeps the operator's imperative ("make me approve"); the node's own
    field says whether approval is automatic, so this renders as
    ``AUTO_APPROVE: "false"``.
    """
    links = dedup_links(build_links())
    nodes = build_nodes(links)
    # Open nodes are those `open_nodes` wired in — intersected with the nodes
    # that actually made it into the topology, so an open node the wiring never
    # attached is not silently given a service definition.
    open_names = [name for name in open_node_names() if name in nodes]
    secured_names = [name for name in nodes if name not in open_names]
    ca_dir, node_keys = make_identities(secured_names, open_names)
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
    e(
        f"# {len(nodes)} nodes ({len(open_names)} of them unauthenticated), "
        f"{len(links)} L2 segments."
    )
    e("#")
    e("# Each docker network is an isolated L2 bridge segment carrying RawL2 mesh")
    e("# frames; the sim image emits one mesh link per attached NIC, so this wiring")
    e("# *is* the topology.  Bring it up with:  python scripts/topology.py up")
    e("")
    # The first *secured* node is the certificate-authority *provider*: it alone
    # mounts the mesh root seed, so the root key lives on exactly one node.
    # Every other secured node is a plain member holding a certificate this CA
    # already signed; the open nodes hold nothing.
    provider_name = secured_names[0]
    # The provider's own management address, so every dashboard knows where to
    # send a sign-in. Derived from the same enumeration that assigns the
    # addresses below rather than recomputed, so the two cannot drift.
    provider_mgmt_ip = f"10.99.0.{list(nodes).index(provider_name) + 2}"

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
        is_open = name in open_names
        # A secured node mounts seed + cert + anchor; an open one mounts a
        # directory holding only a seed, which the entrypoint hands to the
        # management-TLS server rather than to the mesh.
        secrets_dir = ca_dir / ("open" if is_open else "nodes") / name
        e(f"  {name}:")
        e("    !!merge <<: *node")
        e(f"    container_name: wf-{name}")
        e(f"    hostname: {name}")
        # Every node mounts its own pre-issued identity; only the provider also
        # mounts the mesh root seed, so the key that can mint certificates lives
        # on exactly one node.
        e("    volumes:")
        e(f"      - {secrets_dir!s}:/secrets:ro")
        e(f"      - {REPO_ROOT!s}:/workspace:ro")
        # On a Nix host the host-built binary's ELF interpreter (and glibc) live in
        # /nix/store; mount it read-only so a plain `cargo build` artifact is
        # runnable in the Debian-based container without a musl/static rebuild.
        if Path("/nix/store").is_dir():
            e("      - /nix/store:/nix/store:ro")
        if is_provider:
            e(f"      - {ca_dir!s}:/ca:ro")
            # Writable, unlike everything else here: this is the CA's durable
            # state, and it arrives pre-seeded with the user accounts a
            # dashboard signs in as.
            e(f"      - {provider_state_dir(ca_dir)!s}:/ca-state")
        e("    environment:")
        e(f"      NODE_IP: {cfg['ip']}")
        e(f"      RUST_LOG: {cfg['rust_log']}")
        e(f"      MESH_ID: {MESH_ID}")
        if is_open:
            # No `auth:` block, no fail-closed gate: this node routes in the
            # open. Its neighbours here do not, so watch it be heard and
            # dropped — that is what mesh segregation looks like from outside.
            e('      SECURE: "0"')
        if is_provider:
            e('      PROVIDER: "1"')
            e('      CA_STATE_PATH: "/ca-state/ca-state.json"')
            # Gate hand-submitted CSRs on operator approval instead of
            # auto-signing. Nothing enrols on its own here — every node is
            # already certified — so this only affects a CSR you submit
            # yourself. The node's own field says whether approval is
            # automatic, so requiring approval means switching that off.
            e(f'      AUTO_APPROVE: "{str(not require_approval).lower()}"')
        for key, value in cfg["env"].items():
            e(f"      {key}: {value}")
        # This node's own management API, published on loopback (distinct
        # from the `{name}-web` companion's port below) so a *host-run*
        # dashboard can reach it directly — the point being to develop
        # wayfinder-web itself with `cargo leptos watch`'s own fast
        # rebuild/reload, rather than viewing an already-built one through
        # the companion container. `up` prints the exact command for every
        # node; see `print_dev_watch_commands`. Loopback only, same posture
        # as the companion's port.
        e("    ports:")
        e(f'      - "127.0.0.1:{MGMT_PORT_BASE + idx}:7700"')
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
        # How it authenticates depends on what the node it is talking to will
        # accept, and the two cases are opposites:
        #
        # * A secured node is *enrolled*, so the dashboard holds no credential
        #   at all: it runs in login mode, and whoever opens it signs in to the
        #   provider for a session certificate of their own (`admin` or
        #   `viewer`, minted by `make_accounts`).
        # * An open node is *un-enrolled*, so there is no user store to sign in
        #   to and the only credential that grants full management is proof of
        #   the node's own key. So its dashboard presents that node's seed as a
        #   static credential. (A client with no cert is still admitted, but
        #   only to enroll — see `authz::permits` — which is not enough to drive
        #   a dashboard.)
        #
        # `--node-key` pins the node being connected to either way — that node's
        # own ed25519 key, which cannot be defaulted here — and `--provider-key`
        # pins the host a password is about to be sent to.
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
        if is_open:
            e("          --identity /node-identity/seed \\")
        else:
            e(f"          --provider {provider_mgmt_ip}:7700 \\")
            e(f"          --provider-key {node_keys[provider_name]} \\")
        e(f"          --node-key {node_keys[name]}")
        e("    volumes:")
        if is_open:
            e(f"      - {secrets_dir!s}:/node-identity:ro")
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
        # Loopback only. A secured node's dashboard now has a sign-in, but this
        # process terminates no TLS of its own, so a password would cross the
        # network in the clear; an open node's has no sign-in at all.
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
    return "\n".join(lines), DevInfo(
        ca_dir=ca_dir,
        provider_name=provider_name,
        node_keys=node_keys,
        open_names=open_names,
    )


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


def write_compose(path: Path, require_approval: bool = False) -> DevInfo:
    text, dev = render_compose(require_approval)
    path.write_text(text)
    nix_fmt(path)
    print(f"wrote {path}", file=sys.stderr)
    return dev


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
    # Printed with the URLs, not buried in this file: a secured node's dashboard
    # now shows a sign-in page and nothing else, so the accounts are part of
    # knowing how to open it.
    print(
        f"  sign in as {SIM_ADMIN_USER!r} (full management) or {SIM_VIEWER_USER!r} "
        f"(read-only); password {SIM_PASSWORD!r}, no authenticator code.",
        file=sys.stderr,
    )
    print(
        "  an open node's dashboard has no sign-in: it proves the node's own key.",
        file=sys.stderr,
    )


def mgmt_ports() -> dict[str, int]:
    """Each node paired with the host loopback port its own management API is
    published on — what a host-run dashboard's `--addr`/`--provider` connects
    to. Same derivation as `web_urls`, from the topology alone, so it can
    never drift from what `render_compose` actually publishes.
    """
    nodes = node_order(dedup_links(build_links()))
    return {name: MGMT_PORT_BASE + idx for idx, name in enumerate(nodes)}


def print_dev_watch_commands(dev: DevInfo) -> None:
    """Print, for every node, the `cargo leptos watch` invocation that
    develops *wayfinder-web itself* against it live on the host.

    The `{name}-web` companion container each node already gets runs a
    host-*built* binary — fine for viewing the dashboard, but a wayfinder-web
    source change there means `cargo leptos build` plus a container restart.
    Pointing a host-run `cargo leptos watch` at the same node instead gets
    cargo-leptos's own fast wasm/server rebuild-and-reload, and never touches
    the node: only the dashboard process bounces.

    Takes the identities `up` already minted (`dev`) rather than re-deriving
    them the way `mgmt_ports`/`web_urls` do — node keys and an open node's
    seed are random per run, so recomputing them here would print a command
    for a *different* mesh than the one actually running.
    """
    ports = mgmt_ports()
    provider_port = ports[dev.provider_name]
    print(
        "\ndevelop wayfinder-web live against a node (cargo-leptos's own "
        "watcher; the node underneath keeps running, untouched):",
        file=sys.stderr,
    )
    for name, port in ports.items():
        print(
            f"\n  {name}{' (provider)' if name == dev.provider_name else ''}:",
            file=sys.stderr,
        )
        if name in dev.open_names:
            seed_path = dev.ca_dir / "open" / name / "seed"
            print("    cargo leptos watch -- \\", file=sys.stderr)
            print(f"      --addr 127.0.0.1:{port} \\", file=sys.stderr)
            print(f"      --identity {seed_path}", file=sys.stderr)
            print(
                "    open http://127.0.0.1:8080/ — proves the node's own key, no sign-in",
                file=sys.stderr,
            )
        else:
            print("    cargo leptos watch -- \\", file=sys.stderr)
            print(f"      --addr 127.0.0.1:{port} \\", file=sys.stderr)
            print(f"      --provider 127.0.0.1:{provider_port} \\", file=sys.stderr)
            print(
                f"      --provider-key {dev.node_keys[dev.provider_name]} \\",
                file=sys.stderr,
            )
            print(f"      --node-key {dev.node_keys[name]}", file=sys.stderr)
            print(
                f"    open http://127.0.0.1:8080/ and sign in as {SIM_ADMIN_USER!r} or "
                f"{SIM_VIEWER_USER!r} (password {SIM_PASSWORD!r})",
                file=sys.stderr,
            )
    print(
        "\n  only one instance can bind 127.0.0.1:8080 at a time; add --listen to run "
        "another concurrently",
        file=sys.stderr,
    )


def cmd_graph() -> None:
    links = dedup_links(build_links())
    adj: dict[str, set[str]] = {n: set() for n in node_order(links)}
    for members in links:
        for a in members:
            for b in members:
                if a != b:
                    adj[a].add(b)
    open_names = set(open_node_names())
    print(f"{len(adj)} nodes, {len(links)} segments")
    urls = dict(web_urls())
    for node, neighbors in adj.items():
        # Flagged inline rather than listed separately: which of a node's
        # neighbours are open is the thing that explains what it can reach.
        tag = "  [open — no mesh authentication]" if node in open_names else ""
        print(f"  {node}: {', '.join(sorted(neighbors))}{tag}")
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

    # Shared flag: how many unauthenticated nodes to add. Accepted by every
    # subcommand, not just the generating ones, because `graph`/`logs`/`restart`
    # all re-derive the topology and would otherwise describe a different mesh
    # from the one that is running.
    def add_open(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--open",
            type=int,
            default=None,
            metavar="N",
            help="add N nodes running with mesh authentication switched off "
            f"({OPEN_NODE_PREFIX}1..{OPEN_NODE_PREFIX}N), each on its own link to "
            f"the first node (default: {OPEN_NODE_COUNT})",
        )

    p = sub.add_parser("print", help="print the generated compose YAML to stdout")
    add_require_approval(p)
    add_open(p)
    g = sub.add_parser("graph", help="print an ASCII adjacency summary of the topology")
    add_open(g)
    w = sub.add_parser("write", help="write the compose YAML to a path")
    w.add_argument("path", nargs="?", default=str(REPO_ROOT / "docker-compose-sim.yml"))
    add_require_approval(w)
    add_open(w)
    up = sub.add_parser(
        "up", help="generate the ephemeral file and `docker compose up --build -d`"
    )
    up.add_argument("extra", nargs="*", help="extra args passed to `docker compose up`")
    add_require_approval(up)
    add_open(up)
    dn = sub.add_parser(
        "down", help="`docker compose down` the ephemeral stack (removes networks)"
    )
    add_open(dn)
    rs = sub.add_parser(
        "restart",
        help="re-run the entrypoint on the running nodes (`docker compose restart`) "
        "— picks up a host rebuild of the mounted binaries without rebuilding the image",
    )
    rs.add_argument("nodes", nargs="*", help="nodes to restart (default: all)")
    add_open(rs)
    lg = sub.add_parser(
        "logs", help="follow `docker compose logs -f` (optionally for given nodes)"
    )
    lg.add_argument("nodes", nargs="*")
    add_open(lg)
    bl = sub.add_parser(
        "blast",
        help="flood broadcast traffic from a node into the mesh (stress the flood path)",
    )
    add_open(bl)
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

    # `--open` overrides the module-level default for this whole run. Set on the
    # global rather than threaded through every call site because the topology
    # is module state here by design — `build_links`, `web_urls` and `cmd_graph`
    # all read it, and a parameter would have to reach all three in step.
    if getattr(args, "open", None) is not None:
        if args.open < 0:
            parser.error("--open must not be negative")
        global OPEN_NODE_COUNT
        OPEN_NODE_COUNT = args.open

    if args.cmd == "print":
        text, _dev = render_compose(args.require_approval)
        print(text, end="")
        return 0
    if args.cmd == "graph":
        cmd_graph()
        return 0
    if args.cmd == "write":
        write_compose(Path(args.path), args.require_approval)
        return 0
    if args.cmd == "up":
        dev = write_compose(EPHEMERAL, args.require_approval)
        rc = compose("up", "--build", "-d", *args.extra)
        if rc == 0:
            print_web_urls()
            print_dev_watch_commands(dev)
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
