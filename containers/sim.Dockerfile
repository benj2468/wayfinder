# syntax=docker/dockerfile:1
#
# Simulation image for the docker-compose mesh demo.
#
# This image carries no wayfinder binaries: the repo is mounted at /workspace
# (see sim/topology.py) and the host-built binaries under ./target are put on
# PATH (below), so `wayfinder-tap`/`wayfinder-ctl`/`wayfinder-tui` resolve both
# in the entrypoint and via `docker exec`. So it is just a Debian base with a
# shell, iproute2, and tshark + the Lua dissector for poking at the live mesh.
# Build on the host (`cargo build`) before `up`; `topology.py restart` re-execs
# after a rebuild.
#
# The node's config is generated at container start by the embedded entrypoint:
# it discovers every `eth*` NIC docker attached (one per mesh segment) and emits
# a RawL2 link for each, so the topology is driven entirely by which networks a
# service is wired to in docker-compose.yml — no hard-coded interface names.
#
# Identity, by contrast, is *not* generated here. Each node's seed and
# membership certificate are minted on the host by scripts/topology.py before
# the stack comes up and mounted read-only at /secrets, so a node is a mesh
# member from its first instant and its MAC (derived from that seed) is
# reproducible across runs.
#
# That replaced an earlier flow where each node generated a key at startup and
# enrolled against the provider over the management API. Once that API required
# an authenticated TLS handshake, the flow could not work: a node with no
# certificate yet is refused the connection it would have used to request one.
# Pre-issuing sidesteps the bootstrap circularity entirely — at the cost of the
# sim no longer exercising online enrollment, which is worth knowing when
# reading the CSR/approval surfaces it still exposes.

FROM debian:bookworm-slim

# Put the host-built binaries (mounted at /workspace/target, see sim/topology.py)
# on PATH so `wayfinder-tap`/`wayfinder-ctl`/`wayfinder-tui` are runnable by bare
# name everywhere — the entrypoint and an interactive `docker exec`. Debug first
# (the default `cargo build` profile), then release.
ENV PATH="/workspace/target/debug:/workspace/target/release:${PATH}"

# Network tooling for poking around inside the container while debugging the
# mesh: tcpdump (watch RawL2 frames on the wire), net-tools (netstat/ifconfig),
# iproute2 (ip/ss), iputils-ping, and procps (ps/top).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tcpdump \
        net-tools \
        iproute2 \
        iputils-ping \
        procps \
        tshark \
        termshark \
    && rm -rf /var/lib/apt/lists/*

# Wayfinder Lua dissector: lets tshark/termshark decode the BATMAN OGM frames
# flowing over the RawL2 segments (EtherType 0x4305). NOT installed here at
# build time — the entrypoint symlinks it in from the /workspace repo mount
# (see sim/topology.py) on every container start, so an edit to
# libs/wayfinder-shark/wayfinder.lua on the host takes effect on the next
# `docker exec`/`topology.py restart` with no image rebuild.

# Entrypoint: render the node config from env + discovered NICs, then exec the
# node. Generated inline (heredoc) so nothing needs to be COPY'd from the
# .dockerignore-excluded containers/ directory.
#
# The RawL2 EtherType labels the wire transport; it is decoupled from the mesh
# protocol the router demuxes on (carried inside the frame). It defaults to
# 0x4305 (ETH_P_BATMAN) so the bundled Wireshark Lua dissector, which hooks the
# `ethertype` table at 0x4305, decodes the OGM frames out of the box.
RUN cat > /usr/local/bin/entrypoint.sh <<'EOF' && chmod +x /usr/local/bin/entrypoint.sh
#!/bin/sh
set -eu

NODE_IP="${NODE_IP:-10.0.0.1}"
NETMASK="${NETMASK:-255.255.255.0}"
ETHERTYPE="${ETHERTYPE:-0x4305}"
SERVER_ADDR="${SERVER_ADDR:-0.0.0.0:7700}"
MESH_ID="${MESH_ID:-1}"
# The NIC on this subnet is the out-of-band management/enrolment network, NOT a
# mesh link, so it is excluded from the RawL2 links generated below.
MGMT_SUBNET_PREFIX="${MGMT_SUBNET_PREFIX:-10.99.}"
CFG=/etc/wayfinder/config.yml

# The wayfinder binaries are the host-built ones from /workspace/target, put on
# PATH by the image (see the Dockerfile `ENV PATH`), so they are invoked by bare
# name here and resolve identically under `docker exec`.

# /var/lib/wayfinder holds what the node *writes*: the persisted runtime
# security settings and, on the provider, the CA state snapshot. The identity
# it reads lives at /secrets, mounted read-only from the host.
mkdir -p /etc/wayfinder /var/lib/wayfinder

# Wayfinder Lua dissector: symlink from the live /workspace repo mount into
# tshark's global Lua plugin directory (queried fresh each start so it stays
# correct across Wireshark versions/arches). A host edit to
# libs/wayfinder-shark/wayfinder.lua takes effect on the next tshark/termshark
# invocation with no image rebuild.
LUA_DIR="$(tshark -G folders | awk -F'\t' '/Global Lua Plugins/ {print $NF}')"
mkdir -p "$LUA_DIR"
ln -sf /workspace/libs/wayfinder-shark/wayfinder.lua "$LUA_DIR/wayfinder.lua"
echo "wayfinder-sim: symlinked wayfinder.lua -> $LUA_DIR" >&2

cat > "$CFG" <<YAML
local_egress:
  type: Tap
  device_name: wayfinder0
  ip_address: ${NODE_IP}
  netmask: ${NETMASK}
server:
  # TLS is the only management transport there is: the plain-TCP listener this
  # sim used to configure was removed when the management API was hardened, and
  # a config naming it no longer parses at all. Clients authenticate with the
  # mesh identity below, carried as an RFC 7250 raw public key in the handshake.
  type: Tls
  addr: ${SERVER_ADDR}
# The identity this node runs under, pre-issued on the host by
# scripts/topology.py and mounted read-only at /secrets. Configured here rather
# than pushed in at runtime because the node's MAC is *derived from this seed*:
# supplying it up front is what lets the host mint a certificate bound to the
# right MAC before the container exists.
auth:
  seed_path: /secrets/seed
  cert_path: /secrets/cert
  trust_anchor_path: /secrets/anchor
# Fail closed: stay inert on the mesh (no routing, no OGM emission) without a
# valid membership cert. With \`auth:\` above that cert is present from the
# first instant, so this is an assertion rather than a waiting state.
require_auth: true
lazy_cert_distribution: true
# Where a security setting changed through the dashboard is recorded, so it
# survives \`topology.py restart\`. Under /var/lib rather than /secrets because
# the node writes it and /secrets is mounted read-only.
runtime_state_path: /var/lib/wayfinder/runtime.json
YAML

# Provider (certificate-authority) node: it alone holds the mesh root seed
# (mounted at /ca) and can issue or revoke certificates over the management
# API. Every node in this sim already starts with a cert minted on the host, so
# nothing enrolls at runtime — provider mode is here so the CA-side surfaces
# (ListCerts, RevokeNode, the CSR queue, the dashboard's enrollment-policy
# editor) have a live authority to act on.
if [ -n "${PROVIDER:-}" ]; then
  cat >> "$CFG" <<YAML
provider:
  root_seed_path: /ca/seed
  mesh_id: ${MESH_ID}
  cert_ttl_secs: 100000000000
  require_approval: ${REQUIRE_APPROVAL:-false}
  state_path: /var/lib/wayfinder/ca-state.json
YAML
fi

cat >> "$CFG" <<YAML
links:
YAML

# One RawL2 mesh link per docker-attached ethernet NIC, EXCEPT the management
# NIC (identified by its subnet) which carries the dashboard's control plane.
#
# Optionally pin this node's adaptive OGM (Trickle) backoff bounds on every link
# via OGM_I_MIN_MS / OGM_I_MAX_MS. When neither is set, the links omit the `ogm:`
# block and the router falls back to its built-in defaults (1s / 128s).
for ifc in $(ls /sys/class/net | grep '^eth' | sort); do
  ip4="$(ip -4 -o addr show dev "$ifc" 2>/dev/null | awk '{print $4}' | head -1)"
  case "$ip4" in
    "${MGMT_SUBNET_PREFIX}"*) continue ;; # management NIC — not a mesh link
  esac
  cat >> "$CFG" <<YAML
  - type: RawL2
    interface: ${ifc}
    ethertype: ${ETHERTYPE}
YAML
  if [ -n "${OGM_I_MIN_MS:-}" ] || [ -n "${OGM_I_MAX_MS:-}" ]; then
    cat >> "$CFG" <<YAML
    ogm:
      i_min_ms: ${OGM_I_MIN_MS:-1000}
      i_max_ms: ${OGM_I_MAX_MS:-128000}
YAML
  fi
done

echo "wayfinder-sim: generated $CFG" >&2
cat "$CFG" >&2

# Hand the foreground straight to the node. There is no post-start enrollment
# dance any more: the identity is in the config, so the node comes up already a
# member. That removed a `sleep 5` race and a 30-attempt retry loop, and it is
# why this container has no reason to outlive the node.
exec wayfinder-tap --config "$CFG"

EOF

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
