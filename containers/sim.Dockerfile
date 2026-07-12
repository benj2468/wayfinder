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

mkdir -p /etc/wayfinder /etc/wayfinder/secrets

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
  type: Tcp
  addr: ${SERVER_ADDR}
# Fail closed: both provider and member nodes stay inert on the mesh (no
# routing, no OGM emission) until they install a valid membership cert via
# \`set-auth\` below — an unauthenticated node must never act as a router.
require_auth: true
lazy_cert_distribution: true
YAML

# Provider (certificate-authority) node: it alone holds the mesh root seed
# (mounted at /ca) and serves enrolment over the management API.
if [ -n "${PROVIDER:-}" ]; then
  cat >> "$CFG" <<YAML
provider:
  root_seed_path: /ca/seed
  mesh_id: ${MESH_ID}
  cert_ttl_secs: 100000000000
  require_approval: ${REQUIRE_APPROVAL:-false}
YAML
fi

cat >> "$CFG" <<YAML
links:
YAML

# One RawL2 mesh link per docker-attached ethernet NIC, EXCEPT the management
# NIC (identified by its subnet) which carries the enrolment control plane.
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

# Start the node in the background and give it a moment to bring up the TAP.
wayfinder-tap --config "$CFG" &
WAYFINDER_PID=$!
trap 'kill ${WAYFINDER_PID}; wait ${WAYFINDER_PID}' TERM
sleep 5
WAYFINDER_MAC=$(ip link show dev wayfinder0 | awk '/link\/ether/ {print $2}')

if [ -n "${PROVIDER:-}" ]; then
  # The provider self-issues its own member cert from the mounted root seed
  # (it is both the CA and a mesh member).
  echo "wayfinder-sim: provider node — self-issuing cert" >&2
  wayfinder-ctl cert keygen --out-seed /etc/wayfinder/secrets/seed
  wayfinder-ctl cert issue \
      --ca-seed /ca/seed \
      --mesh-id "${MESH_ID}" \
      --mac "${WAYFINDER_MAC}" \
      --node-seed /etc/wayfinder/secrets/seed \
      --not-before 0 \
      --not-after 100000000000000 \
      --out-cert /etc/wayfinder/secrets/cert
  cp /ca/root /etc/wayfinder/secrets/anchor
else
  # A member enrolls online against the provider — no root seed on this node.
  # Retry: the provider's management API may not be up yet.
  echo "wayfinder-sim: enrolling against provider ${PROVIDER_ADDR}" >&2
  # `enroll` generates the identity seed once and, since it is written to
  # --out-seed immediately, reuses it on every retry below — so a retry
  # resubmits the SAME key for this MAC rather than a new one (which a
  # require-approval provider would otherwise reject as a duplicate MAC under a
  # different key).
  i=0
  until wayfinder-ctl enroll \
      --connect "${PROVIDER_ADDR}" \
      --mac "${WAYFINDER_MAC}" \
      --out-seed /etc/wayfinder/secrets/seed \
      --out-cert /etc/wayfinder/secrets/cert \
      --out-anchor /etc/wayfinder/secrets/anchor; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
      echo "wayfinder-sim: enrolment failed after retries" >&2
      exit 1
    fi
    sleep 2
  done
fi

# Push the bundle into the running node over its local management API.
wayfinder-ctl set-auth \
    /etc/wayfinder/secrets/seed \
    /etc/wayfinder/secrets/cert \
    /etc/wayfinder/secrets/anchor

# Hand the foreground back to the node so the container lives as long as it does.
wait "${WAYFINDER_PID}"

EOF

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
