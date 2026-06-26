# syntax=docker/dockerfile:1
#
# Simulation image for the docker-compose mesh demo.
#
# Unlike the production `containers/Dockerfile` (which ships only wayfinder-tap
# on a distroless base), this image bundles BOTH wayfinder-tap and the
# wayfinder-tui dashboard plus a shell and iproute2, so an operator can
# `docker compose exec <node> wayfinder-tui` to inspect the live routing tree.
#
# The node's config is generated at container start by the embedded entrypoint:
# it discovers every `eth*` NIC docker attached (one per mesh segment) and emits
# a RawL2 link for each, so the topology is driven entirely by which networks a
# service is wired to in docker-compose.yml — no hard-coded interface names.

FROM debian:bookworm-slim

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
# flowing over the RawL2 segments (EtherType 0x4305). Installed into tshark's
# global Lua plugin directory — queried at build time so it stays correct
# across Wireshark versions/arches — so every tshark/termshark run loads it.
COPY libs/wayfinder-shark/wayfinder.lua /tmp/wayfinder.lua
RUN dir="$(tshark -G folders | awk -F'\t' '/Global Lua Plugins/ {print $NF}')" \
    && mkdir -p "$dir" \
    && mv /tmp/wayfinder.lua "$dir/wayfinder.lua" \
    && echo "wayfinder-sim: installed wayfinder.lua -> $dir"

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

# Resolve a wayfinder binary: prefer a host-built one from the mounted workspace
# (./target, see sim/topology.py) so a host `cargo build` + `topology.py restart`
# picks up code changes without rebuilding the image; fall back to the binary
# baked into the image. WF_BIN_DIR overrides the search dir (e.g. .../release).
resolve_bin() {
  for d in "${WF_BIN_DIR:-}" /workspace/target/debug /workspace/target/release; do
    if [ -n "$d" ] && [ -x "$d/$1" ]; then
      echo "$d/$1"
      return
    fi
  done
  echo "/usr/local/bin/$1"
}
TAP="$(resolve_bin wayfinder-tap)"
CTL="$(resolve_bin wayfinder-ctl)"
TUI="$(resolve_bin wayfinder-tui)"
echo "wayfinder-sim: using tap=$TAP ctl=$CTL tui=$TUI" >&2

CFG=/etc/wayfinder/config.yml

mkdir -p /etc/wayfinder


cat > "$CFG" <<YAML
local_egress:
  type: Tap
  device_name: wayfinder0
  ip_address: ${NODE_IP}
  netmask: ${NETMASK}
server:
  type: Tcp
  addr: ${SERVER_ADDR}
links:
YAML

# One RawL2 mesh link per docker-attached ethernet NIC. Each NIC is a separate
# mesh segment, so the compose network wiring defines the topology.
#
# Optionally pin this node's adaptive OGM (Trickle) backoff bounds on every link
# via OGM_I_MIN_MS / OGM_I_MAX_MS — handy to model a slow radio that should
# chatter less. When neither is set, the links omit the `ogm:` block and the
# router falls back to its built-in defaults (1s / 64s).
for ifc in $(ls /sys/class/net | grep '^eth' | sort); do
  cat >> "$CFG" <<YAML
  - type: RawL2
    interface: ${ifc}
    ethertype: ${ETHERTYPE}
YAML
  if [ -n "${OGM_I_MIN_MS:-}" ] || [ -n "${OGM_I_MAX_MS:-}" ]; then
    cat >> "$CFG" <<YAML
    ogm:
      i_min_ms: ${OGM_I_MIN_MS:-1000}
      i_max_ms: ${OGM_I_MAX_MS:-64000}
YAML
  fi
done

echo "wayfinder-sim: generated $CFG" >&2
cat "$CFG" >&2

# Start the node in the background, give it a moment to bring up the TAP, then
# enroll it: mint a node key, have the local CA (mounted at /ca) issue a cert
# for this node's MAC, and push the bundle into the running node over its
# management API (SetAuth).
"$TAP" --config "$CFG" &
WAYFINDER_PID=$!

sleep 5

WAYFINDER_MAC=$(ip link show dev wayfinder0 | awk '/link\/ether/ {print $2}')

mkdir -p /etc/wayfinder/secrets

"$CTL" cert keygen --out-seed /etc/wayfinder/secrets/seed
"$CTL" cert issue \
    --ca-seed /ca/seed \
    --mesh-id 1 \
    --mac "${WAYFINDER_MAC}" \
    --node-seed /etc/wayfinder/secrets/seed \
    --not-before 0 \
    --not-after 100000000000000 \
    --out-cert /etc/wayfinder/secrets/cert

# set-auth takes positional <seed> <cert> <trust-anchor> and connects to the
# node's management API (default 127.0.0.1:7700, which the Tcp server serves).
"$CTL" set-auth \
    /etc/wayfinder/secrets/seed \
    /etc/wayfinder/secrets/cert \
    /ca/root

# Hand the foreground back to the node so the container lives as long as it does.
wait "${WAYFINDER_PID}"

EOF

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
