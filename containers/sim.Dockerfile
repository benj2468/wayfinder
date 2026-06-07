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

# Pin the builder to the SAME Debian release as the runtime stage (bookworm).
# The unsuffixed `rust:1.96-slim` tracks the latest Debian (trixie, glibc
# 2.39+); linking against that and running on bookworm-slim (glibc 2.36) fails
# at startup with "GLIBC_2.39 not found".
FROM rust:1.96-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.lock /app/Cargo.lock
COPY Cargo.toml /app/Cargo.toml
COPY libs /app/libs
COPY bins /app/bins
COPY src /app/src

WORKDIR /app
ENV PROTOC=/usr/bin/protoc

RUN cargo build --release -p wayfinder-tap -p wayfinder-tui

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
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/wayfinder-tap /usr/local/bin/wayfinder-tap
COPY --from=builder /app/target/release/wayfinder-tui /usr/local/bin/wayfinder-tui

# Entrypoint: render the node config from env + discovered NICs, then exec the
# node. Generated inline (heredoc) so nothing needs to be COPY'd from the
# .dockerignore-excluded containers/ directory.
#
# The RawL2 EtherType is a free-choice wire transport label, decoupled from the
# mesh protocol the router demuxes on (carried inside the frame). 0xfafa here
# exercises that decoupling — a non-default value still routes correctly.
RUN cat > /usr/local/bin/entrypoint.sh <<'EOF' && chmod +x /usr/local/bin/entrypoint.sh
#!/bin/sh
set -eu

NODE_IP="${NODE_IP:-10.0.0.1}"
NETMASK="${NETMASK:-255.255.255.0}"
ETHERTYPE="${ETHERTYPE:-0xfafa}"
SERVER_ADDR="${SERVER_ADDR:-0.0.0.0:7700}"
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
for ifc in $(ls /sys/class/net | grep '^eth' | sort); do
  cat >> "$CFG" <<YAML
  - type: RawL2
    interface: ${ifc}
    ethertype: ${ETHERTYPE}
YAML
done

echo "wayfinder-sim: generated $CFG" >&2
cat "$CFG" >&2

exec wayfinder-tap --config "$CFG"
EOF

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
