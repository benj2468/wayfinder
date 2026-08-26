# syntax=docker/dockerfile:1
#
# Build environment for producing *Linux* wayfinder binaries on a non-Linux
# host, for `scripts/topology.py`.
#
# The docker sim deliberately ships no binaries in its image: the repo is bind-
# mounted at /workspace and the node containers run the host-built binaries from
# ./target (see containers/sim.Dockerfile). That is a fast dev loop on a Linux
# host and an impossibility on macOS, where `cargo build` emits Mach-O and the
# containers are Linux — the entrypoint fails with "exec format error".
#
# So on macOS the "host build" happens in here instead: this image carries only
# the toolchain, the repo is mounted read-write, and cargo is pointed at
# `target/sim-linux/` so the Linux artifacts sit beside the host's rather than
# fighting them over `target/debug/`. `sim.Dockerfile` puts that directory first
# on the container's PATH, so a node picks these up when they exist and the
# Linux-host flow is untouched when they don't. Incremental rebuilds still work
# — the target directory is on the mount, not in the image — so the loop stays
# `just sim-binaries` then `scripts/topology.py restart`.
#
# Not used on a Linux host, where a plain `cargo build` already produces exactly
# what the containers need. Driven by `just sim-binaries`; see that recipe.
#
# Pinned to the same base as containers/Dockerfile's `builder` stage, for the
# same reason it gives: bookworm's glibc is what the Debian-based sim image
# provides at runtime.
FROM rust:1.96-slim-bookworm

# The same two build-time dependencies the production builder needs, and for
# the same reasons: protoc runs prost-build's codegen for wayfinder-protos, and
# libdbus is what `bluer` (via libs/blue's `std` feature) probes through
# pkg-config. No cross-compilation setup here — this image runs under the
# container runtime's own architecture and builds natively for it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        pkg-config \
        libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*
ENV PROTOC=/usr/bin/protoc

# Compile-time, not runtime: `leptos` reads this through `std::option_env!`, so
# it is baked in when the leptos crate itself compiles. Unset, the dashboard
# asks the browser for `<name>_bg.wasm` while cargo-leptos emits `<name>.wasm`,
# and the page renders but never hydrates. See bins/wayfinder-web/CLAUDE.md.
ENV LEPTOS_OUTPUT_NAME=wayfinder-web

WORKDIR /workspace
