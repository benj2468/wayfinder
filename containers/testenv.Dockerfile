# Choose your required Rust version
FROM rust:1.96-slim

# Install system dependencies (including protoc)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install the LLVM tools preview required for coverage
RUN rustup component add llvm-tools-preview
RUN rustup component add clippy

# Bare-metal target for the embedded (`no_std`) crates (see build:embedded in
# .gitlab-ci.yml) — Tier 2 with prebuilt core/alloc, so no nightly required.
RUN rustup target add thumbv7em-none-eabihf

# Install cargo-nextest and cargo-llvm-cov binaries using pre-compiled installers
# (Much faster than running `cargo install` inside the Dockerfile)
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

RUN cargo binstall -y cargo-nextest
RUN cargo binstall -y cargo-llvm-cov
RUN cargo binstall -y sccache
# Builds/installs the libs/wayfinder-py extension module before the pytest job
# imports it (see test:run:python in .gitlab-ci.yml).
RUN cargo binstall -y maturin

# Ensure protoc is globally accessible (usually /usr/bin/protoc via apt)
ENV PROTOC=/usr/bin/protoc

# Python + tshark for the wayfinder-shark Lua dissector integration tests
# (libs/wayfinder-shark/tests). DEBIAN_FRONTEND=noninteractive keeps the
# wireshark-common debconf prompt (setuid dumpcap for non-root capture) from
# blocking the build; we only read pcaps, so the default (no) is fine.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        tshark \
    && rm -rf /var/lib/apt/lists/*

# `uv` drives the Python side from here on (see root pyproject.toml/uv.lock):
# `uv sync` resolves+installs pytest and every other dev tool, and builds
# `libs/wayfinder-py` (a uv workspace member) from source via maturin.
# Installed system-wide (not into a venv itself) so it's on PATH for the
# unprivileged `ci` user; --break-system-packages is required because Debian
# marks the base interpreter externally-managed (PEP 668).
RUN pip3 install --no-cache-dir --break-system-packages uv

# Unprivileged user for the dissector tests. tshark refuses to load
# `-X lua_script:` dissectors when running as root ("Running as user root ...
# This could be dangerous."), which leaves the wayfinder.* fields unregistered
# and fails the suite. The image's default user stays root (cargo jobs clone and
# build as root); only the pytest job drops to this user via `runuser`.
RUN useradd --create-home --shell /bin/bash ci
