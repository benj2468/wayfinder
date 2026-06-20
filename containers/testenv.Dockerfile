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

# Install cargo-nextest and cargo-llvm-cov binaries using pre-compiled installers
# (Much faster than running `cargo install` inside the Dockerfile)
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

RUN cargo binstall -y cargo-nextest
RUN cargo binstall -y cargo-llvm-cov
RUN cargo binstall -y sccache

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

# pytest from pip (not the python3-pytest apt package). Installed system-wide so
# it is on PATH for the unprivileged `ci` user; --break-system-packages is
# required because Debian marks the base interpreter externally-managed (PEP 668).
RUN pip3 install --no-cache-dir --break-system-packages pytest

# Unprivileged user for the dissector tests. tshark refuses to load
# `-X lua_script:` dissectors when running as root ("Running as user root ...
# This could be dangerous."), which leaves the wayfinder.* fields unregistered
# and fails the suite. The image's default user stays root (cargo jobs clone and
# build as root); only the pytest job drops to this user via `runuser`.
RUN useradd --create-home --shell /bin/bash ci
