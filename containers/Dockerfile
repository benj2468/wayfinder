# syntax=docker/dockerfile:1
#
# Production images for the two runnable Wayfinder binaries.
#
# A single shared `builder` stage compiles the ENTIRE workspace in release mode
# once; the two final stages each copy out just the one binary they ship onto a
# distroless base, so the runtime images stay slim (no Rust toolchain, no apt,
# no shell). Docker reuses the builder layer across both targets, so the
# workspace is only compiled once per `docker build`.
#
# Build the two images by selecting a target:
#
#   docker build -f containers/Dockerfile --target tap -t wayfinder-tap .
#   docker build -f containers/Dockerfile --target tui -t wayfinder-tui .
#
# (Building with no --target stops at `tui`, the last stage.)

# ---------------------------------------------------------------------------
# Shared build stage: compile the whole workspace.
# ---------------------------------------------------------------------------
#
# Pin the builder to the SAME Debian release (bookworm) as the distroless
# runtime base (debian12 == bookworm). The unsuffixed `rust:1.96-slim` tracks
# the latest Debian (newer glibc); linking against that and running on an older
# glibc fails at startup with a "GLIBC_x.yz not found" error.
FROM rust:1.96-slim-bookworm AS builder

# protoc is needed by wayfinder-protos' build.rs (prost-build) to compile the
# management-API .proto files.
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
ENV PROTOC=/usr/bin/protoc

WORKDIR /app

# Copy the pieces cargo needs to resolve and build the workspace. Listing them
# explicitly (rather than `COPY . .`) keeps unrelated files out of the build
# context layer and improves caching.
COPY Cargo.lock Cargo.toml ./
COPY libs ./libs
COPY bins ./bins

# Build the entire workspace once. Both binaries (and everything they depend on)
# come out of this single compile. `--workspace` is required because the repo
# root is itself a package; a plain `cargo build` from here would build only the
# root crate, not the workspace members.
RUN cargo build --release --workspace

# ---------------------------------------------------------------------------
# wayfinder-tap: bridges a TAP device onto the mesh.
# ---------------------------------------------------------------------------
#
# Needs NET_ADMIN (+ /dev/net/tun) to create the kernel TAP device and NET_RAW
# for AF_PACKET RawL2 sockets at runtime — granted by the caller (compose / run
# flags), not baked into the image.
FROM gcr.io/distroless/cc-debian12 AS tap

COPY --from=builder /app/target/release/wayfinder-tap /usr/local/bin/wayfinder-tap

ENTRYPOINT ["/usr/local/bin/wayfinder-tap"]

# ---------------------------------------------------------------------------
# wayfinder-tui: management-API dashboard.
# ---------------------------------------------------------------------------
#
# A terminal UI: run it with `docker run -it` (or a compose service with
# tty/stdin_open) so it has a real TTY.
FROM gcr.io/distroless/cc-debian12 AS tui

COPY --from=builder /app/target/release/wayfinder-tui /usr/local/bin/wayfinder-tui

ENTRYPOINT ["/usr/local/bin/wayfinder-tui"]

# ---------------------------------------------------------------------------
# wayfinder-ctl: management-API command-line client.
# ---------------------------------------------------------------------------
#
# A non-interactive CLI: pass a subcommand, e.g.
# `docker run --rm <image> --connect <addr> node-info`.
FROM gcr.io/distroless/cc-debian12 AS ctl

COPY --from=builder /app/target/release/wayfinder-ctl /usr/local/bin/wayfinder-ctl

ENTRYPOINT ["/usr/local/bin/wayfinder-ctl"]
