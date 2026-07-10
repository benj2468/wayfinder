# syntax=docker/dockerfile:1
#
# Production images for the two runnable Wayfinder binaries, built as
# multi-platform (linux/amd64 + linux/arm64) images.
#
# A single shared `builder` stage compiles the ENTIRE workspace in release mode
# once per target arch; the two final stages each copy out just the one binary
# they ship onto a distroless base, so the runtime images stay slim (no Rust
# toolchain, no apt, no shell).
#
# The builder stage is pinned to `--platform=$BUILDPLATFORM`, so it always runs
# natively on the build host (the GitLab runners are amd64) no matter which
# TARGETPLATFORM buildx is currently assembling, and cross-compiles to that
# target's Rust triple via the matching cross linker. That's a deliberate
# choice over letting buildx emulate the whole build under QEMU: emulating a
# release compile of the workspace is drastically slower than cross-compiling
# it natively. The final stages need no emulation either, since they contain
# no RUN steps (distroless has no shell to run one in) — just COPY from
# `builder` and a multi-arch base image, both resolved per-platform by buildx.
#
# Build a single-platform image locally (uses your host's native arch):
#
#   docker buildx build -f containers/Dockerfile --target tap -t wayfinder-tap --load .
#   docker buildx build -f containers/Dockerfile --target tui -t wayfinder-tui --load .
#
# Build & push a multi-platform image (what CI does):
#
#   docker buildx build -f containers/Dockerfile --target tap \
#       --platform linux/amd64,linux/arm64 -t wayfinder-tap --push .
#
# (Building with no --target stops at `tui`, the last stage.)

# ---------------------------------------------------------------------------
# Shared build stage: cross-compile the whole workspace for TARGETARCH.
# ---------------------------------------------------------------------------
#
# Pin the builder to the SAME Debian release (bookworm) as the distroless
# runtime base (debian12 == bookworm). The unsuffixed `rust:1.96-slim` tracks
# the latest Debian (newer glibc); linking against that and running on an older
# glibc fails at startup with a "GLIBC_x.yz not found" error.
FROM --platform=$BUILDPLATFORM rust:1.96-slim-bookworm AS builder

# protoc is needed by wayfinder-protos' build.rs (prost-build) to compile the
# management-API .proto files. It's a build-time code generator that runs on
# the build host regardless of target arch, so only the native package is
# needed here.
#
# gcc-aarch64-linux-gnu + libc6-dev-arm64-cross give us a cross linker + glibc
# sysroot for the aarch64 target; the amd64 target links fine with the gcc that
# already ships in the rust:slim base.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/*
ENV PROTOC=/usr/bin/protoc

ARG TARGETARCH

# Map Docker's TARGETARCH (amd64/arm64) to the Rust target triple and install
# it via rustup; point cargo/cc at the aarch64 cross linker for that target
# (unused, and harmless, when TARGETARCH is amd64).
RUN case "$TARGETARCH" in \
        amd64) echo x86_64-unknown-linux-gnu > /rust_target ;; \
        arm64) echo aarch64-unknown-linux-gnu > /rust_target ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac
RUN rustup target add "$(cat /rust_target)"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar

WORKDIR /app

# Copy the pieces cargo needs to resolve and build the workspace. Listing them
# explicitly (rather than `COPY . .`) keeps unrelated files out of the build
# context layer and improves caching.
COPY Cargo.lock Cargo.toml ./
COPY libs ./libs
COPY bins ./bins

# Build the entire workspace once per target arch. Both binaries (and
# everything they depend on) come out of this single compile. `--workspace` is
# required because the repo root is itself a package; a plain `cargo build`
# from here would build only the root crate, not the workspace members.
#
# Binaries land under a target-triple-suffixed directory; copy them to a
# fixed, arch-independent path so the final stages below don't need to know
# the triple.
RUN cargo build --release --workspace --target "$(cat /rust_target)" \
    && mkdir /out \
    && cp target/"$(cat /rust_target)"/release/wayfinder-tap \
        target/"$(cat /rust_target)"/release/wayfinder-tui \
        target/"$(cat /rust_target)"/release/wayfinder-ctl \
        /out/

# ---------------------------------------------------------------------------
# wayfinder-tap: bridges a TAP device onto the mesh.
# ---------------------------------------------------------------------------
#
# Needs NET_ADMIN (+ /dev/net/tun) to create the kernel TAP device and NET_RAW
# for AF_PACKET RawL2 sockets at runtime — granted by the caller (compose / run
# flags), not baked into the image.
FROM gcr.io/distroless/cc-debian12 AS tap

COPY --from=builder /out/wayfinder-tap /usr/local/bin/wayfinder-tap

ENTRYPOINT ["/usr/local/bin/wayfinder-tap"]

# ---------------------------------------------------------------------------
# wayfinder-tui: management-API dashboard.
# ---------------------------------------------------------------------------
#
# A terminal UI: run it with `docker run -it` (or a compose service with
# tty/stdin_open) so it has a real TTY.
FROM gcr.io/distroless/cc-debian12 AS tui

COPY --from=builder /out/wayfinder-tui /usr/local/bin/wayfinder-tui

ENTRYPOINT ["/usr/local/bin/wayfinder-tui"]

# ---------------------------------------------------------------------------
# wayfinder-ctl: management-API command-line client.
# ---------------------------------------------------------------------------
#
# A non-interactive CLI: pass a subcommand, e.g.
# `docker run --rm <image> --connect <addr> node-info`.
FROM gcr.io/distroless/cc-debian12 AS ctl

COPY --from=builder /out/wayfinder-ctl /usr/local/bin/wayfinder-ctl

ENTRYPOINT ["/usr/local/bin/wayfinder-ctl"]
