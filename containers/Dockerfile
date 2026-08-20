# syntax=docker/dockerfile:1
#
# Production images for the runnable Wayfinder binaries, built as
# multi-platform (linux/amd64 + linux/arm64) images.
#
# A single shared `builder` stage compiles the ENTIRE workspace in release mode
# once per target arch; each final stage copies out just the one binary it ships
# onto a distroless base, so the runtime images stay slim (no Rust toolchain, no
# apt, no shell).
#
# `web` is the exception with two build inputs: its server binary comes from
# `builder` like the rest, but the browser half (wasm + JS glue + CSS) is
# arch-independent and comes from the separate `site` stage below.
#
# The builder stage is pinned to `--platform=$BUILDPLATFORM`, so it always runs
# natively on the build host (the GitLab runners are amd64) no matter which
# TARGETPLATFORM buildx is currently assembling, and cross-compiles to that
# target's Rust triple via the matching cross linker. That's a deliberate
# choice over letting buildx emulate the whole build under QEMU: emulating a
# release compile of the workspace is drastically slower than cross-compiling
# it natively. The final stages need no emulation either, since they contain
# no RUN steps (distroless has no shell to run one in) — just COPY from
# `builder`, from `runtime-libs`, and a multi-arch base image, all resolved
# per-platform by buildx.
#
# That "no RUN in a final stage" rule is not a style preference: CI's
# `deploy` job sets up no binfmt/QEMU handler at all, so a RUN in a
# distroless stage fails twice over — no shell to exec, and for the foreign
# arch, no emulator to exec it under. Anything a runtime image needs beyond its
# binary is *built* in a $BUILDPLATFORM stage and COPYed in; see `runtime-libs`.
#
# Build a single-platform image locally (uses your host's native arch):
#
#   docker buildx build -f containers/Dockerfile --target tap -t wayfinder-tap --load .
#   docker buildx build -f containers/Dockerfile --target tui -t wayfinder-tui --load .
#   docker buildx build -f containers/Dockerfile --target web -t wayfinder-web --load .
#
# Build & push a multi-platform image (what CI does):
#
#   docker buildx build -f containers/Dockerfile --target tap \
#       --platform linux/amd64,linux/arm64 -t wayfinder-tap --push .
#
# (Building with no --target stops at `web`, the last stage.)

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
#
# libdbus-1-dev is needed because libs/blue links `bluer`, which needs libdbus
# at build time (via pkg-config) even though we only cross-*compile* here (no
# code runs). pkg-config itself only ever probes the *build host's* arch by
# default, so building for TARGETARCH=arm64 on an amd64 host needs an arm64
# libdbus, not just the native one — hence enabling the arm64 foreign arch and
# installing the arch-qualified package alongside the native one.
RUN dpkg --add-architecture arm64 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
        pkg-config \
        libdbus-1-dev \
        libdbus-1-dev:arm64 \
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
#
# pkg-config's own cross-compilation guard (the `pkg-config` crate refuses to
# trust the host's .pc files for a foreign target unless told to) is disabled
# per-target via the `_<target-triple>`-suffixed vars: PKG_CONFIG_ALLOW_CROSS
# opts in, and PKG_CONFIG_LIBDIR pins the search to the arm64 pkgconfig dir
# specifically, so the amd64-target build never picks it up and vice versa.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    PKG_CONFIG_ALLOW_CROSS=1 \
    PKG_CONFIG_LIBDIR_aarch64_unknown_linux_gnu=/usr/lib/aarch64-linux-gnu/pkgconfig

# Compile-time, not runtime, and not a duplicate of the `web` stage's ENV of the
# same name: `leptos` reads this through `std::option_env!`, so its value is
# baked into the binary when the *leptos crate itself* is compiled. Left unset,
# leptos assumes the plain `wasm-bindgen` layout and asks the browser for
# `<name>_bg.wasm`, while cargo-leptos emits `<name>.wasm` — the page renders,
# the wasm 404s, and the dashboard silently never hydrates. `cargo leptos` sets
# it for its own builds; nothing else does, so the cross-compile below has to.
#
# It is set stage-wide rather than on the wayfinder-web build alone so `leptos`
# is only ever compiled once, with the value in place: a per-command override
# would leave the `--workspace` build below compiling it *without* the var, and
# whether cargo then rebuilds it hinges on dep-info env tracking.
ENV LEPTOS_OUTPUT_NAME=wayfinder-web

WORKDIR /app

# Copy the pieces cargo needs to resolve and build the workspace. Listing them
# explicitly (rather than `COPY . .`) keeps unrelated files out of the build
# context layer and improves caching.
COPY Cargo.lock Cargo.toml ./
COPY libs ./libs
COPY bins ./bins
COPY assets ./assets

# Build the entire workspace once per target arch. Every binary (and
# everything they depend on) comes out of this single compile. `--workspace` is
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

# bins/wayfinder-web needs its own invocation: its `default` feature set is
# deliberately empty (so a bare `--workspace` build doesn't fail on the
# dependencies the axum server hangs off), which means the workspace build above
# produced a stub `main` that only panics. `--features ssr` is what compiles the
# real server. The browser half it serves is built in the `site` stage below.
RUN cargo build --release -p wayfinder-web --features ssr \
    --target "$(cat /rust_target)" \
    && cp target/"$(cat /rust_target)"/release/wayfinder-web /out/

# ---------------------------------------------------------------------------
# Site stage: build the browser half of the dashboard.
# ---------------------------------------------------------------------------
#
# `cargo-leptos` compiles bins/wayfinder-web a second time, to
# wasm32-unknown-unknown with `--features hydrate`, then runs wasm-bindgen and
# wasm-opt over the result and minifies the stylesheet — emitting the
# `target/site` bundle the server binary serves as static files.
#
# WebAssembly is a single architecture, so unlike `builder` this stage carries no
# TARGETARCH: it runs natively on the build host and its output is byte-identical
# for every image platform. `--frontend-only` skips the server half, which
# `builder` already cross-compiled for the real target.
FROM --platform=$BUILDPLATFORM rust:1.96-slim-bookworm AS site

# protoc for wayfinder-protos' build.rs — the browser deserializes the same
# proto types the server encodes, so the wasm build generates them too. curl is
# only here to fetch cargo-binstall.
#
# No cross toolchain and no libdbus: the hydrate feature graph reaches neither a
# foreign target nor libs/blue.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        curl \
    && rm -rf /var/lib/apt/lists/*
ENV PROTOC=/usr/bin/protoc

RUN rustup target add wasm32-unknown-unknown

# cargo-binstall pulls prebuilt binaries instead of compiling cargo-leptos from
# source, the same trick containers/testenv.Dockerfile uses.
#
# wasm-bindgen-cli is deliberately NOT installed alongside it: cargo-leptos
# reads the `wasm-bindgen` version out of Cargo.lock and fetches exactly that
# CLI (it refuses to run on a mismatch), so leaving it to do so keeps this file
# out of the version-pin triple that bins/wayfinder-web/CLAUDE.md tracks. It
# fetches its own wasm-opt from Binaryen the same way.
RUN curl -L --proto '=https' --tlsv1.2 -sSf \
    https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh \
    | bash \
    && cargo binstall -y cargo-leptos

WORKDIR /app

# `[[workspace.metadata.leptos]]` lives in the ROOT Cargo.toml, and its
# style-file path points into bins/, so cargo-leptos needs the same context the
# builder stage does.
COPY Cargo.lock Cargo.toml ./
COPY libs ./libs
COPY bins ./bins
COPY assets ./assets

RUN cargo leptos build --release --frontend-only

# ---------------------------------------------------------------------------
# Runtime libs stage: the shared libraries a distroless runtime image lacks.
# ---------------------------------------------------------------------------
#
# `libs/blue`'s host backend (`StdBleLink`) reaches BlueZ over D-Bus through
# `bluer`, which links `libdbus-1.so.3` dynamically — and distroless/cc ships
# only libc/libgcc/libstdc++/libssl, so a `tap` image without this stage builds
# fine and then dies at exec with a "libdbus-1.so.3: cannot open shared object
# file" from the dynamic loader, before `main` ever runs.
#
# The libraries cannot simply be apt-installed in the `tap` stage: distroless
# has no shell or apt, and CI enables no QEMU for the foreign arch (see the
# header). So they are *unpacked* here instead — `dpkg-deb -x` only writes
# files, it never executes a target-arch binary, which is what lets one
# $BUILDPLATFORM-native stage produce a rootfs for either TARGETARCH.
#
# Pinned to bookworm to match both the builder and the distroless runtime base
# (debian12 == bookworm), so these .so's link against the libc already in the
# image rather than a newer one.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS runtime-libs

ARG TARGETARCH

RUN dpkg --add-architecture "$TARGETARCH" \
    && apt-get update \
    && mkdir -p /debs /rootfs \
    && cd /debs \
    && apt-get download \
        libdbus-1-3:"$TARGETARCH" \
        libsystemd0:"$TARGETARCH" \
        libcap2:"$TARGETARCH" \
        libgcrypt20:"$TARGETARCH" \
        libgpg-error0:"$TARGETARCH" \
        liblz4-1:"$TARGETARCH" \
        liblzma5:"$TARGETARCH" \
        libzstd1:"$TARGETARCH" \
    && for deb in *.deb; do dpkg-deb -x "$deb" /rootfs || exit 1; done \
    && rm -rf /debs /var/lib/apt/lists/* \
    && for lib in libdbus-1.so.3 libsystemd.so.0 libcap.so.2 libgcrypt.so.20 \
        libgpg-error.so.0 liblz4.so.1 liblzma.so.5 libzstd.so.1; do \
        find /rootfs -name "$lib" | grep -q . || { echo "missing $lib" >&2; exit 1; }; \
    done

# ---------------------------------------------------------------------------
# wayfinder-tap: bridges a TAP device onto the mesh.
# ---------------------------------------------------------------------------
#
# Needs NET_ADMIN (+ /dev/net/tun) to create the kernel TAP device and NET_RAW
# for AF_PACKET RawL2 sockets at runtime — granted by the caller (compose / run
# flags), not baked into the image.
#
# A `Ble` link needs one thing more, and it is a *mount*, not a capability: the
# host's D-Bus system bus socket, bind-mounted at /run/dbus/system_bus_socket.
# BlueZ is not a library the image could carry — it is `bluetoothd` on the host,
# owning the adapter and reachable only as `org.bluez` on that bus. Running a
# dbus-daemon inside the container instead would come up perfectly and serve an
# empty bus that no BlueZ has ever connected to, so every `Session::new()` would
# fail with a NameHasNoOwner for org.bluez. The container also has to share the
# host's network namespace, since HCI sockets are per-netns; docker-compose.yml
# does both.
FROM gcr.io/distroless/cc-debian12 AS tap

COPY --from=builder /out/wayfinder-tap /usr/local/bin/wayfinder-tap

# The libdbus runtime closure `blue`'s BlueZ backend needs, which the distroless
# base does not ship. Copied wholesale from `runtime-libs` (see there for why it
# is assembled in a separate stage rather than installed here, and for what the
# container still needs mounted in at *run* time to reach BlueZ at all).
COPY --from=runtime-libs /rootfs/ /

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

# ---------------------------------------------------------------------------
# wayfinder-web: management-API dashboard in a browser.
# ---------------------------------------------------------------------------
#
# The one image assembled from two build stages: the cross-compiled axum server
# from `builder`, and the arch-independent wasm/JS/CSS bundle from `site`.
#
#   docker run --rm -p 127.0.0.1:8080:8080 \
#       -v /var/lib/wayfinder:/var/lib/wayfinder:ro \
#       <image> --listen 0.0.0.0:8080 --addr <node-host>:7700
#
# `--listen` is passed by the deployment, never by this image: the binary
# defaults to loopback because it has *no authentication of its own*, and only
# the deployment knows whether loopback means the container's own namespace
# (where no published port could reach it) or the host's. Under
# `network_mode: host` an image-level override would bind the dashboard to
# every host interface — which is exactly the mistake this image used to make.
#
# The server is the only party that speaks the management API, so it needs a
# credential — and there are two kinds, chosen by `--provider`:
#
#   * `--provider <ca-host>:7700 --provider-key <hex> --node-key <hex>` runs it
#     in *login mode*: it holds nothing itself, and each viewer signs in for a
#     short-lived session certificate of their own. Nothing to mount.
#   * without it, the *static credential*: an identity seed (and usually a
#     membership cert) mounted in, defaulting to
#     /var/lib/wayfinder/identity.seed, shared by everyone who can reach the
#     port. What an un-enrolled node — which has no user store to sign in to —
#     is reached with.
#
# Reaching an embedded node over its USB management port instead takes `--serial
# /dev/ttyACM0` and a `--device` flag on `docker run` to pass that port through;
# that port has no authentication of its own either way.
FROM gcr.io/distroless/cc-debian12 AS web

COPY --from=builder /out/wayfinder-web /usr/local/bin/wayfinder-web
COPY --from=site /app/target/site /usr/local/share/wayfinder-web/site

# Outside `cargo leptos`, the binary learns where its own assets are only from
# the environment (`get_configuration(None)` reads these and nothing else), so
# the image has to restate what cargo-leptos would otherwise have exported.
# LEPTOS_SITE_ROOT must match the COPY above; LEPTOS_OUTPUT_NAME and
# LEPTOS_SITE_PKG_DIR must match `[[workspace.metadata.leptos]]` in the root
# Cargo.toml, since they name the files inside the bundle.
#
# LEPTOS_OUTPUT_NAME is needed at *build* time as well, for a different reason —
# see the builder stage.
ENV LEPTOS_OUTPUT_NAME=wayfinder-web \
    LEPTOS_SITE_ROOT=/usr/local/share/wayfinder-web/site \
    LEPTOS_SITE_PKG_DIR=pkg \
    LEPTOS_ENV=PROD

# Documents the port the run command above binds inside the container; it
# publishes nothing on its own. Publishing it to anything wider than the host is
# a reverse proxy's job, and a deployment reached through one has to name that
# proxy's host with `--allowed-host` — the dashboard refuses a `Host` it was
# never told about, which is what stops a page on any site pointing a name it
# controls at this address.
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/wayfinder-web"]
