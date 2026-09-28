# Wayfinder task runner.
#
# This repo is deliberately *not* one Cargo workspace, so no single `cargo`
# invocation covers it. Each firmware binary carries its own `[workspace]` (a
# bare-metal target triple, linker script and panic handler must not leak into
# the host build), `libs/wayfinder-py` carries its own (it needs a linkable
# libpython), and `bins/wayfinder-web` is a member whose `default` feature set
# is empty on purpose — so `cargo build --workspace` compiles a stub of it and
# `cargo nextest run --workspace` never sees its tests.
#
# The practical consequence is that "did I break anything?" takes a dozen
# separate commands, each run from the right directory with the right features.
# Every recipe here mirrors the corresponding `.github/workflows/ci.yml` job, so
# a green `just ci` locally covers the same set of checks the pipeline runs
# (plus a couple of things CI doesn't gate on yet, like `buf lint`).
#
# Start with `just` (lists everything), `just ci` (the full gate), or one of the
# per-area aggregates: `just build`, `just clippy`, `just test`.
#
# Recipe summaries in `just --list` come from the `[doc(...)]` attributes:
# `just` otherwise takes only the last line of a comment block, which turns
# every explanation below into a nonsense one-liner.

# Bare-metal target for the Cortex-M4F boards (both nRF52840s and the STM32F411).
# Kept in sync with the `rustup target add` in containers/testenv.Dockerfile and
# `bareMetalTarget` in flake.nix.
bare_metal_target := "thumbv7em-none-eabihf"

# Browser target for `bins/wayfinder-web`'s hydration bundle.
wasm_target := "wasm32-unknown-unknown"

# Toolchain image `sim-binaries` builds the docker sim's Linux binaries in.
sim_builder_image := "wayfinder-sim-builder:latest"

# `nrf-ieee802154` is a root-workspace member that reaches the nRF52840's
# registers through `nrf-pac`, whose interrupt-vector table is placed with
# `#[link_section = ".vector_table.interrupts"]` — an ELF section name Mach-O
# has no way to express (it wants `__SEGMENT,__section`). So the crate cannot
# be compiled for a macOS *host* at all, and any root-workspace command that
# includes it fails there before reaching anything else.
#
# Dropping it on macOS costs its unit tests locally and nothing else: the
# coverage that matters is `build-embedded`, which cross-compiles both nRF
# boards (and so this crate, which they link) for `bare_metal_target` — the
# only target it ever runs on — and works on every host. CI is Linux, so it
# stays fully covered there.
host_workspace_excludes := if os() == "macos" { "--exclude nrf-ieee802154" } else { "" }

[doc("List the available recipes.")]
default:
    @just --list --unsorted

# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------

[doc("Everything CI runs, in CI's order — the full pre-push gate.")]
ci: fmt-check lint build clippy test

[doc("Compile every workspace: host, web, embedded, python.")]
build: build-workspace build-web build-web-release build-embedded build-py

[doc("Lint every workspace with warnings denied.")]
clippy: clippy-workspace clippy-web clippy-embedded clippy-py

[doc("Run every test suite: host, web, python.")]
test: test-workspace test-web test-pytest

# `cargo clean` only ever empties the target directory of the workspace it is
# run from, so reclaiming the disk takes one invocation per workspace — the same
# split the build recipes work around. `bins/wayfinder-web` shares the root
# target directory (it is a member), so it needs no separate clean.
[doc("Remove the target directory of every workspace: host, python, boards, fuzz.")]
clean: clean-workspace clean-py clean-embedded clean-fuzz

# ---------------------------------------------------------------------------
# Root workspace
# ---------------------------------------------------------------------------

[doc("Build the root workspace (no_std core, host crates, tooling).")]
build-workspace:
    cargo build --workspace {{ host_workspace_excludes }}

# Lints every target — libs, bins, tests and examples — so findings in test code
# can't accumulate unnoticed.
[doc("Lint the root workspace, all targets, warnings denied.")]
clippy-workspace:
    cargo clippy --workspace {{ host_workspace_excludes }} --all-targets -- -D warnings

[doc("Run the root workspace's tests.")]
test-workspace:
    cargo nextest run --workspace {{ host_workspace_excludes }} --release
    # The auth suite again on the boards' rolled SHA-512, so a board and the
    # CA are checked against the same known answers (#73).
    cargo nextest run -p wayfinder-auth --features compact-sha512 --release

# ---------------------------------------------------------------------------
# Hardware-in-the-loop (libs/wayfinder-hil)
# ---------------------------------------------------------------------------
#
# Tests that drive a real board over its management API (design 21). They are
# `#[ignore]`d, so `test-workspace` compiles them and runs none — the crate is a
# workspace member precisely so it keeps compiling on machines with no boards,
# which is what stops it rotting between bench sessions.
#
# Never a CI gate on the shared runner: it has no boards, by the same argument
# that keeps the wall-clock benchmarks manual. A self-hosted runner with parts
# attached would take these as a job pinned to that runner's label, triggered
# only by `workflow_dispatch`.
#
# With no `hil.toml` every test skips with a reason and this exits clean, so
# running it on a machine with nothing plugged in is a no-op rather than a
# failure. Copy `example.hil.toml` to get started.
#
# To flash a board, run `cargo run --release` in its own directory
# (`bins/wayfinder-nrf52840`): the configured runner flashes it and attaches RTT.

[doc("Run the hardware tests against the boards in hil.toml.")]
hil *ARGS:
    cargo nextest run -p wayfinder-hil --run-ignored all {{ ARGS }}

[doc("Show the attached probes and how hil.toml resolves against them.")]
hil-list:
    @echo "=== probes ==="
    -probe-rs list
    @echo ""
    @echo "=== serial devices, as the harness sees them ==="
    cargo run -q -p wayfinder-hil --bin hil-devices
    @echo ""
    @echo "=== inventory ==="
    cargo nextest run -p wayfinder-hil --run-ignored all -E 'test(every_inventoried_board_answers)' --no-capture

# `tests/fresh_board.rs` is about a board that has **never held a credential**,
# and since design 22 a credential is durable — so every other hardware test
# destroys that precondition. Running them all in one invocation means that
# binary always skips, whatever order nextest happens to pick, which is how
# design 20's headline regression test spent a bench session reporting green
# without ever executing. Hence a command that blanks the board and runs it
# alone.
#
# Three steps, and the middle one is the load-bearing one:
#
# - `probe-rs erase` wipes the whole chip. A reflash does *not*: `download`
#   erases only the sectors the image covers, and the node record lives in two
#   pages the linker keeps clear of it — precisely so a node keeps its identity
#   across a firmware update.
# - `probe-rs download` rather than `cargo run`, which is otherwise the better
#   way to flash this board: its runner is `probe-rs run`, which attaches RTT
#   and does not return, so it cannot be chained ahead of a test.
# - Single-board bench, so no `--probe` selector — the same assumption
#   `hil-list` makes.
[doc("Erase the DK, reflash it, and run the tests that need a blank board.")]
hil-fresh:
    cd bins/wayfinder-nrf52840 && cargo build --release
    probe-rs erase --chip nRF52840_xxAA
    probe-rs download --chip nRF52840_xxAA \
        bins/wayfinder-nrf52840/target/{{ bare_metal_target }}/release/wayfinder-nrf52840
    cargo nextest run -p wayfinder-hil --run-ignored all -E 'binary(fresh_board)'
# ---------------------------------------------------------------------------
# Benchmarks (libs/wayfinder-bench)
# ---------------------------------------------------------------------------
#
# Two kinds of measurement live in that crate, and they are used differently.
#
# The criterion suites (`bench`) are wall-clock timings. They are for *reading*
# — comparing a baseline you took before a change against one you take after —
# and are deliberately never gated in CI: a shared docker runner's timings vary
# by more than most real regressions, so a threshold there would either fire
# constantly or catch nothing.
#
# The alloc suite (`bench-alloc`) is an allocation *count*, which is identical
# on a loaded runner and a quiet laptop. That one is asserted, and CI runs it
# with the tests. See `libs/wayfinder-bench/benches/alloc.rs` for why the
# allocation-free property is worth a gate of its own.

[doc("Run every benchmark suite (wall-clock timings; several minutes).")]
bench:
    cargo bench -p wayfinder-bench

# Criterion writes each baseline under `target/criterion/<bench>/<name>`, so the
# usual loop is: save one on `main`, make the change, then compare against it.
[doc("Run the benchmarks and save the results as a named baseline.")]
bench-save name:
    cargo bench -p wayfinder-bench -- --save-baseline {{ name }}

[doc("Run the benchmarks and compare against a saved baseline.")]
bench-against name:
    cargo bench -p wayfinder-bench -- --baseline {{ name }}

# `critcmp` renders two saved baselines side by side with the percentage delta,
# which is far easier to scan than criterion's own per-benchmark output.
# Install it with `cargo install critcmp` if it isn't on PATH.
[doc("Compare two saved baselines as a table (needs critcmp).")]
bench-cmp a b:
    critcmp {{ a }} {{ b }}

# Fast (a few seconds) and deterministic, which is why CI can gate on it.
# Behind the `alloc-gate` feature so a plain `just bench` doesn't try to hand
# criterion's arguments to divan's parser; see the feature's note in
# libs/wayfinder-bench/Cargo.toml.
[doc("Assert the packet-planning core allocates nothing per frame.")]
bench-alloc:
    cargo bench -p wayfinder-bench --features alloc-gate --bench alloc

# `--test` runs every benchmark exactly once, asserting nothing about timing.
# It is the cheap check that the fixtures still converge and the benches still
# compile — worth running after touching routing, without paying for a full
# measurement pass.
[doc("Smoke-run every benchmark once, without measuring.")]
bench-smoke:
    cargo bench -p wayfinder-bench -- --test

# The `test-rust` CI job reports this number for the coverage badge.
[doc("Run the root workspace's tests with a coverage summary.")]
coverage:
    cargo llvm-cov nextest --workspace {{ host_workspace_excludes }}

# Also drops the `cargo leptos` site bundle, which lands under the same target
# directory.
[doc("Remove the root workspace's target directory.")]
clean-workspace:
    cargo clean

# ---------------------------------------------------------------------------
# bins/wayfinder-web
# ---------------------------------------------------------------------------
#
# A workspace member that still needs its own invocations: its `default`
# features are empty (so a plain workspace build proves nothing) and its tests
# sit behind `mock-node`. Both halves are built — the wasm one is where a
# misplaced `cfg` hides, since it drops every server-side dependency.

[doc("Build both halves of the web dashboard (axum server + wasm bundle).")]
build-web:
    cargo build -p wayfinder-web --features ssr
    cargo build -p wayfinder-web --features hydrate --target {{ wasm_target }}

[doc("Lint the web dashboard against its canned node.")]
clippy-web:
    cargo clippy -p wayfinder-web --features mock-node --all-targets -- -D warnings

[doc("Test the web dashboard against its canned node.")]
test-web:
    cargo nextest run -p wayfinder-web --features mock-node --release

# `cargo leptos` runs wasm-bindgen and emits the site bundle the binary serves.
[doc("Build the web dashboard the way it actually ships.")]
build-web-release:
    cargo leptos build --release

[doc("Serve the web dashboard with live reload, for local development.")]
watch-web:
    cargo leptos watch

# ---------------------------------------------------------------------------
# Docker mesh simulation
# ---------------------------------------------------------------------------
#
# `scripts/topology.py` runs each node from the host-built binaries under
# `./target`, bind-mounted into a Linux container. On a Linux host a plain
# `cargo build` is therefore all the sim needs and this recipe is unnecessary.
# On macOS it is the whole story: `cargo build` there emits Mach-O, which a
# Linux container cannot exec at all.

# The cargo registry and git checkouts live in named volumes so a rebuild
# re-resolves nothing, and `target/sim-linux` is on the repo mount rather than
# in the image, so builds are incremental across runs exactly like host ones.
# The loop is `just sim-binaries` then `./scripts/topology.py restart`.
[doc("Build the sim's node binaries for Linux, in a container (macOS hosts).")]
sim-binaries:
    #!/usr/bin/env bash
    set -euo pipefail
    docker build -f containers/sim-builder.Dockerfile -t {{ sim_builder_image }} .
    docker run --rm \
        -v "$PWD":/workspace \
        -v wayfinder-sim-cargo-registry:/usr/local/cargo/registry \
        -v wayfinder-sim-cargo-git:/usr/local/cargo/git \
        -e CARGO_TARGET_DIR=/workspace/target/sim-linux \
        {{ sim_builder_image }} \
        bash -c 'cargo build -p wayfinder-tap -p wayfinder-ctl -p wayfinder-tui && \
            cargo leptos build'

[doc("Bring the docker mesh simulation up (see scripts/topology.py).")]
sim-up *ARGS:
    ./scripts/topology.py up {{ ARGS }}

[doc("Tear the docker mesh simulation down.")]
sim-down:
    ./scripts/topology.py down

# ---------------------------------------------------------------------------
# Cloud certificate authority
# ---------------------------------------------------------------------------
#
# The one deployment target that is not a board and not a container: a
# `wayfinder-tap` in provider mode on an Always Free cloud instance. See
# `infra/oracle/README.md` for the runbook and `docs/design/implemented/11-cloud-auth-provider.md`
# for why it looks like this.

[doc("Build the cloud CA's NixOS system (no cloud account needed).")]
build-ca:
    nix build .#nixosConfigurations.wayfinder-ca.config.system.build.toplevel

# A full VM test: CA-mode startup, an empty capability set, and a real
# request/submit/approve/collect/install enrollment cycle between two nodes.
[doc("Run the cloud CA's NixOS VM test.")]
test-ca:
    nix build .#wayfinder-ca-provider

# The full lifecycle — provision, install, secrets, update, verify — lives in
# `scripts/wayfinder-ca.sh`, which reads the instance address out of OpenTofu
# state rather than taking it as an argument. These are thin passthroughs so
# the common verbs are discoverable from `just --list`; run the script directly
# for the rest (`./scripts/wayfinder-ca.sh --help`).

[doc("Create or reconcile the cloud CA's instance (tofu apply).")]
ca-provision:
    ./scripts/wayfinder-ca.sh provision

# Destructive and normally run once: it erases the instance's boot volume.
# Use `ca-update` for an already-installed node.
[doc("Install NixOS onto the provisioned CA instance (DESTRUCTIVE, first time only).")]
ca-install:
    ./scripts/wayfinder-ca.sh install

[doc("Copy the offline-minted trust material onto the CA.")]
ca-secrets:
    ./scripts/wayfinder-ca.sh secrets

[doc("Roll a config or code change out to the running CA (nixos-rebuild switch).")]
ca-update:
    ./scripts/wayfinder-ca.sh update

[doc("Prove the deployed CA answers over the management API.")]
ca-verify:
    ./scripts/wayfinder-ca.sh verify

[doc("Forward the CA's web dashboard to http://127.0.0.1:8080.")]
ca-dashboard:
    ./scripts/wayfinder-ca.sh dashboard

# ---------------------------------------------------------------------------
# wayfndr.dev landing page
# ---------------------------------------------------------------------------
#
# `www/` is a hand-authored static site with no framework and no bundler, so
# "building" it is assembling a directory: the page's own files plus the logo,
# which is pulled in from `assets/logo/` rather than copied into `www/` so the
# mark keeps one source of truth. `scripts/build-site.sh` does that, and
# `wayfinder-ca.sh` calls the same script — a local `just site-deploy` and a CA
# rollout upload byte-identical directories.
#
# `site-deploy` here is the *preview* path. Production goes out with the node,
# from `wayfinder-ca.sh update` (or `wayfinder-ca.sh site` on its own).
#
# The Pages project itself is provisioned in `infra/oracle/site.tf`, and that
# script reads its name out of `terraform.tfvars`. The default is repeated here
# because a `just` recipe has no business parsing tfvars; rename in both places.

[doc("Assemble the wayfndr.dev landing page into dist/site.")]
site-build:
    ./scripts/build-site.sh

[doc("Serve the built landing page at http://127.0.0.1:8899.")]
site-serve: site-build
    @echo "wayfndr.dev preview -> http://127.0.0.1:8899"
    cd dist/site && python3 -m http.server 8899

[doc("Deploy the landing page to Cloudflare Pages (needs CLOUDFLARE_API_TOKEN).")]
site-deploy branch="main": site-build
    npx --yes wrangler@4 pages deploy dist/site \
        --project-name wayfinder-site \
        --branch {{ branch }} \
        --commit-dirty=true

# ---------------------------------------------------------------------------
# libs/wayfinder-py
# ---------------------------------------------------------------------------
#
# Its own `[workspace]` so the linkable-libpython requirement never leaks into
# the main host build. Run from its own directory rather than via `-p`.

[doc("Build the PyO3 extension crate.")]
build-py:
    cd libs/wayfinder-py && cargo build

[doc("Lint the PyO3 extension crate.")]
clippy-py:
    cd libs/wayfinder-py && cargo clippy --all-targets -- -D warnings

[doc("Remove the PyO3 extension crate's target directory.")]
clean-py:
    cd libs/wayfinder-py && cargo clean

# ---------------------------------------------------------------------------
# Embedded firmware
# ---------------------------------------------------------------------------
#
# Each board is an independent workspace, so each is built from its own
# directory. Cross-compiling for real silicon (rather than relying on `no_std`
# type-checking under the host target) is what catches a stray `std`-only
# dependency — e.g. one pulled in by a workspace default feature.

[doc("Build every board, plus the drivers no board links.")]
build-embedded: build-nrf52840 build-nrf52840-dongle build-stm32f411 build-loose-drivers

[doc("Lint every board, plus the drivers no board links.")]
clippy-embedded: clippy-nrf52840 clippy-nrf52840-dongle clippy-stm32f411 clippy-loose-drivers

# Reads the linked ELF, so it depends on the build rather than on clippy (which
# never links). Mirrors CI's `build-stack-budget`; see `scripts/stack-budget.py`
# for what it gates and why it gates task polls rather than frame size at large.
#
# **Every board is checked in `--release`, which is the profile that gets
# flashed.** The nRF boards used to be checked in `debug`, and the two profiles
# disagreed completely: rustc emitted `node::run`'s body as its own symbol in
# `debug`, leaving a 932-byte trampoline for the gate to find, while in
# `release` the body inlined wholesale into the poll and carried 72,908 bytes
# **before the changes on this branch** (it is 26,756 after them; see the
# budget note below).
# So the gate passed for as long as it has existed on an image nobody flashes,
# while the one that ships sat 5x over budget. Checking `debug` also measures the wrong inlining
# decisions generally; `opt-level` is what moves a frame between a transient
# call and a permanent reservation.
[doc("Check every board image fits the stack the linker left it.")]
stack-budget: stack-budget-nrf52840 stack-budget-nrf52840-dongle stack-budget-stm32f411

# 18% rather than the default 8%, and the reason is structural rather than a
# concession. The 8% share models a task poll frame as *overhead* sitting on
# top of the body's own call chain, which holds while the poll is a trampoline.
# Here it is not: `node::run`'s body inlines into its poll end to end -- the
# compiled poll issues no calls at all -- so the poll frame *is* the body, and
# measuring it against a share meant for overhead compares two different
# things.
#
# What the budget has to establish instead is that the whole chain still fits.
# Worst-case nesting, measured off the release image:
#
#     poll frame                      26,756
#     Driver::run_with_mgmt           21,220
#     embassy_futures MaybeDone       14,436
#     wayfinder_auth verify_signature  5,236
#     ------------------------------ -------
#     worst case                      67,648   of a 164,016-byte region
#
# ~42% of the stack, and that sum is pessimistic (`MaybeDone` wraps
# `run_with_mgmt` rather than nesting beneath it). Re-derive it before raising
# this again; do not raise it to turn a pipeline green.
#
# **This number has moved twice and that is the real signal.** It is ten points
# of the region -- about 16 KB -- worth of bring-up locals -- identity, the link array, the USB device
# setup -- that only run once but are reserved for the node's life, because the
# body and the steady-state loop share one coroutine. Splitting bring-up from
# the run loop is the fix; raising this percentage is not, and a third increase
# should be spent on that instead.
[doc("Check the nRF52840-DK image's stack budget.")]
stack-budget-nrf52840: build-nrf52840-release
    cd bins/wayfinder-nrf52840 && python3 ../../scripts/stack-budget.py \
        target/thumbv7em-none-eabihf/release/wayfinder-nrf52840 --memory-x memory.x \
        --task-poll-pct 18

[doc("Check the nRF52840 dongle image's stack budget.")]
stack-budget-nrf52840-dongle: build-nrf52840-dongle-release
    cd bins/wayfinder-nrf52840-dongle && python3 ../../scripts/stack-budget.py \
        target/thumbv7em-none-eabihf/release/wayfinder-nrf52840-dongle --memory-x memory.x \
        --task-poll-pct 18

[doc("Check the NUCLEO-F411RE image's stack budget.")]
stack-budget-stm32f411: build-stm32f411
    cd bins/wayfinder-stm32f411 && python3 ../../scripts/stack-budget.py \
        target/thumbv7em-none-eabihf/release/wayfinder-stm32f411 --memory-x memory.x

# The loose drivers build into the root target directory, so `clean-workspace`
# already covers them.
[doc("Remove every board workspace's target directory.")]
clean-embedded:
    cd bins/wayfinder-nrf52840 && cargo clean
    cd bins/wayfinder-nrf52840-dongle && cargo clean
    cd bins/wayfinder-stm32f411 && cargo clean

[doc("Build the nRF52840-DK (PCA10056) firmware.")]
build-nrf52840:
    cd bins/wayfinder-nrf52840 && cargo build --locked

# The profile that is actually flashed (`cargo run --release`), and so the one
# `stack-budget-nrf52840` reads. `build-nrf52840` stays on `debug` because that
# is what CI's cross-compile check wants -- a fast type-and-link check of the
# bare-metal target.
[doc("Build the nRF52840-DK firmware in release, as flashed.")]
build-nrf52840-release:
    cd bins/wayfinder-nrf52840 && cargo build --release --locked

[doc("Lint the nRF52840-DK firmware.")]
clippy-nrf52840:
    cd bins/wayfinder-nrf52840 && cargo clippy --locked -- -D warnings

# Building both nRF boards is what proves `libs/wayfinder-nrf` still serves both
# rather than having drifted onto one.
[doc("Build the nRF52840 dongle (PCA10059) firmware.")]
build-nrf52840-dongle:
    cd bins/wayfinder-nrf52840-dongle && cargo build --locked

[doc("Build the nRF52840 dongle firmware in release, as flashed.")]
build-nrf52840-dongle-release:
    cd bins/wayfinder-nrf52840-dongle && cargo build --release --locked

[doc("Lint the nRF52840 dongle firmware.")]
clippy-nrf52840-dongle:
    cd bins/wayfinder-nrf52840-dongle && cargo clippy --locked -- -D warnings

# `--release` is not optional here: 512 KB of flash doesn't fit the crypto stack
# unoptimized.
[doc("Build the NUCLEO-F411RE firmware.")]
build-stm32f411:
    cd bins/wayfinder-stm32f411 && cargo build --release --locked

[doc("Lint the NUCLEO-F411RE firmware.")]
clippy-stm32f411:
    cd bins/wayfinder-stm32f411 && cargo clippy --release --locked -- -D warnings

# `blue`'s nRF backend is unwired: both nRF boards moved to 802.15.4, which
# contends with BLE for the same RADIO peripheral, so nothing links
# `NrfBleLink` or the SoftDevice any more. Building it here keeps it from
# rotting unnoticed — the host (BlueZ) half of `blue` is still very much in
# use by `bins/wayfinder-tap` and is covered by the workspace build.
#
# This used to cover `nrf-ieee802154`, for the mirror-image reason.
[doc("Cross-compile the embedded drivers no board currently links.")]
build-loose-drivers:
    cargo build --locked -p blue --no-default-features \
        --features hardware,softdevice-log --target {{ bare_metal_target }}

[doc("Lint the embedded drivers no board currently links.")]
clippy-loose-drivers:
    cargo clippy --locked -p blue --no-default-features \
        --features hardware,softdevice-log --target {{ bare_metal_target }} -- -D warnings

# ---------------------------------------------------------------------------
# ESP32 (Xtensa) toolchain
# ---------------------------------------------------------------------------
#
# The one board family whose compiler the devShell cannot provide: Xtensa has
# no upstream LLVM backend, so `xtensa-esp32-none-elf` exists only in
# Espressif's rustc fork, which `espup` installs into `$HOME` as a prebuilt
# tarball. flake.nix's `espupWrapped` comment carries the full reasoning,
# including why `rustup` is deliberately absent from PATH and why a build runs
# through `esp-cargo` instead of `cargo +esp`.
#
# These recipes are therefore *not* part of `just ci`, and never will be: they
# download ~2 GB from GitHub and write outside the repo. Run `esp-toolchain`
# once per machine; `esp-check` afterwards to confirm the fork can actually
# execute here (on NixOS that is a question about nix-ld, not about Rust).
#
# `esp32` alone rather than espup's `all` default: each extra Xtensa target is
# another multi-hundred-MB unpack, and the RISC-V ESP32s (C3/C6/H2) need none
# of this — their target ships with the ordinary fenix toolchain.

# Xtensa targets to install the fork for. `esp32,esp32s3` if an S3 joins the
# bench; the RISC-V parts do not belong here.
esp_targets := "esp32"

# Bare-metal target triple for the original ESP32 (Xtensa LX6). `no_std`; the
# `std` counterpart would be `xtensa-esp32-espidf`, which additionally needs
# ESP-IDF and the `ldproxy`/`esp-idf-sys` machinery the devShell also carries.
esp_target := "xtensa-esp32-none-elf"

[doc("Install the Xtensa Rust toolchain for the ESP32 (~2 GB, writes to $HOME).")]
esp-toolchain:
    espup install --targets {{ esp_targets }}

[doc("Update the installed Xtensa Rust toolchain in place.")]
esp-toolchain-update:
    espup update --targets {{ esp_targets }}

[doc("Remove the Xtensa Rust toolchain and Espressif tools from $HOME.")]
esp-toolchain-clean:
    espup uninstall

# Running the fork at all is the check worth having: the tarball unpacking
# successfully says nothing about whether its FHS binaries execute on this host
# (on NixOS that is a nix-ld question), and a target-list that names
# `xtensa-esp32-none-elf` is what separates the fork from the stock rustc that
# `cargo` otherwise means in this shell.
#
# It stops there on purpose — `build-esp32` below is the end-to-end check. The
# fork ships *no prebuilt `core`* for the Xtensa bare-metal targets, so a listed
# target is not a buildable one until `build-std` compiles the sysroot from
# `rust-src` (see `bins/wayfinder-esp32/.cargo/config.toml`).
[doc("Verify the Xtensa toolchain runs here and knows the ESP32 target.")]
esp-check:
    esp-env rustc --version --verbose
    esp-env rustc --print target-list | grep -qx {{ esp_target }}
    @echo "{{ esp_target }}: available"

# ---------------------------------------------------------------------------
# ESP32 firmware
# ---------------------------------------------------------------------------
#
# Its own section rather than joining `build-embedded`/`clippy-embedded`: those
# aggregates are reached by `just ci`, and this board's compiler is not the
# workspace toolchain but a fork installed out of band by `esp-toolchain` above.
# Folding it in would make the full local gate — and CI's `build-embedded` job —
# fail on every machine that has not spent the ~2 GB. Run these explicitly while
# working on the board; the `no_std` crates it will eventually link are covered
# by the root workspace either way.
#
# `esp-cargo` rather than `cargo` throughout, for the reason flake.nix's
# `espupWrapped` comment gives: `cargo +esp` needs a rustup this shell
# deliberately does not have on PATH.

[doc("Build the ESP32 (Xtensa LX6) firmware.")]
build-esp32:
    cd bins/wayfinder-esp32 && esp-cargo build --locked

[doc("Lint the ESP32 firmware.")]
clippy-esp32:
    cd bins/wayfinder-esp32 && esp-cargo clippy --locked --all-targets -- -D warnings

# `espflash` over the USB-serial bridge, then stays attached to the same UART the
# firmware prints on — the ESP32 equivalent of `probe-rs run` on the Cortex-M
# boards, and the only way to observe this image. Needs the board plugged in.
[doc("Flash the ESP32 over USB and monitor its output.")]
flash-esp32:
    cd bins/wayfinder-esp32 && esp-cargo run --locked --release

[doc("Remove the ESP32 firmware's target directory.")]
clean-esp32:
    cd bins/wayfinder-esp32 && esp-cargo clean

# ---------------------------------------------------------------------------
# Python test suite
# ---------------------------------------------------------------------------

# The wayfinder-shark Lua dissector via tshark, and the wayfinder-py extension
# module. `uv run` resolves against the `.venv` `uv sync` builds, not the system
# interpreter.
[doc("Run the pytest suite.")]
test-pytest:
    uv sync --locked
    uv run pytest

# ---------------------------------------------------------------------------
# Formatting and linting
# ---------------------------------------------------------------------------

# Prefer this over `cargo fmt` — the pre-commit hook runs the same thing.
[doc("Format everything (Rust and otherwise) via treefmt.")]
fmt:
    nix fmt

[doc("Verify formatting and the flake without rewriting files.")]
fmt-check:
    nix --extra-experimental-features "nix-command flakes" flake check

[doc("Run every non-Rust lint.")]
lint: lint-protos

# The `COMMENTS` rule is what enforces CLAUDE.md's "every message, field, oneof
# and enum value is documented".
[doc("Lint the management-API protobuf definitions.")]
lint-protos:
    cd libs/wayfinder-protos && buf lint

# ---------------------------------------------------------------------------
# Fuzzing
# ---------------------------------------------------------------------------
#
# `cargo-fuzz` targets are not unit tests and are in no `nextest` run; they need
# an explicit, open-ended invocation. Nightly-only.

[doc("Run one fuzz target for a bounded time, e.g. `just fuzz wayfinder parse_frame 60`.")]
fuzz crate target seconds="60":
    cd libs/{{ crate }}/fuzz && cargo fuzz run {{ target }} -- -max_total_time={{ seconds }}

# Each `libs/*/fuzz` is its own workspace with its own target directory, and a
# fuzzing run leaves the largest artifacts in the repo behind there.
[doc("Remove every fuzz workspace's target directory.")]
clean-fuzz:
    #!/usr/bin/env bash
    set -euo pipefail
    for dir in libs/*/fuzz; do
        (cd "$dir" && cargo clean)
    done

[doc("List every available fuzz target, by crate.")]
fuzz-list:
    #!/usr/bin/env bash
    set -euo pipefail
    for dir in libs/*/fuzz; do
        crate=$(basename "$(dirname "$dir")")
        echo "== ${crate} =="
        (cd "$dir" && cargo fuzz list)
    done
