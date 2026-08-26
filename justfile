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
# Every recipe here mirrors the corresponding `.gitlab-ci.yml` job, so a green
# `just ci` locally covers the same set of checks the pipeline runs (plus a
# couple of things CI doesn't gate on yet, like `buf lint`).
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
# Dropping it on macOS costs its two unit tests locally and nothing else: the
# coverage that matters is `build-loose-drivers`/`clippy-loose-drivers`, which
# cross-compile it for `bare_metal_target` — the only target it ever runs on —
# and work on every host. CI is Linux, so it stays fully covered there.
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

# The `test:run:rust` CI job reports this number for the coverage badge.
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

[doc("Lint the nRF52840-DK firmware.")]
clippy-nrf52840:
    cd bins/wayfinder-nrf52840 && cargo clippy --locked -- -D warnings

# Building both nRF boards is what proves `libs/wayfinder-nrf` still serves both
# rather than having drifted onto one.
[doc("Build the nRF52840 dongle (PCA10059) firmware.")]
build-nrf52840-dongle:
    cd bins/wayfinder-nrf52840-dongle && cargo build --locked

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

# `nrf-ieee802154` is unwired because 802.15.4 and BLE contend for the same RADIO
# peripheral; building it here keeps it from rotting unnoticed.
[doc("Cross-compile the embedded drivers no board currently links.")]
build-loose-drivers:
    cargo build --locked -p nrf-ieee802154 --target {{ bare_metal_target }}

[doc("Lint the embedded drivers no board currently links.")]
clippy-loose-drivers:
    cargo clippy --locked -p nrf-ieee802154 --target {{ bare_metal_target }} -- -D warnings

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
