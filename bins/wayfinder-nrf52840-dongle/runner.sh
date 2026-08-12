#!/usr/bin/env bash
set -euo pipefail

# The dongle has no onboard debugger and no SWD probe wired to its castellated
# pads, so this flashes over the Open Bootloader's USB DFU instead of SWD —
# see `libs/wayfinder-nrf/CLAUDE.md`.
#
# `nrfutil device program` needs a DFU .zip package for a USB/nordicDfu-mode
# device (a raw .hex only works over jlink/mcuBoot, which this board has
# neither of). Building that package needs `nrfutil-nrf5sdk-tools`, which
# Nordic doesn't publish for aarch64-linux — `flake.nix` runs the real
# x86_64-linux build under qemu-user emulation for that step. The actual
# flash (`device program`) runs natively; only package generation is
# emulated.
#
# `--sd-req 0x123` is S140 7.3.0's documented firmware ID (from `nrfutil
# nrf5sdk-tools pkg generate --help`), declaring this app compatible with the
# SoftDevice already on the device. Omitting `sd-req` entirely (as nrfdfu-rs
# does, and the reason it's not used here) makes the bootloader conclude the
# app doesn't need a SoftDevice and overwrite it before placing the app.
ELF_FILE=$1
HEX_FILE="${ELF_FILE%.*}.hex"
PACKAGE="${ELF_FILE%.*}.zip"

# Not `cargo objcopy`: that reinvokes `cargo build` under its own default
# (dev) profile and objcopies *that*, ignoring $ELF_FILE's actual profile
# entirely. Operate on the given ELF directly instead.
rust-objcopy -O ihex "$ELF_FILE" "$HEX_FILE"

nrfutil-nrf5sdk-tools pkg generate \
  --application "$HEX_FILE" \
  --application-version 1 \
  --hw-version 52 \
  --sd-req 0x123 \
  "$PACKAGE"

nrfutil device program --firmware "$PACKAGE" --traits nordicDfu
