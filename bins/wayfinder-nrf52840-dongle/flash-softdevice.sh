#!/usr/bin/env bash
set -euo pipefail

# One-time (per board, or after a chip erase) SoftDevice provisioning for the
# dongle, over the same USB DFU path `runner.sh` uses for the application —
# see `libs/wayfinder-nrf/CLAUDE.md`. Not wired into `cargo run`: this changes
# rarely (pinned at S140 7.3.0) and touching it isn't something an ordinary
# build/flash iteration should ever do by accident. Put the dongle in
# bootloader mode (hold reset until LD2 pulses red) before running this.
#
# Unlike `runner.sh`'s `--sd-req` (which names a SoftDevice this *application*
# depends on), `--sd-req` here is still mandatory but means something
# different for an SD-only package: what SoftDevice must already be present
# for the update to apply. `0x00` is `SD_REQ_APP_OVERWRITES_SD` in Nordic's
# bootloader source — "don't require any particular one", appropriate since
# this is provisioning a SoftDevice from scratch, not depending on one.
SOFTDEVICE_HEX="../../libs/wayfinder-nrf/s140_nrf52_7.3.0_softdevice.hex"
PACKAGE="target/softdevice-dfu-package.zip"

mkdir -p target

nrfutil-nrf5sdk-tools pkg generate \
  --softdevice "$SOFTDEVICE_HEX" \
  --hw-version 52 \
  --sd-req 0x00 \
  "$PACKAGE"

nrfutil device program --firmware "$PACKAGE" --traits nordicDfu
