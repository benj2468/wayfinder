MEMORY
{
  /* nRF52840 dongle (PCA10059): same silicon as the DK — 1MB flash, 256KB RAM,
   * no SoftDevice — but a different flash layout, because the board ships with
   * Nordic's MBR in low flash and its Open Bootloader in high flash.
   *
   * FLASH starts at 0x1000, **not 0** as on the DK. The bottom 4 KiB is the
   * Master Boot Record, which the Open Bootloader depends on and which DFU
   * never rewrites. With no SoftDevice present the bootloader places an
   * application directly above the MBR — `nrf_dfu_bank0_start_addr()` in the
   * nRF5 SDK returns MBR_SIZE when it finds no valid SoftDevice — so 0x1000 is
   * where a DFU-flashed image will actually run from. It used to be 0x27000,
   * above the S140.
   *
   * `runner.sh` must agree: its `--sd-req` now names 0x00 ("no SoftDevice"),
   * which is what makes the bootloader compute that placement and erase any
   * S140 left over from an earlier image. A stale `--sd-req 0x123` would have
   * it place the app above a SoftDevice that is no longer there.
   *
   * The top 128K (0xE0000..0x100000) stays reserved for the Open Bootloader
   * together with its MBR parameter and settings pages — deliberately
   * conservative, since the bootloader is smaller than that but its exact
   * extent depends on which build the dongle shipped with, and under-reserving
   * corrupts the DFU path that is the only way to reflash without a probe.
   *
   * The two 4 KiB pages below that (0xDE000..0xE0000) are the durable identity
   * store, recomputed in `main.rs` as DURABLE_STORE_BASE. The app gets what is
   * left: 0xDE000 - 0x1000 = 884K. Keep ORIGIN, LENGTH and that constant in
   * sync.
   *
   * Flashing over SWD and dropping the bootloader entirely frees the top 128K
   * and the MBR both, in which case this can match the DK's layout — see
   * `libs/wayfinder-nrf/CLAUDE.md`.
   *
   * RAM starts at 0x20000008, **not 0x20000000 as on the DK**. The MBR keeps
   * its interrupt-forwarding address in the first 8 bytes of RAM, and that is
   * the mechanism by which an application above the MBR receives interrupts at
   * all when no SoftDevice is present: the bootloader issues
   * SD_MBR_COMMAND_IRQ_FORWARD_ADDRESS_SET before jumping, and the MBR's
   * vector table at 0 trampolines every IRQ through it.
   *
   * `flip-link` puts the *stack* at the bottom of RAM, so an ORIGIN of
   * 0x20000000 has `stack::paint` overwrite that address during boot. The
   * board then takes a HardFault on its first interrupt, reboots, and halts
   * after MAX_CONSECUTIVE_FAULTS with LD1 dark and no USB — which is exactly
   * what it did. The DK cannot reproduce it: its app is at 0 with no MBR to
   * forward anything, and the old dongle firmware could not either, because
   * the S140's 13112-byte reservation put RAM origin far above these 8 bytes.
   *
   * Keep this in sync with RAM_ORIGIN in `main.rs`. */
  FLASH : ORIGIN = 0x00001000, LENGTH = 884K
  RAM : ORIGIN = 0x20000008, LENGTH = 256K - 8
}
