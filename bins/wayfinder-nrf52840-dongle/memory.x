MEMORY
{
  /* nRF52840 dongle (PCA10059): same silicon as the DK — 1MB flash, 256KB RAM,
   * under the S140 7.3.0 SoftDevice — but a different flash layout, because the
   * board ships with Nordic's Open Bootloader in high flash.
   *
   * FLASH: the bottom 156K (0x0..0x27000) is the SoftDevice, as on the DK. The
   * top 128K (0xE0000..0x100000) is reserved for the Open Bootloader together
   * with its MBR parameter and settings pages. That is a deliberately
   * conservative reservation: the bootloader itself is smaller, but its exact
   * extent depends on which build the dongle shipped with, and over-reserving
   * costs flash the app does not need while under-reserving corrupts the DFU
   * path that is the only way to reflash a dongle without an SWD probe.
   *
   * The two 4 KiB pages below that (0xDE000..0xE0000) are the durable identity
   * store, recomputed in `main.rs` as DURABLE_STORE_BASE. The app gets what is
   * left: 0xDE000 - 0x27000 = 732K. Keep ORIGIN, LENGTH and that constant in
   * sync.
   *
   * Flashing over SWD and dropping the bootloader entirely frees the top 128K,
   * in which case this can match the DK's layout — see `libs/wayfinder-nrf/CLAUDE.md`.
   *
   * RAM: identical to the DK's, and for the same measured reason (the S140's
   * `wanted_app_ram_base` under `nrf_softdevice::Config::default()`). The two
   * boards run the same SoftDevice configuration, so if one moves, so does the
   * other. */
  FLASH : ORIGIN = 0x00027000, LENGTH = 732K
  RAM : ORIGIN = 0x20000000 + 13112, LENGTH = 256K - 13112
}
