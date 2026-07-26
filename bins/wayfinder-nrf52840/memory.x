MEMORY
{
  /* nRF52840: 1MB flash, 256KB RAM, running under the S140 7.3.0 SoftDevice
   * (`libs/blue`'s `hardware` feature / `nrf-softdevice`).
   *
   * FLASH: the bottom 156K (0x0..0x27000) is Nordic's SoftDevice binary
   * (flashed separately — see `libs/blue/CLAUDE.md` — before this firmware's
   * image; `probe-rs download` the s140_nrf52_7.x.x_softdevice.hex first).
   * The app's FLASH region starts right after it, at 0x27000. The top two
   * 4 KiB pages (0xFE000..0x100000) stay carved out of the app's LENGTH —
   * 860K, not 1016K - 156K's full 868K — for the node's durable identity
   * store (`FlashStore`, an A/B ping-pong pair); the base address is
   * recomputed in `main.rs` as `DURABLE_STORE_BASE`. Keep FLASH's origin/
   * SoftDevice size, this LENGTH, and `DURABLE_STORE_BASE` in sync.
   *
   * RAM: the bottom 31K is reserved for the SoftDevice's own connection/GAP
   * state (`nrf-softdevice`'s upstream nrf52840 example for S140 7.3.0 +
   * `Config::default()`). This is a starting estimate, not a measured value —
   * `Softdevice::enable()` calls `sd_ble_enable`, which fails (NoMem) and
   * panics if this is too small, telling you the exact required size via
   * `wanted_app_ram_base`. That message is currently swallowed silently
   * (`panic-halt`, and `nrf-softdevice`'s `log`/`defmt` features are both
   * off), so a too-small reservation here manifests as the board hanging
   * with zero output — if that happens after this change, wire up
   * `nrf-softdevice`'s `log` feature (or temporarily swap `panic-halt`) to
   * read the real number rather than guessing further. */
  FLASH : ORIGIN = 0x00027000, LENGTH = 860K
  RAM : ORIGIN = 0x20000000 + 64K, LENGTH = 256K - 64K
}
