MEMORY
{
  /* nRF52840-DK (PCA10056): 1MB flash, 256KB RAM, under the S140 7.3.0
   * SoftDevice.
   *
   * FLASH: the bottom 156K (0x0..0x27000) is Nordic's SoftDevice binary,
   * flashed separately before this image (`probe-rs download` the
   * s140_nrf52_7.x.x_softdevice.hex first). The top two 4 KiB pages
   * (0xFE000..0x100000) stay carved out of LENGTH — 860K, not the full 868K —
   * for the durable identity store, whose base is recomputed in `main.rs` as
   * DURABLE_STORE_BASE. Keep ORIGIN, LENGTH and that constant in sync.
   *
   * RAM: the bottom 13112 bytes are the SoftDevice's own connection/GAP state.
   * A *measured* value — the `wanted_app_ram_base` the SoftDevice reported on
   * this board — and specific to S140 with `nrf_softdevice::Config::default()`
   * as passed by `blue::NrfBleLink::new`. Changing role or connection counts
   * there changes this number.
   *
   * If it is too small, `sd_ble_enable` fails with NoMem and panics with the
   * size it wanted; the panic handler prints it over RTT. Read the reported
   * number and set it here rather than guessing. */
  FLASH : ORIGIN = 0x00027000, LENGTH = 860K
  RAM : ORIGIN = 0x20000000 + 13112, LENGTH = 256K - 13112
}
