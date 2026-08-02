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
   * RAM: the bottom 13112 bytes are reserved for the SoftDevice's own
   * connection/GAP state. This is a *measured* value, not an estimate — it is
   * the `wanted_app_ram_base` the SoftDevice itself reported on this board,
   * minus the 0x20000000 RAM origin.
   *
   * It is measured for one specific SoftDevice configuration: S140 with
   * `nrf_softdevice::Config::default()` as passed by `blue::NrfBleLink::new`.
   * Changing role or connection counts there changes this number, and the two
   * must move together.
   *
   * If this is too small, `Softdevice::enable()`'s `sd_ble_enable` fails
   * (NoMem) and panics with the required size. That panic is visible: this
   * crate's `#[panic_handler]` in `src/main.rs` prints it over RTT via
   * `rtt_target::rprintln!`, and `blue`'s `softdevice-log` feature (enabled in
   * Cargo.toml) additionally surfaces the SoftDevice's own diagnostics. So a
   * bad value here shows up as a printed panic, not a silent hang — read the
   * reported number and set it here rather than guessing. */
  FLASH : ORIGIN = 0x00027000, LENGTH = 860K
  RAM : ORIGIN = 0x20000000 + 13112, LENGTH = 256K - 13112
}
