MEMORY
{
  /* nRF52840-DK (PCA10056): 1MB flash, 256KB RAM, no SoftDevice.
   *
   * FLASH: the whole part, starting at 0. The bottom 156K used to be Nordic's
   * S140 binary, flashed separately before this image; the firmware drives the
   * radio through `embassy-nrf` now and links no SoftDevice, so that space is
   * the application's. The top two 4 KiB pages (0xFE000..0x100000) stay carved
   * out of LENGTH — 1016K, not the full 1024K — for the durable identity
   * store, whose base is recomputed in `main.rs` as DURABLE_STORE_BASE. Keep
   * ORIGIN, LENGTH and that constant in sync.
   *
   * Flashing the DK is now a single `cargo run --release`: there is no
   * SoftDevice hex to `probe-rs download` first, and an S140 left over from an
   * earlier image is simply overwritten.
   *
   * RAM: the whole part. The bottom 13112 bytes used to be the SoftDevice's
   * connection/GAP state — a measured value, the `wanted_app_ram_base` it
   * reported on this board. Nothing reserves RAM below the application now, so
   * that budget went back to the stack; `just stack-budget` is what checks the
   * result still fits. */
  FLASH : ORIGIN = 0x00000000, LENGTH = 1016K
  RAM : ORIGIN = 0x20000000, LENGTH = 256K
}
