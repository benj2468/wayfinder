MEMORY
{
  /* nRF52840: 1MB flash, 256KB RAM, no SoftDevice reserved.
   *
   * The top two 4 KiB flash pages (0xFE000..0x100000) are carved OUT of the
   * FLASH region below — LENGTH is 1016K, not the full 1024K — so the linker
   * never places code or read-only data there. They are reserved for the
   * node's durable identity store (`FlashStore`, an A/B ping-pong pair); the
   * base address is recomputed in `main.rs` as `DURABLE_STORE_BASE`. Keep the
   * two in sync: shrinking or growing this reservation means changing both. */
  FLASH : ORIGIN = 0x00000000, LENGTH = 1016K
  RAM : ORIGIN = 0x20000000, LENGTH = 256K
}
