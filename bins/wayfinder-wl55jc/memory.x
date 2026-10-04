MEMORY
{
  /* STM32WL55JC (NUCLEO-WL55JC1): 256 KB flash, 64 KB RAM.
   *
   * The 64 KB is all of it, and that is only true because this firmware never
   * releases the Cortex-M0+ (it does not set C2BOOT). The part's SRAM is two
   * contiguous 32 KB banks -- SRAM1 at 0x20000000 and SRAM2 at 0x20008000 --
   * and bringing the second core up with SRAM2 assigned to it would leave CPU1
   * the first bank only. Declared as one region because they are adjacent.
   *
   * Verified against the target description `probe-rs chip info STM32WL55JCIx`
   * reports: NVM 0x08000000..0x08040000, RAM 0x20000000..0x20008000 and
   * 0x20008000..0x20010000.
   *
   * Note this part's Cortex-M4 has **no FPU**, so the target is
   * `thumbv7em-none-eabi` and not the `eabihf` the nRF52840 and STM32F411
   * boards use. See `.cargo/config.toml`.
   */
  FLASH : ORIGIN = 0x08000000, LENGTH = 256K
  RAM : ORIGIN = 0x20000000, LENGTH = 64K
}
