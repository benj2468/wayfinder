MEMORY
{
  /* STM32F411RE (NUCLEO-F411RE): 512 KB flash, 128 KB RAM.
   *
   * Flash is addressed at its real 0x08000000 base, not the 0x00000000 boot
   * alias. The alias is read-only shadowing of whatever BOOT0 selected and is
   * not a programmable region -- `probe-rs` refuses an image there, because no
   * NVM region in the target description covers it. Confirmed against that
   * description: `probe-rs chip info STM32F411RE` reports
   * NVM 0x08000000..0x08080000 and RAM 0x20000000..0x20020000.
   */
  FLASH : ORIGIN = 0x08000000, LENGTH = 512K
  RAM : ORIGIN = 0x20000000, LENGTH = 128K
}
