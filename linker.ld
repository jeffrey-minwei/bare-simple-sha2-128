/* Minimal linker script for nRF52840 (Cortex-M4F) */

ENTRY(Reset_Handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 1M
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}

/* Provide a stack top symbol for the vector table */
_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
  /* Vector table placed at 0x00000000 */
  .isr_vector :
  {
    KEEP(*(.isr_vector))
  } > FLASH

  .text :
  {
    *(.text*) *(.rodata*)
    *(.glue_7) *(.glue_7t)
    *(.eh_frame*)
  } > FLASH

  /* Initialized data: VMA in RAM, LMA in FLASH right after .text */
  .data : AT (LOADADDR(.text) + SIZEOF(.text))
  {
    _sdata = .;
    *(.data*)
    _edata = .;
  } > RAM

  /* Uninitialized data */
  .bss (NOLOAD) :
  {
    _sbss = .;
    *(.bss*) *(COMMON)
    _ebss = .;
  } > RAM

  /* Symbols used by startup code */
  _etext  = LOADADDR(.text) + SIZEOF(.text);
  _sidata = LOADADDR(.data);
}
