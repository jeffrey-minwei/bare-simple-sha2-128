/* nRF52840 minimal linker script (no SoftDevice) */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 1M
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}

/* Provide common stack symbol used by startup */
PROVIDE(_estack = ORIGIN(RAM) + LENGTH(RAM));

SECTIONS
{
  /* Vector table at start of FLASH */
  .isr_vector :
  {
    KEEP(*(.isr_vector))
  } > FLASH

  /* Code and read-only data in FLASH */
  .text :
  {
    *(.text*)
    *(.rodata*)
    *(.glue_7) *(.glue_7t)
    *(.init*) *(.fini*)
    *(.eh_frame*) *(.gcc_except_table*)
    . = ALIGN(4);
  } > FLASH

  /* ARM exception tables (optional) */
  .ARM.extab :
  {
    *(.ARM.extab* .gnu.linkonce.armextab.*)
  } > FLASH

  .ARM.exidx :
  {
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
  } > FLASH

  /* End of code/rodata in FLASH: LMA for .data follows */
  __etext = .;

  /* Place VMA to start of RAM for data */
  . = ORIGIN(RAM);

  /* Initialized data: VMA in RAM, LMA right after __etext in FLASH */
  .data : AT(__etext)
  {
    _sidata = LOADADDR(.data); /* FLASH source */
    _sdata  = .;               /* RAM destination start */
    *(.data*)
    . = ALIGN(4);
    _edata  = .;               /* RAM destination end */
  } > RAM

  /* Zero-initialized data */
  .bss (NOLOAD) :
  {
    _sbss = .;
    *(.bss*) *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  /* End of RAM-used sections: heap base for _sbrk if needed */
  _end = .;  PROVIDE(__end = _end);
}