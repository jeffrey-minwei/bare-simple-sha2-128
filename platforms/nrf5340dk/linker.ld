/* nRF5340 DK - Application core (Cortex-M33F) minimal linker script
 * Secure
 */

ENTRY(Reset_Handler)

/* TODO: more detail description */
MEMORY
{
  /* Code region (XIP) */
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 1M
  /* SRAM region */
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 512K
}

/* TODO: more detail description */
__stack_size = 4K;
__heap_size  = 4K;

/* TODO: more detail description */
PROVIDE(__StackTop   = ORIGIN(RAM) + LENGTH(RAM));
PROVIDE(__StackLimit = __StackTop - __stack_size);

SECTIONS
{
  /* TODO: more detail description */
  .isr_vector :
  {
    . = ALIGN(256);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > FLASH

  /* TODO: more detail description */
  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    *(.glue_7) *(.glue_7t)
    *(.gnu.linkonce.t*) *(.gnu.linkonce.r*)

    /* TODO: more detail description */
    . = ALIGN(4);
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;

    . = ALIGN(4);
    _etext = .;        /* TODO: more detail description */
  } > FLASH

  /* TODO: more detail description */
  .data : AT ( _etext )
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    *(.gnu.linkonce.d*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  /* TODO: more detail description */
  .bss (NOLOAD) :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM
  /* for _sbrk */
  _end = .;  PROVIDE(__end = _end);
  PROVIDE(end = _end);

  /* Heap */
  .heap (NOLOAD) :
  {
    . = ALIGN(8);
    __HeapBase = .;
    . += __heap_size;
    __HeapLimit = .;
  } > RAM

  /* TODO: more detail description */
  ASSERT(__StackLimit >= __HeapLimit, "Error: heap and stack collision")
}

/* TODO: more detail description */
PROVIDE( _sidata = _etext );
PROVIDE( _sdata  = _sdata );
PROVIDE( _edata  = _edata );
PROVIDE( _sbss   = _sbss );
PROVIDE( _ebss   = _ebss );
PROVIDE( _estack = __StackTop );
