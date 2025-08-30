// startup.c
#include <stdint.h>

extern int main(void);

// Linker-provided symbols
extern uint32_t _estack;
extern uint32_t _sidata; // start of init values for .data (in flash)
extern uint32_t _sdata;  // start of .data in RAM
extern uint32_t _edata;  // end of .data in RAM
extern uint32_t _sbss;   // start of .bss
extern uint32_t _ebss;   // end of .bss

void Reset_Handler(void);
void Default_Handler(void);

// Interrupt vector table (minimal)
__attribute__((section(".isr_vector")))
const void *vector_table[] = {
    (void *)&_estack,       // Initial stack pointer
    Reset_Handler,          // Reset
    Default_Handler,        // NMI
    Default_Handler,        // HardFault
    Default_Handler,        // MemManage
    Default_Handler,        // BusFault
    Default_Handler,        // UsageFault
    0, 0, 0, 0,             // Reserved
    Default_Handler,        // SVC
    Default_Handler,        // DebugMon
    0,                      // Reserved
    Default_Handler,        // PendSV
    Default_Handler         // SysTick
    // Add more IRQs as needed...
};

void Reset_Handler(void)
{
    // Copy .data from flash to RAM
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }

    // Zero .bss
    for (uint32_t *b = &_sbss; b < &_ebss; ++b) {
        *b = 0;
    }

    // Call main
    (void)main();

    // If main returns, loop forever
    for(;;) { }
}

void Default_Handler(void)
{
    for(;;) { }
}

