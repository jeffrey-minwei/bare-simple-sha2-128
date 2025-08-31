/* nRF52840 minimal startup (Cortex-M4F) */
#include <stdint.h>

extern uint32_t _estack;
extern uint32_t _sidata; /* LMA: FLASH src for .data */
extern uint32_t _sdata;  /* VMA: RAM dst start for .data */
extern uint32_t _edata;  /* VMA: RAM dst end   for .data */
extern uint32_t _sbss;   /* VMA: RAM start of .bss */
extern uint32_t _ebss;   /* VMA: RAM end   of .bss */

void Reset_Handler(void);
void Default_Handler(void);

void NMI_Handler(void)        __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void)  __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void)        __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void)    __attribute__((weak, alias("Default_Handler")));

/* Minimal vector table */
__attribute__((section(".isr_vector")))
const uint32_t g_pfnVectors[] = {
    (uint32_t)&_estack,       /* Initial Stack Pointer */
    (uint32_t)Reset_Handler,  /* Reset */
    (uint32_t)NMI_Handler,    /* NMI */
    (uint32_t)HardFault_Handler, /* HardFault */
    0, 0, 0, 0, 0, 0, 0,       /* MemManage, BusFault, UsageFault, Reserved x4 */
    (uint32_t)SVC_Handler,    /* SVC */
    0, 0,                      /* DebugMon, Reserved */
    (uint32_t)PendSV_Handler, /* PendSV */
    (uint32_t)SysTick_Handler /* SysTick */
    /* Device IRQs can be added below if needed */
};

void Reset_Handler(void) {
    /* Copy .data from FLASH to RAM */
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) { *dst++ = *src++; }

    /* Zero .bss */
    for (uint32_t *p = &_sbss; p < &_ebss; ++p) { *p = 0; }

    /* Call main */
    extern int main(void);
    (void)main();

    /* If main returns, halt */
    while (1) { __asm volatile("wfi"); }
}

void Default_Handler(void) {
    while (1) { __asm volatile("wfi"); }
}