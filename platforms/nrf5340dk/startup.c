/* nRF5340 DK - Application core (Cortex-M33F) minimal startup
 * Secure, enable FPU, copy .data, clear .bss
 * entry point is main()
 */

#include <stdint.h>

/* 由 linker.ld 提供 */
extern uint32_t _sidata;   /* Flash 中 .data 的來源起點 */
extern uint32_t _sdata;    /* RAM 中 .data 的起點 */
extern uint32_t _edata;    /* RAM 中 .data 的終點 */
extern uint32_t _sbss;     /* RAM 中 .bss 的起點 */
extern uint32_t _ebss;     /* RAM 中 .bss 的終點 */
extern uint32_t _estack;   /* Stack Top (由 linker 設定) */

void Reset_Handler(void);
void Default_Handler(void);

/* TODO: more detail description */
__attribute__((weak)) void SystemInit(void) {}


int main(void);

/* TODO: more detail description */
void NMI_Handler            (void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler      (void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler      (void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler       (void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler     (void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler            (void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler       (void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler         (void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler        (void) __attribute__((weak, alias("Default_Handler")));

/* TODO: more detail description */
void IRQ0_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ1_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ2_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ3_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ4_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ5_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ6_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ7_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ8_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ9_Handler           (void) __attribute__((weak, alias("Default_Handler")));
void IRQ10_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ11_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ12_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ13_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ14_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ15_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ16_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ17_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ18_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ19_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ20_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ21_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ22_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ23_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ24_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ25_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ26_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ27_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ28_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ29_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ30_Handler          (void) __attribute__((weak, alias("Default_Handler")));
void IRQ31_Handler          (void) __attribute__((weak, alias("Default_Handler")));

/* 向量表 (放在 .isr_vector 段) */
__attribute__((section(".isr_vector")))
const void * const g_pfnVectors[] =
{
    /* Initial Stack Pointer */
    (void *)&_estack,

    /* Cortex-M Exceptions */
    Reset_Handler,
    NMI_Handler,
    HardFault_Handler,
    MemManage_Handler,
    BusFault_Handler,
    UsageFault_Handler,
    0, 0, 0, 0,          /* TODO: more detail description */
    SVC_Handler,
    DebugMon_Handler,
    0,                   /* TODO: more detail description */
    PendSV_Handler,
    SysTick_Handler,

    /* TODO: more detail description */
    IRQ0_Handler,  IRQ1_Handler,  IRQ2_Handler,  IRQ3_Handler,
    IRQ4_Handler,  IRQ5_Handler,  IRQ6_Handler,  IRQ7_Handler,
    IRQ8_Handler,  IRQ9_Handler,  IRQ10_Handler, IRQ11_Handler,
    IRQ12_Handler, IRQ13_Handler, IRQ14_Handler, IRQ15_Handler,
    IRQ16_Handler, IRQ17_Handler, IRQ18_Handler, IRQ19_Handler,
    IRQ20_Handler, IRQ21_Handler, IRQ22_Handler, IRQ23_Handler,
    IRQ24_Handler, IRQ25_Handler, IRQ26_Handler, IRQ27_Handler,
    IRQ28_Handler, IRQ29_Handler, IRQ30_Handler, IRQ31_Handler
};

static inline void fpu_enable(void)
{
    /* 啟用 CP10/CP11 (單精度 FPU) */
    volatile uint32_t *CPACR = (uint32_t *)0xE000ED88UL; /* SCB->CPACR */
    *CPACR |= (0xFu << 20);
    __asm volatile ("dsb");
    __asm volatile ("isb");
}

void Reset_Handler(void)
{
    /* TODO：TrustZone/Secure for SAU/IDAU */

    fpu_enable();

    SystemInit();

    /* copy .data, from Flash to RAM */
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) { *dst++ = *src++; }

    /* clear .bss */
    for (dst = &_sbss; dst < &_ebss; ) { *dst++ = 0; }

    volatile uint32_t *VTOR = (uint32_t *)0xE000ED08UL; /* SCB->VTOR */
    *VTOR = (uint32_t)g_pfnVectors;

    (void)main();

    while (1) { __asm volatile ("wfi"); }
}

void Default_Handler(void)
{
    while (1) { __asm volatile ("wfi"); }
}