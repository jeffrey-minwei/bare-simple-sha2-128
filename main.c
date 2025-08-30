// main.c - nRF52840 UARTE0 Hello World (115200/8N1, no HWFC, EasyDMA)
#include <stdint.h>
#include "uart_min.h"

/* 非 const，確保放在 RAM（EasyDMA 來源/目的需在 RAM） */
static uint8_t msg[] = "Hello, world!\r\n";

/* 避免連結器找不到 SystemInit */
__attribute__((weak)) void SystemInit(void) {}

static void uarte0_init(void)
{
    /* 取消 HWFC，只用 TX/RX */
    UARTE_PSEL_RTS = 0xFFFFFFFFu;
    UARTE_PSEL_CTS = 0xFFFFFFFFu;
    UARTE_PSEL_TXD = UART_TX_PIN; /* Port 0 隱含，直接寫 pin number */
    UARTE_PSEL_RXD = UART_RX_PIN;

    UARTE_CONFIG   = 0; /* Parity off, HWFC off */
    UARTE_BAUDRATE = UARTE_BAUDRATE_115200;

    UARTE_ENABLE   = UARTE_ENABLE_Enabled;

    /* 清事件旗標 */
    UARTE_EVENTS_ENDTX = 0;
}

static void uarte0_tx(const void *buf, uint32_t len)
{
    UARTE_TXD_PTR    = (uint32_t)buf;
    UARTE_TXD_MAXCNT = len;

    UARTE_EVENTS_ENDTX = 0;
    UARTE_TASKS_STARTTX = 1;

    /* 阻塞等待傳送完成 */
    while (UARTE_EVENTS_ENDTX == 0) { /* wait */ }

    UARTE_TASKS_STOPTX = 1;
}

int main(void)
{
    SystemInit();

    uarte0_init();
    uarte0_tx(msg, sizeof(msg) - 1);

    // TODO keygen() -> sign()
    // TODO print pk, sig.sha256, sig.len

    for (;;) { /* 不返回 */ }
    /* return 0; */
}

