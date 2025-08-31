#include "uart_min.h"

void uarte0_init(void)
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

void uarte0_tx(const void *buf, uint32_t len)
{
    UARTE_TXD_PTR    = (uint32_t)buf;
    UARTE_TXD_MAXCNT = len;

    UARTE_EVENTS_ENDTX = 0;
    UARTE_TASKS_STARTTX = 1;

    /* 阻塞等待傳送完成 */
    while (UARTE_EVENTS_ENDTX == 0) { /* wait */ }

    UARTE_TASKS_STOPTX = 1;
}

// ========== 傳送字串 ==========
void uarte0_puts(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    uarte0_tx(s, n);
}

// ========== 十六進位列印 ==========
void uarte0_hex(const char *label, const uint8_t *data, size_t len)
{
    static const char hexmap[] = "0123456789ABCDEF";
    char buf[4]; // " XX"
    uarte0_puts(label);
    uarte0_puts(":");

    for (size_t i = 0; i < len; i++) {
        buf[0] = ' ';
        buf[1] = hexmap[(data[i] >> 4) & 0xF];
        buf[2] = hexmap[data[i] & 0xF];
        buf[3] = 0;
        uarte0_puts(buf);
    }
    uarte0_puts("\r\n");
}