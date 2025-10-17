#include "uart_min.h"
#include <string.h>

// 補兩個寄存器寫入（P0 的 PIN_CNF）
#define P0_BASE       0x50000000u
#define P0_PIN_CNF(n) (*(volatile uint32_t *)(P0_BASE + 0x700 + 4*(n)))

#if defined(__x86_64__) || defined(__i386__)
  #define RETURN_IF_X86 return
#else
  #define RETURN_IF_X86 ((void)0)
#endif

void uarte0_init(void)
{
    RETURN_IF_X86;

    /* 先關閉再配置 */
    UARTE_ENABLE = UARTE_ENABLE_Disabled;

    /* GPIO：TX=輸出且斷開輸入；RX=輸入且上拉 */
    P0_PIN_CNF(UART_TX_PIN) = (1u /*DIR=out*/) | (1u<<1 /*INPUT=disconnect*/) | (0u<<2 /*PULL=disabled*/);
    P0_PIN_CNF(UART_RX_PIN) = (0u /*DIR=in*/)  | (0u<<1 /*INPUT=connect*/)    | (3u<<2 /*PULL=pull-up*/);

    /* 針腳對 J2 VCOM0：TX=P0.20、RX=P0.22；關閉硬體流控 */
    UARTE_PSEL_RTS = 0xFFFFFFFFu;
    UARTE_PSEL_CTS = 0xFFFFFFFFu;
    UARTE_PSEL_TXD = 20u;  /* P0.20 */
    UARTE_PSEL_RXD = 22u;  /* P0.22 */

    /* 8N1、115200 */
    UARTE_CONFIG   = 0u;
    UARTE_BAUDRATE = UARTE_BAUDRATE_115200;

    /* 清事件並啟用 */
    UARTE_EVENTS_ENDTX = 0u;
    UARTE_ENABLE       = UARTE_ENABLE_Enabled;
}

void uarte0_hex_byte(uint8_t b) 
{
    RETURN_IF_X86;

    char hex[2];
    const char *digits = "0123456789ABCDEF";
    hex[0] = digits[b >> 4];
    hex[1] = digits[b & 0x0F];
    uarte0_tx(hex, 2);
}

void uarte0_tx(const void *buf, uint32_t len)
{
    RETURN_IF_X86;

    static uint8_t tx_bounce[128];
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        uint32_t n = len > sizeof(tx_bounce) ? sizeof(tx_bounce) : len;
        memcpy(tx_bounce, p, n);            // 確保來源在 RAM

        UARTE_EVENTS_ENDTX = 0;
        UARTE_TXD_PTR    = (uint32_t)tx_bounce;
        UARTE_TXD_MAXCNT = n;
        UARTE_TASKS_STARTTX = 1;
        while (UARTE_EVENTS_ENDTX == 0) { /* wait */ }
        UARTE_TASKS_STOPTX = 1;

        p   += n;
        len -= n;
    }
}

// ========== 傳送字串 ==========
void uarte0_puts(const char *s)
{
    RETURN_IF_X86;

    size_t n = 0;
    while (s[n]) n++;
    uarte0_tx(s, n);
}

// ========== 十六進位列印 ==========
void uarte0_hex(const char *label, const uint8_t *data, size_t len)
{
    RETURN_IF_X86;

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

void uarte0_hex_all(const char *label, const uint8_t *buf, size_t len) 
{
    RETURN_IF_X86;

    uarte0_puts(label);
    uarte0_puts(" (");
    // 印出長度
    char num[16];
    int n = 0;
    size_t tmp = len;
    if (tmp == 0) {
        num[n++] = '0';
    } else {
        char rev[16];
        int r = 0;
        while (tmp > 0 && r < 16) {
            rev[r++] = '0' + (tmp % 10);
            tmp /= 10;
        }
        while (r > 0) num[n++] = rev[--r];
    }
    uarte0_tx(num, n);
    uarte0_puts(" bytes):\n");

    // 印簽章本體
    for (size_t i = 0; i < len; i++) {
        uarte0_hex_byte(buf[i]);
        if ((i & 0x0F) == 0x0F || i == len - 1)
            uarte0_puts("\n");
        else
            uarte0_puts(" ");
    }
}
