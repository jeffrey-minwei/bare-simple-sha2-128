#ifndef UART_MIN_H
#define UART_MIN_H

#include <stdint.h>
#include <stddef.h>

/* ==== UARTE0 base ==== */
#define NRF_UARTE0_BASE       0x40002000UL
#define UARTE_TASKS_STARTRX   (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x000))
#define UARTE_TASKS_STOPRX    (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x004))
#define UARTE_TASKS_STARTTX   (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x008))
#define UARTE_TASKS_STOPTX    (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x00C))

#define UARTE_EVENTS_ENDRX    (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x110))
#define UARTE_EVENTS_ENDTX    (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x120))

#define UARTE_ENABLE          (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x500))
#define UARTE_PSEL_RTS        (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x508))
#define UARTE_PSEL_TXD        (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x50C))
#define UARTE_PSEL_CTS        (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x510))
#define UARTE_PSEL_RXD        (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x514))
#define UARTE_BAUDRATE        (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x524))
#define UARTE_CONFIG          (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x56C))

/* EasyDMA pointers/counters */
#define UARTE_RXD_PTR         (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x534))
#define UARTE_RXD_MAXCNT      (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x538))
#define UARTE_RXD_AMOUNT      (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x53C))

#define UARTE_TXD_PTR         (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x544))
#define UARTE_TXD_MAXCNT      (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x548))
#define UARTE_TXD_AMOUNT      (*(volatile uint32_t*)(NRF_UARTE0_BASE + 0x54C))

/* Enable values (product spec) */
#define UARTE_ENABLE_Disabled 0
#define UARTE_ENABLE_Enabled  8   /* 0x8 for UARTE */

/* Baud (115200) */
#define UARTE_BAUDRATE_115200 0x01D7E000UL

/* DK 預設 VCOM 腳位 (P0.06 TX, P0.08 RX) */
#define UART_TX_PIN           6
#define UART_RX_PIN           8

void uarte0_init(void);

void uarte0_hex_byte(uint8_t b);

void uarte0_tx(const void *buf, uint32_t len);
void uarte0_puts(const char *s);
void uarte0_hex(const char *label, const uint8_t *data, size_t len);
void uarte0_hex_all(const char *label, const uint8_t *buf, size_t len);

#endif 