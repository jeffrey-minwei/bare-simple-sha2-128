// main.c - nRF52840 UARTE0 Hello World (115200/8N1, no HWFC, EasyDMA)

#include "uart_min.h"
#include "keygen.h"
#include "slh_dsa_sign.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
    
/* 非 const，確保放在 RAM（EasyDMA 來源/目的需在 RAM） */
static uint8_t msg[] = "Test UART\r\n";

/* 避免連結器找不到 SystemInit */
__attribute__((weak)) void SystemInit(void) {}

static void uarte0_hex_byte(uint8_t b) {
    char hex[2];
    const char *digits = "0123456789ABCDEF";
    hex[0] = digits[b >> 4];
    hex[1] = digits[b & 0x0F];
    uarte0_tx(hex, 2);
}

void uarte0_hex_all(const char *label, const uint8_t *buf, size_t len) {
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


int main(void)
{
    SystemInit();

    uarte0_init();
    // test uart
    uarte0_tx(msg, sizeof(msg) - 1);

    uint8_t sk[SPX_SK_BYTES];
    uint8_t pk[SPX_PK_BYTES];
    uint8_t real_root[SPX_N] = {0};

    // 測試資料：隨便準備一片葉子跟 auth_path
    uint8_t leaf[SPX_N];
    uint8_t auth_path[SPX_TREE_HEIGHT * SPX_N];
    uint8_t pub_seed[SPX_N];
    for (int i = 0; i < SPX_N; i++) {
        leaf[i] = (uint8_t)(0xA0 + i);
        pub_seed[i] = (uint8_t)(0x55 + i);
    }
    memset(auth_path, 0x11, sizeof(auth_path));

    if (generate_keypair(sk, pk) != 0) {
        for(;;);  // 失敗停在這裡
    }

    // 呼叫 set_real_root 計算 root 並回寫到 sk/pk
    set_real_root(sk, pk, real_root, leaf, 0, auth_path, SPX_TREE_HEIGHT, pub_seed);

    // 輸出結果
    uarte0_hex("sk",   sk,   SPX_SK_BYTES);
    uarte0_hex("pk",   pk,   SPX_PK_BYTES);
    uarte0_hex("real_root", real_root, SPX_N);

    uint8_t log[] = "set_real_root DONE\r\n";
    uarte0_tx(log, sizeof(log) - 1);

    // TODO keygen() -> sign()
    // TODO print pk, sig.sha256, sig.len
    uint8_t sig[SPX_BYTES];
    uint8_t optrand[SPX_N];
    
    // 先準備 optrand（真實用 RNG；先隨便填也行）
    for(int i=0;i<SPX_N;i++) optrand[i] = (uint8_t)(0xA5 ^ i);
    
    // 開簽
    const uint8_t msg[] = "Hello SLH-DSA";  
    size_t msg_len = sizeof(msg) - 1;   // 不含結尾 \0
    slh_dsa_sign(sig, sk, pk, msg, msg_len, optrand);

    uarte0_hex_all("SLH-DSA Signature", sig, SPX_BYTES);
    
    for (;;) { /* 不返回 */ }
    /* return 0; */
}