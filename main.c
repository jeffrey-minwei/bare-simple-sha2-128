// main.c - nRF52840 UARTE0 Hello World (115200/8N1, no HWFC, EasyDMA)
#include <stdint.h>
#include <stddef.h>
    
#include "uart_min.h"
#include "keygen.h"


/* 非 const，確保放在 RAM（EasyDMA 來源/目的需在 RAM） */
static uint8_t msg[] = "Test UART\r\n";

/* 避免連結器找不到 SystemInit */
__attribute__((weak)) void SystemInit(void) {}

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

    for (;;) { /* 不返回 */ }
    /* return 0; */
}
