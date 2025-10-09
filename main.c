// main.c - nRF52840 UARTE0 Hello World (115200/8N1, no HWFC, EasyDMA)

#include "uart_min.h"
#include "common.h"
#include "psa/crypto.h"
#include "keygen.h"
#include "sha256.h"
#include "slh_dsa_sign.h"
#include "fors_sk_gen.h"

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

void test_psa_hash_compute()
{
    const char abc[] = "abc";
    uint8_t out32[32];
    sha256(abc, sizeof(abc) - 1, out32);
    size_t olen = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, 
                                           abc, 
                                           sizeof(abc) - 1, 
                                           out32, 
                                           sizeof(out32), 
                                           &olen);
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_hash_compute fail");
        for(;;);  // 失敗停在這裡
    }
    else
    {
        uarte0_puts("psa_hash_compute success\n");
    }
}

void test_psa_mac_compute(psa_key_id_t key_id)
{
    const char abc[] = "abc";
    uint8_t mac[32]; 
    size_t mac_len = 0;
    psa_status_t status = psa_mac_compute(key_id, 
                                          PSA_ALG_HMAC(PSA_ALG_SHA_256), 
                                          abc, sizeof(abc) - 1, 
                                          mac, sizeof(mac),
                                          &mac_len);
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_mac_compute fail");
        for(;;);  // 失敗停在這裡
    }
    else
    {
        uarte0_puts("psa_mac_compute success\n");
    }
}

int main(void)
{
    SystemInit();

    uarte0_init();
    // test uart
    uarte0_tx(msg, sizeof(msg) - 1);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_crypto_init fail");
        for(;;);  // 失敗停在這裡
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_id(&attributes, 1);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);

    psa_key_id_t key_id;
    status = psa_generate_key(&attributes, &key_id);
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_generate_key fail");
        for(;;);  // 失敗停在這裡
    }
    // Both SK.seed and SK.prf shall be generated using an approved random bit generator
    uarte0_puts("sk_seed, pk_seed and sk_prf generate success\n");

    test_psa_hash_compute();
    test_psa_mac_compute(key_id);

    test_common();

    // TODO keygen() -> sign()
    // TODO print pk, sig.sha256, sig.len
    uint8_t sig[SPX_BYTES];
    uint8_t optrand[SPX_N];
    
    // 先準備 optrand（真實用 RNG；先隨便填也行）
    for(int i=0;i<SPX_N;i++) optrand[i] = (uint8_t)(0xA5 ^ i);
    
    // 開簽
    const uint8_t msg[] = "Hello SLH-DSA";  
    size_t msg_len = sizeof(msg) - 1;   // 不含結尾 \0
    //slh_dsa_sign(sig, sk, pk, msg, msg_len, optrand);

    //uarte0_hex_all("SLH-DSA Signature", sig, SPX_BYTES);
    
    for (;;) { /* 不返回 */ }
    /* return 0; */
}