// main.c - nRF52840 UARTE0 Hello World (115200/8N1, no HWFC, EasyDMA)

#include "uart_min.h"
#include "common.h"
#include "psa/crypto.h"
#include "keygen.h"
#include "sha256.h"
#include "slh_dsa_sign.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* 避免連結器找不到 SystemInit */
__attribute__((weak)) void SystemInit(void) {}

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

void test_uart()
{
    // test uart
    uint8_t msg[] = "Test UART\r\n";
    uarte0_tx(msg, sizeof(msg) - 1);
}

psa_status_t create_sk_prf(psa_key_id_t desired_id, psa_key_id_t *sk_prf_key_id) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, (psa_key_bits_t)(8 * SPX_N));
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_id(&attr, desired_id);

    return psa_generate_key(&attr, sk_prf_key_id);
}

void generate_key(psa_key_id_t *p_sk_seed_key_id, 
                  psa_key_id_t *p_sk_prf_key_id, 
                  psa_key_id_t *p_pk_key_id)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);

    psa_set_key_id(&attributes, 1);
    psa_status_t status = psa_generate_key(&attributes, p_sk_seed_key_id);
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_generate_key sk seed fail");
        for(;;);  // 失敗停在這裡
    }

    status = create_sk_prf(2, p_sk_prf_key_id);
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_generate_key sk prf fail");
        for(;;);  // 失敗停在這裡
    }

    psa_set_key_id(&attributes, 3);
    status = psa_generate_key(&attributes, p_pk_key_id);
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_generate_key public key fail");
        for(;;);  // 失敗停在這裡
    }

    uarte0_puts("psa_generate_key sk_seed, sk_prf, pk_seed generate successfully");
}

int main(void)
{
    SystemInit();

    uarte0_init();

    test_uart();

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_crypto_init fail");
        for(;;);  // 失敗停在這裡
    }

    psa_key_id_t sk_key_id;
    psa_key_id_t sk_prf_key_id;
    psa_key_id_t pk_key_id;
    generate_key(&sk_key_id, &sk_prf_key_id, &pk_key_id);

    test_psa_hash_compute();
    test_psa_mac_compute(pk_key_id);

    test_common();

    uint8_t sig[SPX_BYTES];
    uint8_t optrand[SPX_N];
    
    // 先準備 optrand（真實用 RNG；先隨便填也行）
    for(int i=0;i<SPX_N;i++) optrand[i] = (uint8_t)(0xA5 ^ i);
    
    // 開簽
    const uint8_t msg[] = "Hello SLH-DSA";  
    size_t msg_len = sizeof(msg) - 1;   // 不含結尾 \0
    slh_dsa_sign(sig, sk_key_id, sk_prf_key_id, pk_key_id, msg, msg_len, optrand);

    //uarte0_hex_all("SLH-DSA Signature", sig, SPX_BYTES);
    
    for (;;) { /* 不返回 */ }
    /* return 0; */
}