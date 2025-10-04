#include "../../hal_rng.h"
#include "uart_min.h"

#include <stdint.h>
#include <string.h>

#include "psa/crypto.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

void rng_init(const uint8_t *entropy, const uint8_t *pers, size_t L) {
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) { 
        uarte0_puts("mbedtls_ctr_drbg_seed fail");
    }
}

void rng_bytes(uint8_t *out, size_t len) {
    psa_status_t status = psa_generate_random(out, len);
    if (status != PSA_SUCCESS) { 
        uarte0_puts("mbedtls_ctr_drbg_random fail");
    }
}
