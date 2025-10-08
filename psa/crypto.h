#pragma once

#include <stdint.h>
#include <stddef.h>

/*
 * See https://arm-software.github.io/psa-api/crypto/1.1/api/library/status.html
 */

typedef int32_t psa_status_t;

#define PSA_SUCCESS ((psa_status_t)0)

/**
 * See https://arm-software.github.io/psa-api/crypto/1.1/api/library/library.html#c.psa_crypto_init
 */
psa_status_t psa_crypto_init();

/**
 * See https://arm-software.github.io/psa-api/crypto/1.1/api/ops/rng.html#c.psa_generate_random
 */
psa_status_t psa_generate_random(uint8_t *output, size_t output_size);
