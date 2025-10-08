#include "rng.h"

#include "psa/crypto.h"

#ifndef KAT_RNG
#error "kat_rng.c should only be compiled when -DKAT_RNG is defined (test-only)."
#endif

psa_status_t psa_crypto_init() {
    unsigned char       entropy_input[48];

    for (int i=0; i<48; i++) {
        entropy_input[i] = i;
    }

    unsigned char *personalization_string = NULL;
    randombytes_init(entropy_input, personalization_string, 256);
    return PSA_SUCCESS;
}

psa_status_t psa_generate_random(uint8_t *output, size_t output_size) {
    return randombytes((unsigned char*)output, (unsigned long long)output_size);
}
