#include "../psa/crypto.h"

psa_status_t psa_crypto_init()
{
    unsigned char       entropy_input[48];

    for (int i=0; i<48; i++) {
        entropy_input[i] = i;
    }

    unsigned char *personalization_string = NULL;
    randombytes_init(entropy_input, personalization_string, 256);
    return PSA_SUCCESS;
}

/**
 * See https://arm-software.github.io/psa-api/crypto/1.1/api/ops/rng.html#c.psa_generate_random
 */
psa_status_t psa_generate_random(uint8_t *output, size_t output_size) 
{
    return randombytes((unsigned char*)output, (unsigned long long)output_size);
}
