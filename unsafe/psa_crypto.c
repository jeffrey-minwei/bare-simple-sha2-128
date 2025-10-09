#include <stdint.h>
#include <string.h>

#include "psa/crypto.h"
#include "../kat/rng.h"
#include "../params.h"
#include "../xmss_sign.h"
#include "../sha256.h"
#include "hmac_sha256.h"

// 檔案作用域靜態儲存期（同檔可見）
static uint8_t sk_seed[SPX_N] = {0};
static uint8_t sk_prf[SPX_N] = {0};
static uint8_t pk_seed[SPX_N] = {0};
static uint8_t pk_root[SPX_N] = {0};

/**
 * See https://arm-software.github.io/psa-api/crypto/1.3/api/library/library.html#c.psa_crypto_init
 */
psa_status_t psa_crypto_init(void)
{
    unsigned char       entropy_input[48];

    for (int i=0; i<48; i++) {
        entropy_input[i] = i;
    }

    unsigned char *personalization_string = NULL;
    randombytes_init(entropy_input, personalization_string, 256);

    unsigned char seed[48];
    unsigned char msg[3300];
    unsigned long long  mlen, smlen, mlen1;
    for (int i=0; i<100; i++) {
        randombytes(seed, 48);
        mlen = 33*(i+1);
        randombytes(msg, mlen);
    }

    randombytes_init(seed, NULL, 256);
    return PSA_SUCCESS;
}

/**
 * See https://arm-software.github.io/psa-api/crypto/1.3/api/ops/rng.html#c.psa_generate_random
 */
psa_status_t psa_generate_random(uint8_t * output,
                                 size_t output_size)
{
    return randombytes((unsigned char*)output, (unsigned long long)output_size);
}

/**
 * See https://arm-software.github.io/psa-api/crypto/1.3/api/keys/management.html#c.psa_generate_key
 */
psa_status_t psa_generate_key(const psa_key_attributes_t * attributes,
                              psa_key_id_t * key)
{
    psa_generate_random(sk_seed, SPX_N);
    psa_generate_random(sk_prf, SPX_N);
    psa_generate_random(pk_seed, SPX_N);

    ADRS adrs;
    memset(adrs, 0, 32);

    int d = 7;  // SLH-DSA-SHA2-128s, d is 7
    set_layer_addr(adrs, d-1);

    unsigned int h_prime = 9;
    // PK.root ← xmss_node(SK.seed, 0, ℎ′, PK.seed, ADRS)
    xmss_node(pk_root, sk_seed, 0, h_prime, pk_seed, adrs);

    return PSA_SUCCESS;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * hash,
                              size_t hash_size,
                              size_t * hash_length)
{
    sha256(input, input_length, hash);

    return PSA_SUCCESS;
}

psa_status_t psa_mac_compute(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * mac,
                             size_t mac_size,
                             size_t * mac_length)
{
    
    hmac_sha256(sk_prf, sizeof(sk_prf),
                input, input_length,
                mac);

    return PSA_SUCCESS;
}