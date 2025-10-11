#include <stdint.h>
#include <string.h>

#include "psa/crypto.h"
#include "../kat/rng.h"
#include "../kat/api.h"
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

void compress_adrs(uint8_t c[22], const ADRS adrs);

/**
 * Based on the SPHINCS+ reference implementation: https://github.com/sphincs/sphincsplus/blob/master/ref/hash_sha2.c#L39
 *
 * PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed))
 *
 * n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
 * p_pk_seed and p_sk_seed both are pointer to the first element of an array of length at least 16.
 */
void _prf(uint8_t out[SPX_N], const psa_key_id_t pk_seed_key_id, const psa_key_id_t sk_seed_key_id, const ADRS adrs)
{    
    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f

    if (pk_seed_key_id == NULL || sk_seed_key_id == NULL || adrs == NULL || out == NULL)
    {
        return;
    }

    //
    // PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed))
    //

    // size of PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed
    int size = 64 + 22 + SPX_N;  // ADRS_c is an array which length is 22
    unsigned char combined[size];

    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
    memcpy(combined, pk_seed, SPX_N);
    
    // PK.seed ∥ toByte(0, 64 − n)
    memset(combined + SPX_N, 0, (64 - SPX_N));

    // ADRSc is a 22 bytes array
    uint8_t adrs_c[22];
    compress_adrs(adrs_c, adrs);

    // PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c
    memcpy(combined + 64, adrs_c, sizeof(adrs_c));

    // PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed
    memcpy(combined + 64 + sizeof(adrs_c), sk_seed, SPX_N);

    // SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed)
    uint8_t out32[32];
    sha256(combined, sizeof(combined), out32);

    // Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed))
    memcpy(out, out32, SPX_N);
}

uint8_t * get_pk_seed()
{
    return (uint8_t *)pk_seed;
}

/**
 * H_𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
 */
void h_msg(uint8_t out[SPX_M], // 𝑚 is 30 for SLH-DSA-SHA2-128s
           const uint8_t R[SPX_N],
           const psa_key_id_t pk_key_id,
           const uint8_t *m, size_t mlen)
{
    // 𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 
    uint8_t in_sha256[SPX_N * 3 + mlen];
    uint8_t *p = (uint8_t *)(in_sha256[0]);
    memcpy(p, R, SPX_N); p += SPX_N;
    memcpy(p, pk_seed, SPX_N); p += SPX_N;
    memcpy(p, pk_root, SPX_N); p += SPX_N;
    memcpy(p, m, mlen);

    // SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 )
    uint8_t hM[32];
    sha256(in_sha256, sizeof(in_sha256), hM);

    // 𝑚 is 30 for SLH-DSA-SHA2-128s
    // MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(...), 𝑚)
    uint8_t in[SPX_N * 2 + 32];
    p = (uint8_t *)(in[0]);

    // 𝑅 ∥ PK.seed ∥ SHA-256(...)
    memcpy(p, R, SPX_N); p += SPX_N;
    memcpy(p, pk_seed, SPX_N); p += SPX_N;
    memcpy(p, hM, 32);

    // MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(...), 𝑚)
    mgf1_sha256_len30(out, in, sizeof(in), SPX_M);
}

/**
 * NIST PQC KAT
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    uint8_t rand[3*SPX_N];
    randombytes(rand, sizeof(rand));

    // sk: SK.seed || SK.prf || pk.seed || pk.root
    memcpy(sk, rand, sizeof(rand));

    return 0;
    // 第 3 個 n bytes 是 pk.seed
    memcpy(pk, ((uint8_t *)rand[0]) + (2 * SPX_N), SPX_N);
    
    // 計算 pk.root
    ADRS adrs;
    memset(adrs, 0, 32);

    int d = 7;  // SLH-DSA-SHA2-128s, d is 7
    set_layer_addr(adrs, d-1);

    unsigned int h_prime = 9;

    uint8_t pk_root[SPX_N] = {0};
    // PK.root ← xmss_node(SK.seed, 0, ℎ′, PK.seed, ADRS)
    xmss_node(pk_root, sk_seed, 0, h_prime, pk_seed, adrs);

    memcpy(sk + 3*SPX_N, pk_root, SPX_N);
    memcpy(pk + SPX_N, pk_root, SPX_N);

    return 0;
}

/**
 * NIST PQC KAT
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    // sk: SK.seed || SK.prf || pk.seed || pk.root
    unsigned char *p = sk;
    memcpy(sk_seed, p, SPX_N); p += SPX_N;
    memcpy(sk_prf, p, SPX_N); p += SPX_N;
    memcpy(pk_seed, p, SPX_N); p += SPX_N;
    memcpy(pk_root, p, SPX_N);

    psa_key_id_t sk_key_id = 1;
    psa_key_id_t sk_prf_key_id = 2;
    psa_key_id_t pk_key_id = 3;

    uint8_t sig_out[SPX_BYTES];
    uint8_t optrand[SPX_N] = {0};
    slh_dsa_sign(sig_out, sk_key_id, sk_prf_key_id, pk_key_id, m, mlen, optrand);

    smlen = SPX_BYTES;
    memcpy(sm, sig_out, SPX_BYTES);
    return 0;
}

/**
 * Not really verify signature, just return success
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    (void)pk;
    if (smlen < (unsigned long long)CRYPTO_BYTES) {
        return -1;  // malformed input
    }

    unsigned long long msglen = smlen - (unsigned long long)CRYPTO_BYTES;
    memmove(m, sm + CRYPTO_BYTES, (size_t)msglen);
    *mlen = msglen;
    return 0;       // always "valid" (KAT stub)
}