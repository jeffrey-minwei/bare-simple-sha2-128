#ifndef COMMON_H
#define COMMON_H

#include "params.h"
#include "psa/crypto.h"

#include <stdint.h>
#include <string.h>

void test_common();

/**
 *   See page 22 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 *
 *   ADRS is 32 bytes, which is 8 個 uint32_t
 *     -----------------
 *     | layer address |   4 bytes
 *     |---------------| 
 *     |               |
 *     | tree address  |  12 bytes
 *     |               |
 *     |---------------|
 *     | type          |   4 bytes
 *     |---------------|
 *     |               |
 *     |               |  12 byte
 *     |               |
 *     -----------------
 */
typedef unsigned char ADRS[32];   // ADRS  = 32 bytes
typedef unsigned char N_BYTES[SPX_N];  // n bytes

void compress_adrs(uint8_t c[22], const ADRS adrs);

#define WOTS_HASH  0
#define WOTS_PK    1
#define TREE       2
#define FORS_TREE  3
#define FORS_ROOTS 4
#define WOTS_PRF   5
#define FORS_PRF   6

#ifdef HARD

void crypto_hw_init(void);

#endif

psa_status_t slh_dsa_generate_key(const psa_key_attributes_t * attributes,
                                  psa_key_id_t *p_sk_seed_key_id, 
                                  psa_key_id_t *p_sk_prf_key_id, 
                                  psa_key_id_t *p_pk_key_id);

unsigned long long toInt(const unsigned char *pX, unsigned int n);

void toByte(const unsigned long long x, const unsigned int n, unsigned char *pS);

/**
 * n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
 */
void prf(const uint8_t pk_seed[SPX_N], const uint8_t sk_seed[SPX_N], const ADRS adrs, uint8_t out[SPX_N]);

/**
 * Implemented in unsafe/psa_crypto.c
 */
void _prf(uint8_t out[SPX_N], const psa_key_id_t pk_seed_key_id, const psa_key_id_t sk_seed_key_id, const ADRS adrs);

uint8_t * get_pk_seed();

/**
 * H_𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
 */
void h_msg(uint8_t out[SPX_M], // 𝑚 is 30 for SLH-DSA-SHA2-128s
           const uint8_t R[SPX_N],
           const psa_key_id_t pk,
           const uint8_t *m, size_t mlen);

int mgf1_sha256_len30(uint8_t out[SPX_M],
                      const uint8_t *mask, const size_t mask_len,
                      uint8_t m);

#endif
