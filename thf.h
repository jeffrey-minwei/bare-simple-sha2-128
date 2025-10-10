#ifndef THF_H
#define THF_H

#include <stdint.h>   // uint8_t

#include "common.h"
#include "params.h"

//
// Tweakable Hash Function
//

// See Page 30, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
//
//  𝑛𝑜𝑑𝑒 ← F(PK.seed, ADRS, 𝑠𝑘)
//  𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)

void T(unsigned int len, const psa_key_id_t pk_seed_key_id, ADRS adrs, const uint8_t *p_M, uint8_t out[SPX_N]);

/**
 * F(PK.seed, ADRS, M_1) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ M_1)), len = 1
 */
void F(const psa_key_id_t pk_seed, ADRS adrs, const uint8_t M[16], uint8_t out[SPX_N]);

/**
 * H(PK.seed, ADRS, M_2) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ M_2)), len = 2
 */
void H(const psa_key_id_t pk_seed, ADRS adrs, const uint8_t M[32], uint8_t out[SPX_N]);

#endif