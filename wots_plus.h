#ifndef WOTS_PLUS_H
#define WOTS_PLUS_H

#include "common.h"

void test_wots_plus();

/**
 * See Page 18, Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 * @param pk      [out] WOTS+ public key 𝑝𝑘.
 * @param sk_seed [in] 
 * @param pk_seed [in] 
 * @return void
 */
void wots_pk_gen(uint8_t pk[SPX_N],
                 const psa_key_id_t sk_seed,  
                 const psa_key_id_t pk_seed,
                 ADRS adrs);

/**
 * See Page 20, Algorithm 7, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void wots_sign(N_BYTES out[SPX_LEN],
               const uint8_t M[SPX_N], 
               const psa_key_id_t sk_seed, 
               const psa_key_id_t pk_seed,
               ADRS adrs);

#endif