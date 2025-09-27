#ifndef WOTS_PLUS_H
#define WOTS_PLUS_H

#include "common.h"

void test_wots_plus();

/**
 * See Page 18, Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void wots_pk_gen(const unsigned char sk_seed[SPX_N], 
                 const unsigned char pk_seed[SPX_N], 
                 ADRS adrs);

/**
 * See Page 20, Algorithm 7, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void wots_sign(N_BYTES out[SPX_LEN],
               const unsigned char *M, 
               const unsigned char sk_seed[SPX_N], 
               const unsigned char pk_seed[SPX_N], 
               ADRS adrs);

#endif