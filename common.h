#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#include "params.h"

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

unsigned long long toInt(const unsigned char *pX, unsigned int n);

void toByte(const unsigned long long x, const unsigned int n, unsigned char *pS);

/**
 * n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
 */
void prf(const uint8_t pk_seed[SPX_N], const uint8_t sk_seed[SPX_N], const ADRS adrs, uint8_t out[SPX_N]);

/**
 * See https://github.com/sphincs/sphincsplus/blob/master/ref/address.c#L11
 *
 * ADRS = concat(toByte(l, 4), ADRS[4:32])
 * ADRS[4:32] means ADRS[4, 5, ..., 31]
 */
void set_layer_addr(ADRS adrs, unsigned int layer);

void set_tree_height(ADRS adrs, unsigned long long i);

void set_type_and_clear(ADRS adrs, unsigned int Y);

/**
 * See page 12,13,14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_key_pair_addr(ADRS adrs, unsigned long long i);

/**
 * See page 12,14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_chain_addr(ADRS adrs, unsigned long long i);

/**
 * See page 14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 * ADRS = concat(ADRS[0 ∶ 28], toByte(i, 4))
 */
void set_hash_addr(ADRS adrs, unsigned long long i);

void set_tree_index(ADRS adrs, unsigned int i);

#endif

