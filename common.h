#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

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
typedef uint32_t ADRS[8];   // ADRS  = 8 個 uint32_t

/**
 *   See page 45 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 *
 *   Compressed ADRS is 22 bytes, which is 22 個 uint8_t
 *     -----------------
 *     | layer address |   1 byte
 *     |---------------| 
 *     |               |
 *     | tree address  |   8 bytes
 *     |               |
 *     |---------------|
 *     |     type      |   1 byte
 *     |---------------|
 *     |               |
 *     |               |  12 bytes
 *     |               |
 *     -----------------
 */
typedef uint8_t ADRSc[22];   // Compressed ADRS is 22 bytes

void set_layer_addr_c(ADRSc adrs, unsigned int layer);
void set_tree_height_c(ADRSc adrs, unsigned long long i);
void set_type_and_clear_c(ADRSc adrs, unsigned int Y);
void set_key_pair_addr_c(ADRSc adrs, unsigned int i);
void set_tree_index_c(ADRSc adrs, unsigned int i);


unsigned long long toInt(const unsigned char *pX, unsigned int n);

void toByte(const unsigned long long x, const unsigned int n, unsigned char *pS);

/**
 * n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
 * p_pk_seed is a pointer to the first element of an array of length at least 16.
 * p_sk_seed is a pointer to the first element of an array of length at least 16.
 */
void prf(const uint8_t *p_pk_seed, const uint8_t *p_sk_seed, const uint32_t *addr, unsigned char *p_out);

/**
 * F(PK.seed, ADRS, M_1) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ M_1))
 */
void F(const uint8_t *p_pk_seed, const uint32_t *addr, const uint8_t *p_M_1, unsigned char *p_out);

/**
 * H(PK.seed, ADRS, M_2) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ M_2))
 */
void H(const uint8_t *p_pk_seed, const uint32_t *addr, const uint8_t *p_M_2, unsigned char *p_out);

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
