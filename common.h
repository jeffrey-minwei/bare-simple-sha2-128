#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

unsigned long long toInt(const unsigned char *pX, unsigned int n);

void toByte(const unsigned long long x, const unsigned int n, unsigned long long *pS);

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

#endif