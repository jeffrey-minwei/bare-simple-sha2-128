#include "common.h"
#include "uart_min.h"

#include <stddef.h>
#include <string.h>

void test_common()
{
    unsigned char S[4];
    unsigned int len = 1;
    toByte((unsigned long long)len, 4, S);
    uarte0_hex("S", S, sizeof(S) / sizeof(S[0]));

    unsigned int layer = 1;
    ADRSc adrs_c;
    set_layer_addr_c(adrs_c, layer);

    unsigned long long height = 2;
    set_tree_height_c(adrs_c, height);

    unsigned int type = 4;  // FORS_ROOTS)
    set_type_and_clear_c(adrs_c, type);

    unsigned int idx_keypair = 2;
    set_key_pair_addr_c(adrs_c, idx_keypair);

    unsigned int index_ADRSc = 3;
    set_tree_index_c(adrs_c, index_ADRSc);

    ADRS adrs;
    unsigned long long i = 1;
    set_layer_addr(adrs, len);
    set_tree_height(adrs, i);

    set_type_and_clear(adrs, type);

    unsigned int idx = 2;
    set_key_pair_addr(adrs, idx);

    unsigned int index = 3;
    set_tree_index(adrs, index);
}

/*

Based on the algorithm 2 listed on page 25 of the NIST FIPS 205 document (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf),

Algorithm 2 toInt(X, n)
Converts a byte string to an integer.
Input: n-byte string X.
Output: Integer value of X.
1: total ← 0
2: for i from 0 to n − 1 do
3:     total = (256 * total) + X[i]
4: end for
5: return total
*/

/**
 * Partially inspired by SPHINCS+ reference implementation: https://github.com/sphincs/sphincsplus/blob/master/ref/utils.c#L35
 */
unsigned long long toInt(const unsigned char *pX, unsigned int n)
{
    unsigned long long total = 0;

    if (pX != NULL)
    {
        for (unsigned int i = 0 ; i < n; ++i)
        {
            total = (256 * total) + (unsigned long long)(pX[i]);
        }    
    }

    return total;
}

/*

Based on the algorithm 3 listed on page 25 of the NIST FIPS 205 document (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf),

Algorithm 3 toByte(x, n)
Converts an integer to a byte string.
Input: Integer x, string length n.
Output: Byte string of length n containing binary representation of x in big-endian byte-order.
1: total ← 𝑥
2: for i from 0 to n − 1 do
3:     𝑆[n - 1 - i] ← total mod 256
4:     total ← total >> 8       ▷ least significant 8 bits of 𝑡𝑜𝑡𝑎𝑙
5: end for
6: return 𝑆
*/

/**
 * Based on the SPHINCS+ reference implementation: https://github.com/sphincs/sphincsplus/blob/master/ref/utils.c#L12
 */
void toByte(const unsigned long long x, const unsigned int n, unsigned char *pS)
{
    if (pS == NULL)
    {
        return;
    }

    unsigned long long total = x;

    for (unsigned int i = 0; i < n; ++i) {
        // 𝑆[n - 1 - i] ← total mod 256
        pS[n - 1 - i] = (unsigned char)total & 0xff;

        // total ← total >> 8       ▷ least significant 8 bits of 𝑡𝑜𝑡𝑎𝑙
        total = total >> 8;
    }
}

/*

Based on the page 56 of the NIST FIPS 205 document (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf),

∥ concatenation

PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed))
F(PK.seed, ADRS, M_1) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ M_1))
H(PK.seed, ADRS, M_2) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ M_2))

*/

/**
 * Based on the SPHINCS+ reference implementation: https://github.com/sphincs/sphincsplus/blob/master/ref/hash_sha2.c#L39
 *
 * PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed))
 *
 * n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
 * p_pk_seed and p_sk_seed both are pointer to the first element of an array of length at least 16.
 */
void prf(const uint8_t *p_pk_seed, const uint8_t *p_sk_seed, const uint32_t *addr, unsigned char *p_out)
{
    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
    
    // p_pk_seed is a pointer to the first element of an array of length at least 16.
    // p_sk_seed is a pointer to the first element of an array of length at least 16.

    if (p_pk_seed == NULL || p_sk_seed == NULL || addr == NULL || p_out == NULL)
    {
        return;
    }

    //
    // PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed))
    //

    // toByte(0, 64 − n)
    unsigned char S[48];   // n: 16, 64 - n = 48
    toByte(0, 48, S);

    // PK.seed ∥ toByte(0, 64 − n)
    unsigned char combined[64];

    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
    unsigned int seed_len = 16;
    memcpy(combined, p_pk_seed, seed_len);
    memcpy(combined + seed_len, S, 48);

    // TODO
    
}

/**
 * F(PK.seed, ADRS, M_1) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ M_1))
 */
void F(const uint8_t *p_pk_seed, const uint32_t *addr, const uint8_t *p_M_1, unsigned char *p_out)
{
    if (p_pk_seed == NULL || addr == NULL || p_M_1 == NULL || p_out == NULL)
    {
        return;
    }

    // toByte(0, 64 − n)
    unsigned char S[48];   // n: 16, 64 - n = 48
    toByte(0, 48, S);

    // PK.seed ∥ toByte(0, 64 − n)
    unsigned char combined[64];

    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
    unsigned int seed_len = 16;
    memcpy(combined, p_pk_seed, seed_len);
    memcpy(combined + seed_len, S, 48);

    // TODO
}

/**
 * H(PK.seed, ADRS, M_2) = Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ M_2))
 */
void H(const uint8_t *p_pk_seed, const uint32_t *addr, const uint8_t *p_M_2, unsigned char *p_out)
{
    if (p_pk_seed == NULL || addr == NULL || p_M_2 == NULL || p_out == NULL)
    {
        return;
    }

    // toByte(0, 64 − n)
    unsigned char S[48];   // n: 16, 64 - n = 48
    toByte(0, 48, S);

    // PK.seed ∥ toByte(0, 64 − n)
    unsigned char combined[64];

    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
    unsigned int seed_len = 16;
    memcpy(combined, p_pk_seed, seed_len);
    memcpy(combined + seed_len, S, 48);

    // TODO
}

// start of ADRSc member function

void assign_bytes_c(const unsigned char *src, ADRSc adrs, unsigned int index, unsigned int len)
{
    for(unsigned int i = 0; i < len; ++i)
    {
        adrs[index++] = src[i];  // src[0], src[1], ..., src[len-1]
    }
}

void set_layer_addr_c(ADRSc adrs, unsigned int layer)
{
    if (adrs != NULL)
    {
        unsigned char S[1];
        toByte((unsigned long long)layer, 1, S);

        adrs[0] = S[0];
    }
}

void set_tree_height_c(ADRSc adrs, unsigned long long i)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);

        // ADRS[14:18]
        assign_bytes_c(S, adrs, 14, 4); // 14, 15, 16, 17
    }
}

void set_type_and_clear_c(ADRSc adrs, unsigned int Y)
{
    if (adrs != NULL)
    {
        unsigned char S[1];
        toByte((unsigned long long)Y, 1, S);

        // ADRS[0 ∶ 9] ∥ toByte(Y, 1) ∥ toByte(0, 12)
        adrs[9] = S[0];

        // toByte(0, 12)
        unsigned char zero[12];
        toByte(0, 12, zero);

        // ADRS[0 ∶ 9] ∥ toByte(Y, 1) ∥ toByte(0, 12)
        assign_bytes_c(zero, adrs, 10, 12);
    }
}

void set_key_pair_addr_c(ADRSc adrs, unsigned int i)
{
    if (adrs != NULL)
    {
        // TODO
    }
}

void set_tree_index_c(ADRSc adrs, unsigned int i)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);

        // ADRS[18:22]
        assign_bytes_c(S, adrs, 18, 4); // 18, 19, 20, 21
    }
}

// end of ADRSc member function


void assign_bytes(const unsigned char *src, ADRS adrs, unsigned int index, unsigned int len)
{
    for(unsigned int i = 0; i < len; ++i)
    {
        ((unsigned char*)adrs)[index++] = src[i];  // src[0], src[1], ..., src[len-1]
    }
}

/**
 * See https://github.com/sphincs/sphincsplus/blob/master/ref/address.c#L11
 *
 * ADRS = concat(toByte(l, 4), ADRS[4:32])
 * ADRS[4:32] means ADRS[4, 5, ..., 31]
 */
void set_layer_addr(ADRS adrs, unsigned int layer)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)layer, 4, S);

        // See page 22, Figure 2. Address (ADRS), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
        // ADRS[0:4] is layer address, ADRS[0,1,2,3]
        assign_bytes(S, adrs, 0, 4);
    }
}

/**
 * See https://github.com/sphincs/sphincsplus/blob/master/ref/address.c#L92
 * See page 24, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_tree_height(ADRS adrs, unsigned long long i)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);
    
        // ADRS[24:28]
        assign_bytes(S, adrs, 24, 4); // 24, 25, 26, 27
    }
}

/**
 * See page 24, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_type_and_clear(ADRS adrs, unsigned int Y)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)Y, 4, S);

        // ADRS[16:20], ADRS[16, 17, 18, 19]
        assign_bytes(S, adrs, 16, 4); // 16, 17, 18, 19

        toByte(0, 12, S);
        assign_bytes(S, adrs, 20, 12); // 20, 21, ..., 31
    }
}

/**
 * See page 24, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_key_pair_addr(ADRS adrs, unsigned int i)
{    
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);

        // ADRS[20:24], ADRS[20, 21, 22, 23]
        assign_bytes(S, adrs, 20, 4);   // 20, 21, 22, 23
    }
}

/**
 * See page 24, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_tree_index(ADRS adrs, unsigned int i)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);

        // ADRS[28:32], ADRS[28, 29, 30, 31]
        assign_bytes(S, adrs, 28, 4);   // 28, 29, 30, 31
    }
}
