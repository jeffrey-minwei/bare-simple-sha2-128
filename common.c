#include "common.h"
#include "uart_min.h"

#include <stddef.h>

void test_common()
{
    unsigned char S[4];
    unsigned int len = 1;
    toByte((unsigned long long)len, 4, S);
    uarte0_hex("S", S, sizeof(S));


    ADRS adrs;
    unsigned long long i = 1;
    set_layer_addr(adrs, len);
    set_tree_height(adrs, i);
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

    // TODO
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
        // ADRS[0] is layer address, which length is 4 bytes
        ((unsigned char*)adrs)[0] = S;
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
    
        // ...
        // ADRS[6] is ADRS[24:28]
        // ADRS[7] is ADRS[28:32]
        ((unsigned char*)adrs)[6] = S;
    }
}
