#include "common.h"
#include "hal_rng.h"
#include "uart_min.h"

#include <stddef.h>
#include <string.h>

static void test_rng();

void test_common()
{
    unsigned char S[4];
    unsigned int len = 1;
    toByte((unsigned long long)len, 4, S);
    uarte0_hex("S", S, sizeof(S) / sizeof(S[0]));

    test_rng();

    ADRS adrs;
    unsigned long long i = 1;
    set_layer_addr(adrs, len);
    set_tree_height(adrs, i);

    unsigned int type = 4;  // FORS_ROOTS)
    set_type_and_clear(adrs, type);

    unsigned long long key_pair_addr = 2;
    set_key_pair_addr(adrs, key_pair_addr);

    unsigned long long chain_addr = 2;
    set_chain_addr(adrs, chain_addr);

    unsigned long long hash_addr = 20;
    set_hash_addr(adrs, hash_addr);

    unsigned int index = 3;
    set_tree_index(adrs, index);
}

static void test_rng()
{
    uint8_t sk_seed[SPX_N];
    uint8_t pk_seed[SPX_N];

    unsigned char entropy_input[48];
    for (int i=0; i<48; i++) {
        entropy_input[i] = i;
    }

    rng_init(entropy_input, NULL, 256);
    rng_bytes(sk_seed, SPX_N);
    rng_bytes(pk_seed, SPX_N);
    
    uarte0_hex("pk_seed", pk_seed, SPX_N);

    ADRS adrs;

    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
    uint8_t buf[SPX_N];
    prf(pk_seed, sk_seed, adrs, buf);

    uarte0_hex("prf store to buf", buf, SPX_N);
}

void compress_adrs(uint8_t c[22], const ADRS adrs)
{
    // ADRS𝑐 = ADRS[3] ∥ ADRS[8 ∶ 16] ∥ ADRS[19] ∥ ADRS[20 ∶ 32]
    c[0] = adrs[3];
    memcpy(c, adrs, 1);   // ADRS[3]

    memcpy(c + 1, adrs + 8, 8);   // ADRS[8 ∶ 16], len is 8
    c[9] = adrs[19];              // ... ∥ ADRS[19]

    memcpy(c + 10, adrs + 20, 12);  //  ∥ ADRS[20 ∶ 32], len is 12
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
void prf(const uint8_t pk_seed[SPX_N], const uint8_t sk_seed[SPX_N], const ADRS adrs, uint8_t out[SPX_N])
{    
    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f

    if (pk_seed == NULL || sk_seed == NULL || adrs == NULL || out == NULL)
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
        memcpy(adrs, S, 4); // 0, 1, 2, 3
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
        memcpy(adrs + 24, S, 4);   // 24, 25, 26, 27
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
        memcpy(((unsigned char *)adrs) + 16, S, 4);   // 16, 17, 18, 19

        toByte(0, 12, S);
        memcpy(adrs + 20, S, 12);  // 20, 21, ..., 31
    }
}

/**
 * key_pair_addr is 4 bytes
 */
unsigned long long get_key_pair_addr(ADRS adrs)
{
    unsigned char key_pair_addr[4];

    // ADRS[20:24], ADRS[20, 21, 22, 23]
    memcpy(key_pair_addr, adrs + 20, 4);  // 20, 21, 22, 23

    return toInt(key_pair_addr, 4);
}

/**
 * See page 12,13,14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_key_pair_addr(ADRS adrs, unsigned long long i)
{    
    if (adrs != NULL)
    {
        unsigned char key_pair_addr[4];
        toByte(i, 4, key_pair_addr);

        // ADRS[20:24], ADRS[20, 21, 22, 23]
        memcpy(adrs + 20, key_pair_addr, 4);  // 20, 21, 22, 23
    }
}

/**
 * See page 12,14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_chain_addr(ADRS adrs, unsigned long long i)
{
    if (adrs != NULL)
    {
        unsigned char chain_addr[4];
        toByte(i, 4, chain_addr);

        // ADRS[24:28], ADRS[24, 25, 26, 27]
        memcpy(adrs + 24, chain_addr, 4);   // 24, 25, 26, 27
    }
}

/**
 * See page 14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 * ADRS = concat(ADRS[0 ∶ 28], toByte(i, 4))
 */
void set_hash_addr(ADRS adrs, unsigned long long i)
{
    if (adrs != NULL)
    {
        unsigned char hash_addr[4];
        toByte(i, 4, hash_addr);

        // ADRS[28:32], ADRS[28, 29, 30, 31]
        memcpy(adrs + 28, hash_addr, 4);
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
        memcpy(adrs + 28, S, 4);     // 28, 29, 30, 31
    }
}

