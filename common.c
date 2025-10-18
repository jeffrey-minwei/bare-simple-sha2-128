#include "common.h"
#include "psa/crypto.h"
#include "uart_min.h"

#include <stddef.h>
#include <string.h>

static void test_rng();

void test_common()
{
    unsigned char S[4];
    unsigned int len = 1;
    toByte((unsigned long long)len, 4, S);
#if defined(__x86_64__) || defined(__i386__)
// do nothing
#else
    uarte0_hex("S", S, sizeof(S) / sizeof(S[0]));
#endif

    test_rng();
}

static void test_rng()
{
    uint8_t sk_seed[SPX_N];
    uint8_t pk_seed[SPX_N];

    psa_generate_random(sk_seed, SPX_N);
    psa_generate_random(pk_seed, SPX_N);
    
#if defined(__x86_64__) || defined(__i386__)
// do nothing
#else
    uarte0_hex("pk_seed", pk_seed, SPX_N);
#endif

    ADRS adrs;

    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f
    uint8_t buf[SPX_N];
    prf(pk_seed, sk_seed, adrs, buf);
#if defined(__x86_64__) || defined(__i386__)
// do nothing
#else
    uarte0_hex("prf store to buf", buf, SPX_N);
#endif
}

/**

Based on the algorithm 4 listed on page 26 of the FIPS 205 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf),

Algorithm 4 base_2b(X, b, out_len)
Computes the base 2^b representation of X.
Input: Byte string X of length at least ⌈ (out_len*b) / 8 ⌉, integer b, output length out_len.
Output: Array of out_len integers in the range [0, … , 2b − 1].
1:  in = 0
2:  bits = 0
3:  total = 0
4:  for out from 0 to out_len − 1 do
5:      while bits < b do
6:          total = (total ≪ 8) + X[in]
7:          in = in + 1
8:          bits = bits + 8
9:      end while
10:     bits = bits - b
11:     baseb[out] = (total ≫ bits) mod 2^b
12: end for
13: return baseb

*/

/*
 * Based on the implementation listed on https://github.com/sphincs/sphincsplus/blob/master/ref/wots.c#L45, 
 *    and algorithm 4 listed on page 26 of the FIPS 205 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf),
 **/
void base_2b(const unsigned char *pX, 
             const int b, 
             const int out_len, 
             uint8_t baseb[SPX_K])
{
    if (baseb == NULL) return;

    int in = 0;
    int bits = 0;
    int total = 0;   

    for(int out = 0; out < out_len; out++)
    {
        while(bits < b)
        {
            total = (total << 8) + pX[in];
            in++;
            bits += 8;
        }

        // bits = bits - b
        bits -= b;

        // baseb[out] = (total ≫ bits) mod 2^b
        baseb[out] = (total >> bits) & ((1u << b) - 1u);
    }
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
    size_t olen = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, 
                                           combined, 
                                           sizeof(combined), 
                                           out32, 
                                           sizeof(out32), 
                                           &olen);

    // Trunc_n(SHA-256(PK.seed ∥ toByte(0, 64 − n) ∥ ADRS_c ∥ SK.seed))
    memcpy(out, out32, SPX_N);
}
