#include <stdint.h>   // uint8_t
#include <string.h>   // memcpy

#include "thf.h"
#include "params.h"
#include "sha256.h"

//
// Tweakable Hash Function
//


// See Page 30, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
//
//  𝑛𝑜𝑑𝑒 ← F(PK.seed, ADRS, 𝑠𝑘)
//  𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)

void T(unsigned int len, const uint8_t pk_seed[SPX_N], ADRS adrs, const uint8_t *p_M, uint8_t out[SPX_N])
{
    // See Page 11, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    // Tℓ(PK.seed, ADRS, 𝑀ℓ) 
    // (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an ℓ𝑛-byte message to an 𝑛-byte message.

    // See Page 46, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    // Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))

    // ADRSc is a 22 bytes array
    // size of 𝔹ℓ𝑛 is ℓ*𝑛
    unsigned int mlen = len * SPX_N;
    unsigned int size = 64 + 22 + mlen;
    uint8_t buf[size];
   
    // PK.seed ∥ toByte(0, 64 − n)

    // n is 16 for SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f

    // buf <- PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ
    memcpy(buf, pk_seed, SPX_N);
    // toByte(0, 64 − n)
    unsigned char S[48];   // n: 16, 64 - n = 48
    toByte(0, 48, S);
    memcpy(buf + SPX_N, S, 48);

    // ADRSc is a 22 bytes array
    uint8_t adrs_c[22];
    compress_adrs(adrs_c, adrs);
    // ADRS𝑐
    memcpy(buf + SPX_N + sizeof(S), adrs_c, sizeof(adrs_c));

    // ADRS𝑐 ∥ 𝑀ℓ
    memcpy(buf + SPX_N + sizeof(S) + sizeof(adrs_c), p_M, mlen);

    // SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ)
    uint8_t out32[32];
    sha256(buf, sizeof(buf), out32);

    // Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
    memcpy(out, out32, 16);   // n is 16
}

// F: len = 1
void F(const uint8_t pk_seed[SPX_N], ADRS adrs, const uint8_t M[16], uint8_t out[SPX_N])
{
    T(1, pk_seed, adrs, (uint8_t *)M[0], out);
}

// H: len = 2
void H(const uint8_t pk_seed[SPX_N], ADRS adrs, const uint8_t M[32], uint8_t out[SPX_N])
{
    T(2, pk_seed, adrs, (uint8_t *)M[0], out);
}