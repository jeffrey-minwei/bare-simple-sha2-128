#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../sha256.h"
#include "../uart_min.h"

/**
 * return 0 if all equals
 */
int eq(uint8_t *a, uint8_t *b, unsigned int len)
{
    for(int i = 0; i < len; ++i)
    {
        if (a[i] != b[i])
        {
            // not equals
            return 1;
        }
    }
    // all equals
    return 0;
}

void test_sha256()
{
    uarte0_puts("start test sha256\n");

    // Known-answer tests (KAT) from NIST / RFC 6234.
    static const uint8_t exp_empty[32] = {
        0xE3,0xB0,0xC4,0x42,0x98,0xFC,0x1C,0x14,
        0x9A,0xFB,0xF4,0xC8,0x99,0x6F,0xB9,0x24,
        0x27,0xAE,0x41,0xE4,0x64,0x9B,0x93,0x4C,
        0xA4,0x95,0x99,0x1B,0x78,0x52,0xB8,0x55
    };
    static const uint8_t exp_abc[32] = {
        0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,
        0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
        0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,
        0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
    };

    static const char abc[] = "abc";

    uint8_t out32[32];
    sha256(abc, sizeof(abc) - 1, out32);
    uarte0_hex("sha256 result", out32, sizeof(out32) / sizeof(out32[0]));

    if (0 != eq(out32, exp_abc, sizeof(exp_abc)))
    {
        uarte0_puts("test sha256 FAIL\n");
        return;
    }
    uarte0_puts("test sha256(\"abc\") PASS\n");

    sha256("", 0, out32);
    if (0 != eq(out32, exp_empty, sizeof(exp_empty)))
    {
        uarte0_puts("test sha256 FAIL\n");
        return;
    }
    uarte0_puts("test sha256(\"\") PASS\n");
}

static inline uint32_t rotr(uint32_t x, uint32_t n){ return (x >> n) | (x << (32U - n)); }
static inline uint32_t Ch (uint32_t x, uint32_t y, uint32_t z){ return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){ return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t BSIG0(uint32_t x){ return rotr(x, 2) ^ rotr(x,13) ^ rotr(x,22); }
static inline uint32_t BSIG1(uint32_t x){ return rotr(x, 6) ^ rotr(x,11) ^ rotr(x,25); }
static inline uint32_t SSIG0(uint32_t x){ return rotr(x, 7) ^ rotr(x,18) ^ (x >> 3); }
static inline uint32_t SSIG1(uint32_t x){ return rotr(x,17) ^ rotr(x,19) ^ (x >>10); }

static const uint32_t K[64] = {
  0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
  0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
  0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
  0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
  0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
  0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
  0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
  0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static inline uint32_t rd_be32(const uint8_t b[4]){
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}
static inline void wr_be32(uint8_t out[4], uint32_t w){
    out[0]=(uint8_t)(w>>24); out[1]=(uint8_t)(w>>16); out[2]=(uint8_t)(w>>8); out[3]=(uint8_t)w;
}
static inline void wr_be64(uint8_t out[8], uint64_t w){
    out[0]=(uint8_t)(w>>56); out[1]=(uint8_t)(w>>48); out[2]=(uint8_t)(w>>40); out[3]=(uint8_t)(w>>32);
    out[4]=(uint8_t)(w>>24); out[5]=(uint8_t)(w>>16); out[6]=(uint8_t)(w>> 8); out[7]=(uint8_t)(w    );
}

static void compress(uint32_t H[8], const uint8_t block[64]){
    uint32_t W[64];
    for(int i=0;i<16;i++) W[i] = rd_be32(block + 4*i);
    for(int i=16;i<64;i++) W[i] = SSIG1(W[i-2]) + W[i-7] + SSIG0(W[i-15]) + W[i-16];

    uint32_t a=H[0], b=H[1], c=H[2], d=H[3], e=H[4], f=H[5], g=H[6], h=H[7];
    for(int i=0;i<64;i++){
        uint32_t T1 = h + BSIG1(e) + Ch(e,f,g) + K[i] + W[i];
        uint32_t T2 = BSIG0(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d + T1; d=c; c=b; b=a; a=T1 + T2;
    }
    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

void sha256(const uint8_t *msg, size_t mlen, uint8_t out32[32]) {
    uint32_t H[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };

    uint64_t total_len = 0; // bytes processed

    // process full blocks
    while(mlen >= 64){
        compress(H, msg);
        msg  += 64;
        mlen -= 64;
        total_len += 64;
    }

    // final padding
    uint8_t block[64];
    memset(block, 0, sizeof block);
    if(mlen) memcpy(block, msg, mlen);
    block[mlen] = 0x80;

    total_len += mlen;
    uint64_t bitlen = total_len * 8ULL;

    if(mlen >= 56){
        // no room for length; compress this block first
        compress(H, block);
        memset(block, 0, sizeof block);
    }
    // append 64-bit big-endian message length
    wr_be64(block + 56, bitlen);
    compress(H, block);

    // write output (big-endian)
    for(int i=0;i<8;i++) wr_be32(out32 + 4*i, H[i]);
}