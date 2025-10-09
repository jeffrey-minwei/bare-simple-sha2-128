#include "hmac_sha256.h"

/* --- 32-bit ops --- */
static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t shr (uint32_t x, uint32_t n) { return x >> n; }
static inline uint32_t Ch  (uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t Maj (uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t BSIG0(uint32_t x){ return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
static inline uint32_t BSIG1(uint32_t x){ return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
static inline uint32_t SSIG0(uint32_t x){ return rotr(x,7) ^ rotr(x,18) ^ shr(x,3); }
static inline uint32_t SSIG1(uint32_t x){ return rotr(x,17) ^ rotr(x,19) ^ shr(x,10); }

/* --- constants --- */
static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

/* --- endian helpers (big-endian per spec) --- */
static inline uint32_t load_be32(const uint8_t *p){
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void store_be32(uint8_t *p, uint32_t v){
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)(v);
}
static inline void store_be64(uint8_t *p, uint64_t v){
    for (int i = 7; i >= 0; --i) { p[7 - i] = (uint8_t)(v >> (i * 8)); }
}

/* --- core transform --- */
static void sha256_compress(sha256_ctx *c, const uint8_t block[64]){
    uint32_t W[64];
    for (int i = 0; i < 16; i++) W[i] = load_be32(block + 4*i);
    for (int i = 16; i < 64; i++) W[i] = SSIG1(W[i-2]) + W[i-7] + SSIG0(W[i-15]) + W[i-16];

    uint32_t a=c->s[0], b=c->s[1], c0=c->s[2], d=c->s[3];
    uint32_t e=c->s[4], f=c->s[5], g=c->s[6], h=c->s[7];

    for (int i = 0; i < 64; i++){
        uint32_t T1 = h + BSIG1(e) + Ch(e,f,g) + K[i] + W[i];
        uint32_t T2 = BSIG0(a) + Maj(a,b,c0);
        h = g; g = f; f = e; e = d + T1;
        d = c0; c0 = b; b = a; a = T1 + T2;
    }

    c->s[0] += a; c->s[1] += b; c->s[2] += c0; c->s[3] += d;
    c->s[4] += e; c->s[5] += f; c->s[6] += g; c->s[7] += h;
}

/* --- public API --- */
void sha256_init(sha256_ctx *c){
    c->s[0]=0x6a09e667u; c->s[1]=0xbb67ae85u; c->s[2]=0x3c6ef372u; c->s[3]=0xa54ff53au;
    c->s[4]=0x510e527fu; c->s[5]=0x9b05688cu; c->s[6]=0x1f83d9abu; c->s[7]=0x5be0cd19u;
    c->bits = 0;
    c->idx  = 0;
}

void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n){
    if (n == 0) return;

    /* update bit length (mod 2^64) */
    c->bits += ((uint64_t)n) * 8u;

    /* consume partial -> full blocks */
    if (c->idx){
        size_t need = SHA256_BLOCK_SIZE - c->idx;
        if (n < need){
            memcpy(c->buf + c->idx, p, n);
            c->idx += n;
            return;
        }
        memcpy(c->buf + c->idx, p, need);
        sha256_compress(c, c->buf);
        p += need; n -= need; c->idx = 0;
    }
    /* full blocks directly */
    while (n >= SHA256_BLOCK_SIZE){
        sha256_compress(c, p);
        p += SHA256_BLOCK_SIZE;
        n -= SHA256_BLOCK_SIZE;
    }
    /* leftover */
    if (n){
        memcpy(c->buf, p, n);
        c->idx = n;
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_SIZE]){
    /* padding: 0x80 then zeros, then 64-bit length (be) */
    uint8_t pad[SHA256_BLOCK_SIZE + 8]; /* enough for worst case */
    size_t pad_len;
    size_t i;

    /* append 0x80 */
    pad[0] = 0x80;
    /* number of bytes currently in buffer */
    size_t cur = c->idx;

    /* how much zero padding? we need to leave 8 bytes for length */
    size_t pad_zero;
    if (cur <= 55){
        pad_zero = 55 - cur;
        pad_len  = 1 + pad_zero + 8;
    } else {
        pad_zero = 63 - cur;
        pad_len  = 1 + pad_zero + 8 + 64; /* one extra block */
    }

    /* zeros after 0x80 until length field */
    for (i = 1; i < 1 + pad_zero; i++) pad[i] = 0x00;

    /* length (in bits), big-endian at the end of the last block */
    uint8_t len_be[8];
    store_be64(len_be, c->bits);

    if (cur <= 55){
        /* put length in current block tail */
        sha256_update(c, pad, 1 + pad_zero);
        sha256_update(c, len_be, 8);
    } else {
        /* fill current block, compress, then zeros of new block until length */
        sha256_update(c, pad, 1 + pad_zero);
        /* start new block: zeros until last 8 bytes */
        uint8_t z[56]; memset(z, 0, sizeof(z));
        sha256_update(c, z, sizeof(z));
        sha256_update(c, len_be, 8);
    }

    /* output */
    for (i = 0; i < 8; i++) store_be32(out + 4*i, c->s[i]);

    /* zeroize context (optional, security hygiene) */
    memset(c, 0, sizeof(*c));
}

static void mem_xor(uint8_t *dst, const uint8_t *a, uint8_t b, size_t n) {
    for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)(a[i] ^ b);
}

static void secure_bzero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t*)p;
    while (n--) *v++ = 0;
}


void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA256_DIGEST_SIZE])
{
    uint8_t k0[SHA256_BLOCK_SIZE];
    uint8_t tmp[SHA256_DIGEST_SIZE];
    uint8_t ipad[SHA256_BLOCK_SIZE], opad[SHA256_BLOCK_SIZE];
    sha256_ctx ctx;

    /* 1) key 規範化：> block 就先雜湊；< block 就右側補零 */
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, tmp);
        memset(k0, 0, sizeof(k0));
        memcpy(k0, tmp, SHA256_DIGEST_SIZE);
    } else {
        memset(k0, 0, sizeof(k0));
        memcpy(k0, key, key_len);
    }

    /* 2) 準備 ipad/opad */
    mem_xor(ipad, k0, 0x36, SHA256_BLOCK_SIZE);
    mem_xor(opad, k0, 0x5c, SHA256_BLOCK_SIZE);

    /* 3) 內層：H((K^ipad) || msg) */
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, msg,  msg_len);
    sha256_final(&ctx, tmp);

    /* 4) 外層：H((K^opad) || 內層雜湊) */
    sha256_init(&ctx);
    sha256_update(&ctx, opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, tmp,  SHA256_DIGEST_SIZE);
    sha256_final(&ctx, out);

    /* 5) 清理敏感緩衝區 */
    secure_bzero(k0, sizeof(k0));
    secure_bzero(tmp, sizeof(tmp));
    secure_bzero(ipad, sizeof(ipad));
    secure_bzero(opad, sizeof(opad));
    secure_bzero(&ctx, sizeof(ctx));
}