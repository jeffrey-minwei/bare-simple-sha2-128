// keygen.c — SLH-DSA (SPHINCS+) SHA2-128f-simple seed-only keygen (bare-metal)
// n = 16 bytes
// sk = sk_seed(16) || sk_prf(16) || pub_seed(16) || root(16)
// pk = root(16)    || pub_seed(16)
//
// - No I/O, no OS calls.
// - Uses only <string.h> (memcpy/memset) which is provided by libgcc/newlib-nano on bare-metal.
// - You supply RNG via function pointer; nothing global, no weak stubs.

#include "keygen.h"
#include <stdint.h>
#include <string.h>

static void sha256(const uint8_t *msg, size_t mlen, uint8_t out32[32])
{
    // TODO
}

static void h_pair_trunc(uint8_t out[SPX_N],
                         const uint8_t l[SPX_N],
                         const uint8_t r[SPX_N])
{
    uint8_t buf[SPX_N*2];
    uint8_t h[32];
    memcpy(buf,       l, SPX_N);
    memcpy(buf+SPX_N, r, SPX_N);
    sha256(buf, sizeof buf, h);
    memcpy(out, h, SPX_N); // 取前 N bytes
}

// 計算從 leaf + auth_path 一路往上到根
// root_out: SPX_N bytes
static void compute_root_minimal(uint8_t root_out[SPX_N],
                                 const uint8_t leaf[SPX_N],
                                 uint32_t leaf_idx,
                                 const uint8_t *auth_path, // 長度 = tree_height * SPX_N
                                 uint32_t tree_height)
{
    uint8_t cur[SPX_N];
    memcpy(cur, leaf, SPX_N);

    for(uint32_t h = 0; h < tree_height; ++h) {
        if (leaf_idx & 1) {
            // 當前節點在右側：hash(auth || cur)
            h_pair_trunc(cur, auth_path, cur);
        } else {
            // 當前節點在左側：hash(cur || auth)
            h_pair_trunc(cur, cur, auth_path);
        }
        auth_path += SPX_N;
        leaf_idx >>= 1;
    }
    memcpy(root_out, cur, SPX_N);
}

// Pack helper (inlined): lays out SK/PK exactly per spec.
static inline void spx_sha2_128f_pack(uint8_t *sk, uint8_t *pk,
                                      const uint8_t sk_seed[SPX_N],
                                      const uint8_t sk_prf[SPX_N],
                                      const uint8_t pub_seed[SPX_N],
                                      const uint8_t root[SPX_N]) {
    // sk = sk_seed || sk_prf || pub_seed || root
    memcpy(sk + 0 * SPX_N, sk_seed,  SPX_N);
    memcpy(sk + 1 * SPX_N, sk_prf,   SPX_N);
    memcpy(sk + 2 * SPX_N, pub_seed, SPX_N);
    memcpy(sk + 3 * SPX_N, root,     SPX_N);
    // pk = root || pub_seed
    memcpy(pk + 0 * SPX_N, root,     SPX_N);
    memcpy(pk + 1 * SPX_N, pub_seed, SPX_N);
}

// Seed-only key generation:
// - Fills sk_seed, sk_prf, pub_seed from provided RNG
// - Sets root to zero as a placeholder (real root computed later by your tree code)
// - Packs SK/PK per format
// Returns 0 on success, -1 on bad args.
int spx_sha2_128f_seed_keygen(uint8_t sk[SPX_SK_BYTES],
                              uint8_t pk[SPX_PK_BYTES],
                              spx_rng_fill_fn rng_fill) {
    if (!sk || !pk || !rng_fill) return -1;

    uint8_t sk_seed[SPX_N];
    uint8_t sk_prf[SPX_N];
    uint8_t pub_seed[SPX_N];
    uint8_t root[SPX_N];

    rng_fill(sk_seed,  SPX_N);
    rng_fill(sk_prf,   SPX_N);
    rng_fill(pub_seed, SPX_N);
    memset(root, 0, SPX_N);  // placeholder — compute real root later

    spx_sha2_128f_pack(sk, pk, sk_seed, sk_prf, pub_seed, root);
    return 0;
}

// 簡單 LFSR 當假 RNG
static uint32_t lfsr_state = 0xACE1u;
static void dummy_rng(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        lfsr_state = (lfsr_state >> 1) ^ (-(int)(lfsr_state & 1u) & 0xB400u);
        buf[i] = (uint8_t)(lfsr_state & 0xFFu);
    }
}

// Step 1: 產生隨機金鑰對
int generate_keypair(uint8_t sk[SPX_SK_BYTES], uint8_t pk[SPX_PK_BYTES]) {
    return spx_sha2_128f_seed_keygen(sk, pk, dummy_rng);
}

// Step 2: 寫入真實 root
void set_real_root(uint8_t sk[SPX_SK_BYTES], 
                   uint8_t pk[SPX_PK_BYTES],
                   uint8_t root[SPX_N],
                   const uint8_t *leaf,
                   uint32_t leaf_idx,
                   const uint8_t *auth_path,
                   uint32_t tree_height,
                   const uint8_t pub_seed[SPX_N]) {

    // root 在這裡被計算並回寫
    compute_root_minimal(root, leaf, leaf_idx, auth_path, tree_height);

    memcpy(sk + 3 * SPX_N, root, SPX_N); // SK tail
    memcpy(pk + 0 * SPX_N, root, SPX_N); // PK head
}