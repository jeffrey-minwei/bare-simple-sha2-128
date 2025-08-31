#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SPX_TREE_HEIGHT 8   // 例如 8 層 Merkle 樹

enum { SPX_N = 16 };
enum { SPX_SK_BYTES = 4 * SPX_N };  // 64
enum { SPX_PK_BYTES = 2 * SPX_N };  // 32

// Compile-time sanity (C11 or newer); safe to remove on older compilers.
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(SPX_N == 16, "This file targets SHA2-128f-simple (n=16).");
_Static_assert(SPX_SK_BYTES == 64, "SK size must be 64 bytes.");
_Static_assert(SPX_PK_BYTES == 32, "PK size must be 32 bytes.");
#endif

// RNG callback: must fill 'len' random bytes into 'buf'.
typedef void (*spx_rng_fill_fn)(uint8_t *buf, size_t len);

int  generate_keypair(uint8_t sk[SPX_SK_BYTES], uint8_t pk[SPX_PK_BYTES]);

void set_real_root(uint8_t sk[SPX_SK_BYTES], 
                   uint8_t pk[SPX_PK_BYTES],
                   uint8_t root[SPX_N],
                   const uint8_t *leaf,
                   uint32_t leaf_idx,
                   const uint8_t *auth_path,
                   uint32_t tree_height,
                   const uint8_t pub_seed[SPX_N]);

#endif
