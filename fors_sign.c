#include "common.h"
#include "fors_sign.h"
#include "fors_sk_gen.h"
#include "thf.h"

#include "base_2b.h"
#include "sha256.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
Algorithm 14 fors_skGen(SK.seed, PK.seed, ADRS, idx)

Generates a FORS private-key value.

Input: Secret seed SK.seed, public seed PK.seed, address ADRS, secret key index idx.
Output: n-byte FORS private-key value.
1: skADRS ← ADRS ▷ copy address to create key generation address
2: skADRS.setTypeAndClear(FORS_PRF)
3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
4: skADRS.setTreeIndex(idx)
5: return PRF(PK.seed, SK.seed, skADRS)
*/
void fors_sk_gen(uint8_t out[SPX_N],
                 const psa_key_id_t sk_seed, 
                 const psa_key_id_t pk_seed, 
                 const ADRS adrs, 
                 const unsigned int idx)
{
    // skADRS ← ADRS ▷ copy address to create key generation address
    ADRS skADRS;
    memcpy(skADRS, adrs, 32);   // ADRS  = 32 bytes

    // skADRS.setTypeAndClear(FORS_PRF)
    set_type_and_clear(skADRS, FORS_PRF);

    // skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    set_key_pair_addr(skADRS, get_key_pair_addr(adrs));

    // skADRS.setTreeIndex(idx)
    set_tree_index(skADRS, idx);

    // PRF(PK.seed, SK.seed, skADRS)
    _prf(out, pk_seed, sk_seed, skADRS);

    uarte0_puts("fors_sk_gen DONE\n");
}

/**

Based on the algorithm 16 listed on page 41 of the NIST FIPS 205 document (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf),

Algorithm 16 fors_sign(md, SK.seed, PK.seed, ADRS)
Generates a FORS signature.
Input: Message digest md, secret seed SK.seed, address ADRS, public seed PK.seed.
Output: FORS signature SIG_fors.
1: SIG_fors = NULL  ▷ initialize SIG_fors as a zero-length byte string
2: base_2b(md, a, k, p_indices)    // p_indices is unsigned int *
3: for i from 0 to k − 1 do        ▷ compute signature elements
       i_SIG_fors = fors_sk_gen(SK.seed, PK.seed, ADRS, i * (2^a) + p_indices[i])
4:     SIG_fors = concat(SIG_fors, i_SIG_fors)

5:     for j from 0 to a − 1 do     ▷ compute auth path
6:         s ← ⌊p_indices[i] / (2^j)⌋ ⊕ 1
7:         AUTH[j] ← fors_node(SK.seed, i * (2 ^ (a−j) ) + s, j, PK.seed, ADRS)
8:     end for
9:     SIG_fors = concat(SIG_fors, AUTH)
10: end for
11: return SIG_fors

So, we have to implement base_2b, fors_sk_gen, and fors_node before fors_sign can actually sign.
line 2: base_2b(md, a, k, p_indices), a will be 6, 8, 9, 12 or 14
*/

/**
 * TODO not implemented yet
 * 把 mhash 做一次 sha256 當成 fors_root; 簽章長度回傳 0
 */
size_t fors_sign(uint8_t *sig_ptr, 
                 uint8_t fors_root[SPX_N],
                 const uint8_t mhash[SPX_FORS_MSG_BYTES],
                 const psa_key_id_t sk_key_id, 
                 const psa_key_id_t pk_key_id,
                 uint64_t tree_idx, 
                 uint32_t leaf_idx)
{
    // a will be 6, 8, 9, 12 or 14
    int a = 12;
    int k = 14;

    uint8_t indices[k];
    unsigned char md[21] = {
        0xa3,0x7c,0x05,0xd1,0x9e,0x42,0xb8,0x6f,0x00,0x13,0xc4,
        0x2a,0x59,0x87,0xee,0x31,0x74,0x0b,0x9a,0x26,0xf5
    };
    base_2b(md, a, k, indices);

    ADRS adrs;

    int accumulate_size = 0;

    // for i from 0 to k − 1 do        ▷ compute signature elements
    for (unsigned int i = 0; i < k; ++i)
    {
        // i_SIG_fors = fors_sk_gen(SK.seed, PK.seed, ADRS, i * (2^a) + indices[i])
        uint8_t i_SIG_fors[SPX_N];
        // Output: n-byte FORS private-key value.
        fors_sk_gen(i_SIG_fors, sk_seed, pk_seed, adrs, i * (2^a) + indices[i]);

        // SIG_fors = concat(SIG_fors, i_SIG_fors)
        memcpy(p + accumulate_size, i_SIG_fors, SPX_N);
        accumulate_size += SPX_N;

        // for j from 0 to a − 1 do     ▷ compute auth path
        for (unsigned int j = 0; j < a; ++j)
        {
            // TODO not implemented yet
            // s ← ⌊p_indices[i] / (2^j)⌋ ⊕ 1
            // AUTH[j] ← fors_node(SK.seed, i * (2 ^ (a−j) ) + s, j, PK.seed, ADRS)
        }

        // SIG_fors = concat(SIG_fors, AUTH)
    }

    uint8_t h[32];

    // TODO not implemented yet
    // 把 mhash 做一次 sha256 當成 fors_root; 簽章長度回傳 0
    sha256(mhash, SPX_FORS_MSG_BYTES, h);
    memcpy(fors_root, h, SPX_N);

    // TODO not implemented yet
    return 0;
}

