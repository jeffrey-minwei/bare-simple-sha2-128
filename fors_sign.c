#include "common.h"
#include "fors_sign.h"
#include "fors_sk_gen.h"
#include "thf.h"

#include "base_2b.h"
#include "sha256.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

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
                 const psa_key_id_t sk_seed, 
                 const psa_key_id_t pk_seed,
                 uint64_t tree_idx, 
                 uint32_t leaf_idx)
{

    // a will be 6, 8, 9, 12 or 14
    int a = 6;
    int k = 0;
    base_2b(NULL, a, k, NULL);

    // for i from 0 to k − 1 do        ▷ compute signature elements
    for (unsigned int i = 0; i < k; ++i)
    {
        // TODO not implemented yet
        // i_SIG_fors = fors_sk_gen(SK.seed, PK.seed, ADRS, i * (2^a) + p_indices[i])
        // SIG_fors = concat(SIG_fors, i_SIG_fors)

        // for j from 0 to a − 1 do     ▷ compute auth path
        for (unsigned int j = 0; j < a; ++j)
        {
            // s ← ⌊p_indices[i] / (2^j)⌋ ⊕ 1
            // AUTH[j] ← fors_node(SK.seed, i * (2 ^ (a−j) ) + s, j, PK.seed, ADRS)
        }

        // SIG_fors = concat(SIG_fors, AUTH)
    }

    toInt(NULL, 0);
    toByte(0, 0, NULL);
    prf(NULL, NULL, NULL, NULL);
    F(NULL, NULL, NULL, NULL);
    H(NULL, NULL, NULL, NULL);

    uint8_t h[32];

    // TODO not implemented yet
    // 把 mhash 做一次 sha256 當成 fors_root; 簽章長度回傳 0
    sha256(mhash, SPX_FORS_MSG_BYTES, h);
    memcpy(fors_root, h, SPX_N);
    (void)sig_ptr; (void)sk_seed; (void)pk_seed; (void)tree_idx; (void)leaf_idx;

    // TODO not implemented yet
    return 0;

}

