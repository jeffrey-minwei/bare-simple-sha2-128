#include "common.h"
#include "fors_sign.h"
#include "thf.h"
#include "uart_min.h"
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
                 const psa_key_id_t sk_key_id, 
                 const psa_key_id_t pk_key_id, 
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
    _prf(out, pk_key_id, sk_key_id, skADRS);
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
 * fors_sign(md, SK.seed, PK.seed, ADRS)
 */
size_t fors_sign(uint8_t out[SPX_FORS_SIG_LENGTH], 
                 const uint8_t md[SPX_FORS_MSG_BYTES],
                 const psa_key_id_t sk_seed_key_id, 
                 const psa_key_id_t pk_seed_key_id,
                 const ADRS adrs)
{
    // a will be 6, 8, 9, 12 or 14
    int a = SPX_A;
    int k = SPX_K;

    uint8_t indices[k];

    base_2b(md, a, k, indices);

    uint8_t *p = out;

    // for i from 0 to k − 1 do        ▷ compute signature elements
    for (unsigned int i = 0; i < k; ++i)
    {
        // i_SIG_fors = fors_sk_gen(SK.seed, PK.seed, ADRS, i * (2^a) + indices[i])
        uint8_t i_SIG_fors[SPX_N];
        // Output: n-byte FORS private-key value.
        fors_sk_gen(i_SIG_fors, sk_seed_key_id, pk_seed_key_id, adrs, i * (2^a) + indices[i]);

        // SIG_fors = concat(SIG_fors, i_SIG_fors)
        memcpy(p, i_SIG_fors, SPX_N);
        p += SPX_N;

        uint8_t auth[SPX_A][SPX_N];
        // for j from 0 to a − 1 do     ▷ compute auth path
        for (unsigned int j = 0; j < a; ++j)
        {
            // s ← ⌊indices[i] / (2^j)⌋ ⊕ 1
            const unsigned int W = (unsigned int)(8u * sizeof(unsigned int));
            unsigned int q = (j < W) ? (indices[i] >> j) : 0u;
            unsigned int s = (q ^ 1u);

            // AUTH[j] ← fors_node(SK.seed, i * (2 ^ (a−j) ) + s, j, PK.seed, ADRS)
            fors_node(auth[j], sk_seed_key_id, i * (2 ^ (a - j) ) + s, j, pk_seed_key_id, adrs);
        }
        // SIG_fors = concat(SIG_fors, AUTH)
        memcpy(p, (uint8_t *)(auth[0][0]), SPX_A * SPX_N);
        p += SPX_A * SPX_N;
    }
#ifdef X86
// do nothing
#else
    uarte0_puts("fors_sk_gen DONE\n");
#endif
    return 0;
}

/*
Algorithm 15 fors_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS)
Computes the root of a Merkle subtree of FORS public values.
Input: Secret seed SK.seed, target node index 𝑖, target node height 𝑧, public seed PK.seed, address ADRS.
Output: 𝑛-byte root 𝑛𝑜𝑑𝑒.
1: if 𝑧 = 0 then
2:    𝑠𝑘 ← fors_skGen(SK.seed, PK.seed, ADRS, 𝑖)
3:    ADRS.setTreeHeight(0)
4:    ADRS.setTreeIndex(𝑖)
5:    𝑛𝑜𝑑𝑒 ← F(PK.seed, ADRS, 𝑠𝑘)
6: else
7:    𝑙𝑛𝑜𝑑𝑒 ← fors_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
8:    𝑟𝑛𝑜𝑑𝑒 ← fors_node(SK.seed, 2𝑖 + 1, 𝑧 − 1, PK.seed, ADRS)
9:    ADRS.setTreeHeight(𝑧)
10:   ADRS.setTreeIndex(𝑖)
11:   𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)
12: end if
13: return 𝑛𝑜𝑑𝑒
*/
void fors_node(uint8_t out[SPX_N],
               const psa_key_id_t sk_seed_key_id, 
               unsigned int i, 
               unsigned int z, 
               const psa_key_id_t pk_seed_key_id, 
               ADRS adrs)
{
    if (z == 0)
    {
        // 2: 𝑠𝑘 ← fors_skGen(SK.seed, PK.seed, ADRS, 𝑖)
        uint8_t sk[SPX_N];
        fors_sk_gen(sk, sk_seed_key_id, pk_seed_key_id, adrs, i);

        // 3: ADRS.setTreeHeight(0)
        set_tree_height(adrs, 0);

        // 4: ADRS.setTreeIndex(𝑖)
        set_tree_index(adrs, i);

        // 5: 𝑛𝑜𝑑𝑒 ← F(PK.seed, ADRS, 𝑠𝑘)
        F(pk_seed_key_id, adrs, sk, out);
    }
    else
    {
        uint8_t lnode[SPX_N];
        fors_node(lnode, sk_seed_key_id, 2*i, z - 1, pk_seed_key_id, adrs);

        uint8_t rnode[SPX_N];
        fors_node(rnode, sk_seed_key_id, 2*i + 1, z - 1, pk_seed_key_id, adrs);

        // 9:   ADRS.setTreeHeight(𝑧)
        set_tree_height(adrs, z);
        // 10:  ADRS.setTreeIndex(𝑖)
        set_tree_index(adrs, i);

        uint8_t l_add_r[2*SPX_N];
        // 11:  𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)
        H(pk_seed_key_id, adrs, l_add_r, out);
    }
}


