#include "common.h"
#include "addr.h"
#include "xmss_sign.h"
#include "wots_plus.h"

/**
    Algorithm 10 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)

    Generates an XMSS signature.
    Input: 𝑛-byte message 𝑀, secret seed SK.seed, index 𝑖𝑑𝑥, public seed PK.seed,
    address ADRS.
    Output: XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH).
    1: for 𝑗 from 0 to ℎ′ − 1 do ▷ build authentication path
    2:    𝑘 ← ⌊𝑖𝑑𝑥/2^𝑗⌋ ⊕ 1
    3:    AUTH[𝑗] ← xmss_node(SK.seed, 𝑘, 𝑗, PK.seed, ADRS)
    4: end for
    5: ADRS.setTypeAndClear(WOTS_HASH)
    6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
    7: 𝑠𝑖𝑔 ← wots_sign(𝑀, SK.seed, PK.seed, ADRS)
    8: SIG𝑋𝑀𝑆𝑆 ← 𝑠𝑖𝑔 ∥ A
    9: return SIGxmss
 */
void xmss_sign(N_BYTES out[SPX_XMSS_LEN],
               const uint8_t M[SPX_N], 
               const unsigned char sk_seed[SPX_N], 
               uint8_t idx,
               const unsigned char pk_seed[SPX_N], 
               ADRS adrs)
{

    // h′ = h/d = 9
    uint8_t auth[9][SPX_N];

    // h′ = h/d = 9
    for(int j = 0; j < 9; ++j)
    {
        // 𝑘 ← ⌊𝑖𝑑𝑥/2^𝑗⌋ ⊕ 1
        unsigned int k = (idx >> j) ^ 1u;

        // AUTH[𝑗] ← xmss_node(SK.seed, 𝑘, 𝑗, PK.seed, ADRS)
        xmss_node(auth+j, sk_seed, k, j, pk_seed, adrs);
    }

    // 5: ADRS.setTypeAndClear(WOTS_HASH)
    set_type_and_clear(adrs, WOTS_HASH);

    // 6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
    set_key_pair_addr(adrs, idx);

    // 7: 𝑠𝑖𝑔 ← wots_sign(𝑀, SK.seed, PK.seed, ADRS)
    wots_sign(out, M, sk_seed, pk_seed, adrs);

    // size of sig is len * n bytes
    // len = 35, for SLH-DSA-SHA2-128s
    // out ← WOTS+ signature ∥ AUTH
    memcpy((uint8_t *)(out + 35), (uint8_t *)(auth[0][0]), sizeof(auth));
}