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
    for (int j = 0; j < 9; ++j) // h′=h/d=9
    {
        // 𝑘 ← ⌊𝑖𝑑𝑥/2^𝑗⌋ ⊕ 1
        // AUTH[𝑗] ← xmss_node(SK.seed, 𝑘, 𝑗, PK.seed, ADRS)
    }
    set_type_and_clear(adrs, WOTS_HASH);
    // 6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
    set_key_pair_addr(adrs, idx);

    N_BYTES sig[SPX_LEN];

    // 7: 𝑠𝑖𝑔 ← wots_sign(𝑀, SK.seed, PK.seed, ADRS)
    wots_sign(sig, M, sk_seed, pk_seed, adrs);
    memcpy(out, sig, SPX_LEN * N_BYTES);

    memcpy(out + SPX_LEN * N_BYTES, AUTH, 9);  // h′=h/d=9
}