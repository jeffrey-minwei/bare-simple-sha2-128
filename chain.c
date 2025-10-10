#include "common.h"
#include "addr.h"
#include "thf.h"

#include "chain.h"

#include <string.h>

/**
 * example:
 *     chain(out, sk_seed, i, s, pk_seed, adrs)
 */
void chain(uint8_t out[SPX_N],
           const uint8_t X[SPX_N], 
           const uint8_t i,
           const uint8_t s,
           const psa_key_id_t pk_seed, 
           ADRS adrs)
{
    // 1: tmp <- X
    memcpy(out, X, SPX_N);

    int last_idx = i + s - 1;
    for(unsigned int j = i; j < last_idx; ++j)
    {
        set_hash_addr(adrs, j);
        // 𝑡𝑚𝑝 ← F(PK.seed, ADRS,𝑡𝑚𝑝)
        F(pk_seed, adrs, out, out);
    }
}