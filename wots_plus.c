#include "common.h"
#include "uart_min.h"
#include "wots_plus.h"

#include <string.h>

void test_wots_plus()
{
    ADRS adrs_wots_hash;
    set_type_and_clear(adrs_wots_hash, WOTS_HASH);    // type = 0 (WOTS_HASH)
    
    ADRS adrs_wots_pk;
    set_type_and_clear(adrs_wots_pk, WOTS_PK);        // type = 1 (WOTS_PK)
    // ADRS[24:32], ADRS[24, 25, ..., 29, 30, 31]
    memset((unsigned char *)(adrs_wots_pk[24]), 0, 8);

    ADRS adrs_wots_prf;
    set_type_and_clear(adrs_wots_prf, WOTS_PRF);      // type = 5 (WOTS_PRF)
    set_hash_addr(adrs_wots_prf, 0);
}

/**
 * See Page 18, Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void wots_pk_gen(const unsigned char sk_seed[SPX_N], 
                 const unsigned char pk_seed[SPX_N], 
                 ADRS adrs)
{
    ADRS skADRS;
    memcpy(skADRS, adrs, 32);   // uint32_t[8] => 8 * 4 bytes = 32 bytes

    set_type_and_clear(skADRS, WOTS_PRF);   // type = 5 (WOTS_PRF)

    // 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    unsigned long long key_pair_addr = get_key_pair_addr(adrs);
    set_key_pair_addr(skADRS, key_pair_addr);

    // Page 17, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    // len = 2*n + 3, n = 16 => len = 2*16 + 3 = 35
    unsigned int len = 35;

    // Page 18, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    // 4: for 𝑖 from 0 to len − 1 do 
    for (unsigned int i = 0; i < len; ++i)
    {
        // 5:    skADRS.setChainAddress(i)
        set_chain_addr(skADRS, (unsigned long long)i);
        /* 
          6:     𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS)          ▷ compute secret value for chain i
          7:     ADRS.setChainAddress(𝑖) 
          8:     tmp[i] ← chain(sk, 0, w − 1, PK.seed, ADRS) ▷ compute public value for chain i
         */
    }
    // 9: end for 

    ADRS wotspkADRS;
    memcpy(wotspkADRS, adrs, 32);   // uint32_t[8] => 8 * 4 bytes = 32 bytes

    set_type_and_clear(wotspkADRS, WOTS_PK);   // type = 1 (WOTS_PK)
    // 12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    set_key_pair_addr(wotspkADRS, key_pair_addr);

    // TODO Page 18, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    // 13: pk ← T_len(PK.seed, wotspkADRS, tmp)     ▷ compress public key
    // 14: return pk
}

/**
 * See Page 20, Algorithm 7, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void wots_sign(N_BYTES out[SPX_LEN],
               const unsigned char *M, 
               const unsigned char sk_seed[SPX_N], 
               const unsigned char pk_seed[SPX_N], 
               ADRS adrs)
{
    ADRS skADRS;

    // 8: skADRS ← ADRS ▷ copy address to create key generation key address
    memcpy(skADRS, adrs, 32);

    // 9: skADRS.setTypeAndClear(WOTS_PRF)
    set_type_and_clear(skADRS, WOTS_PRF);

    // 10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    set_key_pair_addr(skADRS, get_key_pair_addr(adrs));

    uint8_t sk[SPX_N];
    for(int i = 0; i < SPX_LEN; ++i)
    {
        // skADRS.setChainAddress(𝑖)
        set_chain_addr(skADRS, i);

        // 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute chain 𝑖 secret value
        prf(pk_seed, sk_seed, skADRS, sk);

        // ADRS.setChainAddress(𝑖)
        set_chain_addr(adrs, i);

        // TODO
        //  𝑠𝑖𝑔[𝑖] ← chain(𝑠𝑘, 0, 𝑚𝑠𝑔[𝑖], PK.seed, ADRS) ▷ compute chain 𝑖 signature value
    }
}

