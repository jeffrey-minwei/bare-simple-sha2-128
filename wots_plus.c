#include "common.h"
#include "addr.h"
#include "uart_min.h"
#include "wots_plus.h"

#include "thf.h"

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
 * example:
 *     𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute secret value for chain 𝑖
 *     chain(out, 𝑠𝑘, i, s, pk_seed, adrs)
 */
void _chain(uint8_t out[SPX_N],
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

/**
 * See Page 18, Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 * @param pk      [out] WOTS+ public key 𝑝𝑘.
 * @param sk_seed [in] 
 * @param pk_seed [in] 
 * @return void
 */
void wots_pk_gen(uint8_t pk[SPX_N],
                 const psa_key_id_t sk_seed, 
                 const psa_key_id_t pk_seed, 
                 ADRS adrs)
{
    ADRS skADRS;
    memcpy(skADRS, adrs, 32);   // uint32_t[8] => 8 * 4 bytes = 32 bytes

    set_type_and_clear(skADRS, WOTS_PRF);   // type = 5 (WOTS_PRF)

    // 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    unsigned long long key_pair_addr = get_key_pair_addr(adrs);
    set_key_pair_addr(skADRS, key_pair_addr);

    // Page 17, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    // 𝑙𝑔𝑤 is 4 for all parameter sets in this standard
    // SPX_LEN = 2*n + 3, n = 16 => len = 2*16 + 3 = 35

    // Page 18, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    // 4: for 𝑖 from 0 to len − 1 do 
    N_BYTES tmp[SPX_LEN];

    uint8_t sk[SPX_N];
    int w = 16;  //  𝑤 = 2^lgw
    for (unsigned int i = 0; i < SPX_LEN; ++i)
    {
        // 5:    skADRS.setChainAddress(i)
        set_chain_addr(skADRS, (unsigned long long)i);

        // 6:     𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS)          ▷ compute secret value for chain i
        _prf(sk, pk_seed, sk_seed, skADRS);

        // 7:     ADRS.setChainAddress(𝑖) 
        set_chain_addr(adrs, i);

        // 8:     tmp[i] ← chain(sk, 0, w - 1, PK.seed, ADRS) ▷ compute public value for chain i
        _chain(tmp[i], sk, 0, w - 1, pk_seed, adrs);
    }

    ADRS wotspkADRS;
    memcpy(wotspkADRS, adrs, 32);   // uint32_t[8] => 8 * 4 bytes = 32 bytes

    set_type_and_clear(wotspkADRS, WOTS_PK);   // type = 1 (WOTS_PK)
    // 12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    set_key_pair_addr(wotspkADRS, key_pair_addr);

    // Page 18, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    // 13: pk ← T_len(PK.seed, wotspkADRS, tmp)     ▷ compress public key
    T(SPX_LEN, pk_seed, wotspkADRS, (const uint8_t *)tmp, pk);  // pk is a n length array
}

static size_t bytes_for_len2_lgw(size_t len2, size_t lgw) {
    uint64_t bits = (uint64_t)len2 * (uint64_t)lgw;
    return (size_t)((bits + 7u) >> 3);
}

/**
 * See Page 20, Algorithm 7, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void wots_sign(N_BYTES out[SPX_LEN],
               const uint8_t M[SPX_N], 
               const psa_key_id_t sk_seed, 
               const psa_key_id_t pk_seed, 
               ADRS adrs)
{
    // 𝑐𝑠𝑢𝑚 ← 0
    unsigned int csum = 0;

    uint8_t msg[SPX_LEN];
    int lgw = 4;
    int len1 = 32;
    // 𝑚𝑠𝑔 ← base_2b(𝑀, 𝑙𝑔𝑤, 𝑙𝑒𝑛1)
    // base_2b output: Array of 𝑜𝑢𝑡_𝑙𝑒𝑛 integers in the range [0, … , 2^𝑏 − 1].
    base_2b(M, lgw, len1, msg);   

    int w = 16;
    // 3: for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
    for (int i = 0; i < len1; ++i) {
        // 4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
        csum <<= (csum + w - 1 - msg[i]);
    }

    int len2 = 3;
    // 6: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8)             ▷ for 𝑙𝑔𝑤 = 4, left shift by 4
    csum <<= ((8 - ((len2 * lgw) % 8)) % 8);

    // toByte(𝑐𝑠𝑢𝑚, ⌈(𝑙𝑒𝑛2⋅𝑙𝑔𝑤)/8⌉)
    uint8_t byte_arr_len = 2; // ⌈(len2⋅lgw)/8⌉;, len2 * lgw = 3 * 4 = 12
    uint8_t byte_arr[byte_arr_len];
    toByte(csum, byte_arr_len, byte_arr);

    // base_2b(M, lgw, len1, msg);
    // 7: 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte(𝑐𝑠𝑢𝑚, ⌈(𝑙𝑒𝑛2⋅𝑙𝑔𝑤)/8⌉), 𝑙𝑔𝑤, 𝑙𝑒𝑛2) ▷ convert to base w
    int size = 1u << lgw;
    uint8_t tmp_msg[size];
    base_2b(byte_arr, lgw, len2, tmp_msg);
    memcpy( ((uint8_t *)msg[0] + size), tmp_msg, sizeof(tmp_msg));

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
        _prf(sk, pk_seed, sk_seed, skADRS);

        // ADRS.setChainAddress(𝑖)
        set_chain_addr(adrs, i);

        // 𝑠𝑖𝑔[𝑖] ← chain(𝑠𝑘, 0, 𝑚𝑠𝑔[𝑖], PK.seed, ADRS) ▷ compute chain 𝑖 signature value
        // chain(uint8_t out[SPX_N], ...
        _chain(out[i], sk, 0, msg[i], pk_seed, adrs);
    }
}
