// slh_dsa_sign.c

#include "psa/crypto.h"
#include "sha256.h"
#include "slh_dsa_sign.h"
#include "fors_sign.h"

#include <stdint.h>
#include <string.h>

// 你專案裡的參數
// SPX_N, SPX_SK_BYTES, SPX_PK_BYTES, SPX_BYTES, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_MSG_BYTES

static void prf_msg(uint8_t R[SPX_N],
                    psa_key_id_t sk_prf_key_id,
                    const uint8_t optrand[SPX_N],
                    const uint8_t *m, 
                    size_t mlen)
{
    uint8_t opt_rand_M[SPX_N + mlen];
    memcpy(opt_rand_M, optrand, SPX_N);
    memcpy(opt_rand_M + SPX_N, m, mlen);

    uint8_t hmac_sha256_out[32];
    size_t mac_len = 0;
    //hmac_sha256(hmac_sha256_out, sk_prf, SPX_N, opt_rand_M, sizeof(opt_rand_M));
    psa_status_t status = psa_mac_compute(sk_prf_key_id, 
                                          PSA_ALG_HMAC(PSA_ALG_SHA_256), 
                                          opt_rand_M, sizeof(opt_rand_M) - 1, 
                                          hmac_sha256_out, sizeof(hmac_sha256_out),
                                          &mac_len);
    if (status != PSA_SUCCESS) { 
        uarte0_puts("psa_mac_compute fail");
        for(;;);  // 失敗停在這裡
    }

    memcpy(R, hmac_sha256_out, SPX_N);
}

/* 主簽章：把 R、FORS、各層 WOTS+ 與 auth path 串起來 */
int slh_dsa_sign(uint8_t sig_out[SPX_BYTES],
                 const uint8_t sk[SPX_SK_BYTES],
                 const uint8_t pk[SPX_PK_BYTES],
                 const uint8_t *m, size_t mlen,
                 const uint8_t optrand[SPX_N])
{
    const uint8_t *SK_SEED  = sk + 0*SPX_N;
    const uint8_t *SK_PRF   = sk + 1*SPX_N;
    const uint8_t *PUB_SEED = sk + 2*SPX_N;

    uint8_t *p = sig_out;

    uint8_t R[SPX_N];
    // 𝑅 ← PRF_𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 )
    // TODO sk_prf_key_id should be passed from parameter of slh_dsa_sign
    psa_key_id_t sk_prf_key_id;
    prf_msg(R, sk_prf_key_id, optrand, m, mlen);
    memcpy(p, R, SPX_N);
    p += SPX_N;

    uint8_t node[SPX_N];
    // TODO sk_seed should be passed from parameter of slh_dsa_sign
    // TODO pk_seed should be passed from parameter of slh_dsa_sign
    psa_key_id_t sk_seed;
    psa_key_id_t pk_key_id;

    // 5: 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) ▷ compute message digest
    uint8_t out[SPX_M];
    h_msg(out, R, pk_key_id, m, mlen);

    // 14: SIG_FORS ← fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
    // 15: SIG ← SIG ∥ SIG_FORS
    size_t used = fors_sign(p, node, mhash, sk_seed, pk_seed, tree_idx, leaf_idx);
    p += used;

    // 16: PK_FORS ← fors_pkFromSig(SIG_FORS, 𝑚𝑑, PK.seed, ADRS) ▷ get FORS key
    // 17: SIG_HT ← ht_sign(PK_FORS, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
    // 18: SIG ← SIG ∥ SIG_HT

    return 0;

}
