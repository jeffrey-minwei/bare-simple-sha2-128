#ifndef FORS_SIGN_H
#define FORS_SIGN_H

#include <stdint.h>
#include <stddef.h>

#ifndef SPX_N
#define SPX_N 16                  // 每個哈希輸出的長度
#endif

#ifndef SPX_FORS_HEIGHT
#define SPX_FORS_HEIGHT 9
#endif

#ifndef SPX_FORS_TREES
#define SPX_FORS_TREES  30
#endif

#ifndef SPX_FORS_MSG_BYTES
// 要簽的 bits 數 / 8 → bytes
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#endif


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
                 const psa_key_id_t sk_seed_key_id, 
                 const psa_key_id_t pk_seed_key_id, 
                 const ADRS adrs, 
                 const unsigned int idx);

size_t fors_sign(uint8_t out[SPX_FORS_SIG_LENGTH], 
                 const uint8_t mhash[SPX_FORS_MSG_BYTES],
                 const psa_key_id_t sk_seed_key_id, 
                 const psa_key_id_t pk_seed_key_id,
                 const ADRS adrs);
                 
void fors_node(uint8_t out[SPX_N],
               const psa_key_id_t sk_seed_key_id, 
               unsigned int i, 
               unsigned int z, 
               const psa_key_id_t pk_seed_key_id, 
               ADRS adrs);
#endif
