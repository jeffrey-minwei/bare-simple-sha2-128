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

size_t fors_sign(uint8_t *sig_ptr, 
                 uint8_t fors_root[SPX_N],
                 const uint8_t mhash[SPX_FORS_MSG_BYTES],
                 const uint8_t *p_sk_seed, 
                 const uint8_t *p_pk_seed,
                 uint64_t tree_idx, 
                 uint32_t leaf_idx);

#endif
