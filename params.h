#ifndef PARAMS_H
#define PARAMS_H

#ifndef SPX_N
#define SPX_N 16
#endif

#ifndef SPX_M
#define SPX_M 30 // 𝑚 is 30 for SLH-DSA-SHA2-128s
#endif

#ifndef SPX_LEN
#define SPX_LEN 35 // 2n + 3 = 2*16 + 3 = 35
#endif

#ifndef SPX_XMSS_LEN
// (ℎ′ + 𝑙𝑒𝑛) for sha2-128s, it is 44
#define SPX_XMSS_LEN  44
#endif

#ifndef SPX_K
#define SPX_K 14 // k is 14 for SLH-DSA-SHA2-128s
#endif

#ifndef SPX_A
#define SPX_A 12 // a is 12 for SLH-DSA-SHA2-128s
#endif

#ifndef SPX_FORS_SIG_LENGTH
#define SPX_FORS_SIG_LENGTH (SPX_K * (SPX_A + 1 ) * SPX_N)
#endif


#define SPX_TREE_HEIGHT 8   // 例如 8 層 Merkle 樹

#define SPX_FULL_HEIGHT 60        // 總高度
#define SPX_D 20                  // 層數
#define SPX_WOTS_BYTES  2144      // WOTS+ 簽章長度

//#define SPX_FORS_BYTES  1700      // FORS 簽章長度
#define SPX_FORS_HEIGHT 9
#define SPX_FORS_TREES  30

// 要簽的 bits 數 / 8 → bytes
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES (SPX_FORS_TREES * SPX_FORS_HEIGHT * SPX_N)

// 總簽章長度
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * (SPX_WOTS_BYTES + (SPX_FULL_HEIGHT/SPX_D)*SPX_N))

#endif