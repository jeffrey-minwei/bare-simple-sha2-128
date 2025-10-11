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

#ifndef SPX_D
#define SPX_D 7 // d is 7 for SLH-DSA-SHA2-128s
#endif

#ifndef SPX_H
#define SPX_H 63 // h is 63 for SLH-DSA-SHA2-128s
#endif

#ifndef SPX_FORS_SIG_LENGTH
#define SPX_FORS_SIG_LENGTH (SPX_K * (SPX_A + 1 ) * SPX_N)
#endif

#ifndef SPX_HT_SIG_LENGTH
#define SPX_HT_SIG_LENGTH  ((SPX_H + SPX_D * SPX_LEN) * SPX_N)
#endif


#define SPX_FORS_HEIGHT 9
#define SPX_FORS_TREES  30

// 要簽的 bits 數 / 8 → bytes
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)

// 總簽章長度 7856
#define SPX_BYTES (SPX_N + SPX_FORS_SIG_LENGTH + SPX_HT_SIG_LENGTH)

#endif