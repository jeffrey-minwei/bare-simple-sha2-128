#ifndef PARAMS_H
#define PARAMS_H

#ifndef SPX_N
#define SPX_N 16
#endif

#ifndef SPX_LEN
#define SPX_LEN 35 // 2n + 3 = 2*16 + 3 = 35
#endif

#ifndef SPX_XMSS_LEN
// (ℎ′ + 𝑙𝑒𝑛) for sha2-128s, it is 44
#define SPX_XMSS_LEN  44
#endif

#endif