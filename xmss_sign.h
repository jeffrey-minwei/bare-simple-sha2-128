#ifndef XMSS_SIGN_H
#define XMSS_SIGN_H

#include "common.h"

// (ℎ′ + 𝑙𝑒𝑛) for sha2-128s, it is 44
#define SPX_XMSS_LEN  44

void xmss_sign(N_BYTES out[SPX_XMSS_LEN],
               const uint8_t M[SPX_N], 
               const unsigned char sk_seed[SPX_N], 
               uint8_t idx,
               const unsigned char pk_seed[SPX_N], 
               ADRS adrs);

#endif