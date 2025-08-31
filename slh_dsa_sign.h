#ifndef SLH_DSA_SIGN_H
#define SLH_DSA_SIGN_H

#include "keygen.h"
#include <stddef.h>

int slh_dsa_sign(uint8_t sig_out[SPX_BYTES],
                 const uint8_t sk[SPX_SK_BYTES],
                 const uint8_t pk[SPX_PK_BYTES],
                 const uint8_t *m, size_t mlen,
                 const uint8_t optrand[SPX_N]);

#endif