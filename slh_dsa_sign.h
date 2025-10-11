#ifndef SLH_DSA_SIGN_H
#define SLH_DSA_SIGN_H

#include "common.h"
#include <stddef.h>

int slh_dsa_sign(uint8_t sig_out[SPX_BYTES],
                 const psa_key_id_t sk_key_id,
                 const psa_key_id_t sk_prf_key_id,
                 const psa_key_id_t pk_key_id,
                 const uint8_t *m, size_t mlen,
                 const uint8_t optrand[SPX_N]);

#endif