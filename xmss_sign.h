#ifndef XMSS_SIGN_H
#define XMSS_SIGN_H

#include "common.h"

// (ℎ′ + 𝑙𝑒𝑛) for sha2-128s, it is 44
#define SPX_XMSS_LEN  44

/**
 * \param out_root [out] n-byte root node
 * \param sk_seed [in] 
 * \param i       [in] target node index
 * \param z       [in] target node height
 * \param pk_seed [in]  
 * \param adrs    [out] 
 */
void xmss_node(uint8_t out_root[SPX_N],
               const psa_key_id_t sk_seed, 
               unsigned int i,
               unsigned int z,
               const psa_key_id_t pk_seed, 
               ADRS adrs);

void xmss_sign(N_BYTES out[SPX_XMSS_LEN],
               const uint8_t M[SPX_N], 
               const psa_key_id_t sk_seed, 
               uint8_t idx,
               const psa_key_id_t pk_seed, 
               ADRS adrs);

#endif