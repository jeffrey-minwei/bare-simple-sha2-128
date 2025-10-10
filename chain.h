#ifndef CHAIN_H
#define CHAIN_H

/**
 * start index 𝑖
 * number of steps 𝑠,
 */
void chain(uint8_t out[SPX_N],
           const uint8_t X[SPX_N], 
           const uint8_t i,
           const uint8_t s,
           const psa_key_id_t pk_seed, 
           ADRS adrs);
#endif