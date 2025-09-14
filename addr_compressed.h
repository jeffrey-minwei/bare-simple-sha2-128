#ifndef ADDR_COMPRESSED_H
#define ADDR_COMPRESSED_H

#include <stdint.h>   // for uint8_t

/**
 *   See page 45 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 *
 *   Compressed ADRS is 22 bytes, which is 22 個 uint8_t
 *     -----------------
 *     | layer address |   1 byte
 *     |---------------| 
 *     |               |
 *     | tree address  |   8 bytes
 *     |               |
 *     |---------------|
 *     |     type      |   1 byte
 *     |---------------|
 *     |               |
 *     |               |  12 bytes
 *     |               |
 *     -----------------
 */
typedef uint8_t ADRSc[22];   // Compressed ADRS is 22 bytes

void set_layer_addr_c(ADRSc adrs, unsigned int layer);
void set_tree_height_c(ADRSc adrs, unsigned long long i);
void set_type_and_clear_c(ADRSc adrs, unsigned int Y);
void set_key_pair_addr_c(ADRSc adrs, unsigned int i);
void set_tree_index_c(ADRSc adrs, unsigned int i);

#endif