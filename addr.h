#ifndef ADDR_H
#define ADDR_H

#include "common.h"

void test_addr();

/**
 * See https://github.com/sphincs/sphincsplus/blob/master/ref/address.c#L11
 *
 * ADRS = concat(toByte(l, 4), ADRS[4:32])
 * ADRS[4:32] means ADRS[4, 5, ..., 31]
 */
void set_layer_addr(ADRS adrs, unsigned int layer);

void set_tree_height(ADRS adrs, unsigned long long i);
void set_type_and_clear(ADRS adrs, unsigned int Y);
unsigned long long get_key_pair_addr(ADRS adrs);
void set_key_pair_addr(ADRS adrs, unsigned long long i);
void set_chain_addr(ADRS adrs, unsigned long long i);
void set_hash_addr(ADRS adrs, unsigned long long i);
void set_tree_index(ADRS adrs, unsigned int i);

#endif