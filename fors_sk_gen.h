#ifndef FORS_SK_GEN
#define FORS_SK_GEN

#include "common.h"

#include <stdint.h>

void fors_sk_gen(const uint8_t *p_sk_seed, 
                 const uint8_t *p_pk_seed, 
                 const ADRS adrs, 
                 const unsigned int idx,
                 unsigned char *out);

void test_fors_sk_gen();

#endif