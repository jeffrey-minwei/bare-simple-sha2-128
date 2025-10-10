#ifndef FORS_SK_GEN
#define FORS_SK_GEN

#include "common.h"

#include <stdint.h>

void fors_sk_gen(const psa_key_id_t sk_seed, 
                 const psa_key_id_t pk_seed, 
                 const ADRS adrs, 
                 const unsigned int idx,
                 unsigned char *out);

void test_fors_sk_gen();

#endif