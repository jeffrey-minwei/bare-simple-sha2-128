#include "fors_sk_gen.h"
#include "common.h"
#include "uart_min.h"

#include <stddef.h>

/*
Algorithm 14 fors_skGen(SK.seed, PK.seed, ADRS, idx)

Generates a FORS private-key value.

Input: Secret seed SK.seed, public seed PK.seed, address ADRS, secret key index idx.
Output: n-byte FORS private-key value.
1: skADRS ← ADRS ▷ copy address to create key generation address
2: skADRS.setTypeAndClear(FORS_PRF)
3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
4: skADRS.setTreeIndex(idx)
5: return PRF(PK.seed, SK.seed,skADRS)
*/
void fors_sk_gen(const uint8_t *p_sk_seed, 
                 const uint8_t *p_pk_seed, 
                 const ADRS adrs, 
                 const unsigned int idx,
                 unsigned char *out)
{
    // FORS_PRF is 6, See page 12 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
    unsigned int type = 6; // FORS_PRF
    set_type_and_clear(adrs, type);

    // TODO skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    set_tree_index(adrs, idx);

    // unsigned char out[16];
    prf(p_pk_seed, p_sk_seed, adrs, out);

    uarte0_puts("fors_sk_gen DONE\n");
}

void test_fors_sk_gen()
{
    int n = 16;
    const uint8_t sk_seed[16];
    const uint8_t pk_seed[16];
    const ADRS adrs;

    unsigned int type = 4;  // FORS_ROOTS)
    set_type_and_clear(adrs, type);

    unsigned int idx = 2;
    set_key_pair_addr(adrs, idx);

    unsigned int index = 3;
    set_tree_index(adrs, index);
    
    unsigned char out[16];
    prf(pk_seed, sk_seed, adrs, out);

    fors_sk_gen(sk_seed, pk_seed, adrs, index, out);

    uarte0_puts("test_fors_sk_gen DONE\n");
}