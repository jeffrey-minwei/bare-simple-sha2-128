#include "common.h"
#include "addr.h"
#include "uart_min.h"

void test_addr()
{
    unsigned char S[4];

    ADRS adrs;

    unsigned int layer_addr = 1;
    set_layer_addr(adrs, layer_addr);

    set_tree_height(adrs, 1);

    set_type_and_clear(adrs, FORS_ROOTS);

    unsigned long long key_pair_addr = 2;
    set_key_pair_addr(adrs, key_pair_addr);

    unsigned long long chain_addr = 2;
    set_chain_addr(adrs, chain_addr);

    unsigned long long hash_addr = 20;
    set_hash_addr(adrs, hash_addr);

    unsigned int index = 3;
    set_tree_index(adrs, index);

    // TODO unit test for each member function
}

/**
 * See https://github.com/sphincs/sphincsplus/blob/master/ref/address.c#L11
 *
 * ADRS = concat(toByte(l, 4), ADRS[4:32])
 * ADRS[4:32] means ADRS[4, 5, ..., 31]
 */
void set_layer_addr(ADRS adrs, unsigned int layer)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)layer, 4, S);
        uarte0_hex("set_layer_addr, S", S, sizeof(S) / sizeof(S[0]));

        // See page 22, Figure 2. Address (ADRS), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
        // ADRS[0:4] is layer address, ADRS[0,1,2,3]
        memcpy(adrs, S, 4); // 0, 1, 2, 3
    }
}

/**
 * See https://github.com/sphincs/sphincsplus/blob/master/ref/address.c#L92
 * See page 24, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_tree_height(ADRS adrs, unsigned long long i)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);
    
        // ADRS[24:28]
        memcpy(adrs + 24, S, 4);   // 24, 25, 26, 27
    }
}

/**
 * See page 24, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_type_and_clear(ADRS adrs, unsigned int Y)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)Y, 4, S);

        // ADRS[16:20], ADRS[16, 17, 18, 19]
        memcpy(adrs + 16, S, 4);   // 16, 17, 18, 19

        toByte(0, 12, S);
        memcpy(adrs + 20, S, 12);  // 20, 21, ..., 31
    }
}

/**
 * key_pair_addr is 4 bytes
 */
unsigned long long get_key_pair_addr(ADRS adrs)
{
    unsigned char key_pair_addr[4];

    // ADRS[20:24], ADRS[20, 21, 22, 23]
    memcpy(key_pair_addr, adrs + 20, 4);  // 20, 21, 22, 23

    return toInt(key_pair_addr, 4);
}

/**
 * See page 12,13,14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_key_pair_addr(ADRS adrs, unsigned long long i)
{    
    if (adrs != NULL)
    {
        unsigned char key_pair_addr[4];
        toByte(i, 4, key_pair_addr);

        // ADRS[20:24], ADRS[20, 21, 22, 23]
        memcpy(adrs + 20, key_pair_addr, 4);  // 20, 21, 22, 23
    }
}

/**
 * See page 12,14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_chain_addr(ADRS adrs, unsigned long long i)
{
    if (adrs != NULL)
    {
        unsigned char chain_addr[4];
        toByte(i, 4, chain_addr);

        // ADRS[24:28], ADRS[24, 25, 26, 27]
        memcpy(adrs + 24, chain_addr, 4);   // 24, 25, 26, 27
    }
}

/**
 * See page 14, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 * ADRS = concat(ADRS[0 ∶ 28], toByte(i, 4))
 */
void set_hash_addr(ADRS adrs, unsigned long long i)
{
    if (adrs != NULL)
    {
        unsigned char hash_addr[4];
        toByte(i, 4, hash_addr);

        // ADRS[28:32], ADRS[28, 29, 30, 31]
        memcpy(adrs + 28, hash_addr, 4);
    }
}

/**
 * See page 24, Table 1. Member functions for addresses, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 */
void set_tree_index(ADRS adrs, unsigned int i)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);

        // ADRS[28:32], ADRS[28, 29, 30, 31]
        memcpy(adrs + 28, S, 4);     // 28, 29, 30, 31
    }
}
