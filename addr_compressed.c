#include "common.h"
#include "addr_compressed.h"

#include <stddef.h>
#include <string.h>

void set_layer_addr_c(ADRSc adrs, unsigned int layer)
{
    if (adrs != NULL)
    {
        unsigned char S[1];
        toByte((unsigned long long)layer, 1, S);

        adrs[0] = S[0];
    }
}

void set_tree_height_c(ADRSc adrs, unsigned long long i)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);

        // ADRS[14:18]
        memcpy(adrs + 14, S, 4); // 14, 15, 16, 17
    }
}

void set_type_and_clear_c(ADRSc adrs, unsigned int Y)
{
    if (adrs != NULL)
    {
        unsigned char S[1];
        toByte((unsigned long long)Y, 1, S);

        // ADRS[0 ∶ 9] ∥ toByte(Y, 1) ∥ toByte(0, 12)
        adrs[9] = S[0];

        // toByte(0, 12)
        unsigned char zero[12];
        toByte(0, 12, zero);

        // ADRS[0 ∶ 9] ∥ toByte(Y, 1) ∥ toByte(0, 12)
        memcpy(adrs + 10, zero, 12); // 10, 11, ..., 21
    }
}

void set_key_pair_addr_c(ADRSc adrs, unsigned int i)
{
    if (adrs != NULL)
    {
        // TODO
    }
}

void set_tree_index_c(ADRSc adrs, unsigned int i)
{
    if (adrs != NULL)
    {
        unsigned char S[4];
        toByte((unsigned long long)i, 4, S);

        // ADRS[18:22]
        memcpy(adrs + 18, S, 4); // 18, 19, 20, 21
    }
}