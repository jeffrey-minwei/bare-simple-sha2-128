#include "base_2b.h"

#include <stddef.h>

/**

Based on the algorithm 4 listed on page 26 of the FIPS 205 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf),

Algorithm 4 base_2b(X, b, out_len)
Computes the base 2^b representation of X.
Input: Byte string X of length at least ⌈ (out_len*b) / 8 ⌉, integer b, output length out_len.
Output: Array of out_len integers in the range [0, … , 2b − 1].
1:  in = 0
2:  bits = 0
3:  total = 0
4:  for out from 0 to out_len − 1 do
5:      while bits < b do
6:          total = (total ≪ 8) + X[in]
7:          in = in + 1
8:          bits = bits + 8
9:      end while
10:     bits = bits - b
11:     baseb[out] = (total ≫ bits) mod 2^b
12: end for
13: return baseb

*/

/*
 * Based on the implementation listed on https://github.com/sphincs/sphincsplus/blob/master/ref/wots.c#L45, 
 *    and algorithm 4 listed on page 26 of the FIPS 205 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf),
 **/
void base_2b(const unsigned char *pX, 
             const int b, 
             const int out_len, 
             unsigned int *baseb)
{
    if (baseb == NULL) return;

    int in = 0;
    int bits = 0;
    int total = 0;   

    for(int out = 0; out < out_len; out++)
    {
        while(bits < b)
        {
            total = (total << 8) + pX[in];
            in++;
            bits += 8;
        }

        // bits = bits - b
        bits -= b;

        // baseb[out] = (total ≫ bits) mod 2^b
        baseb[out] = (total >> bits) & ((1u << b) - 1u);
    }
}