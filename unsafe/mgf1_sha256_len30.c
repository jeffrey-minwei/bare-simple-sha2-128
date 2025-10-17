/* File: mgf1_sha256_len30.c
 *
 * MGF1 with SHA-256, output length = m (you will pass m=30).
 * Counter is fixed to I2OSP(0,4). No VLA, no dynamic allocation.
 *
 * API:
 *   #define SPX_M 30
 *   int mgf1_sha256_len30(uint8_t out[SPX_M],
 *                         const uint8_t *mask, const size_t mask_len,
 *                         uint8_t m);
 *
 * Returns:
 *   0  on success
 *  -1  invalid args
 *  -2  seed too large
 *  -3  m != SPX_M
 *  -4  m > 32 (unsupported in this single-block variant)
 */

#ifndef HARD

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../common.h"
#include "sha256.h"

#ifndef MGF1_MAX_SEED
#define MGF1_MAX_SEED 128u
#endif

static void secure_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) { *v++ = 0u; }
}

int mgf1_sha256_len30(uint8_t out[SPX_M],
                      const uint8_t *mask, const size_t mask_len,
                      uint8_t m)
{
    if (out == NULL || (mask_len > 0 && mask == NULL)) return -1;
    if (mask_len > MGF1_MAX_SEED) return -2;
    if (m != (uint8_t)SPX_M) return -3;     /* enforce m == 30 */
    if (m > 32u) return -4;                 /* single-block guard */

    uint8_t in[MGF1_MAX_SEED + 4];
    uint8_t digest[32];

    if (mask_len) memcpy(in, mask, mask_len);
    /* counter fixed to 0: I2OSP(0,4) = 00 00 00 00 */
    in[mask_len + 0] = 0x00u;
    in[mask_len + 1] = 0x00u;
    in[mask_len + 2] = 0x00u;
    in[mask_len + 3] = 0x00u;

    size_t olen = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, 
                                           in, 
                                           sizeof(in), 
                                           digest, 
                                           sizeof(digest), 
                                           &olen);

    memcpy(out, digest, (size_t)m);

    secure_zero(in, mask_len + 4u);
    secure_zero(digest, sizeof(digest));
    return 0;
}

#endif
