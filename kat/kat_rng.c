#include "rng.h"

#include "../hal_rng.h"

#ifndef KAT_RNG
#error "kat_rng.c should only be compiled when -DKAT_RNG is defined (test-only)."
#endif

void rng_init(const uint8_t *entropy, const uint8_t *pers, size_t L) {
    (void)L;
    randombytes_init((unsigned char*)entropy, (unsigned char*)pers, 256);
}

void rng_bytes(uint8_t *out, size_t len) {
    randombytes((unsigned char*)out, (unsigned long long)len);
}
