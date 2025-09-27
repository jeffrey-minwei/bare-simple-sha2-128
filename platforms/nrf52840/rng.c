#include "../../hal_rng.h"

#include <stdint.h>
#include <string.h>

void rng_init(const uint8_t *entropy, const uint8_t *pers, size_t L) {
    // TODO
}

void rng_bytes(uint8_t *out, size_t len) {
    // TODO use CryptoCell-310 DRBG
}