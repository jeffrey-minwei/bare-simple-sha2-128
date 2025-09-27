#ifndef HAL_RNG_H
#define HAL_RNG_H

#include <stdint.h>  // uint8_t, uint32_t, uint64_t ...
#include <stddef.h>  // size_t

void rng_init(const uint8_t *entropy, const uint8_t *pers, size_t L);

void rng_bytes(uint8_t *out, size_t len);

#endif