#ifndef RDRAND_MIN_H
#define RDRAND_MIN_H

#include <stdint.h>  // uint8_t, uint32_t, uint64_t ...
#include <stddef.h>  // size_t

int rdrand_bytes(uint8_t *out, size_t len);

#endif