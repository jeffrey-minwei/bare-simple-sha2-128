#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifndef HARD
// only compile when computed by software
void sha256(const uint8_t *msg, size_t mlen, uint8_t out32[32]);
#endif

#endif
