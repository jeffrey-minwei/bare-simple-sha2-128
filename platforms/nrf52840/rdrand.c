#include "../../rdrand_min.h"

#include <stdint.h>
#include <string.h>

// 簡單 LFSR 當假 RNG
static uint32_t lfsr_state = 0xACE1u;
void dummy_rng(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        lfsr_state = (lfsr_state >> 1) ^ (-(int)(lfsr_state & 1u) & 0xB400u);
        buf[i] = (uint8_t)(lfsr_state & 0xFFu);
    }
}

int rdrand_bytes(uint8_t *out, size_t len) {
    // TODO use CryptoCell-310 DRBG
    dummy_rng(out,  len);
    return 0;
}