#pragma once

#include <stdint.h>  // uint8_t, uint32_t, ...
#include <stddef.h>  // size_t
#include <string.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t s[8];          /* state */
    uint64_t bits;          /* total length in bits */
    uint8_t  buf[64];       /* partial block buffer */
    size_t   idx;           /* number of bytes in buf */
} sha256_ctx;

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA256_DIGEST_SIZE]);