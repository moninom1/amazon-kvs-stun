/*
 * hmac.c
 *
 *  Created on: Dec 19, 2023
 *      Author: moninom
 */
#include "stun.h"
#include "hmac.h"

void sha1_init(SHA1_CTX *ctx) {
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;

    ctx->length = 0;
}

void sha1_update(SHA1_CTX *ctx, const unsigned char *data, size_t len) {
    size_t block_fill;

    while (len > 0) {
        block_fill = SHA1_BLOCK_SIZE - ctx->length % SHA1_BLOCK_SIZE;

        if (block_fill > len) {
            block_fill = len;
        }

        memcpy(ctx->block + ctx->length % SHA1_BLOCK_SIZE, data, block_fill);
        ctx->length += block_fill;
        data += block_fill;
        len -= block_fill;

        if (ctx->length % SHA1_BLOCK_SIZE == 0) {
            // Process the block
            // ... (see sha1_final implementation)
        }
    }
}

void sha1_final(SHA1_CTX *ctx, unsigned char *result) {
	size_t i;

    // Pad the message
    ctx->block[ctx->length % SHA1_BLOCK_SIZE] = 0x80;

    // Add the length (in bits) to the last 8 bytes
    if (ctx->length % SHA1_BLOCK_SIZE > 55) {
        // Need to process the current block before adding the length
        // ... (see sha1_process_block implementation)
    }

    // Add length in bits as 64-bit big-endian integer
    ctx->length *= 8;
    ctx->block[SHA1_BLOCK_SIZE - 8] = (ctx->length >> 56) & 0xFF;
    ctx->block[SHA1_BLOCK_SIZE - 7] = (ctx->length >> 48) & 0xFF;
    ctx->block[SHA1_BLOCK_SIZE - 6] = (ctx->length >> 40) & 0xFF;
    ctx->block[SHA1_BLOCK_SIZE - 5] = (ctx->length >> 32) & 0xFF;
    ctx->block[SHA1_BLOCK_SIZE - 4] = (ctx->length >> 24) & 0xFF;
    ctx->block[SHA1_BLOCK_SIZE - 3] = (ctx->length >> 16) & 0xFF;
    ctx->block[SHA1_BLOCK_SIZE - 2] = (ctx->length >> 8) & 0xFF;
    ctx->block[SHA1_BLOCK_SIZE - 1] = ctx->length & 0xFF;

    // Process the final block(s)
    // ... (see sha1_process_block implementation)

    // Copy the result to the output buffer
    for (i = 0; i < SHA1_DIGEST_SIZE / 4; i++) {
        result[i * 4]     = (ctx->h[i] >> 24) & 0xFF;
        result[i * 4 + 1] = (ctx->h[i] >> 16) & 0xFF;
        result[i * 4 + 2] = (ctx->h[i] >> 8) & 0xFF;
        result[i * 4 + 3] = ctx->h[i] & 0xFF;
    }
}

void hmac_sha1(const char *key, size_t key_len, const char *message, size_t message_len, unsigned char *result) {
    SHA1_CTX ctx;

    sha1_init(&ctx);

    if (key_len > SHA1_BLOCK_SIZE) {
        // If the key is longer than the block size, hash it
        sha1_update(&ctx, (const unsigned char *)key, key_len);
        sha1_final(&ctx, result);
        key_len = SHA1_DIGEST_SIZE;
    } else {
        // If the key is shorter than the block size, pad with zeros
        memcpy(ctx.block, key, key_len);
        memset(ctx.block + key_len, 0, SHA1_BLOCK_SIZE - key_len);
    }

    // XOR key with outer padding and inner padding
    unsigned char ipad[SHA1_BLOCK_SIZE];
    unsigned char opad[SHA1_BLOCK_SIZE];
    for (size_t i = 0; i < SHA1_BLOCK_SIZE; i++) {
        ipad[i] = 0x36 ^ ctx.block[i];
        opad[i] = 0x5C ^ ctx.block[i];
    }

    // Calculate inner hash: H(Key XOR ipad, Message)
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, (const unsigned char *)message, message_len);
    sha1_final(&ctx, result);

    // Calculate outer hash: H(Key XOR opad, inner hash)
    sha1_init(&ctx);
    sha1_update(&ctx, opad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, result, SHA1_DIGEST_SIZE);
    sha1_final(&ctx, result);
}


