/*
 * hmac.h
 *
 *  Created on: Dec 19, 2023
 *      Author: moninom
 */

#ifndef INC_HMAC_H_
#define INC_HMAC_H_


#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    uint32_t h[5];
    uint32_t length;
    unsigned char block[SHA1_BLOCK_SIZE];
} SHA1_CTX;



void sha1_update(SHA1_CTX *ctx, const unsigned char *data, size_t len);
void sha1_final(SHA1_CTX *ctx, unsigned char *result);
void hmac_sha1(const char *key, size_t key_len, const char *message, size_t message_len, unsigned char *result);

#endif /* INC_HMAC_H_ */
