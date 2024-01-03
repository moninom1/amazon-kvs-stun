#ifndef STUN_SERIALIZER_H
#define STUN_SERIALIZER_H

#include "stunDataTypes.h"

#define KVS_SHA1_DIGEST_LENGTH      20
#define STUN_HMAC_VALUE_LENGTH       KVS_SHA1_DIGEST_LENGTH

#define STUN_ATTRIBUTE_FINGERPRINT_LENGTH (uint16_t) 4

typedef struct StunSerializerContext
{
    uint8_t * pStart;
    size_t totalLength;
    size_t currentIndex;
} StunSerializerContext_t;

StunResult_t StunSerializer_Init( StunSerializerContext_t * pCtx,
                                  uint8_t * pBuffer,
                                  size_t bufferLength );

StunResult_t StunSerializer_AddHeader( StunSerializerContext_t * pCtx,
                                       StunMessageType_t stunPacketType, uint8_t *transactionId );

StunResult_t StunSerializer_addAttribute( StunSerializerContext_t * pCtx, uint8_t type, char * pValue, size_t valueLength );


StunResult_t StunSerializer_Finalize( StunSerializerContext_t * pCtx,
                                      const uint8_t ** pStunMessage,
                                      size_t * pStunMessageLength,
                                      char* msgIntegrity,
                                      char* fingerprint);

#endif /* STUN_SERIALIZER_H */
