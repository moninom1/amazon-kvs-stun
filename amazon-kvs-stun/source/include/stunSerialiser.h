#ifndef STUN_SERIALIZER_H
#define STUN_SERIALIZER_H

#include "stunDataTypes.h"

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

StunResult_t StunSerializer_AddAttributePriority( StunSerializerContext_t * pCtx,
                                                  uint32_t priority );

StunResult_t StunSerializer_AddAttributeUserName( StunSerializerContext_t * pCtx, char * name, uint16_t usernameLen );

/* StunSerializer_AddAttributeFingerprint,
 * StunSerializer_AddAttributeIntegrity,
 * StunSerializer_AddAttributeRealm,
 * StunSerializer_AddAttributeNonce,
 *  ... */

StunResult_t checkFingerprintIntegrityFound( const char *pAttributeBuffer, size_t len );

StunResult_t StunSerializer_Finalize( StunSerializerContext_t * pCtx,
                                      const uint8_t ** pStunMessage,
                                      size_t * pStunMessageLength );

#endif /* STUN_SERIALIZER_H */
