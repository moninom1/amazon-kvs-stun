
#ifndef STUN_DESERIALIZER_H
#define STUN_DESERIALIZER_H

#include "stunDataTypes.h"


typedef struct StunDeserializerContext
{
    const char * pStart;
    size_t totalLength;
    size_t currentIndex;
} StunDeserializerContext_t;

#define STUN_ATTRIBUTE_PRIORITY_LENGTH (uint16_t) 4


StunResult_t StunDeserializer_Init( StunDeserializerContext_t * pCtx,
                                  const uint8_t * pBuffer,
                                  size_t bufferLength );

StunResult_t StunDeserializer_GetHeader( StunDeserializerContext_t * pCtx, StunHeader_t *pStunHeader );


StunResult_t StunDeserializer_FindAttribute ( StunDeserializerContext_t * pCtx,
                                             StunMessageType_t stunMessageType,
                                                char ** ppAttribute);

StunResult_t StunDeserializer_GetAttributePriority ( StunDeserializerContext_t * pCtx,
                                                        uint32_t *priority );

StunResult_t StunDeserializer_GetAttributeUserName( StunDeserializerContext_t * pCtx,
                                                    char ** name, uint16_t *nameLength );

/* StunSerializer_GetAttributeFingerprint,
 * StunSerializer_GetAttributeIntegrity,
 * StunSerializer_GetAttributeRealm,
 * StunSerializer_GetAttributeNonce,
 *  ... */

#endif /* STUN_DESERIALIZER_H */