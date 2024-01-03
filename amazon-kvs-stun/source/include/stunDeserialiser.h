
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

StunResult_t StunDeserializer_GetNextAttribute ( StunDeserializerContext_t * pCtx, uint8_t * pType,
                                                                 const char ** pValue, size_t * pValueLength);

/* StunSerializer_GetAttributeFingerprint,
 * StunSerializer_GetAttributeIntegrity,
 * StunSerializer_GetAttributeRealm,
 * StunSerializer_GetAttributeNonce,
 *  ... */

#endif /* STUN_DESERIALIZER_H */