
#include "stdio.h"
#include <string.h>
#include "stunDeserialiser.h"


/* STUN Message Header:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0|     STUN Message Type     |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Magic Cookie                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     Transaction ID (96 bits)                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define STUN_MESSAGE_HEADER_LENGTH 20

#define STUN_HEADER_MAGIC_COOKIE        0x2112A442

#define STUN_HEADER_LENGTH_OFFSET 2
#define STUN_HEADER_COOKIE_OFFSET 4
#define STUN_HEADER_ID_OFFSET     8


#define SET_UINT16( pDst, val )   ( *((uint16_t*)(pDst)) = val )
#define SET_UINT32( pDst, val )   ( *((uint32_t*)(pDst)) = val )

#define GET_UINT16( val, pSrc )   ( val = *((uint16_t*)(pSrc)))
#define GET_UINT32( val, pSrc )   ( val = *((uint32_t*)(pSrc)) )

#define REMAINING_BUFFER_LENGTH( pCtx ) ( ( pCtx )->totalLength - ( pCtx )->currentIndex )

/*
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |         Type                  |            Length             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Value (variable)                ....
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define STUN_ATTRIBUTE_HEADER_LENGTH 4
#define STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET  2
#define STUN_ATTRIBUTE_HEADER_VALUE_OFFSET   4
#define STUN_MAX_USERNAME_LEN 128

StunResult_t StunDeserializer_Init( StunDeserializerContext_t * pCtx,
                                    const uint8_t * pBuffer,
                                    size_t bufferLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pBuffer == NULL ) ||
        ( bufferLength < STUN_MESSAGE_HEADER_LENGTH ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pCtx->pStart = pBuffer;
        pCtx->totalLength = bufferLength;
        pCtx->currentIndex = 0;
    }

    return result;
}

StunResult_t StunDeserializer_GetHeader( StunDeserializerContext_t * pCtx, StunHeader_t *pStunHeader )
{
    StunResult_t result = STUN_RESULT_OK;
    uint32_t magicCookie;
    uint16_t currentIndex=0;
    const char *pBuffer;
    
    if( ( pCtx == NULL ) ||
        ( pStunHeader == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }
    
    pBuffer = pCtx->pStart;
    
    GET_UINT16(pStunHeader->stunMessageType , &(pBuffer[currentIndex]));
    GET_UINT16(pStunHeader->messageLength, &(pBuffer[currentIndex + STUN_HEADER_LENGTH_OFFSET]));
    
    GET_UINT32(magicCookie, &(pBuffer[currentIndex + STUN_HEADER_COOKIE_OFFSET]));
    if( magicCookie != STUN_HEADER_MAGIC_COOKIE )
        result = STATUS_MAGIC_COOKIE_MISMATCH;
    
    if( result == STUN_RESULT_OK)
    {
        memcpy(pStunHeader->transactionId, &(pBuffer[currentIndex + STUN_HEADER_ID_OFFSET]), STUN_TRANSACTION_ID_LENGTH);
    }

    pCtx->currentIndex += STUN_MESSAGE_HEADER_LENGTH;
    return result;
}

StunResult_t StunDeserializer_GetNextAttribute ( StunDeserializerContext_t * pCtx, uint8_t * pType,
                                                                 const char ** pValue, size_t * pValueLength)
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t type, msgLen, attributeLen;
    uint16_t attributeFound = 0;
    const char *pAttributeBuffer;

    if( ( pCtx == NULL ) ||
        ( pType == NULL ) ||
        ( pValue == NULL ) ||
        ( pValueLength == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }
    
    if( REMAINING_BUFFER_LENGTH( pCtx ) < STUN_ATTRIBUTE_HEADER_LENGTH )
    {
        result = STUN_RESULT_OUT_OF_MEMORY;
    }

    if( result == STUN_RESULT_OK)
    {
        GET_UINT16(*pType , &( pCtx->pStart[ pCtx->currentIndex ] ));
        GET_UINT16( *pValueLength, &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ));
        *pValue = &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] );

        pCtx->currentIndex += STUN_ATTRIBUTE_HEADER_LENGTH + *pValueLength ;
    }

    return result;
}