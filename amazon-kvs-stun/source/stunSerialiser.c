#include "stdio.h"
#include <string.h>
#include "stunSerialiser.h"

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

#define STUN_HEADER_MESSAGE_LENGTH_OFFSET   2
#define STUN_HEADER_MAGIC_COOKIE_OFFSET     4
#define STUN_HEADER_TRANSACTION_ID_OFFSET   8

#define REMAINING_BUFFER_LENGTH( pCtx ) ( ( pCtx )->totalLength - ( pCtx )->currentIndex )

#define SET_UINT16( pDst, val )   ( *((uint16_t*)(pDst)) = val )
#define SET_UINT32( pDst, val )   ( *((uint32_t*)(pDst)) = val )

#define GET_UINT16( val, pSrc )   ( val = *((uint16_t*)(pSrc)))
#define GET_UINT32( val, pSrc )   ( val = *((uint32_t*)(pSrc)) )

// 4 Bytes alignement
#define ALIGN_SIZE(size)    (((size) + (4) -1) & ~((4) -1))

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

/*-----------------------------------------------------------*/

static uint16_t StunMessageTypeToCode( StunMessageType_t messageType )
{
    uint16_t code = 0;

    switch ( messageType )
    {
        case STUN_MESSAGE_TYPE_BINDING_REQUEST:
            code = 0x0001;
            break;

        case STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE:
            code = 0x0101;
            break;

        case STUN_MESSAGE_TYPE_BINDING_FAILURE_RESPONSE:
            code = 0x0111;
            break;

        case STUN_MESSAGE_TYPE_BINDING_INDICATION:
            code = 0x0011;
            break;
    }

    return code;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_Init( StunSerializerContext_t * pCtx,
                                  uint8_t * pBuffer,
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
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddHeader( StunSerializerContext_t * pCtx,
                                       StunMessageType_t stunPacketType, uint8_t *pTransactionId )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pTransactionId == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }
        
    if( result == STUN_RESULT_OK )
    {
        if( REMAINING_BUFFER_LENGTH( pCtx ) < STUN_MESSAGE_HEADER_LENGTH )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        SET_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ), StunMessageTypeToCode( stunPacketType ));
        
        /* Message length is updated in the end. */
        SET_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                          0 );
        
        SET_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ),
                          STUN_HEADER_MAGIC_COOKIE );
        
        memcpy( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_TRANSACTION_ID_OFFSET ] ),
                          pTransactionId, STUN_TRANSACTION_ID_LENGTH );
        
        pCtx->currentIndex += STUN_MESSAGE_HEADER_LENGTH;
        
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_addAttribute( StunSerializerContext_t * pCtx, uint8_t type, char * pValue, size_t valueLength )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t length, paddedLength;
    uint32_t attributeLen;

    if( ( pCtx == NULL ) || ( pValue == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    paddedLength = ALIGN_SIZE(valueLength);
    attributeLen = paddedLength + STUN_ATTRIBUTE_HEADER_LENGTH ;

    if( result == STUN_RESULT_OK )
    {
        if( REMAINING_BUFFER_LENGTH( pCtx ) < attributeLen )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        SET_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ), type );

        SET_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                          paddedLength );

        memcpy( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ), pValue, valueLength);

        pCtx->currentIndex += attributeLen;
    }

    return result;
}

StunResult_t StunSerializer_Finalize( StunSerializerContext_t * pCtx,
                                      const uint8_t ** pStunMessage,
                                      size_t * pStunMessageLength,
                                      char* msgIntegrity,
                                      char* fingerprint)
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t length;

    if( ( pCtx == NULL ) ||
        ( pStunMessageLength == NULL ))
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if(result == STUN_RESULT_OK && msgIntegrity)
    {
        length = STUN_HMAC_VALUE_LENGTH;
        if( strlen(msgIntegrity) != length)
        {
            result = STUN_RESULT_BAD_PARAM;
        }
        else
            StunSerializer_addAttribute( pCtx, STUN_ATTRIBUTE_MESSAGE_INTEGRITY_TYPE, msgIntegrity, length);

    }
    if(result == STUN_RESULT_OK && fingerprint)
    {
        length = STUN_ATTRIBUTE_FINGERPRINT_LENGTH;
        if( strlen(msgIntegrity) != length)
        {
            result = STUN_RESULT_BAD_PARAM;
        }
        else
            StunSerializer_addAttribute( pCtx, STUN_ATTRIBUTE_MESSAGE_INTEGRITY_TYPE, fingerprint, length);

    }
    

    if( result == STUN_RESULT_OK )
    {
        /* Update the message length field in the header. */
        SET_UINT16( &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                          pCtx->currentIndex - STUN_MESSAGE_HEADER_LENGTH );

        *pStunMessage = pCtx->pStart;
        *pStunMessageLength = pCtx->currentIndex;
    }

    return result;
}
/*-----------------------------------------------------------*/
