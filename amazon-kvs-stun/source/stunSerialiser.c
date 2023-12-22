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

#define SERIALIZE_UINT16( pDst, val )
#define SERIALIZE_UINT32( pDst, val )
#define SERIALIZE_BUFFER( pDst, pSrc, srcLength )

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

#define STUN_ATTRIBUTE_PRIORITY_TYPE    0x0024

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
                                       const StunHeader_t * pHeader )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pHeader == NULL ) )
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
        SERIALIZE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                          StunMessageTypeToCode( pHeader->stunMessageType ) );

        /* Message length is updated in the end. */
        SERIALIZE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                          0 );

        SERIALIZE_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ),
                          STUN_HEADER_MAGIC_COOKIE );

        SERIALIZE_BUFFER( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_TRANSACTION_ID_OFFSET ] ),
                          &( pHeader->transactionId[ 0 ] ),
                          STUN_TRANSACTION_ID_LENGTH );

        pCtx->currentIndex += STUN_MESSAGE_HEADER_LENGTH;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributePriority( StunSerializerContext_t * pCtx,
                                                  uint32_t priority )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( REMAINING_BUFFER_LENGTH( pCtx ) < ( sizeof( priority ) + STUN_ATTRIBUTE_HEADER_LENGTH ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        SERIALIZE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                          STUN_ATTRIBUTE_PRIORITY_TYPE );

        SERIALIZE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                          sizeof( priority ) );

        SERIALIZE_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                           priority );

        pCtx->currentIndex += ( sizeof( priority ) + STUN_ATTRIBUTE_HEADER_LENGTH );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_Finalize( StunSerializerContext_t * pCtx,
                                      const uint8_t ** pStunMessage,
                                      size_t * pStunMessageLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pStunMessage == NULL ) ||
        ( pStunMessageLength == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        /* Update the message length field in the header. */
        SERIALIZE_UINT16( &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                          pCtx->currentIndex - STUN_MESSAGE_HEADER_LENGTH );

        *pStunMessage = pCtx->pStart;
        *pStunMessageLength = pCtx->currentIndex;
    }
}
/*-----------------------------------------------------------*/
