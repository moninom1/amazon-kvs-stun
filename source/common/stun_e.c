
#include "stun_e.h"



StunResult_t StunContextInit( char * pBuffer,
                              size_t bufferLength)
{
    StunResult_t result = STUN_RESULT_OK;
    PStunPacket pStunPacket = (PStunPacket) pBuffer;

    if( pBuffer == NULL )
    {
        result = STUN_RESULT_MESSAGE_NULL_BUFFER;
    }

    if( result == STUN_RESULT_OK )
    {
        pStunPacket->ctx.pStart = (char *) ((PStunAttributeHeader) (pStunPacket->attributeList + STUN_ATTRIBUTE_MAX_COUNT));
        // Include size of 20 attribute pointers
        pStunPacket->ctx.remLength = bufferLength - STUN_TOTAL_PACKET_LEN;
        pStunPacket->ctx.currentIndex = 0; 

    }

    printf(" mylog buffer %p pStart %p \n", pBuffer,pStunPacket->ctx.pStart );
    printf(" mylog total len %ld rem length %ld \n", bufferLength,pStunPacket->ctx.remLength);
   
    return result;
}

StunResult_t StunHeaderInit( STUN_PACKET_TYPE stunPacketType,
                             PBYTE transactionId,
                             char * pBuffer, // Application allocated buffer
                             size_t bufferLength )
{
    StunResult_t result = STUN_RESULT_OK;
    PStunPacket pStunPacket = (PStunPacket) pBuffer;

    if( pBuffer == NULL || bufferLength < STUN_HEADER_LEN)
    {
        result = STUN_RESULT_BAD_PARAM;
    }
    else
    {
        pStunPacket->attributesCount = 0;
        pStunPacket->header.messageLength = 0;
        pStunPacket->header.magicCookie = STUN_HEADER_MAGIC_COOKIE;
        pStunPacket->header.stunMessageType = stunPacketType;

        // Generate the transaction id if none is specified
        if (transactionId == NULL) {
            for (int i = 0; i < STUN_TRANSACTION_ID_LEN; i++) {
                pStunPacket->header.transactionId[i] = (BYTE) (RAND() % 0xFF);
            }
        } else {
            memcpy(pStunPacket->header.transactionId, transactionId, STUN_TRANSACTION_ID_LEN);
        }

        // Set the address - calloc should have NULL-ified the actual pointers
        pStunPacket->attributeList = (PStunAttributeHeader*) (pStunPacket + 1);

        // Store the actual allocation size
        pStunPacket->allocationSize = bufferLength;
    }
    printf(" mylog StunHeaderInit\n");
    return result;
}

StunResult_t SerialiseStunHeader( PStunPacket pStunPacket, size_t bufferLength )
{
    StunResult_t result = STUN_RESULT_OK;
    StunContext_t stunCtx = pStunPacket->ctx;
    printf("%d\n",__LINE__);
    char * pCurrentBufferPosition = stunCtx.pStart + stunCtx.currentIndex;

    if (stunCtx.pStart != NULL) {
        printf("stunCtx.remLength %ld STUN_HEADER_LEN %d\n",stunCtx.remLength, STUN_HEADER_LEN);
        if(stunCtx.remLength < STUN_HEADER_LEN)
            result = STATUS_NOT_ENOUGH_MEMORY;
        else
        {
            // Package the STUN packet header
            putInt16((PINT16) (pCurrentBufferPosition), pStunPacket->header.stunMessageType);
            pCurrentBufferPosition += STUN_HEADER_TYPE_LEN;
            // Skip the length - it will be added at the end
            pCurrentBufferPosition += STUN_HEADER_DATA_LEN;
            putInt32((PINT32) pCurrentBufferPosition, STUN_HEADER_MAGIC_COOKIE);
            pCurrentBufferPosition += STUN_HEADER_MAGIC_COOKIE_LEN;
            memcpy(pCurrentBufferPosition, pStunPacket->header.transactionId, STUN_HEADER_TRANSACTION_ID_LEN);
            pCurrentBufferPosition += STUN_HEADER_TRANSACTION_ID_LEN;
            
            pStunPacket->ctx.remLength -= STUN_HEADER_LEN;
            pStunPacket->ctx.currentIndex = STUN_HEADER_LEN;
        }
        
    }
    //pStunPacket->header.messageLength = STUN_HEADER_LEN;
    printf("pStunPacket->ctx.remLength %ld pStunPacket->ctx.currentIndex %d\n",pStunPacket->ctx.remLength, pStunPacket->ctx.currentIndex);
    return result;
}

StunResult_t appendSerialiseStunUsernameAttribute(PStunPacket pStunPacket, PCHAR userName)
{
    StunResult_t result = STUN_RESULT_OK;
    UINT16 length, paddedLength;
    char * pCurrentBufferPosition;
    uint32_t userNameAttributeLen;
    char * msgLen = (char *)pStunPacket->ctx.pStart + STUN_HEADER_TYPE_LEN;

    if(userName == NULL)
        result =  STATUS_NULL_ARG;
    else
    {
        //CHK_STATUS(getFirstAvailableStunAttribute(pStunPacket, &pAttributeHeader));
        pCurrentBufferPosition = pStunPacket->ctx.pStart + pStunPacket->ctx.currentIndex;
        pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pCurrentBufferPosition;

        length = (UINT16) STRNLEN(userName, STUN_MAX_USERNAME_LEN);
        paddedLength = (UINT16) ROUND_UP(length, 4);

        userNameAttributeLen = STUN_ATTRIBUTE_HEADER_LEN + paddedLength;

        //CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

        if (pCurrentBufferPosition != NULL && pStunPacket->ctx.remLength < userNameAttributeLen) {
            result = STATUS_NOT_ENOUGH_MEMORY;
        }
        else {
            // Package the message header first
            PACKAGE_STUN_ATTR_HEADER(pCurrentBufferPosition, STUN_ATTRIBUTE_TYPE_USERNAME, length);

            // Package the user name
            memcpy(pCurrentBufferPosition + STUN_ATTRIBUTE_HEADER_LEN, userName, paddedLength);
        }
        // Fix-up the STUN header message length
       //printf("\npaddedLength %d, STUN_ATTRIBUTE_HEADER_LEN %d \n",  paddedLength, STUN_ATTRIBUTE_HEADER_LEN);
        pStunPacket->header.messageLength += paddedLength + STUN_ATTRIBUTE_HEADER_LEN;
        
        putInt16((PINT16) (msgLen), pStunPacket->header.messageLength);

        pStunPacket->ctx.remLength -= paddedLength + STUN_ATTRIBUTE_HEADER_LEN;
        pStunPacket->ctx.currentIndex += paddedLength + STUN_ATTRIBUTE_HEADER_LEN;
    }
    return result;
}

StunResult_t appendSerialisePriorityAttribute(PStunPacket pStunPacket, UINT32 priority)
{
    StunResult_t result = STUN_RESULT_OK;
    UINT16 length, paddedLength;
    char * pCurrentBufferPosition;
    uint32_t encodedLen;
    char * msgLen = (char *)pStunPacket->ctx.pStart + STUN_HEADER_TYPE_LEN;

    pCurrentBufferPosition = pStunPacket->ctx.pStart + pStunPacket->ctx.currentIndex;

    pStunPacket->attributeList[pStunPacket->attributesCount++] = (PStunAttributeHeader) pCurrentBufferPosition;

    length = STUN_ATTRIBUTE_PRIORITY_LEN;

    // Fix-up the STUN header message length
    pStunPacket->header.stunMessageType = 0;
    pStunPacket->header.messageLength += length + STUN_ATTRIBUTE_HEADER_LEN;
    
    encodedLen = STUN_ATTRIBUTE_HEADER_LEN + STUN_ATTRIBUTE_PRIORITY_LEN;

    //CHK(!fingerprintFound && !messaageIntegrityFound, STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY);

    if (pCurrentBufferPosition != NULL && pStunPacket->ctx.remLength >= encodedLen) {
        
            PACKAGE_STUN_ATTR_HEADER(pCurrentBufferPosition, STUN_ATTRIBUTE_TYPE_PRIORITY, length);
            // Package the value
            putInt32((PINT32) (pCurrentBufferPosition + STUN_ATTRIBUTE_HEADER_LEN), priority);

            pStunPacket->ctx.remLength -= encodedLen;
            pStunPacket->ctx.currentIndex += encodedLen;

            putInt16((PINT16) (msgLen), pStunPacket->header.messageLength);
    }
    else
    {
        result = STATUS_NOT_ENOUGH_MEMORY;
    }

    return result;
    

}


StunResult_t serializeStunPacketNew(PStunPacket pStunPacket, PBYTE password, UINT32 passwordLen, BOOL generateMessageIntegrity, BOOL generateFingerprint,
                                        char **pBuffer, PUINT32 pSize)
{

    StunResult_t result = STUN_RESULT_OK;
    
    //Not using generateMessageIntegrity generateFingerprint  - which appends these attributes if set to 1
    *pBuffer = (char *)pStunPacket->ctx.pStart;
    if(pBuffer == NULL)
        result = STATUS_NOT_ENOUGH_MEMORY;

    return result;
}


StunResult_t deserializeStunPacketNew(PBYTE pStunBuffer, UINT32 bufferSize, PBYTE password, UINT32 passwordLen, PStunPacket* ppStunPacket)
{
    StunResult_t result = STUN_RESULT_OK;

    // TBD
    
    return result;
}
