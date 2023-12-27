/*
 * test.c
 *
 *  Created on: Dec 15, 2023
 *      Author: moninom
 */

#include "stunSerialiser.h"
#include "stunDataTypes.h"
#include "commondefs.h"
#include "stun.h"

int fail = 0;

#define EXPECT_EQ(actual, expected) \
    do { \
        if ((actual) != (expected)) { \
            printf("Expectation failed: %s:%d\n", __FILE__, __LINE__); \
            fail = 1; \
        } \
    } while (0)

#define EXPECT_NE(actual, expected) \
    do { \
        if ((actual) == (expected)) { \
            printf("Expectation failed: %s:%d\n", __FILE__, __LINE__); \
            fail = 1; \
        } \
    } while (0)

#define EXPECT_TRUE(condition) \
    do { \
        if (!(condition)) { \
        	printf("Expectation failed: %s:%d\n", __FILE__, __LINE__); \
            fail = 1; \
        } \
    } while (0)

#define TEST_STUN_PASSWORD (PCHAR) "bf1f29259cea581c873248d4ae73b30f"

void printBuffer(uint8_t * pBuffer, size_t bufferLength)
{
    for(int i=0;i<bufferLength;i++)
    {
        printf("0x%02x ",pBuffer[i]);
        if(i==19)
            printf("\n");
    }
    printf("\n");
}

int oldTest()
{
    PBYTE pBuffer = NULL;
    UINT32 size;
    BYTE transactionId[STUN_TRANSACTION_ID_LEN];

    MEMCPY(transactionId, (PBYTE) "ABCDEFGHIJKL", STUN_TRANSACTION_ID_LEN);

    PStunPacket pStunPacket = NULL, pSerializedStunPacket = NULL;

    //
    // Create STUN packet and add various attributes
    //
    EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, transactionId, &pStunPacket));
    
    EXPECT_EQ(pStunPacket->header.magicCookie, STUN_HEADER_MAGIC_COOKIE);
    EXPECT_EQ(pStunPacket->header.messageLength, 0);
    EXPECT_EQ(pStunPacket->header.stunMessageType, STUN_PACKET_TYPE_BINDING_REQUEST);
    EXPECT_EQ(pStunPacket->allocationSize, STUN_PACKET_ALLOCATION_SIZE);
    EXPECT_EQ(pStunPacket->attributesCount, 0);

    printf("\nPrint serialized header size = %d \n ",pStunPacket->ctx.currentIndex );
    for(int i=0;i<20;i++)
    {
        printf("0x%x ", pStunPacket->ctx.pStart[i]);
    }

    EXPECT_EQ(STATUS_SUCCESS, appendStunPriorityAttribute(pStunPacket, 10));
    printf("\n\nPrint serialized header + Priority Attribute size = %d \n",pStunPacket->ctx.currentIndex);
    
    for(int i=0;i<pStunPacket->ctx.currentIndex; i++)
    {
        printf("0x%x ", pStunPacket->ctx.pStart[i]);
    }

    EXPECT_EQ(pStunPacket->header.messageLength, 8);

    EXPECT_EQ(STATUS_SUCCESS, appendStunUsernameAttribute(pStunPacket, (PCHAR) "abc"));
    printf("\n\nPrint serialized packet header + Priority Attribute + user attribute till %d \n ",pStunPacket->ctx.currentIndex);
    for(int i=0;i<pStunPacket->ctx.currentIndex; i++)
    {
        printf("0x%x ", pStunPacket->ctx.pStart[i]);
    }

    printf("\n\n Append stun attr done\n");

    EXPECT_EQ(pStunPacket->header.messageLength, 16);

    // // Validate the attributes
    EXPECT_EQ(pStunPacket->attributesCount, 2);

    PStunAttributePriority pAttribute = (PStunAttributePriority) pStunPacket->attributeList[0];
    
    EXPECT_EQ( getInt16(pAttribute->attribute.type), STUN_ATTRIBUTE_TYPE_PRIORITY);
    EXPECT_EQ( getInt16(pAttribute->attribute.length), 4);
    EXPECT_EQ(10, getInt32(pAttribute->priority));

    PCHAR attUsername = (char *)pStunPacket->attributeList[1];
    PStunAttributeUsername pStunAttributeUsername = (PStunAttributeUsername) attUsername; 
    EXPECT_EQ(getInt16(pStunAttributeUsername->attribute.type), STUN_ATTRIBUTE_TYPE_USERNAME);
    EXPECT_EQ(getInt16(pStunAttributeUsername->attribute.length), 3);

    PCHAR userName = attUsername +STUN_ATTRIBUTE_HEADER_LEN;
    EXPECT_EQ(0, memcmp("abc", userName, 3));
    
    EXPECT_EQ(pStunPacket->header.messageLength, 16);
    
    PCHAR serialisedpacket;
    size = pStunPacket->ctx.currentIndex;
    
    // EXPECT_EQ(STATUS_SUCCESS,
    //            serializeStunPacketNew(pStunPacket, (PBYTE) TEST_STUN_PASSWORD, STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), TRUE, TRUE, &serialisedpacket, &size));
    // printf("Serialize done\n");
    
    printf("Serialize packet \n");
    for(int i=0;i<size; i++)
    {
        printf("0x%x ", serialisedpacket[i]);
    }
    printf("\n");

    // De-serialize it back again - TODO
    //  EXPECT_EQ(
    //     STATUS_SUCCESS,
    //      deserializeStunPacket(serialisedpacket, size, (PBYTE) TEST_STUN_PASSWORD, (UINT32) STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), &pSerializedStunPacket));

    // EXPECT_EQ(pSerializedStunPacket->header.magicCookie, STUN_HEADER_MAGIC_COOKIE);
    // printf("pSerializedStunPacket->header.messageLength %d\n",pSerializedStunPacket->header.messageLength);
    // EXPECT_EQ(pSerializedStunPacket->header.messageLength, 16);
    // EXPECT_EQ(pSerializedStunPacket->header.stunMessageType, STUN_PACKET_TYPE_BINDING_REQUEST);

    // // Validate the values
    // printf(" pSerializedStunPacket->attributesCount %d\n",pSerializedStunPacket->attributesCount);
    // EXPECT_EQ(pSerializedStunPacket->attributesCount, 2);
    // EXPECT_EQ(pSerializedStunPacket->attributeList[0]->type, STUN_ATTRIBUTE_TYPE_PRIORITY);
    // EXPECT_EQ(10, ((PStunAttributePriority) pSerializedStunPacket->attributeList[0])->priority);
    // EXPECT_EQ(pSerializedStunPacket->attributeList[1]->type, STUN_ATTRIBUTE_TYPE_USERNAME);
    // EXPECT_EQ(0, MEMCMP("abc", ((PStunAttributeUsername) pSerializedStunPacket->attributeList[1])->userName, 3));
    // EXPECT_EQ(pSerializedStunPacket->attributeList[2]->type, STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY);
    // EXPECT_EQ(pSerializedStunPacket->attributeList[3]->type, STUN_ATTRIBUTE_TYPE_FINGERPRINT);

    // EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));
    // EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pSerializedStunPacket));
    // SAFE_MEMFREE(pBuffer);
    
    return fail;
}

int testSerialisation()
{
    StunSerializerContext_t stunContext;
    size_t bufferLength=50;
    uint8_t * pBuffer;
    uint32_t priority = 10;
    const StunHeader_t stunHeader;
    const uint8_t * pStunMessage;
    size_t stunMessageLength;
    uint8_t transactionId[STUN_TRANSACTION_ID_LEN];
    char *userName = "Monika";

    memcpy(transactionId, (PBYTE) "ABCDEFGHIJKL", STUN_TRANSACTION_ID_LEN);

    //This could be done if we do not want to waste memory
    //bufferLength = STUN_HEADER_LEN + STUN_ATTRIBUTE_HEADER_LEN + sizeof(priority); // HEADER + Priority Attribute Header + Priority

    pBuffer = malloc(bufferLength);
    EXPECT_NE( pBuffer, NULL );

    EXPECT_EQ(STATUS_SUCCESS, StunSerializer_Init( &stunContext, pBuffer, bufferLength ));

    EXPECT_EQ( STATUS_SUCCESS, StunSerializer_AddHeader( &stunContext, STUN_MESSAGE_TYPE_BINDING_REQUEST, transactionId ));
    printBuffer(pBuffer, 20);

    EXPECT_EQ( STATUS_SUCCESS, StunSerializer_AddAttributePriority( &stunContext, priority ));

    EXPECT_EQ( STATUS_SUCCESS, StunSerializer_AddAttributeUserName( &stunContext, userName ));

    EXPECT_EQ( STATUS_SUCCESS, StunSerializer_Finalize( &stunContext, &pStunMessage, &stunMessageLength ));
    printf("Serialised Message Length %ld\n",stunMessageLength );
    printBuffer(pBuffer, stunMessageLength);

}
int main()
{
    int status;
    
    status = testSerialisation();
    if(status == 1)
        printf("\n ----Result : Test Failed----\n\n");
    else
        printf("\n ----Result : Test Passed----\n\n");
}