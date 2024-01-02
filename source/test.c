/*
 * test.c
 *
 *  Created on: Dec 15, 2023
 *      Author: moninom
 */

#include "stunSerialiser.h"
#include "stunDeserialiser.h"
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

    EXPECT_EQ(STATUS_SUCCESS, appendStunPriorityAttribute(pStunPacket, 10));
    EXPECT_EQ(pStunPacket->header.messageLength, 8);

    EXPECT_EQ(STATUS_SUCCESS, appendStunUsernameAttribute(pStunPacket, (PCHAR) "monika"));
    EXPECT_EQ(pStunPacket->header.messageLength, 20);

    EXPECT_EQ(pStunPacket->attributesCount, 2);
    EXPECT_EQ(pStunPacket->attributeList[0]->type, STUN_ATTRIBUTE_TYPE_PRIORITY);
    EXPECT_EQ(10, ((PStunAttributePriority) pStunPacket->attributeList[0])->priority);
    EXPECT_EQ(pStunPacket->attributeList[1]->type, STUN_ATTRIBUTE_TYPE_USERNAME);
    EXPECT_EQ(0, MEMCMP("monika", ((PStunAttributeUsername) pStunPacket->attributeList[1])->userName, 6));

    // Serialize it
    EXPECT_EQ(STATUS_SUCCESS,
              serializeStunPacket_new(pStunPacket, (PBYTE) TEST_STUN_PASSWORD, STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), 0, 0, NULL, &size));
    printf("size %d\n", size);
    EXPECT_TRUE(NULL != (pBuffer = malloc(size)));
        
    EXPECT_EQ(STATUS_SUCCESS,
              serializeStunPacket_new(pStunPacket, (PBYTE) TEST_STUN_PASSWORD, STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), 0, 0, pBuffer, &size));

    printBuffer(pBuffer,size );

    //De-serialize it back again
    EXPECT_EQ( STATUS_SUCCESS,
         deserializeStunPacket_new(pBuffer, size, (PBYTE) TEST_STUN_PASSWORD, (UINT32) STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), &pSerializedStunPacket));

    EXPECT_EQ(pSerializedStunPacket->header.magicCookie, STUN_HEADER_MAGIC_COOKIE);
    EXPECT_EQ(pSerializedStunPacket->header.messageLength, 20);
    EXPECT_EQ(pSerializedStunPacket->header.stunMessageType, STUN_PACKET_TYPE_BINDING_REQUEST);

    // Validate the values
    EXPECT_EQ(pSerializedStunPacket->attributesCount, 2);
    EXPECT_EQ(pSerializedStunPacket->attributeList[0]->type, STUN_ATTRIBUTE_TYPE_PRIORITY);
    EXPECT_EQ(10, ((PStunAttributePriority) pSerializedStunPacket->attributeList[0])->priority);
    EXPECT_EQ(pSerializedStunPacket->attributeList[1]->type, STUN_ATTRIBUTE_TYPE_USERNAME);
    EXPECT_EQ(pSerializedStunPacket->attributeList[1]->length, 8);
    EXPECT_EQ(0, MEMCMP("monika", ((PStunAttributeUsername) pSerializedStunPacket->attributeList[1])->userName, 6));

    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));
    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pSerializedStunPacket));
    SAFE_MEMFREE(pBuffer);
    
    return fail;
}

int testSerialisation()
{
    StunSerializerContext_t stunContext;
    StunDeserializerContext_t stunDContext;
    size_t bufferLength=50;
    uint8_t * pBuffer;
    uint32_t priority = 10, priorityD;
    StunHeader_t stunHeader;
    const uint8_t * pStunMessage;
    size_t stunMessageLength;
    uint8_t transactionId[STUN_TRANSACTION_ID_LEN];
    char *userName = "Monika", *userNameD;
    uint16_t usernameLen;

    memcpy(transactionId, (PBYTE) "ABCDEFGHIJKL", STUN_TRANSACTION_ID_LEN);

    //This could be done if we do not want to waste memory
    //bufferLength = STUN_HEADER_LEN + STUN_ATTRIBUTE_HEADER_LEN + sizeof(priority); // HEADER + Priority Attribute Header + Priority

    pBuffer = malloc(bufferLength);
    EXPECT_NE( pBuffer, NULL );

    /* --------------------- Serialisation --------------------- */

    EXPECT_EQ(STATUS_SUCCESS, StunSerializer_Init( &stunContext, pBuffer, bufferLength ));

    EXPECT_EQ( STATUS_SUCCESS, StunSerializer_AddHeader( &stunContext, STUN_MESSAGE_TYPE_BINDING_REQUEST, transactionId ));
    printBuffer(pBuffer, 20);

    EXPECT_EQ( STATUS_SUCCESS, StunSerializer_AddAttributePriority( &stunContext, priority ));

    EXPECT_EQ( STATUS_SUCCESS, StunSerializer_AddAttributeUserName( &stunContext, userName, strlen(userName) ));

    EXPECT_EQ( STATUS_SUCCESS, StunSerializer_Finalize( &stunContext, &pStunMessage, &stunMessageLength ));
    printf("Serialised Message Length %ld\n",stunMessageLength );
    printBuffer(pBuffer, stunMessageLength);


    /* --------------------- Deserialisation --------------------- */

    EXPECT_EQ( STATUS_SUCCESS, StunDeserializer_Init( &stunDContext, pStunMessage, stunMessageLength));
    printf("\nDeserialised values :\n\n");
    EXPECT_EQ( STATUS_SUCCESS, StunDeserializer_GetHeader( &stunDContext, &stunHeader ));
    EXPECT_EQ(stunHeader.messageLength, stunMessageLength - 20);
    EXPECT_EQ(stunHeader.stunMessageType, STUN_MESSAGE_TYPE_BINDING_REQUEST);
    EXPECT_EQ( 0, memcmp(stunHeader.transactionId, transactionId, STUN_TRANSACTION_ID_LENGTH));
    printf("Header messageLength = %d, stunMessageType %d\n", stunHeader.messageLength, stunHeader.stunMessageType);

    EXPECT_EQ( STATUS_SUCCESS, StunDeserializer_GetAttributePriority(&stunDContext, &priorityD));
    printf("Priority = %d\n", priorityD);
    EXPECT_EQ(priority, priorityD);

    EXPECT_EQ( STATUS_SUCCESS, StunDeserializer_GetAttributeUserName(&stunDContext, &userNameD, &usernameLen));
    EXPECT_EQ(8, usernameLen); // rounded size
    printf("UserName Length = %d\nUserName : ", usernameLen);
    for(int i=0;i<usernameLen;i++)
    {
        printf("%x ",userNameD[i]);
    }

    // Expected to be not found
    char *try;
    EXPECT_EQ( STATUS_NO_ATTRIBUTE_FOUND, StunDeserializer_FindAttribute ( &stunDContext, STUN_ATTRIBUTE_FINGERPRINT, &try));

    return fail;

}
int main()
{
    int status;
    
    status = testSerialisation();
    if(status == 1)
        printf("\n\n----Result : Test Failed----\n\n");
    else
        printf("\n\n----Result : Test Passed----\n\n");

    status = oldTest();
    if(status == 1)
        printf("\n\n----Result : Test Failed----\n\n");
    else
        printf("\n\n----Result : Test Passed----\n\n");
}