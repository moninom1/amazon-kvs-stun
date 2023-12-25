/*
 * test.c
 *
 *  Created on: Dec 15, 2023
 *      Author: moninom
 */

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

int serializeDeserializeStunControlAttribute()
{
    BYTE transactionId[STUN_TRANSACTION_ID_LEN];
    PStunPacket pStunPacket, pDeserializedPacket;
    UINT32 stunPacketBufferSize = STUN_PACKET_ALLOCATION_SIZE, actualPacketSize = 0;
    BYTE stunPacketBuffer[STUN_PACKET_ALLOCATION_SIZE];
    PStunAttributeHeader pStunAttributeHeader;
    PStunAttributeIceControl pStunAttributeIceControl;
    UINT64 magicValue = 123;

    EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, transactionId, &pStunPacket));
        EXPECT_EQ(STATUS_SUCCESS, appendStunIceControllAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED, magicValue));
        EXPECT_EQ(STATUS_SUCCESS, serializeStunPacket(pStunPacket, NULL, 0, FALSE, FALSE, NULL, &actualPacketSize));
        EXPECT_TRUE(actualPacketSize < stunPacketBufferSize);
        EXPECT_EQ(STATUS_SUCCESS, serializeStunPacket(pStunPacket, NULL, 0, FALSE, FALSE, stunPacketBuffer, &actualPacketSize));


        EXPECT_EQ(STATUS_SUCCESS, deserializeStunPacket(stunPacketBuffer, actualPacketSize, NULL, 0, &pDeserializedPacket));
        EXPECT_EQ(STATUS_SUCCESS, getStunAttribute(pDeserializedPacket, STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED, &pStunAttributeHeader));
        EXPECT_TRUE(pStunAttributeHeader != NULL);
        pStunAttributeIceControl = (PStunAttributeIceControl) pStunAttributeHeader;
        EXPECT_EQ(pStunAttributeIceControl->tieBreaker, magicValue);

        EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));
        EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pDeserializedPacket));

        return fail;

}



int basicValidParseTest()
{
    BYTE bindingRequestBytes[] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x70, 0x66,
                                  0x68, 0x6e, 0x70, 0x62, 0x50, 0x66, 0x41, 0x61, 0x6b, 0x4d};

    BYTE bindingSuccessResponseXorMappedAddressBytes1[] = {0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0x70, 0x66, 0x68,
                                                           0x6e, 0x70, 0x62, 0x50, 0x66, 0x41, 0x61, 0x6b, 0x4d, 0x00, 0x20,
                                                           0x00, 0x08, 0x00, 0x01, 0x14, 0x00, 0x17, 0xe2, 0x60, 0xe9};


    PStunPacket pStunPacket = NULL;
    PStunAttributeHeader pAttribute;
    PStunAttributeAddress pStunAttributeAddress = NULL;

   //
    // Binding request
    //
    EXPECT_EQ(STATUS_SUCCESS,
                  deserializeStunPacket(bindingSuccessResponseXorMappedAddressBytes1, SIZEOF(bindingSuccessResponseXorMappedAddressBytes1),
                                        (PBYTE) TEST_STUN_PASSWORD, (UINT32) STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), &pStunPacket));
        EXPECT_EQ(pStunPacket->header.magicCookie, STUN_HEADER_MAGIC_COOKIE);
        EXPECT_EQ(pStunPacket->header.messageLength, 12);
        EXPECT_EQ(pStunPacket->header.stunMessageType, STUN_PACKET_TYPE_BINDING_RESPONSE_SUCCESS);
        EXPECT_EQ(pStunPacket->attributesCount, 1);
        EXPECT_EQ(pStunPacket->attributeList[0]->type, STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS);


    return fail;
}


int createStunPackageValidityTests()
{
    BYTE transactionId[STUN_TRANSACTION_ID_LEN] = {0};
    PStunPacket pStunPacket;

    EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, transactionId, &pStunPacket));

    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));
    EXPECT_TRUE(NULL == pStunPacket);
    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));

    EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, transactionId, &pStunPacket));
    EXPECT_EQ(0, MEMCMP(pStunPacket->header.transactionId, transactionId, STUN_TRANSACTION_ID_LEN));
    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));

    // Random transaction id
    EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, NULL, &pStunPacket));
    EXPECT_NE(0, MEMCMP(pStunPacket->header.transactionId, transactionId, STUN_TRANSACTION_ID_LEN));
    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));
    return fail;
}

int  appendAddressAttributeMaxCountTest()
{
    BYTE transactionId[STUN_TRANSACTION_ID_LEN];
    PStunPacket pStunPacket;
    UINT32 i;
    KvsIpAddress address;

    address.family = KVS_IP_FAMILY_TYPE_IPV4;

    EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, transactionId, &pStunPacket));

    for (i = 0; i <= STUN_ATTRIBUTE_MAX_COUNT; i++) {
        EXPECT_EQ(STATUS_SUCCESS, appendStunAddressAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS, &address));
    }

    // Should fail with one more
    EXPECT_EQ(STATUS_STUN_MAX_ATTRIBUTE_COUNT, appendStunAddressAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS, &address));

    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));
    return fail;
}

// int roundtripAfterCreateAddFidelityTest ()
// {
//     PBYTE pBuffer = NULL;
//     UINT32 size;
//     BYTE transactionId[STUN_TRANSACTION_ID_LEN];
//     KvsIpAddress address;

//     address.family = KVS_IP_FAMILY_TYPE_IPV4;
//     address.port = (UINT16) getInt16(12345);
//     MEMCPY(address.address, (PBYTE) "0123456789abcdef", IPV6_ADDRESS_LENGTH);

//     MEMCPY(transactionId, (PBYTE) "ABCDEFGHIJKL", STUN_TRANSACTION_ID_LEN);

//     PStunPacket pStunPacket = NULL, pSerializedStunPacket = NULL;

//     //
//     // Create STUN packet and add various attributes
//     //
//     EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, transactionId, &pStunPacket));
//     EXPECT_EQ(pStunPacket->header.magicCookie, STUN_HEADER_MAGIC_COOKIE);
//     EXPECT_EQ(pStunPacket->header.messageLength, 0);
//     EXPECT_EQ(pStunPacket->header.stunMessageType, STUN_PACKET_TYPE_BINDING_REQUEST);
//     EXPECT_EQ(pStunPacket->allocationSize, STUN_PACKET_ALLOCATION_SIZE);
//     EXPECT_EQ(pStunPacket->attributesCount, 0);
//     return fail;
// }



int attributeDetectionTest()
{
    PStunAttributeHeader pUsernameAttribute;
    BYTE transactionId[STUN_TRANSACTION_ID_LEN];
    PStunPacket pStunPacket;
    CHAR userName[70 + 1];

    MEMSET(userName, 'a', ARRAY_SIZE(userName));
    userName[ARRAY_SIZE(userName) - 1] = '\0';

    EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, transactionId, &pStunPacket));

    EXPECT_EQ(STATUS_SUCCESS, getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_USERNAME, &pUsernameAttribute));
    EXPECT_TRUE(NULL == pUsernameAttribute);
    EXPECT_EQ(STATUS_SUCCESS, appendStunUsernameAttribute(pStunPacket, userName));
    EXPECT_EQ(STATUS_SUCCESS, getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_USERNAME, &pUsernameAttribute));
    EXPECT_TRUE(NULL != pUsernameAttribute);
    EXPECT_TRUE(pUsernameAttribute->type == STUN_ATTRIBUTE_TYPE_USERNAME);

    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));
    return fail;
}

int roundtripAfterCreateAddFidelityTest()
{
    PBYTE pBuffer = NULL;
    UINT32 size;
    BYTE transactionId[STUN_TRANSACTION_ID_LEN];
    KvsIpAddress address;

    address.family = KVS_IP_FAMILY_TYPE_IPV4;
    address.port = (UINT16) getInt16(12345);
    MEMCPY(address.address, (PBYTE) "0123456789abcdef", IPV6_ADDRESS_LENGTH);

    MEMCPY(transactionId, (PBYTE) "ABCDEFGHIJKL", STUN_TRANSACTION_ID_LEN);

    PStunPacket pStunPacket = NULL, pSerializedStunPacket = NULL;

    //
    // Create STUN packet and add various attributes
    //
    EXPECT_EQ(STATUS_SUCCESS, createStunPacket(STUN_PACKET_TYPE_BINDING_REQUEST, transactionId, &pStunPacket));
    printf("Creates stun packt\n");
    EXPECT_EQ(pStunPacket->header.magicCookie, STUN_HEADER_MAGIC_COOKIE);
    EXPECT_EQ(pStunPacket->header.messageLength, 0);
    EXPECT_EQ(pStunPacket->header.stunMessageType, STUN_PACKET_TYPE_BINDING_REQUEST);
    EXPECT_EQ(pStunPacket->allocationSize, STUN_PACKET_ALLOCATION_SIZE);
    EXPECT_EQ(pStunPacket->attributesCount, 0);

    printf("Append stun attr 0\n");
    EXPECT_EQ(STATUS_SUCCESS, appendStunPriorityAttribute(pStunPacket, 10));
    EXPECT_EQ(STATUS_SUCCESS, appendStunUsernameAttribute(pStunPacket, (PCHAR) "abc"));
    printf("Append stun attr done\n");

    EXPECT_EQ(pStunPacket->header.messageLength, 16);

    // Validate the attributes
    EXPECT_EQ(pStunPacket->attributesCount, 2);
    EXPECT_EQ(pStunPacket->attributeList[0]->type, STUN_ATTRIBUTE_TYPE_PRIORITY);
    EXPECT_EQ(10, ((PStunAttributePriority) pStunPacket->attributeList[0])->priority);
    EXPECT_EQ(pStunPacket->attributeList[1]->type, STUN_ATTRIBUTE_TYPE_USERNAME);
    EXPECT_EQ(0, memcmp("abc", ((PStunAttributeUsername) pStunPacket->attributeList[1])->userName, 3));

    printf("Serialize stun packet \n");
    // Serialize it
    EXPECT_EQ(STATUS_SUCCESS,
              serializeStunPacket(pStunPacket, (PBYTE) TEST_STUN_PASSWORD, STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), TRUE, TRUE, NULL, &size));
    printf("Serialize stun packet len %d\n",size);
    pBuffer = (PBYTE) malloc(size);
    if(pBuffer == NULL)
        printf("NULL BUFFER\n");

    EXPECT_EQ(STATUS_SUCCESS,
              serializeStunPacket(pStunPacket, (PBYTE) TEST_STUN_PASSWORD, STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), TRUE, TRUE, pBuffer, &size));
    printf("Serialize done\n");
    
    printf("Serialize packet \n");
    for(int i=0;i<size; i++)
    {
        printf("0x%02x ", pBuffer[i]);
    }
    printf("\n");

    // De-serialize it back again
    EXPECT_EQ(
        STATUS_SUCCESS,
        deserializeStunPacket(pBuffer, size, (PBYTE) TEST_STUN_PASSWORD, (UINT32) STRLEN(TEST_STUN_PASSWORD) * SIZEOF(CHAR), &pSerializedStunPacket));

    EXPECT_EQ(pSerializedStunPacket->header.magicCookie, STUN_HEADER_MAGIC_COOKIE);
    printf("pSerializedStunPacket->header.messageLength %d\n",pSerializedStunPacket->header.messageLength);
    EXPECT_EQ(pSerializedStunPacket->header.messageLength, 48);
    EXPECT_EQ(pSerializedStunPacket->header.stunMessageType, STUN_PACKET_TYPE_BINDING_REQUEST);

    // Validate the values
    printf(" pSerializedStunPacket->attributesCount %d\n",pSerializedStunPacket->attributesCount);
    EXPECT_EQ(pSerializedStunPacket->attributesCount, 4);
    EXPECT_EQ(pSerializedStunPacket->attributeList[0]->type, STUN_ATTRIBUTE_TYPE_PRIORITY);
    EXPECT_EQ(10, ((PStunAttributePriority) pSerializedStunPacket->attributeList[0])->priority);
    EXPECT_EQ(pSerializedStunPacket->attributeList[1]->type, STUN_ATTRIBUTE_TYPE_USERNAME);
    EXPECT_EQ(0, MEMCMP("abc", ((PStunAttributeUsername) pSerializedStunPacket->attributeList[1])->userName, 3));
    EXPECT_EQ(pSerializedStunPacket->attributeList[2]->type, STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY);
    EXPECT_EQ(pSerializedStunPacket->attributeList[3]->type, STUN_ATTRIBUTE_TYPE_FINGERPRINT);

    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pStunPacket));
    EXPECT_EQ(STATUS_SUCCESS, freeStunPacket(&pSerializedStunPacket));
    SAFE_MEMFREE(pBuffer);
    
    return fail;
}
int main()
{
    int f ;
    initializeEndianness();
    //f = createStunPackageValidityTests();
    // if(f==1)
    //     printf("FAIL\n");
    // else
    //     printf("pass\n");
    
    f = roundtripAfterCreateAddFidelityTest();
    if(f==1)
        printf("FAIL\n");
    else
        printf("pass\n");
}