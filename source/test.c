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

    initializeEndianness();
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


int main()
{
    int f = basicValidParseTest();
    if(f==1)
        printf("FAIL\n");
    else
        printf("pass\n");
    
    f = serializeDeserializeStunControlAttribute();
    if(f==1)
        printf("FAIL\n");
    else
        printf("pass\n");
}