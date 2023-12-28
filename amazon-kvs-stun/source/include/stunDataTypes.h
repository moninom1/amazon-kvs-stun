#ifndef STUN_DATA_TYPES_H
#define STUN_DATA_TYPES_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

#define STUN_TRANSACTION_ID_LENGTH  12

typedef enum StunResult
{
    STUN_RESULT_OK,
    STUN_RESULT_BAD_PARAM,
    STUN_RESULT_OUT_OF_MEMORY,
    STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY,
    STATUS_MAGIC_COOKIE_MISMATCH,
    STATUS_NO_ATTRIBUTE_FOUND,
    STATUS_INVALID_ATTRIBUTE_LENGTH
} StunResult_t;

typedef enum StunMessageType
{
    STUN_MESSAGE_TYPE_BINDING_REQUEST = 0x0001,
    STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE,
    STUN_MESSAGE_TYPE_BINDING_FAILURE_RESPONSE,
    STUN_MESSAGE_TYPE_BINDING_INDICATION
} StunMessageType_t;

typedef enum StunAttributeType
{
    STUN_ATTRIBUTE_USERNAME_TYPE = 0x0006,
    STUN_ATTRIBUTE_MESSAGE_INTEGRITY = 0x0008,
    STUN_ATTRIBUTE_PRIORITY_TYPE = 0x0024,
    STUN_ATTRIBUTE_FINGERPRINT = 0x8028,
} StunAttributeType_t;

typedef struct StunHeader
{
    StunMessageType_t stunMessageType;
    uint16_t messageLength;   
    uint8_t transactionId[ STUN_TRANSACTION_ID_LENGTH ];
} StunHeader_t;

typedef struct StunAttributeHeader
{
    uint16_t type; // Type of the STUN attribute
    uint16_t length; // Length of the value
} StunAttributeHeader_t;

#endif /* STUN_DATA_TYPES_H */
