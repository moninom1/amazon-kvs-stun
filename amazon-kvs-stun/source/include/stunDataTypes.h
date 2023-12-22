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
    STUN_RESULT_OUT_OF_MEMORY
} StunResult_t;

typedef enum StunMessageType
{
    STUN_MESSAGE_TYPE_BINDING_REQUEST,
    STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE,
    STUN_MESSAGE_TYPE_BINDING_FAILURE_RESPONSE,
    STUN_MESSAGE_TYPE_BINDING_INDICATION
} StunMessageType_t;

typedef struct StunHeader
{
    StunMessageType_t stunMessageType;
    uint8_t transactionId[ STUN_TRANSACTION_ID_LENGTH ];
} StunHeader_t;

#endif /* STUN_DATA_TYPES_H */
