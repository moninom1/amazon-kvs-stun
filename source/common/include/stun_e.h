/*
 * stun_e.h
 *
 *  Created on: Dec 22, 2023
 *      Author: moninom
 */

#ifndef STUN_E_H_
#define STUN_E_H_

#include <stdio.h>
#include <string.h> 

#include "../../include/stun.h"

#define STUN_TOTAL_PACKET_LEN 224 // (pStunPacket + 1 ) + ( STUN_ATTRIBUTE_MAX_COUNT pointers )

typedef enum StunResult
{
    STUN_RESULT_OK,
    STUN_RESULT_BASE = 0x51000000,
    STUN_RESULT_BAD_PARAM,
    STUN_RESULT_MESSAGE_END,
    STUN_RESULT_MESSAGE_NULL_BUFFER,
    STUN_RESULT_MESSAGE_MALFORMED_NO_ENOUGH_INFO,
    STUN_RESULT_MESSAGE_MALFORMED_NO_VALUE,
    STUN_RESULT_MESSAGE_MALFORMED_INVALID_ADDRESS_TYPE,
    STUN_RESULT_OUT_OF_MEMORY,
    STUN_RESULT_SNPRINTF_ERROR
} StunResult_t;


StunResult_t StunContextInit( char * pBuffer,
                              size_t bufferLength);

StunResult_t StunHeaderInit( STUN_PACKET_TYPE stunPacketType,
                             PBYTE transactionId,
                             char * pBuffer,
                             size_t bufferLength );

StunResult_t SerialiseStunHeader( PStunPacket pStunPacket,
                                    size_t bufferLength );

StunResult_t appendSerialiseStunUsernameAttribute(PStunPacket pStunPacket,
                                                     PCHAR userName);

StunResult_t appendSerialisePriorityAttribute(PStunPacket pStunPacket,
                                                     UINT32 priority);

StunResult_t serializeStunPacketNew(PStunPacket pStunPacket, PBYTE password, UINT32 passwordLen, BOOL generateMessageIntegrity, BOOL generateFingerprint,
                                        char **pBuffer, PUINT32 pSize);

#endif /* STUN_E_H_ */