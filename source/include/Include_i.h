/*
 * Include_i.h
 *
 *  Created on: Dec 18, 2023
 *      Author: moninom
 */

#ifndef INC_INCLUDE_I_H_
#define INC_INCLUDE_I_H_

#include "crc32.h"

#define STATUS_COMMON_PRODUCER_BASE                         0x15000000
#define STATUS_HMAC_GENERATION_ERROR                        STATUS_COMMON_PRODUCER_BASE + 0x00000010


#define KVS_SHA1_HMAC hmac_sha1


#define COMPUTE_CRC32(pBuffer, len) (updateCrc32(0, pBuffer, len))

// Max uFrag and uPwd length as documented in https://tools.ietf.org/html/rfc5245#section-15.4
#define ICE_MAX_UFRAG_LEN 256
#define ICE_MAX_UPWD_LEN  256

// Max stun username attribute len: https://tools.ietf.org/html/rfc5389#section-15.3
#define STUN_MAX_USERNAME_LEN (UINT16) 512

// https://tools.ietf.org/html/rfc5389#section-15.7
#define STUN_MAX_REALM_LEN (UINT16) 128

// https://tools.ietf.org/html/rfc5389#section-15.8
#define STUN_MAX_NONCE_LEN (UINT16) 128

// https://tools.ietf.org/html/rfc5389#section-15.6
#define STUN_MAX_ERROR_PHRASE_LEN (UINT16) 128

// Byte sizes of the IP addresses
#define IPV6_ADDRESS_LENGTH (UINT16) 16
#define IPV4_ADDRESS_LENGTH (UINT16) 4

#define CERTIFICATE_FINGERPRINT_LENGTH 160

#define MAX_UDP_PACKET_SIZE 65507

#define KVS_SHA1_DIGEST_LENGTH      20

#define STATUS_WEBRTC_BASE 0x55000000
#define STATUS_SDP_BASE                         STATUS_WEBRTC_BASE + 0x01000000
#define STATUS_STUN_BASE                                           STATUS_SDP_BASE + 0x01000000
#define STATUS_STUN_MESSAGE_INTEGRITY_NOT_LAST                     STATUS_STUN_BASE + 0x00000001
#define STATUS_STUN_MESSAGE_INTEGRITY_SIZE_ALIGNMENT               STATUS_STUN_BASE + 0x00000002
#define STATUS_STUN_FINGERPRINT_NOT_LAST                           STATUS_STUN_BASE + 0x00000003
#define STATUS_STUN_MAGIC_COOKIE_MISMATCH                          STATUS_STUN_BASE + 0x00000004
#define STATUS_STUN_INVALID_ADDRESS_ATTRIBUTE_LENGTH               STATUS_STUN_BASE + 0x00000005
#define STATUS_STUN_INVALID_USERNAME_ATTRIBUTE_LENGTH              STATUS_STUN_BASE + 0x00000006
#define STATUS_STUN_INVALID_MESSAGE_INTEGRITY_ATTRIBUTE_LENGTH     STATUS_STUN_BASE + 0x00000007
#define STATUS_STUN_INVALID_FINGERPRINT_ATTRIBUTE_LENGTH           STATUS_STUN_BASE + 0x00000008
#define STATUS_STUN_MULTIPLE_MESSAGE_INTEGRITY_ATTRIBUTES          STATUS_STUN_BASE + 0x00000009
#define STATUS_STUN_MULTIPLE_FINGERPRINT_ATTRIBUTES                STATUS_STUN_BASE + 0x0000000A
#define STATUS_STUN_ATTRIBUTES_AFTER_FINGERPRINT_MESSAGE_INTEGRITY STATUS_STUN_BASE + 0x0000000B
#define STATUS_STUN_MESSAGE_INTEGRITY_AFTER_FINGERPRINT            STATUS_STUN_BASE + 0x0000000C
#define STATUS_STUN_MAX_ATTRIBUTE_COUNT                            STATUS_STUN_BASE + 0x0000000D
#define STATUS_STUN_MESSAGE_INTEGRITY_MISMATCH                     STATUS_STUN_BASE + 0x0000000E
#define STATUS_STUN_FINGERPRINT_MISMATCH                           STATUS_STUN_BASE + 0x0000000F
#define STATUS_STUN_INVALID_PRIORITY_ATTRIBUTE_LENGTH              STATUS_STUN_BASE + 0x00000010
#define STATUS_STUN_INVALID_USE_CANDIDATE_ATTRIBUTE_LENGTH         STATUS_STUN_BASE + 0x00000011
#define STATUS_STUN_INVALID_LIFETIME_ATTRIBUTE_LENGTH              STATUS_STUN_BASE + 0x00000012
#define STATUS_STUN_INVALID_REQUESTED_TRANSPORT_ATTRIBUTE_LENGTH   STATUS_STUN_BASE + 0x00000013
#define STATUS_STUN_INVALID_REALM_ATTRIBUTE_LENGTH                 STATUS_STUN_BASE + 0x00000014
#define STATUS_STUN_INVALID_NONCE_ATTRIBUTE_LENGTH                 STATUS_STUN_BASE + 0x00000015
#define STATUS_STUN_INVALID_ERROR_CODE_ATTRIBUTE_LENGTH            STATUS_STUN_BASE + 0x00000016
#define STATUS_STUN_INVALID_ICE_CONTROL_ATTRIBUTE_LENGTH           STATUS_STUN_BASE + 0x00000017
#define STATUS_STUN_INVALID_CHANNEL_NUMBER_ATTRIBUTE_LENGTH        STATUS_STUN_BASE + 0x00000018
#define STATUS_STUN_INVALID_CHANGE_REQUEST_ATTRIBUTE_LENGTH        STATUS_STUN_BASE + 0x00000019
/*!@} */


typedef enum {
    KVS_IP_FAMILY_TYPE_IPV4 = (UINT16) 0x0001,
    KVS_IP_FAMILY_TYPE_IPV6 = (UINT16) 0x0002,
} KVS_IP_FAMILY_TYPE;

typedef struct {
    UINT16 family;
    UINT16 port;                       // port is stored in network byte order
    BYTE address[IPV6_ADDRESS_LENGTH]; // address is stored in network byte order
    BOOL isPointToPoint;
} KvsIpAddress, *PKvsIpAddress;

#define IS_IPV4_ADDR(pAddress) ((pAddress)->family == KVS_IP_FAMILY_TYPE_IPV4)

// Used for ensuring alignment
#define ALIGN_UP_TO_MACHINE_WORD(x) ROUND_UP((x), SIZEOF(SIZE_T))

////////////////////////////////////////////////////
// Endianness functionality
////////////////////////////////////////////////////
typedef INT16 (*getInt16Func)(INT16);
typedef INT32 (*getInt32Func)(INT32);
typedef INT64 (*getInt64Func)(INT64);
typedef VOID (*putInt16Func)(PINT16, INT16);
typedef VOID (*putInt32Func)(PINT32, INT32);
typedef VOID (*putInt64Func)(PINT64, INT64);

extern getInt16Func getInt16;
extern getInt32Func getInt32;
extern getInt64Func getInt64;
extern putInt16Func putInt16;
extern putInt32Func putInt32;
extern putInt64Func putInt64;

PUBLIC_API BOOL isBigEndian();
PUBLIC_API VOID initializeEndianness();

/**
 * Endianness functionality
 */
INT16 getInt16Swap(INT16);
INT16 getInt16NoSwap(INT16);
INT32 getInt32Swap(INT32);
INT32 getInt32NoSwap(INT32);
INT64 getInt64Swap(INT64);
INT64 getInt64NoSwap(INT64);

VOID putInt16Swap(PINT16, INT16);
VOID putInt16NoSwap(PINT16, INT16);
VOID putInt32Swap(PINT32, INT32);
VOID putInt32NoSwap(PINT32, INT32);
VOID putInt64Swap(PINT64, INT64);
VOID putInt64NoSwap(PINT64, INT64);

#endif /* INC_INCLUDE_I_H_ */
