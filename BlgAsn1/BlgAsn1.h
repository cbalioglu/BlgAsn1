/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#pragma once

#ifndef BLGASN1_H
#define BLGASN1_H

#include <windows.h>

#if _WIN32_WINNT < 0x0500
#error The ASN.1 DER Library requires Windows 2000 or later.
#endif

#ifdef __cplusplus
#define BLGASN1_EXTERN_C extern "C"
#else
#define BLGASN1_EXTERN_C
#endif

#if defined(BLGASN1_LIB_IMPL) || defined(BLGASN1_LIB_STATIC)
#define BLGASN1API BLGASN1_EXTERN_C
#else
#define BLGASN1API BLGASN1_EXTERN_C DECLSPEC_IMPORT
#endif

#define BLGASN1CALL __stdcall

#ifdef _M_CEE_PURE
#define BLGASN1INLINECALL __clrcall
#else
#define BLGASN1INLINECALL __stdcall
#endif

#define BLGASN1_MAKE_ERROR(Code) ((DWORD) (0x20000000 | (Code)))

#define ERROR_BLGASN1_EOD          BLGASN1_MAKE_ERROR(100L)
#define ERROR_BLGASN1_UNEXP_EOD    BLGASN1_MAKE_ERROR(101L)
#define ERROR_BLGASN1_TOO_LARGE    BLGASN1_MAKE_ERROR(102L)
#define ERROR_BLGASN1_CORRUPT      BLGASN1_MAKE_ERROR(103L)
#define ERROR_BLGASN1_CONSTRAINT   BLGASN1_MAKE_ERROR(104L)
#define ERROR_BLGASN1_BADTAG       BLGASN1_MAKE_ERROR(105L)
#define ERROR_BLGASN1_PRIMITIVE    BLGASN1_MAKE_ERROR(106L)

// ASN.1 DER classes.
#define BLG_DER_CLASS_UNIVERSAL     0x00
#define BLG_DER_CLASS_APPLICATION   0x01
#define BLG_DER_CLASS_CONTEXT       0x02
#define BLG_DER_CLASS_PRIVATE       0x03

// ASN.1 DER UNIVERSAL class tags.
#define BLG_DER_TAG_BOOLEAN            0x01
#define BLG_DER_TAG_INTEGER            0x02
#define BLG_DER_TAG_OCTET_STRING       0x03
#define BLG_DER_TAG_NULL               0x05
#define BLG_DER_TAG_UTF8_STRING        0x0C
#define BLG_DER_TAG_SEQUENCE           0x10
#define BLG_DER_TAG_SEQUENCE_OF        0x10
#define BLG_DER_TAG_SET                0x11
#define BLG_DER_TAG_SET_OF             0x11
#define BLG_DER_TAG_PRINTABLE_STRING   0x13
#define BLG_DER_TAG_IA5_STRING         0x16
#define BLG_DER_TAG_GENERALIZED_TIME   0x18
#define BLG_DER_TAG_BMP_STRING         0x1E

DECLARE_HANDLE(HBLG_DER_ENCODER);
DECLARE_HANDLE(HBLG_DER_DECODER);


BLGASN1API
HBLG_DER_ENCODER
BLGASN1CALL
BlgDerCreateEncoder(
    IN PBYTE Buffer,
    IN DWORD BufferCb,
    IN DWORD Flags
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDestroyEncoder(
    IN HBLG_DER_ENCODER EncoderHandle
    );


// Valid values for Parameter of BlgDerGetEncoderParam.
#define BLG_DER_ENC_PARAM_BUFFER       0x01 // Return the pointer to the underlying buffer.
#define BLG_DER_ENC_PARAM_BUFFER_CB    0x02 // Return the size of the underlying buffer.
#define BLG_DER_ENC_PARAM_ENCODED_CB   0x03 // Return the number of encoded bytes.

BLGASN1API
BOOL
BLGASN1CALL
BlgDerGetEncoderParam(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN DWORD Parameter,
    OUT PVOID Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerBeginConstructed(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEndConstructed(
    IN HBLG_DER_ENCODER EncoderHandle
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerWriteRaw(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN CONST BYTE *Value,
    IN DWORD ValueCb
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncTag(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN BOOLEAN Constructed,
    IN DWORD Tag
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncLen(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN DWORD Len
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncBool(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN BOOLEAN Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncNull(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncOctetString(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN CONST BYTE *Value,
    IN INT ValueCb
    );

// Not implemented yet.
BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncObjectIdentifier(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncInt(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE  Class,
    IN DWORD Tag,
    IN BOOL Positive,
    IN CONST BYTE *Value,
    IN DWORD ValueCb
    );

__inline
BOOL
BLGASN1INLINECALL
BlgDerEncInt16(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN SHORT Value
    )
{
    return BlgDerEncInt(EncoderHandle, Class, Tag, Value >= 0, (CONST PBYTE) &Value, sizeof(SHORT));
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerEncInt32(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN INT Value
    )
{
    return BlgDerEncInt(EncoderHandle, Class, Tag, Value >= 0, (CONST PBYTE) &Value, sizeof(INT));
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerEncUInt16(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN WORD Value
    )
{
    return BlgDerEncInt(EncoderHandle, Class, Tag, TRUE, (CONST PBYTE) &Value, sizeof(WORD));
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerEncUInt32(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN DWORD Value
    )
{
    return BlgDerEncInt(EncoderHandle, Class, Tag, TRUE, (CONST PBYTE) &Value, sizeof(DWORD));
}

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncIA5String(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value,
    IN INT ValueCch
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncUtf8String(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value,
    IN INT ValueCch
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncBmpString(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value,
    IN INT ValueCch
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerEncGeneralizedTime(
    IN HBLG_DER_ENCODER  EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN CONST SYSTEMTIME *Value
    );

// Valid values for Flag of BlgDerCreateDecoder.
#define BLG_DER_DEC_FLAG_RELAXED   0x0001 // Use relaxed decoding rules. (BER)

BLGASN1API
HBLG_DER_DECODER
BLGASN1CALL
BlgDerCreateDecoder(
    IN CONST BYTE *Encoded,
    IN DWORD EncodedCb,
    IN DWORD Flag
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDestroyDecoder(
    IN HBLG_DER_DECODER DecoderHandle
    );

// Valid values for Parameter of BlgDerGetDecoderParam.
#define BLG_DER_DEC_PARAM_ENCODED      0x01 // Return the pointer to the underlying encoded data.
#define BLG_DER_DEC_PARAM_ENCODED_CB   0x02 // Return the size of the underlying encoded data.
#define BLG_DER_DEC_PARAM_DECODED_CB   0x03 // Return the number of bytes decoded.

BLGASN1API
BOOL
BLGASN1CALL
BlgDerGetDecoderParam(
    IN HBLG_DER_DECODER DecoderHandle,
    IN DWORD Parameter,
    OUT PVOID Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerHasMoreData(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerHasValue(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    );

BOOL
BLGASN1CALL
BlgDerMoveToFirst(
    IN HBLG_DER_DECODER DecoderHandle
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerMoveToNext(
    IN HBLG_DER_DECODER DecoderHandle
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerMoveToChild(
    IN HBLG_DER_DECODER DecoderHandle
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerMoveToParent(
    IN HBLG_DER_DECODER DecoderHandle
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerCompareTag(
    IN HBLG_DER_DECODER DecoderHandle,
    IN BYTE Class,
    IN BOOL Constructed,
    IN DWORD Tag,
    OUT PBOOL IsEqual
    );

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsBoolean(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, FALSE, BLG_DER_TAG_BOOLEAN, Result);
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsNull(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, FALSE, BLG_DER_TAG_NULL, Result);
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsOctetString(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, FALSE, BLG_DER_TAG_OCTET_STRING, Result);
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsInteger(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, FALSE, BLG_DER_TAG_INTEGER, Result);
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsIA5String(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, FALSE, BLG_DER_TAG_IA5_STRING, Result);
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsUtf8String(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, FALSE, BLG_DER_TAG_UTF8_STRING, Result);
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsBmpString(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, FALSE, BLG_DER_TAG_BMP_STRING, Result);
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsGeneralizedTime(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, FALSE, BLG_DER_TAG_GENERALIZED_TIME, Result);
}

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsSequence(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, TRUE, BLG_DER_TAG_SEQUENCE, Result);
}

#define BlgDerIsSequenceOf BlgDerIsSequence

__inline
BOOL
BLGASN1INLINECALL
BlgDerIsSet(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )
{
    return BlgDerCompareTag(DecoderHandle, BLG_DER_CLASS_UNIVERSAL, TRUE, BLG_DER_TAG_SET, Result);
}

#define BlgDerIsSetOf BlgDerIsSet

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecTag(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBYTE Class OPTIONAL,
    OUT PBOOL Constructed OPTIONAL,
    OUT PDWORD Tag
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecBool(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecOctetString(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBYTE Buffer OPTIONAL,
    IN OUT PDWORD BufferCb
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecInt(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Positive OPTIONAL,
    OUT PBYTE Buffer OPTIONAL,
    IN OUT PDWORD BufferCb
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecInt16(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PSHORT Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecInt32(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PINT Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecUInt16(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWORD Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecUInt32(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PDWORD Value
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecIA5String(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWSTR Buffer OPTIONAL,
    IN OUT PDWORD BufferCch
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecUtf8String(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWSTR Buffer OPTIONAL,
    IN OUT PDWORD BufferCch
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecBmpString(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWSTR Buffer OPTIONAL,
    IN OUT PDWORD BufferCch
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecGeneralizedTime(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PSYSTEMTIME Value
    );

typedef struct _BLG_DER_CHILD_NODE
{
    BYTE  Class;
    BOOL  Constructed;
    DWORD Tag;
    BOOL  Optional;

} BLG_DER_CHILD_NODE, *PBLG_DER_CHILD_NODE;

typedef CONST BLG_DER_CHILD_NODE *PCBLG_DER_CHILD_NODE;

// Called by BlgDerDecSequence for every node in the sequence that has a
// matching entry in the specified node list.
typedef
BOOL
(BLGASN1CALL *PBLG_DER_DECODE_NODE_ROUTINE)(
    IN HBLG_DER_DECODER Decoder,
    IN DWORD Index,
    IN PCBLG_DER_CHILD_NODE Node,
    IN PVOID Context
    );

BLGASN1API
BOOL
BLGASN1CALL
BlgDerDecSequence(
    IN HBLG_DER_DECODER Decoder,
    IN PCBLG_DER_CHILD_NODE Nodes,
    IN DWORD NodeCount,
    IN PBLG_DER_DECODE_NODE_ROUTINE DecodeRoutine,
    IN PVOID Context
    );

#endif