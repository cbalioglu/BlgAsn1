/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#pragma once

#ifndef BLGASN1P_H
#define BLGASN1P_H

#include <windows.h>

#include "BlgAsn1.h"

extern HANDLE g_Heap;

#define BLGASN1_FLAGON(x, Flag) (((x) & (Flag)) > 0)

__inline
BOOL
BLGASN1INLINECALL
BlgpIsLittleEndian(
    VOID
    )
{
    WORD t = 1;
    return *(PBYTE) &t;
}

__inline
PSINGLE_LIST_ENTRY
BLGASN1INLINECALL
BlgPopEntryList(
    IN PSINGLE_LIST_ENTRY ListHead
    )
{
    PSINGLE_LIST_ENTRY Entry = ListHead->Next;

    if (Entry)
    {
        ListHead->Next = Entry->Next;
    }

    return Entry;
}

__inline
VOID
BLGASN1INLINECALL
BlgPushEntryList(
    IN PSINGLE_LIST_ENTRY ListHead,
    IN PSINGLE_LIST_ENTRY Entry
    )
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

typedef struct _BLGP_DER_ENCODER
{
    PBYTE Buffer;
    DWORD BufferCb;
    PBYTE Ptr;
    DWORD Flags;
    SINGLE_LIST_ENTRY Stack;

} BLGP_DER_ENCODER, *PBLGP_DER_ENCODER;

typedef struct _BLGP_DER_DECODER_NODE
{
    SINGLE_LIST_ENTRY ParentLink;
    CONST BYTE *Tag;
    CONST BYTE *Value;
    DWORD ValueCb;

} BLGP_DER_DECODER_NODE, *PBLGP_DER_DECODER_NODE;

typedef struct _BLGP_DER_DECODER
{
    CONST BYTE *Encoded;
    DWORD EncodedCb;
    DWORD Flags;
    BLGP_DER_DECODER_NODE CurrentNode;

} BLGP_DER_DECODER, *PBLGP_DER_DECODER;

// Calculates the number of encoded bytes.
#define BLGP_DER_ENCODED_CB(Encoder) ((DWORD) ((Encoder)->Ptr - (Encoder)->Buffer))

VOID
BLGASN1CALL
BlgpCopyMemory(
    IN PBYTE Destination,
    IN CONST BYTE *Source,
    IN DWORD Cb
    );

DWORD
BLGASN1CALL
BlgpNonZeroByteLength(
    IN CONST BYTE *Buffer,
    IN DWORD BufferCb
    );

BOOL
BLGASN1CALL
BlgpValidateState(
    IN PBLGP_DER_DECODER Decoder
    );

#endif