/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

typedef struct _BLGP_DER_ENCODER_NODE
{
    SINGLE_LIST_ENTRY Link;
    PBYTE ValueOffset;

} BLGP_DER_ENCODER_NODE, *PBLGP_DER_ENCODER_NODE;

HBLG_DER_ENCODER
BLGASN1CALL
BlgDerCreateEncoder(
    IN PBYTE Buffer,
    IN DWORD BufferCb,
    IN DWORD Flags
    )

/*++

Routine Description:

    Creates a new ASN.1 DER encoder.

Arguments:

    Buffer - Pointer to a buffer that receives the ASN.1 DER encoded data.

    BufferCb - Size, in bytes, of the buffer pointed to by the Buffer parameter.

    Flags - Additional settings for the encoder to be created.

Return Value:

    The handle to the encoder if the routine succeeds; otherwise, NULL.

--*/

{
    PBLGP_DER_ENCODER Encoder = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, sizeof(BLGP_DER_ENCODER));
    if (!Encoder)
    {
        SetLastError(ERROR_OUTOFMEMORY);

        return NULL;
    }

    Encoder->Buffer = Buffer;
    Encoder->BufferCb = BufferCb;
    Encoder->Ptr = Buffer;
    Encoder->Flags = Flags;

    return (HBLG_DER_ENCODER) Encoder;
}

BOOL
BLGASN1CALL
BlgDerDestroyEncoder(
    IN HBLG_DER_ENCODER EncoderHandle
    )

/*++

Routine Description:

    Destroys the specified encoder.

Arguments:

    EncoderHandle - Handle to the encoder to be destroyed.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;
    PSINGLE_LIST_ENTRY Link;

    if (!Encoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    while ((Link = BlgPopEntryList(&Encoder->Stack)))
    {
        HeapFree(g_Heap, 0, CONTAINING_RECORD(Link, BLGP_DER_ENCODER_NODE, Link));
    }

    return HeapFree(g_Heap, 0, Encoder);
}

BOOL
BLGASN1CALL
BlgDerGetEncoderParam(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN DWORD Parameter,
    OUT PVOID Value
    )

/*++

Routine Description:

    Returns the value of an encoder parameter.

Arguments:

    EncoderHandle - Handle to the encoder to be examined.

    Parameter - Type of the parameter.

    Value - Pointer to a caller specific memory location that receives the value of the parameter.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;

    if (!Encoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    switch (Parameter)
    {
    case BLG_DER_ENC_PARAM_BUFFER:
        *(PBYTE *) Value = Encoder->Buffer;

        break;

    case BLG_DER_ENC_PARAM_BUFFER_CB:
        *(PDWORD) Value = Encoder->BufferCb;

        break;

    case BLG_DER_ENC_PARAM_ENCODED_CB:
        *(PDWORD) Value = BLGP_DER_ENCODED_CB(Encoder);

        break;

    default:
        return FALSE;
    }

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerBeginConstructed(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag
    )

/*++

Routine Description:

    Begins the encoding of a constructed node.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Class - Class of the constructed node.

    Tag - Tag of the constructed node.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;
    PBLGP_DER_ENCODER_NODE Node;

    if (!Encoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (!BlgDerEncTag(EncoderHandle, Class, TRUE, Tag))
    {
        return FALSE;
    }

    if (!BlgDerEncLen(EncoderHandle, 0))
    {
        return FALSE;
    }

    Node = HeapAlloc(g_Heap, 0, sizeof(BLGP_DER_ENCODER_NODE));
    if (!Node)
    {
        SetLastError(ERROR_OUTOFMEMORY);

        return FALSE;
    }

    Node->ValueOffset = Encoder->Ptr;

    BlgPushEntryList(&Encoder->Stack, &Node->Link);

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerEndConstructed(
    IN HBLG_DER_ENCODER EncoderHandle
    )

/*++

Routine Description:

    Ends the encoding of a constructed node.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;
    PBLGP_DER_ENCODER_NODE Node;
    PSINGLE_LIST_ENTRY Link;
    DWORD Len;

    if (!Encoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    Link = BlgPopEntryList(&Encoder->Stack);
    if (!Link)
    {
        SetLastError(ERROR_INVALID_STATE);

        return FALSE;
    }

    Node = CONTAINING_RECORD(Link, BLGP_DER_ENCODER_NODE, Link);

    Len = (DWORD) (Encoder->Ptr - Node->ValueOffset);

    if (Len > 127)
    {
        PBYTE Bits = (PBYTE) &Len;

        DWORD OctetCount = BlgpNonZeroByteLength(Bits, sizeof(DWORD));

        if (Encoder->Buffer)
        {
            PBYTE LengthPtr = Node->ValueOffset - 1;

            if (BLGP_DER_ENCODED_CB(Encoder) + OctetCount > Encoder->BufferCb)
            {
                HeapFree(g_Heap, 0, Node);

                SetLastError(ERROR_INSUFFICIENT_BUFFER);

                return FALSE;
            }

            MoveMemory(Node->ValueOffset + OctetCount, Node->ValueOffset, Len);

            *LengthPtr++ = (BYTE) OctetCount | 0x80;

            BlgpCopyMemory(LengthPtr, Bits, OctetCount);
        }

        Encoder->Ptr += OctetCount;
    }
    else
    {
        if (Encoder->Buffer)
        {
            *(Node->ValueOffset - 1) = (BYTE) Len;
        }
    }

    HeapFree(g_Heap, 0, Node);

    return TRUE;
}