/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

static
BOOL
BLGASN1CALL
BlgpMoveToNode(
    IN CONST BYTE *Encoded,
    IN DWORD EncodedCb,
    IN CONST BYTE *Offset,
    OUT PBLGP_DER_DECODER_NODE Node
    );

static
BOOL
BLGASN1CALL
BlgpMovePointer(
    IN CONST BYTE *Encoded,
    IN DWORD EncodedCb,
    IN OUT CONST BYTE **Ptr
    );

HBLG_DER_DECODER
BLGASN1CALL
BlgDerCreateDecoder(
    IN
    CONST BYTE *Encoded,
    IN DWORD EncodedCb,
    IN DWORD Flags
    )

/*++

Routine Description:

    Creates a new ASN.1 DER decoder.

Arguments:

    Encoded - Pointer to a buffer containing the encoded ASN1.DER data.

    EncodedCb - Size, in bytes, of the encoded data pointed to by the Encoded parameter.

    Flags - Additional settings for the decoder to be created.

Return Value:

    The handle to the decoder if the routine succeeds; otherwise, NULL.

--*/

{
    PBLGP_DER_DECODER Decoder;

    if (!Encoded)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    Decoder = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, sizeof(BLGP_DER_DECODER));
    if (!Decoder)
    {
        SetLastError(ERROR_OUTOFMEMORY);

        return NULL;
    }

    Decoder->Encoded = Encoded;
    Decoder->EncodedCb = EncodedCb;
    Decoder->Flags = Flags;
    Decoder->CurrentNode.Tag = Encoded;
    Decoder->CurrentNode.Value = Encoded;

    return (HBLG_DER_DECODER) Decoder;
}

BOOL
BLGASN1CALL
BlgDerDestroyDecoder(
    IN HBLG_DER_DECODER DecoderHandle
    )

/*++

Routine Description:

    Destroys the specified decoder.

Arguments:

    DecoderHandle - Handle to the decoder to be destroyed.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    PSINGLE_LIST_ENTRY ParentLink;

    if (!Decoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    while ((ParentLink = BlgPopEntryList(&Decoder->CurrentNode.ParentLink)))
    {
        HeapFree(g_Heap, 0, CONTAINING_RECORD(ParentLink, BLGP_DER_DECODER_NODE, ParentLink));
    }

    return HeapFree(g_Heap, 0, Decoder);
}

BOOL
BLGASN1CALL
BlgDerGetDecoderParam(
    IN HBLG_DER_DECODER DecoderHandle,
    IN DWORD Parameter,
    OUT PVOID Value
    )

/*++

Routine Description:

    Returns the value of a decoder parameter.

Arguments:

    DecoderHandle - Handle to the decoder to be examined.

    Parameter - Type of the parameter.

    Value - Pointer to a caller specific memory location that receives the value of the parameter.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;

    if (!Decoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    switch (Parameter)
    {
    case BLG_DER_DEC_PARAM_ENCODED:
        *(CONST BYTE **) Value = Decoder->Encoded;

        break;

    case BLG_DER_DEC_PARAM_ENCODED_CB:
        *(PDWORD) Value = Decoder->EncodedCb;

        break;

    case BLG_DER_DEC_PARAM_DECODED_CB:
        *(PDWORD) Value = (DWORD) (Decoder->CurrentNode.Tag - Decoder->Encoded);

        break;

    default:
        return FALSE;
    }

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerHasMoreData(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )

/*++

Routine Description:

    Checks whether the underlying buffer has more data to be decoded.

Arguments:

    DecoderHandle - Handle to the decoder to be examined.

    Result - Pointer to a variable that receives whether the buffer has more data to be decoded.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    PBLGP_DER_DECODER_NODE CurrentNode = &Decoder->CurrentNode;

    if (Result)
    {
        *Result = FALSE;
    }

    if (!Decoder || !Result)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    *Result = (CurrentNode->Value + CurrentNode->ValueCb < Decoder->Encoded + Decoder->EncodedCb);

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerHasValue(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Result
    )

/*++

Routine Description:

    Checks whether the current node has a value.

Arguments:

    DecoderHandle - Handle to the decoder to be examined.

    Result - Pointer to a variable that receives whether the node has a value.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;

    if (!Result)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }
    else
    {
        *Result = FALSE;
    }

    if (!BlgpValidateState(Decoder))
    {
        return FALSE;
    }

    *Result = (Decoder->CurrentNode.ValueCb == 0);

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerMoveToFirst(
    IN HBLG_DER_DECODER DecoderHandle
    )

/*++

Routine Description:

    Moves the specified decoder to the first child node of the current parent node.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    PBLGP_DER_DECODER_NODE CurrentNode = &Decoder->CurrentNode;
    CONST BYTE *Encoded;
    DWORD EncodedCb;

    if (!Decoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (CurrentNode->ParentLink.Next != NULL)
    {
        PBLGP_DER_DECODER_NODE ParentNode =
            CONTAINING_RECORD(CurrentNode->ParentLink.Next, BLGP_DER_DECODER_NODE, ParentLink);

        Encoded = ParentNode->Value;
        EncodedCb = ParentNode->ValueCb;
    }
    else
    {
        Encoded = Decoder->Encoded;
        EncodedCb = Decoder->EncodedCb;
    }

    if (EncodedCb == 0)
    {
        SetLastError(ERROR_BLGASN1_EOD);

        return FALSE;
    }

    return BlgpMoveToNode(Encoded, EncodedCb, Encoded, CurrentNode);
}

BOOL
BLGASN1CALL
BlgDerMoveToNext(
    IN HBLG_DER_DECODER DecoderHandle
    )

/*++

Routine Description:

    Moves the specified decoder to the very next node of the current node.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    PBLGP_DER_DECODER_NODE CurrentNode = &Decoder->CurrentNode;
    CONST BYTE *Encoded;
    DWORD EncodedCb;

    if (!Decoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (CurrentNode->ParentLink.Next != NULL)
    {
        PBLGP_DER_DECODER_NODE ParentNode =
            CONTAINING_RECORD(CurrentNode->ParentLink.Next, BLGP_DER_DECODER_NODE, ParentLink);

        Encoded = ParentNode->Value;
        EncodedCb = ParentNode->ValueCb;
    }
    else
    {
        Encoded = Decoder->Encoded;
        EncodedCb = Decoder->EncodedCb;
    }

    if (CurrentNode->Value + CurrentNode->ValueCb == Encoded + EncodedCb)
    {
        SetLastError(ERROR_BLGASN1_EOD);

        return FALSE;
    }

    return BlgpMoveToNode(Encoded, EncodedCb, CurrentNode->Value + CurrentNode->ValueCb, CurrentNode);
}

BOOL
BLGASN1CALL
BlgDerMoveToChild(
    IN HBLG_DER_DECODER DecoderHandle
    )

/*++

Routine Description:

    Moves the specified decoder to the first child node of the current node.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    PBLGP_DER_DECODER_NODE CurrentNode = &Decoder->CurrentNode;
    PBLGP_DER_DECODER_NODE ParentNode;

    if (!BlgpValidateState(Decoder))
    {
        return FALSE;
    }

    if (!BLGASN1_FLAGON(*CurrentNode->Tag, 0x20))
    {
        SetLastError(ERROR_BLGASN1_PRIMITIVE);

        return FALSE;
    }

    if (CurrentNode->ValueCb == 0)
    {
        SetLastError(ERROR_BLGASN1_EOD);

        return FALSE;
    }

    ParentNode = HeapAlloc(g_Heap, 0, sizeof(BLGP_DER_DECODER_NODE));
    if (!ParentNode)
    {
        SetLastError(ERROR_OUTOFMEMORY);

        return FALSE;
    }

    ParentNode->Tag = CurrentNode->Tag;
    ParentNode->Value = CurrentNode->Value;
    ParentNode->ValueCb = CurrentNode->ValueCb;

    if (!BlgpMoveToNode(ParentNode->Value, ParentNode->ValueCb, ParentNode->Value, CurrentNode))
    {
        HeapFree(g_Heap, 0, ParentNode);

        return FALSE;
    }

    BlgPushEntryList(&CurrentNode->ParentLink, &ParentNode->ParentLink);

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerMoveToParent(
    IN HBLG_DER_DECODER DecoderHandle
    )

/*++

Routine Description:

    Moves the specified decoder to the parent node of the current node.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    PBLGP_DER_DECODER_NODE CurrentNode = &Decoder->CurrentNode;
    PBLGP_DER_DECODER_NODE ParentNode;
    PSINGLE_LIST_ENTRY ParentLink;

    if (!Decoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    ParentLink = BlgPopEntryList(&CurrentNode->ParentLink);
    if (!ParentLink)
    {
        SetLastError(ERROR_INVALID_STATE);

        return FALSE;
    }

    ParentNode = CONTAINING_RECORD(ParentLink, BLGP_DER_DECODER_NODE, ParentLink);

    CurrentNode->Tag = ParentNode->Tag;
    CurrentNode->Value = ParentNode->Value;
    CurrentNode->ValueCb = ParentNode->ValueCb;

    HeapFree(g_Heap, 0, ParentNode);

    return TRUE;
}

BOOL
BLGASN1CALL
BlgpMoveToNode(
    IN CONST BYTE *Encoded,
    IN DWORD EncodedCb,
    IN CONST BYTE *Offset,
    OUT PBLGP_DER_DECODER_NODE Node
    )

/*++

Routine Description:

    Moves the specified decoder to the encoded node at the specified offset and decodes it.

Arguments:

    Encoded - Pointer to a buffer containing the encoded data.

    EncodedCb - Size, in bytes, of the encoded data pointed to by the Encoded parameter.

    Offset - Pointer to the encoded node.

    Node - Pointer to a structure that receives the decoded node.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    CONST BYTE *Ptr = Offset;
    DWORD ValueCb = 0;

    // Check if the tag has additional octets.
    if (((*Ptr) & 0x1F) == 0x1F)
    {
        if (!BlgpMovePointer(Encoded, EncodedCb, &Ptr))
        {
            return FALSE;
        }

        // Move to the last tag octet.
        while ((CHAR) *Ptr < 0)
        {
            if (!BlgpMovePointer(Encoded, EncodedCb, &Ptr))
            {
                return FALSE;
            }
        }
    }

    // Move to the first length octet.
    if (!BlgpMovePointer(Encoded, EncodedCb, &Ptr))
    {
        return FALSE;
    }

    // Check if the length has additional octets.
    if ((CHAR) *Ptr < 0)
    {
        DWORD LenLength, i;

        // The length cannot be larger than 32 bit. So check if the length is larger than 4 bytes.
        if ((LenLength = ~(~(*Ptr) | 0x80)) > 4)
        {
            SetLastError(ERROR_BLGASN1_TOO_LARGE);

            return FALSE;
        }

        if (Ptr + LenLength >= Encoded + EncodedCb)
        {
            SetLastError(ERROR_BLGASN1_UNEXP_EOD);

            return FALSE;
        }

        for (i = 0; i < LenLength; i++)
        {
            ValueCb += (*++Ptr) << ((LenLength - 1 - i) * 8);
        }
    }
    else
    {
        ValueCb = *Ptr;
    }

    if (++Ptr + ValueCb > Encoded + EncodedCb)
    {
        SetLastError(ERROR_BLGASN1_UNEXP_EOD);

        return FALSE;
    }

    Node->Tag = Offset;
    Node->Value = Ptr;
    Node->ValueCb = ValueCb;

    return TRUE;
}

BOOL
BLGASN1CALL
BlgpMovePointer(
    IN CONST BYTE *Encoded,
    IN DWORD EncodedCb,
    IN OUT CONST BYTE **Ptr
    )

/*++

Routine Description:

    Moves the specified pointer variable one byte forward within the boundaries of the
    specified buffer.

Arguments:

    Encoded - Pointer to a buffer containing the encoded data.

    EncodedCb - Size, in bytes, of the encoded data pointed to by the Encoded parameter.

    Ptr - Address of a pointer specifying the current position within the buffer. When the
        routine returns, the pointer contains the new position.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    if ((DWORD) ((*Ptr) - Encoded + 1) >= EncodedCb)
    {
        SetLastError(ERROR_BLGASN1_UNEXP_EOD);

        return FALSE;
    }

    (*Ptr)++;

    return TRUE;
}

BOOL
BLGASN1CALL
BlgpValidateState(
    IN PBLGP_DER_DECODER Decoder
    )

/*++

Routine Description:

    Validates the internal state of the specified decoder.

Arguments:

    DecoderHandle - Handle to the decoder to be examined.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    if (!Decoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    // If the current node's value buffer points to the first byte of the encoded buffer, it means
    // that one of the BlgDerMoveToFirst or BlgDerMoveToNext routines is not yet called to move to
    // the first node of the encoded buffer.
    if (Decoder->CurrentNode.Value == Decoder->Encoded)
    {
        SetLastError(ERROR_INVALID_STATE);

        return FALSE;
    }

    return TRUE;
}