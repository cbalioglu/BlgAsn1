/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

BOOL
BLGASN1CALL
BlgDerEncOctetString(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN CONST BYTE *Value,
    IN INT ValueCb
    )

/*++

Routine Description:

    Encodes an ASN.1 Octet String value.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Class - Class of the node.

    Tag - Tag of the node.

    Value - Pointer to a byte buffer to be encoded.

    ValueCb - Size, in bytes, of the buffer pointed to by the Value parameter.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;

    if (Encoder == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (!BlgDerEncTag(EncoderHandle, Class, FALSE,
            (Class == BLG_DER_CLASS_UNIVERSAL && Tag == 0) ? BLG_DER_TAG_OCTET_STRING : Tag))
    {
        return FALSE;
    }

    if (!BlgDerEncLen(EncoderHandle, ValueCb))
    {
        return FALSE;
    }

    if (Encoder->Buffer != NULL)
    {
        if (BLGP_DER_ENCODED_CB(Encoder) + ValueCb > Encoder->BufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        CopyMemory(Encoder->Ptr, Value, ValueCb);
    }

    Encoder->Ptr += ValueCb;

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerDecOctetString(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBYTE Buffer OPTIONAL,
    IN OUT PDWORD BufferCb
    )

/*++

Routine Description:

    Decodes an Octet String.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Buffer - Pointer to a buffer that receives the decoded byte stream.

    BufferCb - Pointer to a variable specifying the size of the buffer, in bytes. When the
        routine returns, the variable contains the number of bytes stored in the buffer.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    PBLGP_DER_DECODER_NODE CurrentNode = &Decoder->CurrentNode;
    DWORD LocalBufferCb;

    if (!BufferCb)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }
    else
    {
        LocalBufferCb = *BufferCb;
        *BufferCb = 0;
    }

    if (!BlgpValidateState(Decoder))
    {
        return FALSE;
    }

    *BufferCb = CurrentNode->ValueCb;

    if (Buffer)
    {
        if (CurrentNode->ValueCb > LocalBufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        CopyMemory(Buffer, CurrentNode->Value, CurrentNode->ValueCb);
    }

    return TRUE;
}