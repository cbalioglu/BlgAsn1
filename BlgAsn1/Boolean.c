/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

BOOL
BLGASN1CALL
BlgDerEncBool(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN BOOLEAN Value
    )

/*++

Routine Description:

    Encodes an ASN.1 BOOLEAN value.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Class - Class of the node.

    Tag - Tag of the node.

    Value - Boolean value to be encoded.

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

    if (!BlgDerEncTag(EncoderHandle, Class, FALSE,
            (Class == BLG_DER_CLASS_UNIVERSAL && Tag == 0) ? BLG_DER_TAG_BOOLEAN : Tag))
    {
        return FALSE;
    }

    if (!BlgDerEncLen(EncoderHandle, 1))
    {
        return FALSE;
    }

    if (Encoder->Buffer)
    {
        if (BLGP_DER_ENCODED_CB(Encoder) + 1 > Encoder->BufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        *Encoder->Ptr = Value ? 0xFF : 0x00;
    }

    Encoder->Ptr++;

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerDecBool(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Value
    )

/*++

Routine Description:

    Decodes an ASN.1 BOOLEAN value.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Value - Pointer to a variable that receives the decoded boolean value.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    PBLGP_DER_DECODER_NODE CurrentNode = &Decoder->CurrentNode;

    if (!Value)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }
    else
    {
        *Value = FALSE;
    }

    if (!BlgpValidateState(Decoder))
    {
        return FALSE;
    }

    if (CurrentNode->ValueCb != 1)
    {
        SetLastError(ERROR_BLGASN1_CORRUPT);

        return FALSE;
    }

    // If the BLG_DER_DEC_FLAG_RELAXED flag is not set, the value must be either 0 or 255. All
    // other values are considered invalid. Otherwise, any non-zero value is decoded as TRUE.
    if (*CurrentNode->Value == 0x00)
    {
        return TRUE;
    }
    if (*CurrentNode->Value == 0xFF || BLGASN1_FLAGON(Decoder->Flags, BLG_DER_DEC_FLAG_RELAXED))
    {
        return *Value = TRUE, TRUE;
    }

    SetLastError(ERROR_BLGASN1_CORRUPT);

    return FALSE;
}