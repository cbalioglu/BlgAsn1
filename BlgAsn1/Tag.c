/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

BOOL
BLGASN1CALL
BlgDerEncTag(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN BOOLEAN Constructed,
    IN DWORD Tag
    )

/*++

Routine Description:

    Encodes an ASN.1 DER tag.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Class - Class.

    Constructed - Boolean value indicating whether the node is constructed.

    Tag - Tag.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;
    BYTE OctetCount, i;

    if (!Encoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (Tag <= 30)
    {
        OctetCount = 1;
    }
    else
    {
        for (i = 0; i < 28; i++)
        {
            if (Tag & (0x80000000 >> i))
            {
                OctetCount = ((32 - i) / 7) + (((32 - i) % 7) > 0 ? 1 : 0) + 1;

                break;
            }
        }
    }

    if (Encoder->Buffer)
    {
        if (BLGP_DER_ENCODED_CB(Encoder) + OctetCount > Encoder->BufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        if (OctetCount == 1)
        {
            Encoder->Ptr[0] = (BYTE) Tag;
        }
        else
        {
            Encoder->Ptr[0] = (BYTE) 0x1F;

            OctetCount--;

            for (i = 0; i < OctetCount; i++)
            {
                Encoder->Ptr[OctetCount - i] = (BYTE) ((Tag & (0x7F << (i * 7))) >> (i * 7));

                if (i)
                {
                    Encoder->Ptr[OctetCount - i] |= 0x80;
                }
            }

            OctetCount++;
        }

        if (Constructed)
        {
            Encoder->Ptr[0] |= 0x20;
        }

        if (Class != BLG_DER_CLASS_UNIVERSAL)
        {
            Encoder->Ptr[0] |= (Class << 6);
        }
    }

    Encoder->Ptr += OctetCount;

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerDecTag(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBYTE Class OPTIONAL,
    OUT PBOOL Constructed OPTIONAL,
    OUT PDWORD Tag
    )

/*++

Routine Description:

    Decodes an ASN.1 DER tag.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Class - Pointer to a variable that receives the class.

    Constructed - Pointer to a variable that receives whether the tag is constructed.

    Tag - Pointer to a variable that receives the tag.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    CONST BYTE *Ptr;

    if (Class)
    {
        *Class = 0;
    }

    if (Constructed)
    {
        *Constructed = 0;
    }

    if (!Tag)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }
    else
    {
        *Tag = 0;
    }

    if (!BlgpValidateState(Decoder))
    {
        return FALSE;
    }

    Ptr = Decoder->CurrentNode.Tag;

    if (Class)
    {
        *Class = ((*Ptr) >> 6);
    }

    if (Constructed)
    {
        *Constructed = BLGASN1_FLAGON(*Ptr, 0x20);
    }

    if (((*Ptr) & 0x1F) == 0x1F)
    {
        DWORD Cb = 1;
        while ((CHAR) *(++Ptr) < 0)
        {
            Cb++;
        }

        // If the number of encoded octets is greater than five or if the first element has more
        // than four bits defined, return error. The value cannot be decoded as an 32 bit value.
        if (Cb > 5 || (Cb == 5 && (*(Ptr - 4) & 0xF0) != 0x80))
        {
            SetLastError(ERROR_BLGASN1_TOO_LARGE);

            return FALSE;
        }

        do
        {
            // Clear the most significant bit and shift n * 7 bits to the left.
            *Tag |= ((~(~(*(Ptr - Cb + 1)) | 0x80)) << ((Cb - 1) * 7));

        } while (--Cb > 0);
    }
    else
    {
        *Tag = ((*Ptr) & 0x1F);
    }

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerCompareTag(
    IN HBLG_DER_DECODER DecoderHandle,
    IN BYTE Class,
    IN BOOL Constructed,
    IN DWORD Tag,
    OUT PBOOL IsEqual
    )

/*++

Routine Description:

    Compares the tag of the current node with the specified tag.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Class - Class of the tag to be compared.

    Constructed - Indicates whether the tag to be compared is constructed.

    Tag - Tag to be compared.

    IsEqual - Pointer to a variable that receives whether the current tag equals the specified tag.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    BYTE NodeClass;
    BOOL NodeConstructed;
    DWORD NodeTag;

    if (!IsEqual)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }
    else
    {
        *IsEqual = FALSE;
    }

    if (!BlgDerDecTag(DecoderHandle, &NodeClass, &NodeConstructed, &NodeTag))
    {
        return FALSE;
    }

    if (Class == NodeClass && Constructed == NodeConstructed && Tag == NodeTag)
    {
        *IsEqual = TRUE;
    }

    return TRUE;
}