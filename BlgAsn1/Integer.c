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
BlgpDecodeInteger(
    IN  HBLG_DER_DECODER DecoderHandle,
    IN  BOOL Signed,
    OUT PBYTE Buffer,
    IN  DWORD BufferCb
    );

BOOL
BLGASN1CALL
BlgDerEncInt(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN BOOL Positive,
    IN CONST BYTE *Value,
    IN DWORD ValueCb
    )

/*++

Routine Description:

    Encodes an ASN.1 INTEGER value.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Class - Class of the node.

    Tag - Tag of the node.

    Positive - Boolean value indicating whether the value is positive.

    Value - Pointer to a buffer containing the integer to be encoded.

    ValueCb - Size, in bytes, of the value pointed to by the Value parameter.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;
    DWORD Shift = 0;
    DWORD OctetCount;

    if (!Encoder || !Value)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (Positive)
    {
        OctetCount = BlgpNonZeroByteLength(Value, ValueCb);

        // If the value is positive and the most significant bit is one, an empty octet must be
        // appended to the beginning of the encoded value.
        if (BlgpIsLittleEndian())
        {
            if ((CHAR) Value[OctetCount - 1] < 0)
            {
                OctetCount++; Shift++;
            }
        }
        else
        {
            if ((CHAR) Value[0] < 0)
            {
                OctetCount++; Shift++;
            }
        }
    }
    else
    {
        // If the value is negative, discard the leading bytes with the value 0xFF. They have no
        // significance for the decoding process.
        if (BlgpIsLittleEndian())
        {
            for (OctetCount = ValueCb; OctetCount > 1; OctetCount--)
            {
                if (Value[OctetCount - 1] != 0xFF)
                {
                    break;
                }
            }
        }
        else
        {
            for (OctetCount = ValueCb; OctetCount > 1; OctetCount--)
            {
                if (Value[ValueCb - OctetCount] != 0xFF)
                {
                    break;
                }
            }
        }
    }

    if (!BlgDerEncTag(EncoderHandle, Class, FALSE,
            (Class == BLG_DER_CLASS_UNIVERSAL && Tag == 0) ? BLG_DER_TAG_INTEGER : Tag))
    {
        return FALSE;
    }

    if (!BlgDerEncLen(EncoderHandle, OctetCount))
    {
        return FALSE;
    }

    if (Encoder->Buffer != NULL)
    {
        if (BLGP_DER_ENCODED_CB(Encoder) + OctetCount > Encoder->BufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        if (Shift > 0)
        {
            *Encoder->Ptr = 0;
        }

        BlgpCopyMemory(Encoder->Ptr + Shift, Value, OctetCount - Shift);
    }

    Encoder->Ptr += OctetCount;

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerDecInt(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PBOOL Positive OPTIONAL,
    OUT PBYTE Buffer OPTIONAL,
    IN OUT PDWORD BufferCb
    )

/*++

Routine Description:

    Decodes an ASN.1 INTEGER value.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Positive - Pointer to a variable that receives whether the integer is positive.

    Buffer - Pointer to a buffer that receives the decoded integer.

    BufferCb - Pointer to a variable specifying the size of the buffer, in bytes. When the
        routine returns, the variable contains the number of bytes stored in the buffer.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    DWORD ValueCb, LocalBufferCb;
    CONST BYTE *Value;

    if (Positive)
    {
        *Positive = FALSE;
    }

    if (!BufferCb)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }
    else
    {
        LocalBufferCb = *BufferCb; *BufferCb = 0;
    }

    if (!BlgpValidateState(Decoder))
    {
        return FALSE;
    }

    Value = Decoder->CurrentNode.Value;
    ValueCb = Decoder->CurrentNode.ValueCb;

    if ((CHAR) *Value >= 0)
    {
        if (Positive)
        {
            *Positive = TRUE;
        }

        if (*Value == 0)
        {
            Value++; ValueCb--;
        }
    }

    *BufferCb = ValueCb;

    if (Buffer)
    {
        if (ValueCb > LocalBufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        BlgpCopyMemory(Buffer, Value, ValueCb);
    }

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerDecInt16(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PSHORT Value
    )

/*++

Routine Description:

    Decodes an 16 bit signed ASN.1 INTEGER value.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Value - Pointer to a variable that receives the decoded integer.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    return BlgpDecodeInteger(DecoderHandle, TRUE, (PBYTE) Value, sizeof(SHORT));
}

BOOL
BLGASN1CALL
BlgDerDecInt32(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PINT Value
    )

/*++

Routine Description:

    Decodes an 32 bit signed ASN.1 INTEGER value.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Value - Pointer to a variable that receives the decoded integer.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    return BlgpDecodeInteger(DecoderHandle, TRUE, (PBYTE) Value, sizeof(INT));
}

BOOL
BLGASN1CALL
BlgDerDecUInt16(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWORD Value
    )

/*++

Routine Description:

    Decodes an 16 bit unsigned ASN.1 INTEGER value.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Value - Pointer to a variable that receives the decoded integer.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    return BlgpDecodeInteger(DecoderHandle, FALSE, (PBYTE) Value, sizeof(WORD));
}

BOOL
BLGASN1CALL
BlgDerDecUInt32(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PDWORD Value
    )

/*++

Routine Description:

    Decodes an 32 bit unsigned ASN.1 INTEGER value.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Value - Pointer to a variable that receives the decoded integer.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    return BlgpDecodeInteger(DecoderHandle, FALSE, (PBYTE) Value, sizeof(DWORD));
}

static
BOOL
BLGASN1CALL
BlgpDecodeInteger(
    IN HBLG_DER_DECODER DecoderHandle,
    IN BOOL Signed,
    OUT PBYTE Buffer,
    IN DWORD BufferCb
    )
{
    DWORD ValueCb = BufferCb;
    BOOL Positive;

    if (!Buffer)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    ZeroMemory(Buffer, BufferCb);

    if (!BlgDerDecInt(DecoderHandle, &Positive, Buffer, &ValueCb))
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            SetLastError(ERROR_BLGASN1_TOO_LARGE);
        }

        return FALSE;
    }

    if (BufferCb > ValueCb)
    {
        if (BlgpIsLittleEndian())
        {
            // If the value is negative, the leading zero octets must be filled with the value
            // 0xFF to generate the two's complement of the original value.
            if (!Positive)
            {
                FillMemory(Buffer + ValueCb, BufferCb - ValueCb, 0xFF);
            }
        }
        else
        {
            MoveMemory(Buffer + BufferCb - ValueCb, Buffer, ValueCb);

            // If the value is positive, clear the shifted bytes; otherwise fill with the value
            // 0xFF to generate the two's complement of the original value.
            if (Positive)
            {
                ZeroMemory(Buffer, BufferCb - ValueCb);
            }
            else
            {
                FillMemory(Buffer, BufferCb - ValueCb, 0xFF);
            }
        }
    }

    if (Signed)
    {
        // If the buffer represents a signed integer and the value is positive, check the most
        // significant bit. If it is one, it means that we have an overflow.
        if (Positive)
        {
            if (BlgpIsLittleEndian())
            {
                if ((CHAR) Buffer[BufferCb - 1] < 0)
                {
                    ZeroMemory(Buffer, BufferCb);

                    SetLastError(ERROR_BLGASN1_TOO_LARGE);

                    return FALSE;
                }
            }
            else
            {
                if ((CHAR) Buffer[0] < 0)
                {
                    ZeroMemory(Buffer, BufferCb);

                    SetLastError(ERROR_BLGASN1_TOO_LARGE);

                    return FALSE;
                }
            }
        }
    }
    else
    {
        if (!Positive)
        {
            ZeroMemory(Buffer, BufferCb);

            SetLastError(ERROR_BLGASN1_CORRUPT);

            return FALSE;
        }
    }

    return TRUE;
}