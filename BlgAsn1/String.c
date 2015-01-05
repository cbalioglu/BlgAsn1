/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>
#include <strsafe.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

static
BOOL
BLGASN1CALL
BlgpDerEncString(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value,
    IN INT ValueCch,
    IN UINT CodePage
    );

static
BOOL
BLGASN1CALL
BlgpDerDecString(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWSTR Buffer OPTIONAL,
    IN OUT PDWORD BufferCch,
    IN UINT CodePage
    );

static __inline
VOID
BLGASN1CALL
BlgpChangeEndiannes(
    IN PBYTE Destination,
    IN CONST BYTE *Source,
    IN size_t Cch
    );

BOOL
BLGASN1CALL
BlgDerEncIA5String(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value,
    IN INT ValueCch
    )
{
    return BlgpDerEncString(EncoderHandle, Class, Tag, Value, ValueCch, 1250);
}

BOOL
BLGASN1CALL
BlgDerEncUtf8String(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value,
    IN INT ValueCch
    )
{
    return BlgpDerEncString(EncoderHandle, Class, Tag, Value, ValueCch, CP_UTF8);
}

BOOL
BLGASN1CALL
BlgDerEncBmpString(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value,
    IN INT ValueCch
    )
{
    return BlgpDerEncString(EncoderHandle, Class, Tag, Value, ValueCch, 1201);
}

BOOL
BLGASN1CALL
BlgDerDecIA5String(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWSTR Buffer OPTIONAL,
    IN OUT PDWORD BufferCch
    )
{
    return BlgpDerDecString(DecoderHandle, Buffer, BufferCch, 20105);
}

BOOL
BLGASN1CALL
BlgDerDecUtf8String(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWSTR Buffer OPTIONAL,
    IN OUT PDWORD BufferCch
    )
{
    return BlgpDerDecString(DecoderHandle, Buffer, BufferCch, CP_UTF8);
}

BOOL
BLGASN1CALL
BlgDerDecBmpString(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWSTR Buffer OPTIONAL,
    IN OUT PDWORD BufferCch
    )
{
    return BlgpDerDecString(DecoderHandle, Buffer, BufferCch, 1201);
}

BOOL
BLGASN1CALL
BlgpDerEncString(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value,
    IN INT ValueCch,
    IN UINT CodePage
    )
{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;
    size_t Cch;
    size_t OctetCount;

    if (!Encoder || !Value)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (ValueCch == -1)
    {
        if (FAILED(StringCchLength(Value, MAXLONG, &Cch)))
        {
            SetLastError(ERROR_INVALID_PARAMETER);

            return FALSE;
        }
    }
    else
    {
        Cch = ValueCch;
    }

    if (Class == BLG_DER_CLASS_UNIVERSAL && Tag == 0)
    {
        switch (CodePage)
        {
        case 1250:
            Tag = BLG_DER_TAG_IA5_STRING;

            break;

        case CP_UTF8:
            Tag = BLG_DER_TAG_UTF8_STRING;

            break;

        case 1201:
            Tag = BLG_DER_TAG_BMP_STRING;

            break;
        }
    }

    if (CodePage != 1201)
    {
        OctetCount = WideCharToMultiByte(CodePage, 0, Value, (INT) Cch, NULL, 0, NULL, NULL);
        if (OctetCount == 0)
        {
            return FALSE;
        }
    }
    else
    {
        OctetCount = Cch * sizeof(WCHAR);
    }

    if (!BlgDerEncTag(EncoderHandle, Class, FALSE, Tag))
    {
        return FALSE;
    }

    if (!BlgDerEncLen(EncoderHandle, (DWORD) OctetCount))
    {
        return FALSE;
    }

    if (Encoder->Buffer)
    {
        if (BLGP_DER_ENCODED_CB(Encoder) + OctetCount > Encoder->BufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        if (CodePage != 1201)
        {
            if (WideCharToMultiByte(CodePage, 0, Value, (INT) Cch, Encoder->Ptr, (INT) OctetCount, NULL, NULL) == 0)
            {
                return FALSE;
            }
        }
        else
        {
            BlgpChangeEndiannes(Encoder->Ptr, (CONST BYTE *) Value, Cch);
        }
    }

    Encoder->Ptr += OctetCount;

    return TRUE;
}

BOOL
BLGASN1CALL
BlgpDerDecString(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PWSTR Buffer OPTIONAL,
    IN OUT PDWORD BufferCch,
    IN UINT CodePage
    )
{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    DWORD ValueCch, LocalBufferCch;

    if (!BufferCch)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }
    else
    {
        LocalBufferCch = *BufferCch; *BufferCch = 0;
    }

    if (!BlgpValidateState(Decoder))
    {
        return FALSE;
    }

    if (CodePage != 1201)
    {
        ValueCch = MultiByteToWideChar(CodePage, 0, Decoder->CurrentNode.Value, Decoder->CurrentNode.ValueCb, NULL, 0);
        if (ValueCch == 0)
        {
            SetLastError(ERROR_BLGASN1_CORRUPT);

            return FALSE;
        }
    }
    else
    {
        ValueCch = Decoder->CurrentNode.ValueCb / sizeof(WCHAR);
    }

    if (Buffer)
    {
        *BufferCch = ValueCch;

        if (++ValueCch > LocalBufferCch)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        if (CodePage != 1201)
        {
            if (MultiByteToWideChar(CodePage, 0,
                    Decoder->CurrentNode.Value, Decoder->CurrentNode.ValueCb, Buffer, ValueCch) == 0)
            {
                SetLastError(ERROR_BLGASN1_CORRUPT);

                return FALSE;
            }
        }
        else
        {
            BlgpChangeEndiannes((PBYTE) Buffer, Decoder->CurrentNode.Value, ValueCch - 1);
        }

        Buffer[ValueCch - 1] = 0;
    }
    else
    {
        *BufferCch = ValueCch + 1;
    }

    return TRUE;
}

static __inline
VOID
BLGASN1CALL
BlgpChangeEndiannes(
    IN PBYTE Destination,
    IN CONST BYTE *Source,
    IN size_t Cch
    )
{
    DWORD i;

    for (i = 0; i < Cch * 2; i += 2)
    {
        Destination[i] = Source[i + 1];
        Destination[i + 1] = Source[i];
    }
}