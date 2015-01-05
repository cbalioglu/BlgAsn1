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
BlgpParseComponent(
    IN OUT LPCSTR *Component,
    IN BYTE Cch,
    OUT PWORD Value
    );

BOOL
BLGASN1CALL
BlgDerEncGeneralizedTime(
    IN HBLG_DER_ENCODER  EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN CONST SYSTEMTIME *Value
    )

/*++

Routine Description:

    Encodes an ASN.1 GeneralizedTime value.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Class - Class of the node.

    Tag - Tag of the node.

    Value - Pointer to the date and time value to be encoded.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;

    if (!Encoder || !Value)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (GetDateFormat(LOCALE_INVARIANT, 0, Value, NULL, NULL, 0) == 0 ||
        GetTimeFormat(LOCALE_INVARIANT, 0, Value, NULL, NULL, 0) == 0)
    {
        return FALSE;
    }

    if (!BlgDerEncTag(EncoderHandle, Class, FALSE,
            (Class == BLG_DER_CLASS_UNIVERSAL && Tag == 0) ? BLG_DER_TAG_GENERALIZED_TIME : Tag))
    {
        return FALSE;
    }

    if (!BlgDerEncLen(EncoderHandle, 15))
    {
        return FALSE;
    }

    if (Encoder->Buffer != NULL)
    {
        CHAR Buffer[16];

        if (BLGP_DER_ENCODED_CB(Encoder) + 15 > Encoder->BufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        StringCchPrintfA(Buffer, 16, "%d%02d%02d%02d%02d%02dZ",
            Value->wYear, Value->wMonth, Value->wDay, Value->wHour, Value->wMinute, Value->wSecond);

        CopyMemory(Encoder->Ptr, Buffer, 15);
    }

    Encoder->Ptr += 15;

    return TRUE;
}

BOOL
BLGASN1CALL
BlgDerDecGeneralizedTime(
    IN HBLG_DER_DECODER DecoderHandle,
    OUT PSYSTEMTIME Value
    )

/*++

Routine Description:

    Decodes an ASN.1 GeneralizedTime value.

Arguments:

    DecoderHandle - Handle to the decoder to be used.

    Value - Pointer to a SYSTEMTIME structure that receives the decoded date and time value.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_DECODER Decoder = (PBLGP_DER_DECODER) DecoderHandle;
    LPCSTR Ptr = Decoder->CurrentNode.Value;
    LPCSTR End = Decoder->CurrentNode.Value + Decoder->CurrentNode.ValueCb;
    SYSTEMTIME SysTime = {0};
    LPCSTR Sign = NULL;
    WORD Hour = 0;
    WORD Minute = 0;
    FILETIME Time;

    if (!Value)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }
    else
    {
        ZeroMemory(Value, sizeof(SYSTEMTIME));
    }

    if (!BlgpValidateState(Decoder))
    {
        return FALSE;
    }

    if (End - Ptr < 10 || End - Ptr > 24)
    {
        SetLastError(ERROR_BLGASN1_CORRUPT);

        return FALSE;
    }

    if (!BlgpParseComponent(&Ptr, 4, &SysTime.wYear))
    {
        return FALSE;
    }
    if (!BlgpParseComponent(&Ptr, 2, &SysTime.wMonth))
    {
        return FALSE;
    }
    if (!BlgpParseComponent(&Ptr, 2, &SysTime.wDay))
    {
        return FALSE;
    }
    if (!BlgpParseComponent(&Ptr, 2, &SysTime.wHour))
    {
        return FALSE;
    }

    if (Ptr == End)
    {
        goto DoneParsing;
    }

    if (*Ptr >= '0' && *Ptr <= '9')
    {
        if (End - Ptr < 2)
        {
            SetLastError(ERROR_BLGASN1_CORRUPT);

            return FALSE;
        }

        if (!BlgpParseComponent(&Ptr, 2, &SysTime.wMinute))
        {
            return FALSE;
        }

        if (Ptr == End)
        {
            goto DoneParsing;
        }

        if (*Ptr >= '0' && *Ptr <= '9')
        {
            if (End - Ptr < 2)
            {
                SetLastError(ERROR_BLGASN1_CORRUPT);

                return FALSE;
            }

            if (!BlgpParseComponent(&Ptr, 2, &SysTime.wSecond))
            {
                return FALSE;
            }

            if (Ptr == End)
            {
                goto DoneParsing;
            }
        }
    }

    if (*Ptr == '.' || *Ptr == ',')
    {
        BYTE Cch = 0;

        if (*Ptr == ',' && !BLGASN1_FLAGON(Decoder->Flags, BLG_DER_DEC_FLAG_RELAXED))
        {
            SetLastError(ERROR_BLGASN1_CORRUPT);

            return FALSE;
        }

        Ptr++;

        // Calculate the character length of the fraction component.
        while (Ptr[Cch] >= '0' && Ptr[Cch] <= '9' && Ptr + Cch != End)
        {
            Cch++;
        }

        if (Cch > 0)
        {
            BlgpParseComponent(&Ptr, Cch > 3 ? 3 : Cch, &SysTime.wMilliseconds);

            // According to the DER specification a non-zero fraction must be specified if a
            // decimal dot exists.
            if (SysTime.wMilliseconds == 0 && !BLGASN1_FLAGON(Decoder->Flags, BLG_DER_DEC_FLAG_RELAXED))
            {
                SetLastError(ERROR_BLGASN1_CORRUPT);

                return FALSE;
            }

            if (Cch > 3)
            {
                Ptr += Cch - 3;
            }
        }
        else
        {
            // According to the DER specification a non-zero fraction must be specified if a
            // decimal dot exists.
            if (!BLGASN1_FLAGON(Decoder->Flags, BLG_DER_DEC_FLAG_RELAXED))
            {
                SetLastError(ERROR_BLGASN1_CORRUPT);

                return FALSE;
            }
        }

        if (Ptr == End)
        {
            goto DoneParsing;
        }
    }

    if (*Ptr == '+' || *Ptr == '-')
    {
        DWORD Cch;

        // According to the DER specification only UTC time representations are allowed.
        if (!BLGASN1_FLAGON(Decoder->Flags, BLG_DER_DEC_FLAG_RELAXED))
        {
            SetLastError(ERROR_BLGASN1_CORRUPT);

            return FALSE;
        }

        Sign = Ptr++;

        Cch = (DWORD) (End - Ptr);
        if (Cch == 2 || Cch == 4)
        {
            if (!BlgpParseComponent(&Ptr, 2, &Hour))
            {
                return FALSE;
            }

            if (*Sign == '+')
            {
                if (Hour > 13)
                {
                    SetLastError(ERROR_BLGASN1_CORRUPT);

                    return FALSE;
                }
            }
            else
            {
                if (Hour > 12)
                {
                    SetLastError(ERROR_BLGASN1_CORRUPT);

                    return FALSE;
                }
            }
        }
        else
        {
            SetLastError(ERROR_BLGASN1_CORRUPT);

            return FALSE;
        }

        if (Cch == 4)
        {
            if (!BlgpParseComponent(&Ptr, 2, &Minute))
            {
                return FALSE;
            }

            if (Minute > 59)
            {
                SetLastError(ERROR_BLGASN1_CORRUPT);

                return FALSE;
            }

            if (*Sign == '+')
            {
                if (Hour == 13 && Minute != 0)
                {
                    SetLastError(ERROR_BLGASN1_CORRUPT);

                    return FALSE;
                }
            }
            else
            {
                if (Hour == 12 && Minute != 0)
                {
                    SetLastError(ERROR_BLGASN1_CORRUPT);

                    return FALSE;
                }
            }
        }

        if (Ptr != End)
        {
            SetLastError(ERROR_BLGASN1_CORRUPT);

            return FALSE;
        }
    }
    else if (*Ptr != 'Z' || End - Ptr != 1)
    {
        SetLastError(ERROR_BLGASN1_CORRUPT);

        return FALSE;
    }

DoneParsing:
    if (*Ptr != 'Z' && !BLGASN1_FLAGON(Decoder->Flags, BLG_DER_DEC_FLAG_RELAXED))
    {
        SetLastError(ERROR_BLGASN1_CORRUPT);

        return FALSE;
    }

    if (!SystemTimeToFileTime(&SysTime, &Time))
    {
        SetLastError(ERROR_BLGASN1_CORRUPT);

        return FALSE;
    }

    if (Sign == NULL && *Ptr != 'Z')
    {
        FILETIME UtcTime;
        LocalFileTimeToFileTime(&Time, &UtcTime);
        FileTimeToSystemTime(&UtcTime, Value);
    }
    else
    {
        if (Sign != NULL)
        {
            ULARGE_INTEGER Temp;
            // We do not cast the structure to ULARGE_INTEGER because of possible alignment faults
            // on some architectures.
            CopyMemory(&Temp, &Time, sizeof(FILETIME));

            if (*Sign == '+')
            {
                Temp.QuadPart += (((INT64) ((Hour * 60) + Minute)) * 600000000);
            }
            else
            {
                Temp.QuadPart -= (((INT64) ((Hour * 60) + Minute)) * 600000000);
            }

            CopyMemory(&Time, &Temp, sizeof(FILETIME));
        }

        FileTimeToSystemTime(&Time, Value);
    }

    return TRUE;
}

static
BOOL
BLGASN1CALL
BlgpParseComponent(
    IN OUT LPCSTR *Component,
    IN BYTE Cch,
    OUT PWORD Value
    )

/*++

Routine Description:

    Parses an unsigned integer value.

Remarks:

    This routine is only capable of parsing up to 9999.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    BYTE i;

    *Value = 0;

    for (i = Cch; i > 0; i--)
    {
        if (**Component < '0' || **Component > '9')
        {
            SetLastError(ERROR_BLGASN1_CORRUPT);

            return FALSE;
        }

        switch (i)
        {
        case 1:
            *Value += ((**Component) - '0');

            break;

        case 2:
            *Value += ((**Component) - '0') * 10;

            break;

        case 3:
            *Value += ((**Component) - '0') * 100;

            break;

        case 4:
            *Value += ((**Component) - '0') * 1000;

            break;
        }

        (*Component)++;
    }

    return TRUE;
}