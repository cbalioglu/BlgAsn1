/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

BOOL
BLGASN1CALL
BlgDerEncLen(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN DWORD Len
    )

/*++

Routine Description:

    Encodes an ASN.1 DER length.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Len - Length.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;
    PBYTE Bits = (PBYTE) &Len;
    DWORD OctetCount;

    if (!Encoder)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (Len <= 127)
    {
        OctetCount = 1;
    }
    else
    {
        OctetCount = BlgpNonZeroByteLength(Bits, sizeof(DWORD)) + 1;
    }

    if (Encoder->Buffer != NULL)
    {
        if (BLGP_DER_ENCODED_CB(Encoder) + OctetCount > Encoder->BufferCb)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);

            return FALSE;
        }

        if (OctetCount == 1)
        {
            *Encoder->Ptr = (BYTE) Len;
        }
        else
        {
            *Encoder->Ptr = (BYTE) (OctetCount - 1) | 0x80;

            BlgpCopyMemory(Encoder->Ptr + 1, Bits, OctetCount - 1);
        }
    }

    Encoder->Ptr += OctetCount;

    return TRUE;
}