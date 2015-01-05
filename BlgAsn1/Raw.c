/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

BOOL
BLGASN1CALL
BlgDerWriteRaw(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN CONST BYTE *Value,
    IN DWORD ValueCb
    )

/*++

Routine Description:

    Writes a raw byte stream.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Value - Pointer to a buffer to be written.

    ValueCb - Size, in bytes, of the buffer pointed to by the Value parameter.

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

    if (Encoder->Buffer)
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