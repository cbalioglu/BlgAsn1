/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

BOOL
BLGASN1CALL
BlgDerEncNull(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag
    )

/*++

Routine Description:

    Encodes an ASN.1 NULL value.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Class - Class of the node.

    Tag - Tag of the node.

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
            (Class == BLG_DER_CLASS_UNIVERSAL && Tag == 0) ? BLG_DER_TAG_NULL : Tag))
    {
        return FALSE;
    }

    if (!BlgDerEncLen(EncoderHandle, 0))
    {
        return FALSE;
    }

    return TRUE;
}