/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>
#include <strsafe.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

// TODO: Implement!
BOOL
BLGASN1CALL
BlgDerEncObjectIdentifier(
    IN HBLG_DER_ENCODER EncoderHandle,
    IN BYTE Class,
    IN DWORD Tag,
    IN PCWSTR Value
    )

/*++

Routine Description:

    Encodes an ASN.1 Object Identifier value.

Arguments:

    EncoderHandle - Handle to the encoder to be used.

    Class - Class of the node.

    Tag - Tag of the node.

    Value - Object Identifier value to be encoded.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    PBLGP_DER_ENCODER Encoder = (PBLGP_DER_ENCODER) EncoderHandle;
    //DWORD Arcs[32];
    //DWORD ArcsCount = 0;
    //PCWSTR Ptr;

    if (!Encoder || !Value)
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (FAILED(StringCchLength(Value, STRSAFE_MAX_CCH, NULL)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    return TRUE;
}