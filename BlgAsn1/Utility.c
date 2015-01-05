/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

VOID
BLGASN1CALL
BlgpCopyMemory(
    IN PBYTE Destination,
    IN CONST BYTE *Source,
    IN DWORD Cb
    )
{
    if (BlgpIsLittleEndian())
    {
        DWORD i;
        for (i = 0; i < Cb; i++)
        {
            Destination[i] = Source[Cb - 1 - i];
        }
    }
    else
    {
        CopyMemory(Destination, Source, Cb);
    }
}

DWORD
BLGASN1CALL
BlgpNonZeroByteLength(
    IN CONST BYTE *Buffer,
    IN DWORD BufferCb
    )

/*++

Routine Description:

    This routine calculates the length of the specified buffer, excluding the leading bytes with
    the value zero.

--*/

{
    DWORD OctetCount;

    if (BlgpIsLittleEndian())
    {
        for (OctetCount = BufferCb; OctetCount > 1; OctetCount--)
        {
            if (Buffer[OctetCount - 1] != 0)
            {
                break;
            }
        }
    }
    else
    {
        for (OctetCount = BufferCb; OctetCount > 1; OctetCount--)
        {
            if (Buffer[BufferCb - OctetCount] != 0)
            {
                break;
            }
        }
    }

    return OctetCount;
}