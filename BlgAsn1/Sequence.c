/*++

Copyright (c) 2006 Can Balioglu. All rights reserved.

See License.txt in the project root for license information.

--*/

#include <windows.h>

#include "BlgAsn1.h"
#include "BlgAsn1p.h"

BOOL
BLGASN1CALL
BlgDerDecSequence(
    IN HBLG_DER_DECODER Decoder,
    IN PCBLG_DER_CHILD_NODE Nodes,
    IN DWORD NodeCount,
    IN PBLG_DER_DECODE_NODE_ROUTINE DecodeRoutine,
    IN PVOID Context
    )

/*++

Routine Description:

    Decodes an ASN.1 SEQUENCE node.

Arguments:

    Decoder - Handle to the decoder to be used.

    Nodes - Array of nodes allowed to appear in the sequence.

    NodeCount - Number of nodes in the Nodes parameter.

    DecodeRoutine - Routine to be called for decoding a child node.

    Context - Pointer to the caller defined context value to be passed to the decoding routine.

Return Value:

    TRUE if the routine succeeds; otherwise, FALSE.

--*/

{
    BOOL IsOk = FALSE, ParseNext = TRUE;
    BYTE Class;
    BOOL Constructed;
    DWORD Tag, i;

    if (!BlgDerMoveToChild(Decoder))
    {
        if (GetLastError() == ERROR_BLGASN1_EOD)
        {
            for (i = 0; i < NodeCount; i++)
            {
                if (!Nodes[i].Optional)
                {
                    SetLastError(ERROR_BLGASN1_UNEXP_EOD);

                    return FALSE;
                }
            }

            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    for (i = 0; i < NodeCount; i++)
    {
        if (ParseNext && !BlgDerDecTag(Decoder, &Class, &Constructed, &Tag))
        {
            goto Leave;
        }

        if (Nodes[i].Class != Class || Nodes[i].Constructed != Constructed || Nodes[i].Tag != Tag)
        {
            if (!Nodes[i].Optional)
            {
                SetLastError(ERROR_BLGASN1_CONSTRAINT);

                goto Leave;
            }
            else
            {
                ParseNext = FALSE;

                continue;
            }
        }
        else
        {
            ParseNext = TRUE;
        }

        if (!DecodeRoutine(Decoder, i, Nodes + i, Context))
        {
            goto Leave;
        }

        if (!BlgDerMoveToNext(Decoder))
        {
            if (GetLastError() == ERROR_BLGASN1_EOD)
            {
                for (i++; i < NodeCount; i++)
                {
                    if (!Nodes[i].Optional)
                    {
                        SetLastError(ERROR_BLGASN1_UNEXP_EOD);

                        goto Leave;
                    }
                }

                goto Success;
            }
            else
            {
                goto Leave;
            }
        }
    }

    if (!ParseNext)
    {
        SetLastError(ERROR_BLGASN1_BADTAG);

        goto Leave;
    }

Success:
    IsOk = TRUE;

Leave:
    BlgDerMoveToParent(Decoder);

    return IsOk;
}