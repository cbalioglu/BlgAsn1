<h1>ASN.1 DER Library</h1>

<p>BlgAsn1 is a library for encoding and decoding Abstract Syntax Notation One (ASN.1) data structures using Distinguished Encoding Rules (DER).</p>

<p>It is written in C and currently supports Windows XP or later. Porting to POSIX systems is planned.</p>

<p>The API is mostly documented in the source code. If you are familiar with native Windows programming, you will find the naming and usage conventions fairly similar to those of standard Windows APIs.</p>

<p>Below is a list of routines that are currently implemented:</p>

<pre>
BlgDerCreateEncoder
BlgDerDestroyEncoder
BlgDerGetEncoderParam
BlgDerBeginConstructed
BlgDerEndConstructed
BlgDerWriteRaw
BlgDerEncTag
BlgDerEncLen
BlgDerEncBool
BlgDerEncNull
BlgDerEncOctetString
BlgDerEncObjectIdentifier
BlgDerEncInt
BlgDerEncIA5String
BlgDerEncUtf8String
BlgDerEncBmpString
BlgDerEncGeneralizedTime
BlgDerCreateDecoder
BlgDerDestroyDecoder
BlgDerGetDecoderParam
BlgDerHasMoreData
BlgDerHasValue
BlgDerMoveToFirst
BlgDerMoveToNext
BlgDerMoveToChild
BlgDerMoveToParent
BlgDerCompareTag
BlgDerDecTag
BlgDerDecBool
BlgDerDecOctetString
BlgDerDecInt
BlgDerDecInt16
BlgDerDecInt32
BlgDerDecUInt16
BlgDerDecUInt32
BlgDerDecIA5String
BlgDerDecUtf8String
BlgDerDecBmpString
BlgDerDecGeneralizedTime
</pre>