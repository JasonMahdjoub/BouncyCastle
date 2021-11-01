package com.distrimind.bouncycastle.asn1.its;

import com.distrimind.bouncycastle.asn1.ASN1Choice;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     IssuerIdentifier ::= CHOICE {
 *         sha256AndDigest HashedId8,
 *         self HashAlgorithm,
 *         ...,
 *         sha384AndDigest HashedId8
 *     }
 * </pre>
 */
public class IssuerIdentifier
    extends ASN1Object
    implements ASN1Choice
{

    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
