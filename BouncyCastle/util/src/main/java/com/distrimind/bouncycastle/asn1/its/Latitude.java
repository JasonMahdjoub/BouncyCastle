package com.distrimind.bouncycastle.asn1.its;

import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     Latitude ::= NinetyDegreeInt
 *
 *     NinetyDegreeInt ::= INTEGER {
 *         min (-900000000),
 *         max (900000000),
 *         unknown (900000001)
 *     }
 * </pre>
 */
public class Latitude
    extends ASN1Object
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
