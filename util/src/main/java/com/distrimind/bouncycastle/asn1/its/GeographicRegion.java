package com.distrimind.bouncycastle.asn1.its;

import com.distrimind.bouncycastle.asn1.ASN1Choice;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     GeographicRegion ::= CHOICE {
 *         circularRegion CircularRegion,
 *         rectangularRegion SequenceOfRectangularRegion,
 *         polygonalRegion PolygonalRegion,
 *         identifiedRegion SequenceOfIdentifiedRegion,
 *         ...
 *     }
 * </pre>
 */
public class GeographicRegion
    extends ASN1Object
    implements ASN1Choice
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
