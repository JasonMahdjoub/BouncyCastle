package com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes;

import com.distrimind.bouncycastle.asn1.ASN1Object;

/**
 * Common interface for ITS curve points.
 */
public abstract class EccCurvePoint
    extends ASN1Object
{
    public abstract byte[] getEncodedPoint();
}
