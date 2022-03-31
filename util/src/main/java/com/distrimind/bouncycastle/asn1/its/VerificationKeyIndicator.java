package com.distrimind.bouncycastle.asn1.its;

import com.distrimind.bouncycastle.asn1.ASN1Choice;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     VerificationKeyIndicator ::= CHOICE {
 *         verificationKey PublicVerificationKey,
 *         reconstructionValue EccP256CurvePoint,
 *         ...
 *     }
 * </pre>
 */
public class VerificationKeyIndicator
    extends ASN1Object
    implements ASN1Choice
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
