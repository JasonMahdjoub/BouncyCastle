package com.distrimind.bouncycastle.its.asn1;

import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     SEQUENCE OF PsidGroupPermissions
 * </pre>
 */
public class SequenceOfPsidGroupPermissions
    extends ASN1Object
{
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }
}