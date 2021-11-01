package com.distrimind.bouncycastle.asn1.its;

import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     SymmRecipientInfo ::= SEQUENCE {
 *         recipientId HashedId8,
 *         encKey SymmetricCiphertext
 *     }
 * </pre>
 */
public class SymmRecipientInfo
    extends ASN1Object
{
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }
}
