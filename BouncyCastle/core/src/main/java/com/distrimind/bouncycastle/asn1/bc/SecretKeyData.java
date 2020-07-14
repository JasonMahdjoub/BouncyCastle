package com.distrimind.bouncycastle.asn1.bc;

import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     SecretKeyData ::= SEQUENCE {
 *         keyAlgorithm OBJECT IDENTIFIER,
 *         keyBytes OCTET STRING
 *     }
 * </pre>
 */
public class SecretKeyData
    extends ASN1Object
{
    private final ASN1ObjectIdentifier keyAlgorithm;
    private final ASN1OctetString keyBytes;

    public SecretKeyData(ASN1ObjectIdentifier keyAlgorithm, byte[] keyBytes)
    {
        this.keyAlgorithm = keyAlgorithm;
        this.keyBytes = new DEROctetString(Arrays.clone(keyBytes));
    }

    private SecretKeyData(ASN1Sequence seq)
    {
        this.keyAlgorithm = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.keyBytes = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static SecretKeyData getInstance(Object o)
    {
        if (o instanceof SecretKeyData)
        {
            return (SecretKeyData)o;
        }
        else if (o != null)
        {
            return new SecretKeyData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public byte[] getKeyBytes()
    {
        return Arrays.clone(keyBytes.getOctets());
    }

    public ASN1ObjectIdentifier getKeyAlgorithm()
    {
        return keyAlgorithm;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(keyAlgorithm);
        v.add(keyBytes);

        return new DERSequence(v);
    }
}
