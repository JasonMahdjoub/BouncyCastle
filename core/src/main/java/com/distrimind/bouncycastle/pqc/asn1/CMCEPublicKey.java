package com.distrimind.bouncycastle.pqc.asn1;


import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.util.Arrays;

/**
 *
 *    Classic McEliece Public Key Format.
 *    See https://datatracker.ietf.org/doc/draft-uni-qsckeys/ for details.
 *    <pre>
 *        McEliecePublicKey ::= SEQUENCE {
 *        T       OCTET STRING    -- public key
 *    }
 *    </pre>
 */
public class CMCEPublicKey
    extends ASN1Object
{

    private byte[] T;

    public CMCEPublicKey(byte[] t)
    {
        this.T = t;
    }

    public CMCEPublicKey(ASN1Sequence seq)
    {
        T = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
    }

    public byte[] getT()
    {
        return Arrays.clone(T);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(T));
        return new DERSequence(v);
    }

    public static  CMCEPublicKey getInstance(Object o)
    {
        if (o instanceof CMCEPrivateKey)
        {
            return (CMCEPublicKey) o;
        }
        else if (o != null)
        {
            return new CMCEPublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
