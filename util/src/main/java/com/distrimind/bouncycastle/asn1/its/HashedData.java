package com.distrimind.bouncycastle.asn1.its;

import com.distrimind.bouncycastle.asn1.ASN1Choice;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.DEROctetString;

/**
 * <pre>
 *     HashedData ::= CHOICE {
 *         sha256HashedData OCTET STRING (SIZE(32))
 *     }
 * </pre>
 */
public class HashedData
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1OctetString hashData;

    public HashedData(byte[] digest)
    {
        this.hashData = new DEROctetString(digest);
    }

    private HashedData(ASN1OctetString hashData)
    {
        this.hashData = hashData;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return hashData;
    }

    public ASN1OctetString getHashData()
    {
        return hashData;
    }

    public void setHashData(ASN1OctetString hashData)
    {
        this.hashData = hashData;
    }
}
