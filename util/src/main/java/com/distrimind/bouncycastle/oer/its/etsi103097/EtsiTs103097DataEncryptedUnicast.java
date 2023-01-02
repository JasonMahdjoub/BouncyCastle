package com.distrimind.bouncycastle.oer.its.etsi103097;

import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class EtsiTs103097DataEncryptedUnicast
    extends EtsiTs103097Data
{
    public EtsiTs103097DataEncryptedUnicast(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EtsiTs103097DataEncryptedUnicast(ASN1Sequence src)
    {
        super(src);
    }

    public static EtsiTs103097DataEncryptedUnicast getInstance(Object o)
    {
        if (o instanceof EtsiTs103097DataEncrypted)
        {
            return (EtsiTs103097DataEncryptedUnicast)o;
        }
        if (o != null)
        {
            return new EtsiTs103097DataEncryptedUnicast(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}