package com.distrimind.bouncycastle.oer.its.etsi102941;

import com.distrimind.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class CaCertificateRekeyingMessage
    extends EtsiTs103097DataSigned
{

    public CaCertificateRekeyingMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected CaCertificateRekeyingMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static CaCertificateRekeyingMessage getInstance(Object o)
    {
        if (o instanceof CaCertificateRekeyingMessage)
        {
            return (CaCertificateRekeyingMessage)o;
        }
        if (o != null)
        {
            return new CaCertificateRekeyingMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}