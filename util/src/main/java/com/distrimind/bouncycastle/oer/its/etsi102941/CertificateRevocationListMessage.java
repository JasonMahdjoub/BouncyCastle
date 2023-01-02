package com.distrimind.bouncycastle.oer.its.etsi102941;

import com.distrimind.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class CertificateRevocationListMessage
    extends EtsiTs103097DataSigned
{

    public CertificateRevocationListMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected CertificateRevocationListMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static CertificateRevocationListMessage getInstance(Object o)
    {
        if (o instanceof CertificateRevocationListMessage)
        {
            return (CertificateRevocationListMessage)o;
        }
        if (o != null)
        {
            return new CertificateRevocationListMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
