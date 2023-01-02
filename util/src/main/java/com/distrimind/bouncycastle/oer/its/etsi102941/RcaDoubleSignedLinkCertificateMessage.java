package com.distrimind.bouncycastle.oer.its.etsi102941;

import com.distrimind.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class RcaDoubleSignedLinkCertificateMessage
    extends EtsiTs103097DataSigned
{

    public RcaDoubleSignedLinkCertificateMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected RcaDoubleSignedLinkCertificateMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static RcaDoubleSignedLinkCertificateMessage getInstance(Object o)
    {
        if (o instanceof RcaDoubleSignedLinkCertificateMessage)
        {
            return (RcaDoubleSignedLinkCertificateMessage)o;
        }
        if (o != null)
        {
            return new RcaDoubleSignedLinkCertificateMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}