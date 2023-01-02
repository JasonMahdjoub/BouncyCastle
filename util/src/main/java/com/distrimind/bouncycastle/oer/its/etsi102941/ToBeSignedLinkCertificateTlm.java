package com.distrimind.bouncycastle.oer.its.etsi102941;

import com.distrimind.bouncycastle.oer.its.ieee1609dot2.HashedData;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class ToBeSignedLinkCertificateTlm
    extends ToBeSignedLinkCertificate
{
    public ToBeSignedLinkCertificateTlm(Time32 expiryTime, HashedData certificateHash)
    {
        super(expiryTime, certificateHash);
    }

    protected ToBeSignedLinkCertificateTlm(ASN1Sequence seq)
    {
        super(seq);
    }

    private ToBeSignedLinkCertificateTlm(ToBeSignedLinkCertificate cert)
    {
        super(cert.getExpiryTime(), cert.getCertificateHash());
    }


    public static ToBeSignedLinkCertificateTlm getInstance(Object o)
    {
        if (o instanceof ToBeSignedLinkCertificateTlm)
        {
            return (ToBeSignedLinkCertificateTlm)o;
        }

        if (o instanceof ToBeSignedLinkCertificate)
        {
            return new ToBeSignedLinkCertificateTlm((ToBeSignedLinkCertificate)o);
        }

        if (o != null)
        {
            return new ToBeSignedLinkCertificateTlm(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
