package com.distrimind.bouncycastle.its.asn1;

import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class ExplicitCertificate
    extends CertificateBase
{
    private ExplicitCertificate(ASN1Sequence seq)
    {
        super(seq);
    }
}
