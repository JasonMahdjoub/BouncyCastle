package com.distrimind.bouncycastle.its.bc;

import com.distrimind.bouncycastle.its.ITSCertificate;
import com.distrimind.bouncycastle.its.ITSImplicitCertificateBuilder;
import com.distrimind.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;

public class BcITSImplicitCertificateBuilder
    extends ITSImplicitCertificateBuilder
{
    public BcITSImplicitCertificateBuilder(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, new BcDigestCalculatorProvider(), tbsCertificate);
    }
}
