package com.distrimind.bouncycastle.its.jcajce;

import java.security.Provider;

import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.distrimind.bouncycastle.its.ITSCertificate;
import com.distrimind.bouncycastle.its.ITSImplicitCertificateBuilder;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;

public class JcaITSImplicitCertificateBuilderBuilder
{
    private final JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();

    public JcaITSImplicitCertificateBuilderBuilder setProvider(Provider provider)
    {
        this.digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaITSImplicitCertificateBuilderBuilder setProvider(String providerName)
    {
        this.digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public ITSImplicitCertificateBuilder build(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
        throws OperatorCreationException
    {
        return new ITSImplicitCertificateBuilder(issuer, digestCalculatorProviderBuilder.build(), tbsCertificate);
    }
}
