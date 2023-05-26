package com.distrimind.bouncycastle.pkcs.jcajce;

import java.security.Provider;

import com.distrimind.bouncycastle.asn1.pkcs.PBMAC1Params;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.operator.MacCalculator;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.operator.PBEMacCalculatorProvider;

public class JcePBMac1CalculatorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcePBMac1CalculatorProviderBuilder()
    {
    }

    public JcePBMac1CalculatorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePBMac1CalculatorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public PBEMacCalculatorProvider build()
    {
        return new PBEMacCalculatorProvider()
        {
            public MacCalculator get(AlgorithmIdentifier algorithm, char[] password)
                throws OperatorCreationException
            {
                if (!PKCSObjectIdentifiers.id_PBMAC1.equals(algorithm.getAlgorithm()))
                {
                    throw new OperatorCreationException("protection algorithm not PB mac based");
                }

                JcePBMac1CalculatorBuilder bldr
                    = new JcePBMac1CalculatorBuilder(PBMAC1Params.getInstance(algorithm.getParameters())).setHelper(helper);

                return bldr.build(password);
            }
        };
    }
}
