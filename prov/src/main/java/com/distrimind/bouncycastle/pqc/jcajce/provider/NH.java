package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import com.distrimind.bouncycastle.pqc.jcajce.provider.newhope.NHKeyFactorySpi;

public class NH
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".newhope.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.NH", PREFIX + "NHKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.NH", PREFIX + "NHKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyAgreement.NH", PREFIX + "KeyAgreementSpi");

            AsymmetricKeyInfoConverter keyFact = new NHKeyFactorySpi();

            registerOid(provider, PQCObjectIdentifiers.newHope, "NH", keyFact);
        }
    }
}
