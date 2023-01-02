package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.jcajce.provider.falcon.FalconKeyFactorySpi;

public class Falcon
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".falcon.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.FALCON", PREFIX + "FalconKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.FALCON", PREFIX + "FalconKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.FALCON", PREFIX + "FalconKeyGeneratorSpi");

            addSignatureAlgorithm(provider, "FALCON", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.falcon);

            addSignatureAlias(provider, "FALCON", BCObjectIdentifiers.falcon_512);
            addSignatureAlias(provider, "FALCON", BCObjectIdentifiers.falcon_1024);

            AsymmetricKeyInfoConverter keyFact = new FalconKeyFactorySpi();

            registerOid(provider, BCObjectIdentifiers.falcon_512, "FALCON", keyFact);
            registerOid(provider, BCObjectIdentifiers.falcon_1024, "FALCON", keyFact);
        }
    }
}
