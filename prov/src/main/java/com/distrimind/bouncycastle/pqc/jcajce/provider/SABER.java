package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.jcajce.provider.saber.SABERKeyFactorySpi;

public class SABER
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".saber.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SABER", PREFIX + "SABERKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SABER", PREFIX + "SABERKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.SABER", PREFIX + "SABERKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new SABERKeyFactorySpi();

            provider.addAlgorithm("Cipher.SABER", PREFIX + "SABERCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_saber, "SABER");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_saber, "SABER", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.pqc_kem_saber, "SABER");
        }
    }
}
