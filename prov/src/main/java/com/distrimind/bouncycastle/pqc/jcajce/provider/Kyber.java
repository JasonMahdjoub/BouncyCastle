package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.jcajce.provider.kyber.KyberKeyFactorySpi;

public class Kyber
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".kyber.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.KYBER", PREFIX + "KyberKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.KYBER", PREFIX + "KyberKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.KYBER", PREFIX + "KyberKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new KyberKeyFactorySpi();

            provider.addAlgorithm("Cipher.KYBER", PREFIX + "KyberCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_kyber, "KYBER");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_kyber, "KYBER", keyFact);
        }
    }
}
