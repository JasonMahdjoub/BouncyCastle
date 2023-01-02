package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.jcajce.provider.hqc.HQCKeyFactorySpi;

public class HQC
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".hqc.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.HQC", PREFIX + "HQCKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.HQC", PREFIX + "HQCKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.HQC", PREFIX + "HQCKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new HQCKeyFactorySpi();

            provider.addAlgorithm("Cipher.HQC", PREFIX + "HQCCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_hqc, "HQC");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_hqc, "HQC", keyFact);
        }
    }
}
