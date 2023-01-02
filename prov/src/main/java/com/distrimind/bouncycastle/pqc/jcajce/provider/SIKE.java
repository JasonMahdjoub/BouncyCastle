package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.jcajce.provider.sike.SIKEKeyFactorySpi;

public class SIKE
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".sike.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SIKE", PREFIX + "SIKEKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SIKE", PREFIX + "SIKEKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.SIKE", PREFIX + "SIKEKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new SIKEKeyFactorySpi();

            provider.addAlgorithm("Cipher.SIKE", PREFIX + "SIKECipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_sike, "SIKE");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_sike, "SIKE", keyFact);
        }
    }
}
