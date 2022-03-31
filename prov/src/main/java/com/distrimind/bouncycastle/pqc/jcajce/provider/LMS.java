package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class LMS
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".lms.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.LMS", PREFIX + "LMSKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");

            provider.addAlgorithm("KeyPairGenerator.LMS", PREFIX + "LMSKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");

            provider.addAlgorithm("Signature.LMS", PREFIX + "LMSSignatureSpi$generic");
            provider.addAlgorithm("Alg.Alias.Signature." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");
        }
    }
}
