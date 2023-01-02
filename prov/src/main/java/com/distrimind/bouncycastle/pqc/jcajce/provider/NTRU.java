package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyFactorySpi;

public class NTRU
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".ntru.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.NTRU", PREFIX + "NTRUKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.NTRU", PREFIX + "NTRUKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.NTRU", PREFIX + "NTRUKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new NTRUKeyFactorySpi();

            provider.addAlgorithm("Cipher.NTRU", PREFIX + "NTRUCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_ntru, "NTRU");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_ntru, "NTRU", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntruhps2048509, "NTRU", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntruhps2048677, "NTRU", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntruhps4096821, "NTRU", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntruhrss701, "NTRU", keyFact);
        }
    }
}
