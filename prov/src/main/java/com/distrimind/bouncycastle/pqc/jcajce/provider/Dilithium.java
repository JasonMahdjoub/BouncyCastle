package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyFactorySpi;

public class Dilithium
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".dilithium.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.DILITHIUM", PREFIX + "DilithiumKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.DILITHIUM", PREFIX + "DilithiumKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.DILITHIUM", PREFIX + "DilithiumKeyGeneratorSpi");

            addSignatureAlgorithm(provider, "DILITHIUM", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.dilithium);

            addSignatureAlias(provider, "DILITHIUM", BCObjectIdentifiers.dilithium2);
            addSignatureAlias(provider, "DILITHIUM", BCObjectIdentifiers.dilithium3);
            addSignatureAlias(provider, "DILITHIUM", BCObjectIdentifiers.dilithium5);
            addSignatureAlias(provider, "DILITHIUM", BCObjectIdentifiers.dilithium2_aes);
            addSignatureAlias(provider, "DILITHIUM", BCObjectIdentifiers.dilithium3_aes);
            addSignatureAlias(provider, "DILITHIUM", BCObjectIdentifiers.dilithium5_aes);

            AsymmetricKeyInfoConverter keyFact = new DilithiumKeyFactorySpi();

            registerOid(provider, BCObjectIdentifiers.dilithium2, "DILITHIUM", keyFact);
            registerOid(provider, BCObjectIdentifiers.dilithium3, "DILITHIUM", keyFact);
            registerOid(provider, BCObjectIdentifiers.dilithium5, "DILITHIUM", keyFact);
            registerOid(provider, BCObjectIdentifiers.dilithium2_aes, "DILITHIUM", keyFact);
            registerOid(provider, BCObjectIdentifiers.dilithium3_aes, "DILITHIUM", keyFact);
            registerOid(provider, BCObjectIdentifiers.dilithium5_aes, "DILITHIUM", keyFact);
        }
    }
}
