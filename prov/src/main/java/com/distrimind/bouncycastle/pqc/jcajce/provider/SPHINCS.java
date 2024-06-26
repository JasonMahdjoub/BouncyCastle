package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import com.distrimind.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;

public class SPHINCS
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".sphincs.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SPHINCS256", PREFIX + "Sphincs256KeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SPHINCS256", PREFIX + "Sphincs256KeyPairGeneratorSpi");

            addSignatureAlgorithm(provider, "SHA512", "SPHINCS256", PREFIX + "SignatureSpi$withSha512", PQCObjectIdentifiers.sphincs256_with_SHA512);
            addSignatureAlgorithm(provider, "SHA3-512", "SPHINCS256", PREFIX + "SignatureSpi$withSha3_512", PQCObjectIdentifiers.sphincs256_with_SHA3_512);

            AsymmetricKeyInfoConverter keyFact = new Sphincs256KeyFactorySpi();

            registerOid(provider, PQCObjectIdentifiers.sphincs256, "SPHINCS256", keyFact);
            registerOidAlgorithmParameters(provider, PQCObjectIdentifiers.sphincs256, "SPHINCS256");
        }
    }
}
