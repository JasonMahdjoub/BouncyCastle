package com.distrimind.bouncycastle.pqc.jcajce.provider;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;

public class SPHINCSPlus
{
    private static final String PREFIX = "com.distrimind.bouncycastle.pqc.jcajce.provider" + ".sphincsplus.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SPHINCSPLUS", PREFIX + "SPHINCSPlusKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SPHINCSPLUS", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.SPHINCS+", "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.SPHINCS+", "SPHINCSPLUS");

            addSignatureAlgorithm(provider, "SPHINCSPLUS", PREFIX + "SignatureSpi$Direct", BCObjectIdentifiers.sphincsPlus);

            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_shake_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_sha_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_sha_512.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_shake_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_sha_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_sha_512.getId(), "SPHINCSPLUS");

            provider.addAlgorithm("Alg.Alias.Signature.SPHINCS+", "SPHINCSPLUS");

            AsymmetricKeyInfoConverter keyFact = new SPHINCSPlusKeyFactorySpi();

            registerOid(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha_256, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha_512, "SPHINCSPLUS", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS");
        }
    }
}
