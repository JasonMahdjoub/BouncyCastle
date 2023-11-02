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

            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_128s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_128f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_128s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_128f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_128s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_128f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_192s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_192f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_192s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_192f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_192s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_192f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_256s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_256f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_256s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_256f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_256s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple);

            provider.addAlgorithm("Alg.Alias.Signature.SPHINCS+", "SPHINCSPLUS");

            AsymmetricKeyInfoConverter keyFact = new SPHINCSPlusKeyFactorySpi();

            registerOid(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, "SPHINCSPLUS", keyFact);
        }
    }
}
