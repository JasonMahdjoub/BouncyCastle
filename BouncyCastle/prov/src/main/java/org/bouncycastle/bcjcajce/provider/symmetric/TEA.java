package org.bouncycastle.bcjcajce.provider.symmetric;

import org.bouncycastle.bccrypto.CipherKeyGenerator;
import org.bouncycastle.bccrypto.engines.TEAEngine;
import org.bouncycastle.bcjcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.bcjcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.bcjcajce.provider.util.AlgorithmProvider;

public final class TEA
{
    private TEA()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new TEAEngine());
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("TEA", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "TEA IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = TEA.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.TEA", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.TEA", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.TEA", PREFIX + "$AlgParams");

        }
    }
}