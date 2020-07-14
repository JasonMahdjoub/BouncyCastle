package org.bouncycastle.bcjcajce.provider.symmetric;

import org.bouncycastle.bccrypto.CipherKeyGenerator;
import org.bouncycastle.bccrypto.engines.Salsa20Engine;
import org.bouncycastle.bcjcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.bcjcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.bcjcajce.provider.util.AlgorithmProvider;

public final class Salsa20
{
    private Salsa20()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new Salsa20Engine(), 8);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Salsa20", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Salsa20 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Salsa20.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.SALSA20", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.SALSA20", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.SALSA20", PREFIX + "$AlgParams");
        }
    }
}