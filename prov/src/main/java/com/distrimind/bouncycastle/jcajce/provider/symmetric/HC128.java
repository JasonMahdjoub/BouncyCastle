package com.distrimind.bouncycastle.jcajce.provider.symmetric;

import com.distrimind.bouncycastle.crypto.CipherKeyGenerator;
import com.distrimind.bouncycastle.crypto.engines.HC128Engine;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class HC128
{
    private HC128()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new HC128Engine(), 16);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("HC128", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "HC128 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = HC128.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.HC128", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.HC128", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.HC128", PREFIX + "$AlgParams");
        }
    }
}
