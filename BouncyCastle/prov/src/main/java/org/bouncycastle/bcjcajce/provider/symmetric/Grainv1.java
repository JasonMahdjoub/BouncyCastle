package org.bouncycastle.bcjcajce.provider.symmetric;

import org.bouncycastle.bccrypto.CipherKeyGenerator;
import org.bouncycastle.bccrypto.engines.Grainv1Engine;
import org.bouncycastle.bcjcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.bcjcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.bcjcajce.provider.util.AlgorithmProvider;

public final class Grainv1
{
    private Grainv1()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new Grainv1Engine(), 8);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Grainv1", 80, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Grainv1 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Grainv1.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.Grainv1", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.Grainv1", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.Grainv1", PREFIX + "$AlgParams");
        }
    }
}
