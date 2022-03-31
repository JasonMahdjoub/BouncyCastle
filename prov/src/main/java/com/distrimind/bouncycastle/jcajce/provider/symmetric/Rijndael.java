package com.distrimind.bouncycastle.jcajce.provider.symmetric;

import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.CipherKeyGenerator;
import com.distrimind.bouncycastle.crypto.engines.RijndaelEngine;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import com.distrimind.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class Rijndael
{
    private Rijndael()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new RijndaelEngine();
                }
            });
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Rijndael", 192, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Rijndael IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Rijndael.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.RIJNDAEL", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.RIJNDAEL", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.RIJNDAEL", PREFIX + "$AlgParams");

        }
    }
}
