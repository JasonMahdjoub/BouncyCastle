package com.distrimind.bouncycastle.jcajce.provider.symmetric;

import com.distrimind.bouncycastle.crypto.CipherKeyGenerator;
import com.distrimind.bouncycastle.crypto.engines.VMPCKSA3Engine;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class VMPCKSA3
{
    private VMPCKSA3()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new VMPCKSA3Engine(), 16);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("VMPC-KSA3", 128, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = VMPCKSA3.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.VMPC-KSA3", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.VMPC-KSA3", PREFIX + "$KeyGen");

        }
    }
}
