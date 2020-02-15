package org.bouncycastle.bcjcajce.provider.symmetric;

import org.bouncycastle.bccrypto.CipherKeyGenerator;
import org.bouncycastle.bccrypto.engines.VMPCKSA3Engine;
import org.bouncycastle.bcjcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.bcjcajce.provider.util.AlgorithmProvider;

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
