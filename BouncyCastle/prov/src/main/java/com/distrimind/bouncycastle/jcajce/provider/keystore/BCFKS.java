package com.distrimind.bouncycastle.jcajce.provider.keystore;

import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class BCFKS
{
    private static final String PREFIX = "com.distrimind.bouncycastle.jcajce.provider.keystore" + ".bcfks.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyStore.BCFKS", PREFIX + "BcFKSKeyStoreSpi$Std");
            provider.addAlgorithm("KeyStore.BCFKS-DEF", PREFIX + "BcFKSKeyStoreSpi$Def");

            provider.addAlgorithm("KeyStore.IBCFKS", PREFIX + "BcFKSKeyStoreSpi$StdShared");
            provider.addAlgorithm("KeyStore.IBCFKS-DEF", PREFIX + "BcFKSKeyStoreSpi$DefShared");
        }
    }
}
