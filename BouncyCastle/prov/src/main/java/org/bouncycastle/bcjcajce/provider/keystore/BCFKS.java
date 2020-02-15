package org.bouncycastle.bcjcajce.provider.keystore;

import org.bouncycastle.bcjcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.bcjcajce.provider.util.AsymmetricAlgorithmProvider;

public class BCFKS
{
    private static final String PREFIX = "org.bouncycastle.bcjcajce.provider.keystore" + ".bcfks.";

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
