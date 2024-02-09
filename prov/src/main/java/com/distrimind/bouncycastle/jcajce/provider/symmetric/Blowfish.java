package com.distrimind.bouncycastle.jcajce.provider.symmetric;

import com.distrimind.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import com.distrimind.bouncycastle.crypto.CipherKeyGenerator;
import com.distrimind.bouncycastle.crypto.engines.BlowfishEngine;
import com.distrimind.bouncycastle.crypto.macs.CMac;
import com.distrimind.bouncycastle.crypto.modes.CBCBlockCipher;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import com.distrimind.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.distrimind.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class Blowfish
{
    private Blowfish()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlowfishEngine());
        }
    }

    public static class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new BlowfishEngine()), 64);
        }
    }

    public static class CMAC
        extends BaseMac
    {
        public CMAC()
        {
            super(new CMac(new BlowfishEngine()));
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Blowfish", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Blowfish IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Blowfish.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Mac.BLOWFISHCMAC", PREFIX + "$CMAC");
            provider.addAlgorithm("Cipher.BLOWFISH", PREFIX + "$ECB");
            provider.addAlgorithm("Cipher", MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, PREFIX + "$CBC");
            provider.addAlgorithm("KeyGenerator.BLOWFISH", PREFIX + "$KeyGen");
            provider.addAlgorithm("Alg.Alias.KeyGenerator", MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, "BLOWFISH");
            provider.addAlgorithm("AlgorithmParameters.BLOWFISH", PREFIX + "$AlgParams");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters", MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, "BLOWFISH");

        }
    }
}
