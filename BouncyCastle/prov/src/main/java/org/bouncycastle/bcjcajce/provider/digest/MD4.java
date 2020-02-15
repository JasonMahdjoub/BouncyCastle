package org.bouncycastle.bcjcajce.provider.digest;

import org.bouncycastle.bcasn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.bccrypto.CipherKeyGenerator;
import org.bouncycastle.bccrypto.digests.MD4Digest;
import org.bouncycastle.bccrypto.macs.HMac;
import org.bouncycastle.bcjcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.bcjcajce.provider.symmetric.util.BaseMac;

public class MD4
{
    private MD4()
    {

    }

    /**
     * MD4 HashMac
     */
    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new MD4Digest()));
        }
    }

    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACMD4", 128, new CipherKeyGenerator());
        }
    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new MD4Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new MD4Digest((MD4Digest)digest);

            return d;
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = MD4.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.MD4", PREFIX + "$Digest");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers.md4, "MD4");

            addHMACAlgorithm(provider, "MD4", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
        }
    }
}
