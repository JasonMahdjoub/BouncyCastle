package com.distrimind.bouncycastle.jcajce.provider.test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;

import junit.framework.Assert;
import junit.framework.TestCase;
import com.distrimind.bouncycastle.jcajce.provider.digest.GOST3411;
import com.distrimind.bouncycastle.jcajce.provider.digest.MD2;
import com.distrimind.bouncycastle.jcajce.provider.digest.MD4;
import com.distrimind.bouncycastle.jcajce.provider.digest.MD5;
import com.distrimind.bouncycastle.jcajce.provider.digest.RIPEMD128;
import com.distrimind.bouncycastle.jcajce.provider.digest.RIPEMD160;
import com.distrimind.bouncycastle.jcajce.provider.digest.RIPEMD256;
import com.distrimind.bouncycastle.jcajce.provider.digest.RIPEMD320;
import com.distrimind.bouncycastle.jcajce.provider.digest.SHA1;
import com.distrimind.bouncycastle.jcajce.provider.digest.SHA224;
import com.distrimind.bouncycastle.jcajce.provider.digest.SHA256;
import com.distrimind.bouncycastle.jcajce.provider.digest.SHA3;
import com.distrimind.bouncycastle.jcajce.provider.digest.SHA384;
import com.distrimind.bouncycastle.jcajce.provider.digest.SHA512;
import com.distrimind.bouncycastle.jcajce.provider.digest.SM3;
import com.distrimind.bouncycastle.jcajce.provider.digest.Tiger;
import com.distrimind.bouncycastle.jcajce.provider.digest.Whirlpool;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.AES;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.ARC4;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Blowfish;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.CAST5;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.CAST6;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Camellia;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.ChaCha;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.DES;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.DESede;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.GOST28147;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Grain128;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Grainv1;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.HC128;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.HC256;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.IDEA;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Noekeon;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.PBEPBKDF2;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.PBEPKCS12;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.RC2;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.RC5;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.RC6;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Rijndael;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.SEED;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Salsa20;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Serpent;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Skipjack;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.TEA;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.Twofish;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.VMPC;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.VMPCKSA3;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.XSalsa20;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.XTEA;

public class PrivateConstructorTest
    extends TestCase
{
    public void testSymmetric()
        throws Exception
    {
        evilNoConstructionTest(AES.class);
        evilNoConstructionTest(ARC4.class);
        evilNoConstructionTest(Blowfish.class);
        evilNoConstructionTest(Camellia.class);
        evilNoConstructionTest(CAST5.class);
        evilNoConstructionTest(CAST6.class);
        evilNoConstructionTest(DESede.class);
        evilNoConstructionTest(DES.class);
        evilNoConstructionTest(GOST28147.class);
        evilNoConstructionTest(Grain128.class);
        evilNoConstructionTest(Grainv1.class);
        evilNoConstructionTest(HC128.class);
        evilNoConstructionTest(HC256.class);
        evilNoConstructionTest(IDEA.class);
        evilNoConstructionTest(Noekeon.class);
        evilNoConstructionTest(PBEPBKDF2.class);
        evilNoConstructionTest(PBEPKCS12.class);
        evilNoConstructionTest(RC2.class);
        evilNoConstructionTest(RC5.class);
        evilNoConstructionTest(RC6.class);
        evilNoConstructionTest(Rijndael.class);
        evilNoConstructionTest(ChaCha.class);
        evilNoConstructionTest(Salsa20.class);
        evilNoConstructionTest(XSalsa20.class);
        evilNoConstructionTest(SEED.class);
        evilNoConstructionTest(Serpent.class);
        evilNoConstructionTest(Skipjack.class);
        evilNoConstructionTest(TEA.class);
        evilNoConstructionTest(Twofish.class);
        evilNoConstructionTest(VMPC.class);
        evilNoConstructionTest(VMPCKSA3.class);
        evilNoConstructionTest(XTEA.class);
    }

    public void testDigest()
        throws Exception
    {
        evilNoConstructionTest(GOST3411.class);
        evilNoConstructionTest(MD2.class);
        evilNoConstructionTest(MD4.class);
        evilNoConstructionTest(MD5.class);
        evilNoConstructionTest(RIPEMD128.class);
        evilNoConstructionTest(RIPEMD160.class);
        evilNoConstructionTest(RIPEMD256.class);
        evilNoConstructionTest(RIPEMD320.class);
        evilNoConstructionTest(SHA1.class);
        evilNoConstructionTest(SHA224.class);
        evilNoConstructionTest(SHA256.class);
        evilNoConstructionTest(SHA384.class);
        evilNoConstructionTest(SHA3.class);
        evilNoConstructionTest(SHA512.class);
        evilNoConstructionTest(SM3.class);
        evilNoConstructionTest(Tiger.class);
        evilNoConstructionTest(Whirlpool.class);
    }

    private static void evilNoConstructionTest(Class clazz)
        throws InvocationTargetException, IllegalAccessException, InstantiationException
    {
        Constructor[] constructors = clazz.getDeclaredConstructors();
        Assert.assertEquals("Class should only have one constructor", 1, constructors.length);
        Constructor constructor = constructors[0];
        Assert.assertEquals("Constructor should be private", Modifier.PRIVATE, constructor.getModifiers());
        Assert.assertFalse("Constructor should be inaccessible", constructor.isAccessible());
        constructor.setAccessible(true); // don't try this at home
        Assert.assertEquals("Constructor return type wrong!!", clazz, constructor.newInstance().getClass());
    }
}
