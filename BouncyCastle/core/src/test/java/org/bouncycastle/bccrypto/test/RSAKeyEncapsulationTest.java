package org.bouncycastle.bccrypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.bccrypto.AsymmetricCipherKeyPair;
import org.bouncycastle.bccrypto.digests.SHA1Digest;
import org.bouncycastle.bccrypto.generators.KDF2BytesGenerator;
import org.bouncycastle.bccrypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.bccrypto.kems.RSAKeyEncapsulation;
import org.bouncycastle.bccrypto.params.KeyParameter;
import org.bouncycastle.bccrypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.bcutil.test.SimpleTest;

/**
 * Tests for the RSA Key Encapsulation Mechanism
 */
public class RSAKeyEncapsulationTest
    extends SimpleTest
{
    public String getName()
    {
        return "RSAKeyEncapsulation";
    }

    public void performTest()
        throws Exception
    {
        // Generate RSA key pair
        RSAKeyPairGenerator        rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 1024, 5));
        AsymmetricCipherKeyPair    keys   = rsaGen.generateKeyPair();
        
        // Set RSA-KEM parameters
        RSAKeyEncapsulation     kem;
        KDF2BytesGenerator        kdf = new KDF2BytesGenerator(new SHA1Digest());
        SecureRandom            rnd = new SecureRandom();
        byte[]                    out = new byte[128];
        KeyParameter            key1, key2;
        
        // Test RSA-KEM
        kem = new RSAKeyEncapsulation(kdf, rnd);
        
        kem.init(keys.getPublic());
        key1 = (KeyParameter)kem.encrypt(out, 128);
        
        kem.init(keys.getPrivate());
        key2 = (KeyParameter)kem.decrypt(out, 128);

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed test");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new RSAKeyEncapsulationTest());
    }
}
