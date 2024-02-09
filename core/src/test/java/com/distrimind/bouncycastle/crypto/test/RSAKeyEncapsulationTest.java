package com.distrimind.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.crypto.digests.SHA1Digest;
import com.distrimind.bouncycastle.crypto.generators.KDF2BytesGenerator;
import com.distrimind.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import com.distrimind.bouncycastle.crypto.kems.RSAKEMExtractor;
import com.distrimind.bouncycastle.crypto.kems.RSAKEMGenerator;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.RSAKeyParameters;
import com.distrimind.bouncycastle.util.test.SimpleTest;

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
        RSAKEMGenerator kemGen;
        RSAKEMExtractor kemExt;
        KDF2BytesGenerator        kdf = new KDF2BytesGenerator(new SHA1Digest());
        SecureRandom            rnd = new SecureRandom();
        byte[]                    out = new byte[128];
        KeyParameter            key1, key2;
        
        // Test RSA-KEM
        kemGen = new RSAKEMGenerator(128 / 8, kdf, rnd);
        
        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(keys.getPublic());
        key1 = new KeyParameter(secEnc.getSecret());
        
        kemExt = new RSAKEMExtractor((RSAKeyParameters)keys.getPrivate(), 128 / 8, kdf);
        key2 = new KeyParameter(kemExt.extractSecret(secEnc.getEncapsulation()));

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
