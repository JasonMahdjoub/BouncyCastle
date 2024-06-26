package com.distrimind.bouncycastle.pqc.jcajce.provider.test;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import com.distrimind.bouncycastle.jcajce.spec.KEMExtractSpec;
import com.distrimind.bouncycastle.jcajce.spec.KEMGenerateSpec;
import com.distrimind.bouncycastle.jcajce.spec.KEMParameterSpec;
import com.distrimind.bouncycastle.jcajce.spec.KTSParameterSpec;
import com.distrimind.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import com.distrimind.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for SNTRUPime with the BCPQC provider.
 */
public class SNTRUPrimeTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testBasicKEMAES()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(SNTRUPrimeParameterSpec.sntrup1013, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("AES-KWP"));
    }

    public void testBasicKEMCamellia()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KTSParameterSpec.Builder("Camellia-KWP", 256).build());
    }

    public void testBasicKEMSEED()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KTSParameterSpec.Builder("SEED", 128).build());
    }

    public void testBasicKEMARIA()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("ARIA"));
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("ARIA-KWP"));
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KTSParameterSpec ktsParameterSpec)
            throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BCPQC");

        byte[] keyBytes;
        if (algorithm.endsWith("KWP"))
        {
            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0faa");
        }
        else
        {
            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        }
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        w1.init(Cipher.WRAP_MODE, kp.getPublic(), ktsParameterSpec);

        byte[] data = w1.wrap(key);

        Cipher w2 = Cipher.getInstance(algorithm, "BCPQC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

    public void testGenerateAES()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("SNTRUPrime", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testGenerateAES256()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup1277, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("SNTRUPrime", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
}
