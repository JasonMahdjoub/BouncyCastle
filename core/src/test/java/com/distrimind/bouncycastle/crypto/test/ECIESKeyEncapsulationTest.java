package com.distrimind.bouncycastle.crypto.test;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.asn1.sec.SECNamedCurves;
import com.distrimind.bouncycastle.asn1.x9.X9ECParameters;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.crypto.digests.SHA1Digest;
import com.distrimind.bouncycastle.crypto.generators.ECKeyPairGenerator;
import com.distrimind.bouncycastle.crypto.generators.KDF2BytesGenerator;
import com.distrimind.bouncycastle.crypto.kems.ECIESKEMExtractor;
import com.distrimind.bouncycastle.crypto.kems.ECIESKEMGenerator;
import com.distrimind.bouncycastle.crypto.params.ECDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECKeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the ECIES Key Encapsulation Mechanism
 */
public class ECIESKeyEncapsulationTest
    extends SimpleTest
{
    public String getName()
    {
        return "ECIESKeyEncapsulation";
    }

    public void performTest()
        throws Exception
    {
        
        // Set EC domain parameters and generate key pair
        X9ECParameters            spec     = SECNamedCurves.getByName("secp224r1");
        ECDomainParameters        ecDomain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
        ECKeyPairGenerator        ecGen    = new ECKeyPairGenerator();

        ecGen.init(new ECKeyGenerationParameters(ecDomain, new SecureRandom()));

        AsymmetricCipherKeyPair    keys      = ecGen.generateKeyPair();
        
        // Set ECIES-KEM parameters
        ECIESKEMGenerator kemGen;
        ECIESKEMExtractor kemExt;
        KDF2BytesGenerator        kdf = new KDF2BytesGenerator(new SHA1Digest());
        SecureRandom            rnd = new SecureRandom();
        byte[]                    out = new byte[57];
        KeyParameter            key1, key2;

        // Test basic ECIES-KEM
        kemGen = new ECIESKEMGenerator(128 / 8, kdf, rnd);
        
        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(keys.getPublic());

        key1 = new KeyParameter(secEnc.getSecret());
        
        kemExt = new ECIESKEMExtractor((ECPrivateKeyParameters)keys.getPrivate(), 128 / 8, kdf);

        key2 = new KeyParameter(kemExt.extractSecret(secEnc.getEncapsulation()));

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed basic test");
        }

        // Test ECIES-KEM using new cofactor mode
        kemGen = new ECIESKEMGenerator(128 / 8, kdf, rnd, true, false, false);

        secEnc = kemGen.generateEncapsulated(keys.getPublic());

        key1 = new KeyParameter(secEnc.getSecret());

        kemExt = new ECIESKEMExtractor((ECPrivateKeyParameters)keys.getPrivate(), 128 / 8, kdf, true, false, false);

        key2 = new KeyParameter(kemExt.extractSecret(secEnc.getEncapsulation()));

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed cofactor test");
        }
        // Test ECIES-KEM using old cofactor mode
        kemGen = new ECIESKEMGenerator(128 / 8, kdf, rnd, false, true, false);

        secEnc = kemGen.generateEncapsulated(keys.getPublic());

        key1 = new KeyParameter(secEnc.getSecret());

        kemExt = new ECIESKEMExtractor((ECPrivateKeyParameters)keys.getPrivate(), 128 / 8, kdf, false, true, false);

        key2 = new KeyParameter(kemExt.extractSecret(secEnc.getEncapsulation()));

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed old cofactor test");
        }

        // Test ECIES-KEM using single hash mode
        kemGen = new ECIESKEMGenerator(128 / 8, kdf, rnd, false, false, true);

        secEnc = kemGen.generateEncapsulated(keys.getPublic());

        key1 = new KeyParameter(secEnc.getSecret());

        kemExt = new ECIESKEMExtractor((ECPrivateKeyParameters)keys.getPrivate(), 128 / 8, kdf, false, false, true);

        key2 = new KeyParameter(kemExt.extractSecret(secEnc.getEncapsulation()));

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed single hash test");
        }

        // Test ECIES-KEM using new cofactor mode and single hash mode
        kemGen = new ECIESKEMGenerator(128 / 8, kdf, rnd, true, false, true);

        secEnc = kemGen.generateEncapsulated(keys.getPublic());

        key1 = new KeyParameter(secEnc.getSecret());

        kemExt = new ECIESKEMExtractor((ECPrivateKeyParameters)keys.getPrivate(), 128 / 8, kdf, true, false, true);

        key2 = new KeyParameter(kemExt.extractSecret(secEnc.getEncapsulation()));

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed cofactor and single hash test");
        }

        // Test ECIES-KEM using old cofactor mode and single hash mode
        kemGen = new ECIESKEMGenerator(128 / 8, kdf, rnd, false, true, true);

        secEnc = kemGen.generateEncapsulated(keys.getPublic());

        key1 = new KeyParameter(secEnc.getSecret());

        kemExt = new ECIESKEMExtractor((ECPrivateKeyParameters)keys.getPrivate(), 128 / 8, kdf, false, true, true);

        key2 = new KeyParameter(kemExt.extractSecret(secEnc.getEncapsulation()));

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed old cofactor and single hash test");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new ECIESKeyEncapsulationTest());
    }
}
