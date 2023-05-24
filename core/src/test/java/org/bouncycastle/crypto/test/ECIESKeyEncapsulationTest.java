package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.kems.ECIESKEMExtractor;
import org.bouncycastle.crypto.kems.ECIESKEMGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.test.SimpleTest;

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
