package com.distrimind.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.pqc.jcajce.interfaces.KyberPrivateKey;
import com.distrimind.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for Kyber with BCPQC provider.
 */
public class KyberKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("Kyber", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_kyber.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        KyberParameterSpec[] specs =
            new KyberParameterSpec[]
                {
                        KyberParameterSpec.kyber512,
                        KyberParameterSpec.kyber768,
                        KyberParameterSpec.kyber1024,
                        KyberParameterSpec.kyber512_aes,
                        KyberParameterSpec.kyber768_aes,
                        KyberParameterSpec.kyber1024_aes
                };
        kf = KeyFactory.getInstance("Kyber", "BCPQC");

        kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            performKeyPairEncodingTest(specs[i].getName(), kp);

            assertEquals(kp.getPublic(), ((KyberPrivateKey)kp.getPrivate()).getPublicKey());;
        }
    }

}
