package com.distrimind.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for Dilithium with BC provider.
 */
public class DilithiumKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("Dilithium", "BC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        DilithiumParameterSpec[] specs =
            new DilithiumParameterSpec[]
                {
                        DilithiumParameterSpec.dilithium2,
                        DilithiumParameterSpec.dilithium3,
                        DilithiumParameterSpec.dilithium5,
                        DilithiumParameterSpec.dilithium2_aes,
                        DilithiumParameterSpec.dilithium3_aes,
                        DilithiumParameterSpec.dilithium5_aes,
                };
        kf = KeyFactory.getInstance("Dilithium", "BC");

        kpg = KeyPairGenerator.getInstance("Dilithium", "BC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(specs[i].getName(), kpg.generateKeyPair());
        }
    }

}
