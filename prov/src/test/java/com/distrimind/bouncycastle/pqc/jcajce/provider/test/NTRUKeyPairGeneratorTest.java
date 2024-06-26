package com.distrimind.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import com.distrimind.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for NTRU with BC provider.
 */
public class NTRUKeyPairGeneratorTest
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
        kf = KeyFactory.getInstance("NTRU", "BC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_ntru.getId(), "BC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        NTRUParameterSpec[] specs =
            new NTRUParameterSpec[]
                {
                    NTRUParameterSpec.ntruhps2048509,
                    NTRUParameterSpec.ntruhps2048677,
                    NTRUParameterSpec.ntruhps4096821,
                    NTRUParameterSpec.ntruhps40961229,
                    NTRUParameterSpec.ntruhrss701,
                    NTRUParameterSpec.ntruhrss1373
                };
        kf = KeyFactory.getInstance("NTRU", "BC");

        kpg = KeyPairGenerator.getInstance("NTRU", "BC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
