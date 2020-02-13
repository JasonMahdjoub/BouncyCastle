package org.bouncycastle.bccrypto.test;

import java.security.SecureRandom;

import org.bouncycastle.bccrypto.AsymmetricCipherKeyPair;
import org.bouncycastle.bccrypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.bccrypto.agreement.X448Agreement;
import org.bouncycastle.bccrypto.generators.X448KeyPairGenerator;
import org.bouncycastle.bccrypto.params.X448KeyGenerationParameters;
import org.bouncycastle.bcutil.test.SimpleTest;

public class X448Test
    extends SimpleTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    public String getName()
    {
        return "X448";
    }

    public static void main(String[] args)
    {
        runTest(new X448Test());
    }

    public void performTest()
    {
        for (int i = 0; i < 10; ++i)
        {
            testAgreement();
        }
    }

    private void testAgreement()
    {
        AsymmetricCipherKeyPairGenerator kpGen = new X448KeyPairGenerator();
        kpGen.init(new X448KeyGenerationParameters(RANDOM));

        AsymmetricCipherKeyPair kpA = kpGen.generateKeyPair();
        AsymmetricCipherKeyPair kpB = kpGen.generateKeyPair();

        X448Agreement agreeA = new X448Agreement();
        agreeA.init(kpA.getPrivate());
        byte[] secretA = new byte[agreeA.getAgreementSize()];
        agreeA.calculateAgreement(kpB.getPublic(), secretA, 0);

        X448Agreement agreeB = new X448Agreement();
        agreeB.init(kpB.getPrivate());
        byte[] secretB = new byte[agreeB.getAgreementSize()];
        agreeB.calculateAgreement(kpA.getPublic(), secretB, 0);

        if (!areEqual(secretA, secretB))
        {
            fail("X448 agreement failed");
        }
    }
}
