package com.distrimind.bouncycastle.openpgp.test;

import java.security.Security;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import com.distrimind.bouncycastle.openpgp.PGPUtil;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class PGPParsingTest
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        PGPPublicKeyRingCollection pubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(this.getClass().getResourceAsStream("bigpub.asc")), new JcaKeyFingerprintCalculator());
    }

    public String getName()
    {
        return "PGPParsingTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPParsingTest());
    }
}
