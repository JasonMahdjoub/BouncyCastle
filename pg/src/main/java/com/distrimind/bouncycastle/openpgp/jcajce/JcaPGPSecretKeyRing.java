package com.distrimind.bouncycastle.openpgp.jcajce;

import java.io.IOException;
import java.io.InputStream;

import com.distrimind.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPSecretKeyRing;

public class JcaPGPSecretKeyRing
    extends PGPSecretKeyRing
{
    private static KeyFingerPrintCalculator getFingerPrintCalculator()
    {
        return new JcaKeyFingerprintCalculator();
    }

    public JcaPGPSecretKeyRing(byte[] encoding)
        throws IOException, PGPException
    {
        super(encoding, getFingerPrintCalculator());
    }

    public JcaPGPSecretKeyRing(InputStream in)
        throws IOException, PGPException
    {
        super(in, getFingerPrintCalculator());
    }
}
