package com.distrimind.bouncycastle.openpgp.bc;

import java.io.IOException;
import java.io.InputStream;

import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPSecretKeyRing;
import com.distrimind.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import com.distrimind.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public class BcPGPSecretKeyRing
    extends PGPSecretKeyRing
{
    private static KeyFingerPrintCalculator fingerPrintCalculator = new BcKeyFingerprintCalculator();

    public BcPGPSecretKeyRing(byte[] encoding)
        throws IOException, PGPException
    {
        super(encoding, fingerPrintCalculator);
    }

    public BcPGPSecretKeyRing(InputStream in)
        throws IOException, PGPException
    {
        super(in, fingerPrintCalculator);
    }
}
