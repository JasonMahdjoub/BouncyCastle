package com.distrimind.bouncycastle.openpgp.bc;

import java.io.IOException;
import java.io.InputStream;

import com.distrimind.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import com.distrimind.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import com.distrimind.bouncycastle.openpgp.PGPPublicKeyRing;

public class BcPGPPublicKeyRing
    extends PGPPublicKeyRing
{
    private static KeyFingerPrintCalculator fingerPrintCalculator = new BcKeyFingerprintCalculator();

    public BcPGPPublicKeyRing(byte[] encoding)
        throws IOException
    {
        super(encoding, fingerPrintCalculator);
    }

    public BcPGPPublicKeyRing(InputStream in)
        throws IOException
    {
        super(in, fingerPrintCalculator);
    }
}
