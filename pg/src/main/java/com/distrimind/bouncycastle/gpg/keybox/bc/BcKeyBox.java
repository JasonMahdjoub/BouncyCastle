package com.distrimind.bouncycastle.gpg.keybox.bc;

import java.io.IOException;
import java.io.InputStream;

import com.distrimind.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import com.distrimind.bouncycastle.gpg.keybox.KeyBox;

public class BcKeyBox
    extends KeyBox
{
    public BcKeyBox(byte[] encoding)
        throws IOException
    {
        super(encoding, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
    }

    public BcKeyBox(InputStream input)
        throws IOException
    {
        super(input, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
    }
}
