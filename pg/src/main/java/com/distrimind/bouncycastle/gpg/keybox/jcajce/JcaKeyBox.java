package com.distrimind.bouncycastle.gpg.keybox.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import com.distrimind.bouncycastle.gpg.keybox.BlobVerifier;
import com.distrimind.bouncycastle.gpg.keybox.KeyBox;
import com.distrimind.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

public class JcaKeyBox
    extends KeyBox
{
    JcaKeyBox(byte[] encoding, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier verifier)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException
    {
        super(encoding, fingerPrintCalculator, verifier);
    }

    JcaKeyBox(InputStream input, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier verifier)
        throws IOException
    {
        super(input, fingerPrintCalculator, verifier);
    }
}
