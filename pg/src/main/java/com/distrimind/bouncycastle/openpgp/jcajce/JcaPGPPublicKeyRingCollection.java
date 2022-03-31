package com.distrimind.bouncycastle.openpgp.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import com.distrimind.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class JcaPGPPublicKeyRingCollection
    extends PGPPublicKeyRingCollection
{
    public JcaPGPPublicKeyRingCollection(byte[] encoding)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding));
    }

    public JcaPGPPublicKeyRingCollection(InputStream in)
        throws IOException, PGPException
    {
        super(in, new JcaKeyFingerprintCalculator());
    }

    public JcaPGPPublicKeyRingCollection(Collection collection)
        throws IOException, PGPException
    {
        super(collection);
    }
}
