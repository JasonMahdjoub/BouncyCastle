package com.distrimind.bouncycastle.openpgp.bc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

import com.distrimind.bouncycastle.openpgp.PGPPublicKeyRing;
import com.distrimind.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPublicKeyRingCollection;

public class BcPGPPublicKeyRingCollection
    extends PGPPublicKeyRingCollection
{
    public BcPGPPublicKeyRingCollection(byte[] encoding)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding));
    }

    public BcPGPPublicKeyRingCollection(InputStream in)
        throws IOException, PGPException
    {
        super(in, new BcKeyFingerprintCalculator());
    }

    public BcPGPPublicKeyRingCollection(Collection<PGPPublicKeyRing> collection)
    {
        super(collection);
    }
}
