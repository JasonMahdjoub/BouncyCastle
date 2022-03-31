package com.distrimind.bouncycastle.openpgp.operator;

import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPrivateKey;

public interface PGPContentSignerBuilder
{
    public PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey)
        throws PGPException;
}
