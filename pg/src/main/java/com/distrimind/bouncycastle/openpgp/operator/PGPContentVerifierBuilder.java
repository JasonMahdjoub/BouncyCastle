package com.distrimind.bouncycastle.openpgp.operator;

import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;

public interface PGPContentVerifierBuilder
{
    PGPContentVerifier build(final PGPPublicKey publicKey)
        throws PGPException;
}
