package com.distrimind.bouncycastle.openpgp.operator;

import com.distrimind.bouncycastle.openpgp.PGPException;

public interface PGPContentVerifierBuilderProvider
{
    PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
        throws PGPException;
}
