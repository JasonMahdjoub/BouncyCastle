package com.distrimind.bouncycastle.openpgp.operator;

import com.distrimind.bouncycastle.openpgp.PGPException;

public interface PublicKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
            throws PGPException;
}
