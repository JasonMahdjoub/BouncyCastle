package com.distrimind.bouncycastle.openpgp.operator;

import com.distrimind.bouncycastle.bcpg.ContainedPacket;
import com.distrimind.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import com.distrimind.bouncycastle.openpgp.PGPException;

/**
 * An encryption method that can be applied to encrypt data in a {@link PGPEncryptedDataGenerator}.
 */
public abstract class PGPKeyEncryptionMethodGenerator
{
    public abstract ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException;

    public abstract ContainedPacket generateV5(int encAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
        throws PGPException;

    public abstract ContainedPacket generateV6(int encAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
        throws PGPException;
}
