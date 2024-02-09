package com.distrimind.bouncycastle.openpgp.operator.bc;

import com.distrimind.bouncycastle.bcpg.AEADEncDataPacket;
import com.distrimind.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPSessionKey;
import com.distrimind.bouncycastle.openpgp.operator.PGPDataDecryptor;
import com.distrimind.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

/**
 * A decryptor factory for handling PGP session keys.
 */
public class BcSessionKeyDataDecryptorFactory
    implements SessionKeyDataDecryptorFactory
{
    private final PGPSessionKey sessionKey;

    public BcSessionKeyDataDecryptorFactory(PGPSessionKey sessionKey)
    {
        this.sessionKey = sessionKey;
    }

    @Override
    public PGPSessionKey getSessionKey()
    {
        return sessionKey;
    }

    // OpenPGP v4
    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }

    // OpenPGP v5
    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
        throws PGPException
    {
        return BcAEADUtil.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
    }

    // OpenPGP v6
    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
            throws PGPException
    {
        return BcAEADUtil.createOpenPgpV6DataDecryptor(seipd, sessionKey);
    }

}
