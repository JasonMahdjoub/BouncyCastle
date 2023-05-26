package com.distrimind.bouncycastle.openpgp.operator.bc;

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

    public PGPSessionKey getSessionKey()
    {
        return sessionKey;
    }

    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }
    
    public PGPDataDecryptor createDataDecryptor(int aeadAlgorithm, byte[] iv, int chunkSize, int encAlgorithm, byte[] key)
        throws PGPException
    {
        return BcUtil.createDataDecryptor(aeadAlgorithm, iv, chunkSize, encAlgorithm, key);
    }
}
