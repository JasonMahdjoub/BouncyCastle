package com.distrimind.bouncycastle.openpgp.operator.bc;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.bcpg.S2K;
import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.BufferedBlockCipher;
import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import com.distrimind.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * A BC lightweight method generator for supporting PBE based encryption operations.
 */
public class BcPBEKeyEncryptionMethodGenerator
    extends PBEKeyEncryptionMethodGenerator
{
    /**
     * Create a PBE encryption method generator using the provided digest and the default S2K count
     * for key generation.
     *
     * @param passPhrase          the passphrase to use as the primary source of key material.
     * @param s2kDigestCalculator the digest calculator to use for key calculation.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator)
    {
        super(passPhrase, s2kDigestCalculator);
    }

    /**
     * Create a PBE encryption method generator using the default SHA-1 digest and the default S2K
     * count for key generation.
     *
     * @param passPhrase the passphrase to use as the primary source of key material.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase)
    {
        this(passPhrase, new SHA1PGPDigestCalculator());
    }

    /**
     * Create a PBE encryption method generator using Argon2 for S2K key generation.
     *
     * @param passPhrase   passphrase
     * @param argon2Params parameters for argon2
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, S2K.Argon2Params argon2Params)
    {
        super(passPhrase, argon2Params);
    }

    /**
     * Create a PBE encryption method generator using the provided calculator and S2K count for key
     * generation.
     *
     * @param passPhrase          the passphrase to use as the primary source of key material.
     * @param s2kDigestCalculator the digest calculator to use for key calculation.
     * @param s2kCount            the single byte {@link S2K} count to use.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator, int s2kCount)
    {
        super(passPhrase, s2kDigestCalculator, s2kCount);
    }

    /**
     * Create a PBE encryption method generator using the default SHA-1 digest calculator and a S2K
     * count other than the default for key generation.
     *
     * @param passPhrase the passphrase to use as the primary source of key material.
     * @param s2kCount   the single byte {@link S2K} count to use.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, int s2kCount)
    {
        super(passPhrase, new SHA1PGPDigestCalculator(), s2kCount);
    }

    public PBEKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        super.setSecureRandom(random);

        return this;
    }

    protected byte[] encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);
            BufferedBlockCipher cipher = BcUtil.createSymmetricKeyWrapper(true, engine, key, new byte[engine.getBlockSize()]);

            byte[] out = new byte[sessionInfo.length];

            int len = cipher.processBytes(sessionInfo, 0, sessionInfo.length, out, 0);

            len += cipher.doFinal(out, len);

            return out;
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("encryption failed: " + e.getMessage(), e);
        }
    }
}
