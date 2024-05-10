package com.distrimind.bouncycastle.crypto.kems;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.CryptoServicePurpose;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bouncycastle.crypto.DerivationFunction;
import com.distrimind.bouncycastle.crypto.KeyEncapsulation;
import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.crypto.constraints.ConstraintUtils;
import com.distrimind.bouncycastle.crypto.constraints.DefaultServiceProperties;
import com.distrimind.bouncycastle.crypto.params.ECKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.util.Arrays;

/**
 * The ECIES Key Encapsulation Mechanism (ECIES-KEM) from ISO 18033-2.
 * @deprecated use ECIESKEMGenerator, ECIESKEMExtractor
 */
public class ECIESKeyEncapsulation
    implements KeyEncapsulation
{
    private DerivationFunction kdf;
    private SecureRandom rnd;
    private ECKeyParameters key;
    private boolean CofactorMode;
    private boolean OldCofactorMode;
    private boolean SingleHashMode;

    /**
     * Set up the ECIES-KEM.
     *
     * @param kdf the key derivation function to be used.
     * @param rnd the random source for the session key.
     */
    public ECIESKeyEncapsulation(
        DerivationFunction kdf,
        SecureRandom rnd)
    {
        this.kdf = kdf;
        this.rnd = rnd;
        this.CofactorMode = false;
        this.OldCofactorMode = false;
        this.SingleHashMode = false;
    }

    /**
     * Set up the ECIES-KEM.
     *
     * @param kdf             the key derivation function to be used.
     * @param rnd             the random source for the session key.
     * @param cofactorMode    if true use the new cofactor ECDH.
     * @param oldCofactorMode if true use the old cofactor ECDH.
     * @param singleHashMode  if true use single hash mode.
     */
    public ECIESKeyEncapsulation(
        DerivationFunction kdf,
        SecureRandom rnd,
        boolean cofactorMode,
        boolean oldCofactorMode,
        boolean singleHashMode)
    {
        this.kdf = kdf;
        this.rnd = rnd;

        // If both cofactorMode and oldCofactorMode are set to true
        // then the implementation will use the new cofactor ECDH 
        this.CofactorMode = cofactorMode;
        // https://www.shoup.net/iso/std4.pdf, Page 34.
        if (cofactorMode)
        {
            this.OldCofactorMode = false;
        }
        else
        {
            this.OldCofactorMode = oldCofactorMode;
        }
        this.SingleHashMode = singleHashMode;
    }

    /**
     * Initialise the ECIES-KEM.
     *
     * @param key the recipient's public (for encryption) or private (for decryption) key.
     */
    public void init(CipherParameters key)
        throws IllegalArgumentException
    {
        if (!(key instanceof ECKeyParameters))
        {
            throw new IllegalArgumentException("EC key required");
        }
        else
        {
            this.key = (ECKeyParameters)key;
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("ECIESKem",
            ConstraintUtils.bitsOfSecurityFor(this.key.getParameters().getCurve()), key, CryptoServicePurpose.ANY));
    }

    /**
     * Generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param outOff the offset for the output buffer.
     * @param keyLen the length of the session key.
     * @return the random session key.
     * @deprecated use ECIESKEMGenerator
     */
    public CipherParameters encrypt(byte[] out, int outOff, int keyLen)
        throws IllegalArgumentException
    {
        if (!(key instanceof ECPublicKeyParameters))
        {
            throw new IllegalArgumentException("Public key required for encryption");
        }

        ECIESKEMGenerator kemGen = new ECIESKEMGenerator(keyLen, kdf, rnd, CofactorMode, OldCofactorMode, SingleHashMode);

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(key);

        byte[] encLen = secEnc.getEncapsulation();
        System.arraycopy(encLen, 0, out, outOff, encLen.length);

        return new KeyParameter(secEnc.getSecret());
    }

    /**
     * Generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param keyLen the length of the session key.
     * @return the random session key.
     * @deprecated use ECIESKEMGenerator
     */
    public CipherParameters encrypt(byte[] out, int keyLen)
    {
        return encrypt(out, 0, keyLen);
    }

    /**
     * Decrypt an encapsulated session key.
     *
     * @param in     the input buffer for the encapsulated key.
     * @param inOff  the offset for the input buffer.
     * @param inLen  the length of the encapsulated key.
     * @param keyLen the length of the session key.
     * @return the session key.
     * @deprecated use ECIESKEMExtractor
     */
    public CipherParameters decrypt(byte[] in, int inOff, int inLen, int keyLen)
        throws IllegalArgumentException
    {
        if (!(key instanceof ECPrivateKeyParameters))
        {
            throw new IllegalArgumentException("Private key required for encryption");
        }
        ECPrivateKeyParameters prvKey = (ECPrivateKeyParameters)key;

        ECIESKEMExtractor kemExt = new ECIESKEMExtractor(prvKey, keyLen, kdf, CofactorMode, OldCofactorMode, SingleHashMode);

        byte[] secret = kemExt.extractSecret(Arrays.copyOfRange(in, inOff, inOff + inLen));
        
        return new KeyParameter(secret);
    }

    /**
     * Decrypt an encapsulated session key.
     *
     * @param in     the input buffer for the encapsulated key.
     * @param keyLen the length of the session key.
     * @return the session key.
     * @deprecated use ECIESKEMExtractor
     */
    public CipherParameters decrypt(byte[] in, int keyLen)
    {
        return decrypt(in, 0, in.length, keyLen);
    }
}
