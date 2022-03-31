package com.distrimind.bouncycastle.openpgp.operator.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPrivateKey;
import com.distrimind.bouncycastle.openpgp.operator.PGPContentSigner;
import com.distrimind.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import com.distrimind.bouncycastle.openpgp.operator.PGPDigestCalculator;
import com.distrimind.bouncycastle.util.io.TeeOutputStream;

public class BcPGPContentSignerBuilder
    implements PGPContentSignerBuilder
{
    private BcPGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
    private BcPGPKeyConverter           keyConverter = new BcPGPKeyConverter();
    private int                         hashAlgorithm;
    private SecureRandom                random;
    private int keyAlgorithm;

    public BcPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm)
    {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    public BcPGPContentSignerBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey)
        throws PGPException
    {
        final PGPDigestCalculator digestCalculator = digestCalculatorProvider.get(hashAlgorithm);
        final Signer signer = BcImplProvider.createSigner(keyAlgorithm, hashAlgorithm);

        if (random != null)
        {
            signer.init(true, new ParametersWithRandom(keyConverter.getPrivateKey(privateKey), random));
        }
        else
        {
            signer.init(true, keyConverter.getPrivateKey(privateKey));
        }

        return new PGPContentSigner()
        {
            public int getType()
            {
                return signatureType;
            }

            public int getHashAlgorithm()
            {
                return hashAlgorithm;
            }

            public int getKeyAlgorithm()
            {
                return keyAlgorithm;
            }

            public long getKeyID()
            {
                return privateKey.getKeyID();
            }

            public OutputStream getOutputStream()
            {
                return new TeeOutputStream(new SignerOutputStream(signer), digestCalculator.getOutputStream());
            }

            public byte[] getSignature()
            {
                try
                {
                    return signer.generateSignature();
                }
                catch (CryptoException e)
                {    // TODO: need a specific runtime exception for PGP operators.
                    throw new IllegalStateException("unable to create signature");
                }
            }

            public byte[] getDigest()
            {
                return digestCalculator.getDigest();
            }
        };
    }
}
