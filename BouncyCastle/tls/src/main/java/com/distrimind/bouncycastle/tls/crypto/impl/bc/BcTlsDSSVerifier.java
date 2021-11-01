package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import com.distrimind.bouncycastle.crypto.DSA;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.digests.NullDigest;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.signers.DSADigestSigner;
import com.distrimind.bouncycastle.tls.DigitallySigned;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import com.distrimind.bouncycastle.tls.crypto.TlsCryptoUtils;

/**
 * BC light-weight base class for the verifiers supporting the two DSA style algorithms from FIPS PUB 186-4: DSA and ECDSA.
 */
public abstract class BcTlsDSSVerifier
    extends BcTlsVerifier
{
    protected BcTlsDSSVerifier(BcTlsCrypto crypto, AsymmetricKeyParameter publicKey)
    {
        super(crypto, publicKey);
    }

    protected abstract DSA createDSAImpl(int cryptoHashAlgorithm);

    protected abstract short getSignatureAlgorithm();

    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash)
    {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        if (algorithm != null && algorithm.getSignature() != getSignatureAlgorithm())
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = (null == algorithm)
            ? CryptoHashAlgorithm.sha1
            : TlsCryptoUtils.getHash(algorithm.getHash());

        Signer signer = new DSADigestSigner(createDSAImpl(cryptoHashAlgorithm), new NullDigest());
        signer.init(false, publicKey);
        if (algorithm == null)
        {
            // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            signer.update(hash, 16, 20);
        }
        else
        {
            signer.update(hash, 0, hash.length);
        }
        return signer.verifySignature(signedParams.getSignature());
    }
}
