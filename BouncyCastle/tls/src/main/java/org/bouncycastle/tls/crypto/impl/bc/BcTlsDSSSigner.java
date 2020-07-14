package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.crypto.DSA;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bouncycastle.crypto.signers.DSADigestSigner;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.HashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;

/**
 * BC light-weight base class for the signers implementing the two DSA style algorithms from FIPS PUB 186-4: DSA and ECDSA.
 */
public abstract class BcTlsDSSSigner
    extends BcTlsSigner
{
    protected BcTlsDSSSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)
    {
        super(crypto, privateKey);
    }

    protected abstract DSA createDSAImpl(short hashAlgorithm);

    protected abstract short getSignatureAlgorithm();

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        if (algorithm != null && algorithm.getSignature() != getSignatureAlgorithm())
        {
            throw new IllegalStateException();
        }
        
        short hashAlgorithm = algorithm == null ? HashAlgorithm.sha1 : algorithm.getHash();
        
        Signer s = new DSADigestSigner(createDSAImpl(hashAlgorithm), crypto.createDigest(HashAlgorithm.none));
        s.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));
        Signer signer = s;
        if (algorithm == null)
        {
            // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            signer.update(hash, 16, 20);
        }
        else
        {
            signer.update(hash, 0, hash.length);
        }
        try
        {
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
