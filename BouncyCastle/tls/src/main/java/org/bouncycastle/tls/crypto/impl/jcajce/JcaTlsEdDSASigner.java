package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;

import com.distrimind.bouncycastle.tls.HashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.crypto.TlsSigner;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamSigner;

public abstract class JcaTlsEdDSASigner
    implements TlsSigner
{
    protected final JcaTlsCrypto crypto;
    protected final PrivateKey privateKey;
    protected final short algorithmType;
    protected final String algorithmName;

    public JcaTlsEdDSASigner(JcaTlsCrypto crypto, PrivateKey privateKey, short algorithmType, String algorithmName)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.algorithmType = algorithmType;
        this.algorithmName = algorithmName;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        if (algorithm == null
            || algorithm.getSignature() != algorithmType
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        return crypto.createStreamSigner(algorithmName, null, privateKey, false);
    }
}
