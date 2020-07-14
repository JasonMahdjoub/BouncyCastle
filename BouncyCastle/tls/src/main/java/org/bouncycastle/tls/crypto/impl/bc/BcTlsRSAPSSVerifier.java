package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.engines.RSAEngine;
import com.distrimind.bouncycastle.crypto.params.RSAKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.PSSSigner;
import com.distrimind.bouncycastle.tls.DigitallySigned;
import com.distrimind.bouncycastle.tls.HashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamVerifier;

/**
 * Operator supporting the verification of RSASSA-PSS signatures using the BC light-weight API.
 */
public class BcTlsRSAPSSVerifier
    extends BcTlsVerifier
{
    private final short signatureAlgorithm;

    public BcTlsRSAPSSVerifier(BcTlsCrypto crypto, RSAKeyParameters publicKey, short signatureAlgorithm)
   {
        super(crypto, publicKey);

        if (!SignatureAlgorithm.isRSAPSS(signatureAlgorithm))
        {
            throw new IllegalArgumentException("signatureAlgorithm");
        }

        this.signatureAlgorithm = signatureAlgorithm;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null
            || algorithm.getSignature() != signatureAlgorithm
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        short hash = SignatureAlgorithm.getRSAPSSHashAlgorithm(signatureAlgorithm);
        Digest digest = crypto.createDigest(hash);

        PSSSigner verifier = new PSSSigner(new RSAEngine(), digest, digest.getDigestSize());
        verifier.init(false, publicKey);

        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
