package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.engines.RSAEngine;
import com.distrimind.bouncycastle.crypto.params.RSAKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.PSSSigner;
import com.distrimind.bouncycastle.tls.DigitallySigned;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureScheme;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamVerifier;

/**
 * Operator supporting the verification of RSASSA-PSS signatures using the BC light-weight API.
 */
public class BcTlsRSAPSSVerifier
    extends BcTlsVerifier
{
    private final int signatureScheme;

    public BcTlsRSAPSSVerifier(BcTlsCrypto crypto, RSAKeyParameters publicKey, int signatureScheme)
   {
        super(crypto, publicKey);

        if (!SignatureScheme.isRSAPSS(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.signatureScheme = signatureScheme;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        Digest digest = crypto.createDigest(cryptoHashAlgorithm);

        PSSSigner verifier = new PSSSigner(new RSAEngine(), digest, digest.getDigestSize());
        verifier.init(false, publicKey);

        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
