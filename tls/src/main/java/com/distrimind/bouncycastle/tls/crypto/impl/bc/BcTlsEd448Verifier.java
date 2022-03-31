package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.Ed448Signer;
import com.distrimind.bouncycastle.tls.DigitallySigned;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureScheme;
import com.distrimind.bouncycastle.tls.TlsUtils;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamVerifier;

public class BcTlsEd448Verifier
    extends BcTlsVerifier
{
    public BcTlsEd448Verifier(BcTlsCrypto crypto, Ed448PublicKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != SignatureScheme.ed448)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        Ed448Signer verifier = new Ed448Signer(TlsUtils.EMPTY_BYTES);
        verifier.init(false, publicKey);

        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
