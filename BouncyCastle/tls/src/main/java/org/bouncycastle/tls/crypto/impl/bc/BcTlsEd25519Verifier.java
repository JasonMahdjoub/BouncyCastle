package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import com.distrimind.bouncycastle.crypto.signers.Ed25519Signer;
import com.distrimind.bouncycastle.tls.DigitallySigned;
import com.distrimind.bouncycastle.tls.HashAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamVerifier;

public class BcTlsEd25519Verifier
    extends BcTlsVerifier
{
    public BcTlsEd25519Verifier(BcTlsCrypto crypto, Ed25519PublicKeyParameters publicKey)
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
        if (algorithm == null
            || algorithm.getSignature() != SignatureAlgorithm.ed25519
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKey);

        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
