package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ParametersWithID;
import com.distrimind.bouncycastle.crypto.signers.SM2Signer;
import com.distrimind.bouncycastle.tls.DigitallySigned;
import com.distrimind.bouncycastle.tls.SignatureAndHashAlgorithm;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamVerifier;
import com.distrimind.bouncycastle.util.Arrays;

public class BcTlsSM2Verifier
    extends BcTlsVerifier
{
    protected final byte[] identifier;

    public BcTlsSM2Verifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey, byte[] identifier)
    {
        super(crypto, publicKey);

        this.identifier = Arrays.clone(identifier);
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null
            // TODO[RFC 8998] 
//            || algorithm.getSignature() != SignatureAlgorithm.sm2
//            || algorithm.getHash() != HashAlgorithm.sm3
            )
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        ParametersWithID parametersWithID = new ParametersWithID(publicKey, identifier);

        SM2Signer verifier = new SM2Signer();
        verifier.init(false, parametersWithID);

        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
