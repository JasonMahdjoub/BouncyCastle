package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bccrypto.CryptoException;
import org.bouncycastle.bccrypto.Digest;
import org.bouncycastle.bccrypto.engines.RSABlindedEngine;
import org.bouncycastle.bccrypto.io.SignerOutputStream;
import org.bouncycastle.bccrypto.params.ParametersWithRandom;
import org.bouncycastle.bccrypto.params.RSAKeyParameters;
import org.bouncycastle.bccrypto.signers.PSSSigner;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/**
 * Operator supporting the generation of RSASSA-PSS signatures using the BC light-weight API.
 */
public class BcTlsRSAPSSSigner
    extends BcTlsSigner
{
    private final short signatureAlgorithm;

    public BcTlsRSAPSSSigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, short signatureAlgorithm)
    {
        super(crypto, privateKey);

        if (!SignatureAlgorithm.isRSAPSS(signatureAlgorithm))
        {
            throw new IllegalArgumentException("signatureAlgorithm");
        }

        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null
            || algorithm.getSignature() != signatureAlgorithm
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        short hash = SignatureAlgorithm.getRSAPSSHashAlgorithm(signatureAlgorithm);
        Digest digest = crypto.createDigest(hash);

        PSSSigner signer = new PSSSigner(new RSABlindedEngine(), digest, HashAlgorithm.getOutputSize(hash));
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));

        final SignerOutputStream sigOut = new SignerOutputStream(signer);

        return new TlsStreamSigner()
        {
            public OutputStream getOutputStream()
            {
                return sigOut;
            }

            public byte[] getSignature() throws IOException
            {
                try
                {
                    return sigOut.getSigner().generateSignature();
                }
                catch (CryptoException e)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error, e);
                }
            }
        };
    }
}
