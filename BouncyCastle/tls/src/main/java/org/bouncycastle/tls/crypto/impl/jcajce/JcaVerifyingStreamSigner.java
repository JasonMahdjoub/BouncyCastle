package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

import com.distrimind.bouncycastle.jcajce.io.OutputStreamFactory;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamSigner;
import com.distrimind.bouncycastle.util.io.TeeOutputStream;

class JcaVerifyingStreamSigner
    implements TlsStreamSigner
{
    private final Signature signer;
    private final Signature verifier;
    private final OutputStream output;

    JcaVerifyingStreamSigner(Signature signer, Signature verifier)
    {
        OutputStream outputSigner = OutputStreamFactory.createStream(signer);
        OutputStream outputVerifier = OutputStreamFactory.createStream(verifier);

        this.signer = signer;
        this.verifier = verifier;
        this.output = new TeeOutputStream(outputSigner, outputVerifier);
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            byte[] signature = signer.sign();
            if (verifier.verify(signature))
            {
                return signature;
            }
        }
        catch (SignatureException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
