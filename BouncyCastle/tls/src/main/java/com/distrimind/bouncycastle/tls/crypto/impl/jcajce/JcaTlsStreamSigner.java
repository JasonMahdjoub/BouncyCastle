package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

import com.distrimind.bouncycastle.jcajce.io.OutputStreamFactory;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamSigner;

class JcaTlsStreamSigner
    implements TlsStreamSigner
{
    private final Signature signer;
    private final OutputStream output;

    JcaTlsStreamSigner(Signature signer)
    {
        this.signer = signer;
        this.output = OutputStreamFactory.createStream(signer);
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            return signer.sign();
        }
        catch (SignatureException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
