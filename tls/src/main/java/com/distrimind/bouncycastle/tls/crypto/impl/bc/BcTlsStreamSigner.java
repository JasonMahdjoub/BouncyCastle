package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.io.SignerOutputStream;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamSigner;

class BcTlsStreamSigner
    implements TlsStreamSigner
{
    private final SignerOutputStream output;

    BcTlsStreamSigner(Signer signer)
    {
        this.output = new SignerOutputStream(signer);
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            return output.getSigner().generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
