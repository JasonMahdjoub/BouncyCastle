package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.io.SignerOutputStream;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.crypto.TlsStreamSigner;
import com.distrimind.bouncycastle.util.io.TeeOutputStream;

class BcVerifyingStreamSigner
    implements TlsStreamSigner
{
    private final Signer signer;
    private final Signer verifier;
    private final TeeOutputStream output;

    BcVerifyingStreamSigner(Signer signer, Signer verifier)
    {
        OutputStream outputSigner = new SignerOutputStream(signer);
        OutputStream outputVerifier = new SignerOutputStream(verifier);

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
            byte[] signature = signer.generateSignature();
            if (verifier.verifySignature(signature))
            {
                return signature;
            }
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
